//! Live runtime (config + keys + clients) behind an `ArcSwap`, with atomic
//! reload on SIGHUP or file change. A failed reload keeps the old runtime.

use std::{
  collections::HashMap,
  num::NonZeroU32,
  path::{Path, PathBuf},
  sync::{Arc, Mutex},
  time::SystemTime,
};

use arc_swap::ArcSwap;
use governor::{DefaultKeyedRateLimiter, Quota};
use tracing::{error, info, warn};

use crate::{
  config::Config,
  github::GitHubApp,
  keys::AppKey,
  oidc::{Issuer, ReplayCache, replay_cache},
};

pub struct Runtime {
  pub config: Config,
  pub issuers: Vec<Arc<Issuer>>,
  pub apps: HashMap<String, Arc<GitHubApp>>,
  pub limiter: Option<Arc<DefaultKeyedRateLimiter<String>>>,
}

impl Runtime {
  /// Load keys and build clients. Issuers with unchanged config keep their JWKS cache.
  pub fn build(
    config: Config,
    previous: Option<&Runtime>,
    http: &reqwest::Client,
  ) -> Result<Runtime, String> {
    let mut apps = HashMap::new();
    for app in &config.apps {
      let keys = app
        .keys
        .iter()
        .map(AppKey::load)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("app {}: {e}", app.name))?;
      apps.insert(
        app.name.clone(),
        Arc::new(GitHubApp::new(
          app.clone(),
          keys,
          http.clone(),
          previous
            .and_then(|p| p.apps.get(&app.name))
            .map(|a| a.as_ref()),
        )),
      );
    }
    let issuers = config
      .issuers
      .iter()
      .map(|cfg| {
        previous
          .and_then(|p| p.issuers.iter().find(|i| &i.config == cfg).cloned())
          .unwrap_or_else(|| Arc::new(Issuer::new(cfg.clone(), http.clone())))
      })
      .collect();
    // Unchanged limits keep their limiter, so a reload does not reset quotas.
    let reused = previous
      .filter(|p| p.config.limits == config.limits)
      .and_then(|p| p.limiter.clone());
    let limiter = reused.or_else(|| {
      config.limits.map(|l| {
        let count = NonZeroU32::new(l.count).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::with_period(l.per / count.get())
          .expect("rate period is non-zero")
          .allow_burst(NonZeroU32::new(l.burst).unwrap_or(NonZeroU32::MIN));
        Arc::new(DefaultKeyedRateLimiter::keyed(quota))
      })
    });
    Ok(Runtime {
      config,
      issuers,
      apps,
      limiter,
    })
  }

  pub fn ready(&self) -> bool {
    self.issuers.iter().all(|i| i.ready())
  }
}

pub struct AppState {
  pub runtime: ArcSwap<Runtime>,
  pub replay: ReplayCache,
  pub http: reqwest::Client,
  pub config_path: PathBuf,
  /// Key files of the last config that parsed, even if loading it failed, so a
  /// key file that shows up later still triggers a reload.
  watched: Mutex<Vec<PathBuf>>,
}

pub fn http_client() -> reqwest::Client {
  reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(15))
    .user_agent("gluon-token-broker")
    // Never follow redirects: JWKS must come from the issuer, API calls from GitHub.
    .redirect(reqwest::redirect::Policy::none())
    .build()
    .expect("http client")
}

impl AppState {
  pub fn new(runtime: Runtime, config_path: PathBuf, http: reqwest::Client) -> AppState {
    AppState {
      watched: Mutex::new(runtime.config.watched_files()),
      runtime: ArcSwap::from_pointee(runtime),
      replay: replay_cache(),
      http,
      config_path,
    }
  }

  /// Re-read config and keys; on any error the running config stays active.
  pub fn reload(&self) -> Result<(), String> {
    let result = Config::load(&self.config_path).and_then(|config| {
      *self.watched.lock().unwrap() = config.watched_files();
      Runtime::build(config, Some(&self.runtime.load()), &self.http)
    });
    let label = if result.is_ok() { "ok" } else { "error" };
    metrics::counter!("broker_config_reload_total", "result" => label).increment(1);
    let runtime = result?;
    self.runtime.store(Arc::new(runtime));
    self.spawn_jwks_fetch();
    info!("configuration reloaded");
    Ok(())
  }

  /// Fetch JWKS for issuers that never succeeded, retrying until they do.
  pub fn spawn_jwks_fetch(&self) {
    for issuer in self.runtime.load().issuers.iter().filter(|i| !i.ready()) {
      let issuer = issuer.clone();
      tokio::spawn(async move {
        let mut delay = std::time::Duration::from_secs(1);
        while let Err(e) = issuer.refresh().await {
          warn!("initial jwks fetch for {} failed: {e}", issuer.config.name);
          tokio::time::sleep(delay).await;
          delay = (delay * 2).min(std::time::Duration::from_secs(60));
        }
      });
    }
  }

  fn fingerprint(&self) -> Vec<Option<SystemTime>> {
    let mut files = vec![self.config_path.clone()];
    files.extend(self.watched.lock().unwrap().iter().cloned());
    files.iter().map(|p| mtime(p)).collect()
  }
}

fn mtime(path: &Path) -> Option<SystemTime> {
  std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// SIGHUP and polling for ConfigMap/Secret updates, which send no signal.
pub fn spawn_reloaders(state: Arc<AppState>) {
  let hup = state.clone();
  tokio::spawn(async move {
    let Ok(mut signal) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
    else {
      error!("cannot install SIGHUP handler");
      return;
    };
    while signal.recv().await.is_some() {
      info!("SIGHUP received, reloading");
      if let Err(e) = hup.reload() {
        error!("reload failed, keeping current config: {e}");
      }
    }
  });

  // Drop limiter entries whose quota has fully recovered.
  let cleanup = state.clone();
  tokio::spawn(async move {
    loop {
      tokio::time::sleep(std::time::Duration::from_secs(60)).await;
      if let Some(limiter) = &cleanup.runtime.load().limiter {
        limiter.retain_recent();
        limiter.shrink_to_fit();
      }
    }
  });

  tokio::spawn(async move {
    let mut last = state.fingerprint();
    loop {
      let interval = state.runtime.load().config.server.reload_interval;
      if interval.is_zero() {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        continue;
      }
      tokio::time::sleep(interval).await;
      let now = state.fingerprint();
      if now != last {
        info!("config or key file changed, reloading");
        if let Err(e) = state.reload() {
          error!("reload failed, keeping current config: {e}");
        }
        // Remember the failed state too, so a broken file is not retried every tick.
        last = state.fingerprint();
      }
    }
  });
}

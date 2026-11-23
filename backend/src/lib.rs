use std::{path::PathBuf, sync::Arc};

use axum::{Router, routing::get};
use centaurus::{
  backend::{init::run_app_connect_info, middleware::logging::logging},
  version_header,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::net::TcpListener;
use tracing::info;

pub use crate::{
  config::Config,
  state::{AppState, Runtime},
};

pub mod api;
pub mod config;
pub mod github;
pub mod keys;
pub mod oidc;
pub mod policy;
pub mod state;

pub struct App {
  app: Router,
  listener: TcpListener,
  metrics: Option<(Router, TcpListener)>,
  pub state: Arc<AppState>,
}

fn prometheus() -> PrometheusHandle {
  static HANDLE: std::sync::OnceLock<PrometheusHandle> = std::sync::OnceLock::new();
  HANDLE
    .get_or_init(|| {
      PrometheusBuilder::new()
        .install_recorder()
        .expect("install metrics recorder")
    })
    .clone()
}

impl App {
  pub async fn new(config_path: PathBuf) -> Result<App, String> {
    let config = Config::load(&config_path)?;
    let http = state::http_client();
    let runtime = Runtime::build(config, None, &http)?;
    let server = runtime.config.server.clone();
    let state = Arc::new(AppState::new(runtime, config_path, http));

    let handle = prometheus();
    let metrics_router =
      Router::new().route("/metrics", get(move || std::future::ready(handle.render())));

    let mut app = logging(api::router(state.clone()), |path| path.starts_with("/v1"));
    version_header!(app);

    let listener = TcpListener::bind(server.listen)
      .await
      .map_err(|e| format!("bind {}: {e}", server.listen))?;
    let metrics = match server.metrics_listen {
      Some(addr) => Some((
        metrics_router,
        TcpListener::bind(addr)
          .await
          .map_err(|e| format!("bind {addr}: {e}"))?,
      )),
      None => {
        app = app.merge(metrics_router);
        None
      }
    };

    state.spawn_jwks_fetch();
    state::spawn_reloaders(state.clone());

    Ok(App {
      app,
      listener,
      metrics,
      state,
    })
  }

  pub fn port(&self) -> u16 {
    self.listener.local_addr().expect("listener address").port()
  }

  pub fn metrics_port(&self) -> Option<u16> {
    self
      .metrics
      .as_ref()
      .map(|(_, l)| l.local_addr().expect("metrics address").port())
  }

  pub async fn run(self) {
    info!("Listening on {}", self.listener.local_addr().unwrap());
    if let Some((router, listener)) = self.metrics {
      info!("Metrics on {}", listener.local_addr().unwrap());
      tokio::spawn(run_app_connect_info(listener, router));
    }
    run_app_connect_info(self.listener, self.app).await;
  }
}

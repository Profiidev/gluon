//! GitHub App API client.

use std::{
  sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
  },
  time::{Duration, Instant},
};

use jsonwebtoken::{Algorithm, Header};
use moka::sync::Cache;
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{instrument, warn};

use crate::{
  config::AppConfig,
  keys::AppKey,
  policy::{Level, Permissions},
};

#[derive(Debug)]
pub enum GhError {
  /// 404 / 422 from GitHub: not installed or not accessible.
  NotInstalled(String),
  /// Rate limited or backing off.
  RateLimited,
  /// Anything else.
  Upstream(String),
}

pub type GhResult<T> = Result<T, GhError>;

enum Auth<'a> {
  App,
  Token(&'a str),
}

#[derive(Debug, Clone)]
pub struct RepoInfo {
  pub id: u64,
  pub owner_id: u64,
  pub installation_id: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MintedRepo {
  pub id: u64,
  pub full_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Minted {
  pub token: String,
  pub expires_at: String,
  #[serde(default)]
  pub permissions: Permissions,
  #[serde(default)]
  pub repositories: Vec<MintedRepo>,
}

#[derive(Serialize)]
struct AppClaims<'a> {
  iat: u64,
  exp: u64,
  iss: &'a str,
}

pub struct GitHubApp {
  pub config: AppConfig,
  keys: Vec<AppKey>,
  /// Index of the key that last worked.
  key_index: AtomicUsize,
  jwt: Mutex<Option<(String, u64, usize)>>,
  http: reqwest::Client,
  // Shared with the previous runtime on reload (moka caches clone by reference).
  backoff_until: Arc<Mutex<Option<Instant>>>,
  installations: Cache<u64, u64>,
  installation_permissions: Cache<u64, Permissions>,
  repos: Cache<String, Result<RepoInfo, String>>,
}

/// GitHub login / repository name: `[A-Za-z0-9._-]{1,100}`, not `.` or `..`.
pub fn valid_name(s: &str) -> bool {
  (1..=100).contains(&s.len())
    && s != "."
    && s != ".."
    && s
      .bytes()
      .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `owner/name` with both parts valid.
pub fn valid_full_name(s: &str) -> bool {
  s.split_once('/')
    .is_some_and(|(o, n)| valid_name(o) && valid_name(n))
}

/// Resolved names live an hour, failures five minutes.
struct RepoExpiry;

impl moka::Expiry<String, Result<RepoInfo, String>> for RepoExpiry {
  fn expire_after_create(
    &self,
    _key: &String,
    value: &Result<RepoInfo, String>,
    _now: Instant,
  ) -> Option<Duration> {
    Some(Duration::from_secs(if value.is_ok() { 3600 } else { 300 }))
  }
}

fn now() -> u64 {
  jsonwebtoken::get_current_timestamp()
}

impl GitHubApp {
  /// `previous` with the same config hands over its caches and rate-limit backoff.
  pub fn new(
    config: AppConfig,
    keys: Vec<AppKey>,
    http: reqwest::Client,
    previous: Option<&GitHubApp>,
  ) -> GitHubApp {
    // Same App on the same API: keep backoff and caches even if keys or
    // installation pins changed (static pins are checked before the cache).
    if let Some(p) = previous
      .filter(|p| p.config.client_id == config.client_id && p.config.api_base == config.api_base)
    {
      return GitHubApp {
        config,
        keys,
        key_index: AtomicUsize::new(0),
        jwt: Mutex::new(None),
        http,
        backoff_until: p.backoff_until.clone(),
        installations: p.installations.clone(),
        installation_permissions: p.installation_permissions.clone(),
        repos: p.repos.clone(),
      };
    }
    GitHubApp {
      config,
      keys,
      key_index: AtomicUsize::new(0),
      jwt: Mutex::new(None),
      http,
      backoff_until: Arc::new(Mutex::new(None)),
      installations: Cache::builder()
        .time_to_live(Duration::from_secs(3600))
        .build(),
      installation_permissions: Cache::builder()
        .time_to_live(Duration::from_secs(300))
        .build(),
      // Failures are cached too, so unknown names cannot be retried in a loop.
      repos: Cache::builder()
        .max_capacity(10_000)
        .expire_after(RepoExpiry)
        .build(),
    }
  }

  /// RS256 app JWT, cached and refreshed one minute before expiry.
  fn app_jwt(&self, key: usize) -> GhResult<String> {
    let mut cache = self.jwt.lock().unwrap();
    if let Some((jwt, exp, k)) = cache.as_ref()
      && *k == key
      && *exp > now() + 60
    {
      return Ok(jwt.clone());
    }
    let iat = now() - 60;
    let exp = iat + 9 * 60;
    let claims = AppClaims {
      iat,
      exp,
      iss: &self.config.client_id,
    };
    let jwt = jsonwebtoken::encode(
      &Header::new(Algorithm::RS256),
      &claims,
      &self.keys[key].encoding,
    )
    .map_err(|_| GhError::Upstream("signing app jwt failed".into()))?;
    *cache = Some((jwt.clone(), exp, key));
    Ok(jwt)
  }

  /// Send a request; for app-JWT calls a 401 rotates through the keys.
  #[instrument(skip(self, auth, body), fields(app = %self.config.name))]
  async fn call(
    &self,
    method: Method,
    path: &str,
    endpoint: &'static str,
    auth: Auth<'_>,
    body: Option<Value>,
  ) -> GhResult<(StatusCode, Value)> {
    // Revoking must still work while backing off, or internal tokens would linger.
    let is_revoke = method == Method::DELETE && path == "/installation/token";
    if !is_revoke
      && let Some(until) = *self.backoff_until.lock().unwrap()
      && until > Instant::now()
    {
      return Err(GhError::RateLimited);
    }
    let attempts = match auth {
      Auth::App => self.keys.len(),
      Auth::Token(_) => 1,
    };
    let start = self.key_index.load(Ordering::Relaxed);
    for attempt in 0..attempts {
      let key = (start + attempt) % self.keys.len().max(1);
      let bearer = match auth {
        Auth::App => self.app_jwt(key)?,
        Auth::Token(t) => t.to_string(),
      };
      let mut req = self
        .http
        .request(method.clone(), format!("{}{path}", self.config.api_base))
        .bearer_auth(bearer)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "gluon-token-broker");
      if let Some(b) = &body {
        req = req.json(b);
      }
      let res = req
        .send()
        .await
        .map_err(|e| GhError::Upstream(format!("{endpoint}: {e}")))?;
      let status = res.status();
      metrics::counter!(
        "broker_github_requests_total",
        "endpoint" => endpoint,
        "status" => status.as_u16().to_string()
      )
      .increment(1);
      let headers = res.headers().clone();
      if status == StatusCode::UNAUTHORIZED && matches!(auth, Auth::App) && attempt + 1 < attempts {
        warn!(
          "app {}: key {} rejected, trying next key",
          self.config.name, self.keys[key].origin
        );
        continue;
      }
      if matches!(auth, Auth::App) && status.is_success() {
        self.key_index.store(key, Ordering::Relaxed);
      }
      let text = res.text().await.unwrap_or_default();
      let value = serde_json::from_str(&text).unwrap_or(Value::Null);
      self.track_rate_limit(&headers, status, &value, matches!(auth, Auth::App));
      return Ok((status, value));
    }
    Err(GhError::Upstream(format!("{endpoint}: no key accepted")))
  }

  /// Record remaining quota and back off on 403/429 rate limits.
  fn track_rate_limit(
    &self,
    headers: &reqwest::header::HeaderMap,
    status: StatusCode,
    body: &Value,
    app_auth: bool,
  ) {
    let header = |name: &str| {
      headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    };
    let remaining = header("x-ratelimit-remaining");
    if let Some(r) = remaining {
      metrics::gauge!(
        "broker_github_ratelimit_remaining",
        "app" => self.config.name.clone(),
        // App-JWT calls count against the app, token calls against an installation.
        "installation" => if app_auth { "app" } else { "installation" }
      )
      .set(r as f64);
    }
    let secondary = status == StatusCode::TOO_MANY_REQUESTS
      || (status == StatusCode::FORBIDDEN
        && body["message"]
          .as_str()
          .is_some_and(|m| m.to_ascii_lowercase().contains("rate limit")));
    if !secondary && !(status == StatusCode::FORBIDDEN && remaining == Some(0)) {
      return;
    }
    // GitHub: honour retry-after, else wait for the reset, else at least a minute.
    let wait = header("retry-after")
      .or_else(|| {
        (remaining == Some(0))
          .then(|| header("x-ratelimit-reset").map(|reset| reset.saturating_sub(now())))
          .flatten()
      })
      .or(Some(60));
    if let Some(secs) = wait {
      let secs = secs.clamp(1, 900);
      warn!(
        "app {}: GitHub rate limit, backing off {secs}s",
        self.config.name
      );
      *self.backoff_until.lock().unwrap() = Some(Instant::now() + Duration::from_secs(secs));
    }
  }

  fn expect_ok(endpoint: &str, status: StatusCode, body: &Value) -> GhResult<()> {
    if status.is_success() {
      return Ok(());
    }
    let msg = format!(
      "{endpoint}: {status} {}",
      body["message"].as_str().unwrap_or("")
    );
    Err(match status {
      // Redirects are not followed; a 301 means the repository was renamed or moved.
      s if s.is_redirection() => {
        warn!(
          "{endpoint}: {status}, repository renamed or moved; update the config if a rule names it"
        );
        GhError::NotInstalled(msg)
      }
      StatusCode::NOT_FOUND | StatusCode::UNPROCESSABLE_ENTITY => GhError::NotInstalled(msg),
      StatusCode::TOO_MANY_REQUESTS => GhError::RateLimited,
      StatusCode::FORBIDDEN if msg.contains("rate limit") => GhError::RateLimited,
      _ => GhError::Upstream(msg),
    })
  }

  /// Installation for an account; static config wins.
  pub async fn installation_for_owner(&self, owner_id: u64, owner_login: &str) -> GhResult<u64> {
    if !valid_name(owner_login) {
      return Err(GhError::NotInstalled("invalid owner login".into()));
    }
    if let Some(id) = self.config.installations.get(&owner_id) {
      return Ok(*id);
    }
    if let Some(id) = self.installations.get(&owner_id) {
      return Ok(id);
    }
    // /users/{u}/installation also resolves organizations.
    let (status, body) = self
      .call(
        Method::GET,
        &format!("/users/{owner_login}/installation"),
        "GET /users/{u}/installation",
        Auth::App,
        None,
      )
      .await?;
    Self::expect_ok("installation lookup", status, &body)?;
    let account_id = body["account"]["id"].as_u64();
    if account_id != Some(owner_id) {
      return Err(GhError::NotInstalled(format!(
        "installation account {account_id:?} does not match owner {owner_id}"
      )));
    }
    let id = body["id"]
      .as_u64()
      .ok_or_else(|| GhError::Upstream("installation without id".into()))?;
    self.installations.insert(owner_id, id);
    Ok(id)
  }

  /// Permissions the installation actually has (cached 5 min).
  pub async fn installation_permissions(&self, installation_id: u64) -> GhResult<Permissions> {
    if let Some(p) = self.installation_permissions.get(&installation_id) {
      return Ok(p);
    }
    let (status, body) = self
      .call(
        Method::GET,
        &format!("/app/installations/{installation_id}"),
        "GET /app/installations/{id}",
        Auth::App,
        None,
      )
      .await?;
    Self::expect_ok("installation", status, &body)?;
    let perms: Permissions = body["permissions"]
      .as_object()
      .map(|m| {
        m.iter()
          .filter_map(|(k, v)| {
            serde_json::from_value::<Level>(v.clone())
              .ok()
              .map(|l| (k.clone(), l))
          })
          .collect()
      })
      .unwrap_or_default();
    self
      .installation_permissions
      .insert(installation_id, perms.clone());
    Ok(perms)
  }

  /// Resolve `owner/name` to its ID, owner and installation.
  pub async fn resolve_repo(self: &Arc<Self>, full_name: &str) -> GhResult<RepoInfo> {
    let key = full_name.to_ascii_lowercase();
    if let Some(cached) = self.repos.get(&key) {
      return cached.map_err(GhError::NotInstalled);
    }
    let result = self.lookup_repo(full_name).await;
    match &result {
      Ok(info) => self.repos.insert(key, Ok(info.clone())),
      Err(GhError::NotInstalled(e)) => self.repos.insert(key, Err(e.clone())),
      // Transient failures are not cached.
      Err(_) => {}
    }
    result
  }

  async fn lookup_repo(self: &Arc<Self>, full_name: &str) -> GhResult<RepoInfo> {
    if !valid_full_name(full_name) {
      return Err(GhError::NotInstalled("invalid repository name".into()));
    }
    let (owner, name) = full_name.split_once('/').unwrap();
    let (status, body) = self
      .call(
        Method::GET,
        &format!("/repos/{owner}/{name}/installation"),
        "GET /repos/{o}/{r}/installation",
        Auth::App,
        None,
      )
      .await?;
    Self::expect_ok("repo installation", status, &body)?;
    let installation_id = body["id"]
      .as_u64()
      .ok_or_else(|| GhError::Upstream("installation without id".into()))?;
    let owner_id = body["account"]["id"]
      .as_u64()
      .ok_or_else(|| GhError::Upstream("installation without account".into()))?;
    // The ID needs an installation token; a metadata-only token for just this repo.
    let body = json!({ "repositories": [name], "permissions": { "metadata": "read" } });
    let id = self
      .with_internal_token(installation_id, body, |_, minted| async move {
        Ok(minted.repositories.first().map(|r| r.id))
      })
      .await?;
    let info = RepoInfo {
      id: id.ok_or_else(|| GhError::NotInstalled(format!("{full_name} not in installation")))?,
      owner_id,
      installation_id,
    };
    Ok(info)
  }

  /// All repository IDs of an installation (owner-wide targets).
  pub async fn installation_repos(self: &Arc<Self>, installation_id: u64) -> GhResult<Vec<u64>> {
    // shortcut: listing needs an installation token without repository_ids; it is
    // metadata-only, never returned to a caller and always revoked.
    let body = json!({ "permissions": { "metadata": "read" } });
    self
      .with_internal_token(installation_id, body, |app, minted| async move {
        let mut ids = Vec::new();
        for page in 1.. {
          let (status, body) = app
            .call(
              Method::GET,
              &format!("/installation/repositories?per_page=100&page={page}"),
              "GET /installation/repositories",
              Auth::Token(&minted.token),
              None,
            )
            .await?;
          Self::expect_ok("installation repos", status, &body)?;
          let repos = body["repositories"].as_array().cloned().unwrap_or_default();
          ids.extend(repos.iter().filter_map(|r| r["id"].as_u64()));
          if repos.len() < 100 {
            break;
          }
        }
        Ok(ids)
      })
      .await
  }

  /// Mint an internal token, hand it to `f`, and always revoke it. Runs as its
  /// own task, so a cancelled request cannot skip the revocation.
  async fn with_internal_token<T, F, Fut>(
    self: &Arc<Self>,
    installation_id: u64,
    body: Value,
    f: F,
  ) -> GhResult<T>
  where
    T: Send + 'static,
    F: FnOnce(Arc<Self>, Minted) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = GhResult<T>> + Send,
  {
    let app = self.clone();
    tokio::spawn(async move {
      let minted = app.mint_raw(installation_id, body).await?;
      let token = minted.token.clone();
      let result = f(app.clone(), minted).await;
      if let Err(e) = app.revoke(&token).await {
        warn!(
          "app {}: revoking internal token failed: {e:?}",
          app.config.name
        );
      }
      result
    })
    .await
    .map_err(|e| GhError::Upstream(format!("internal token task: {e}")))?
  }

  async fn mint_raw(&self, installation_id: u64, body: Value) -> GhResult<Minted> {
    let (status, body) = self
      .call(
        Method::POST,
        &format!("/app/installations/{installation_id}/access_tokens"),
        "POST /app/installations/{id}/access_tokens",
        Auth::App,
        Some(body),
      )
      .await?;
    Self::expect_ok("mint", status, &body)?;
    serde_json::from_value(body).map_err(|e| GhError::Upstream(format!("mint response: {e}")))
  }

  /// Mint a token, always scoped by repository_ids and permissions.
  pub async fn mint(
    &self,
    installation_id: u64,
    repository_ids: &[u64],
    permissions: &Permissions,
  ) -> GhResult<Minted> {
    assert!(
      !repository_ids.is_empty() && !permissions.is_empty(),
      "refusing to mint an unscoped token"
    );
    self
      .mint_raw(
        installation_id,
        json!({ "repository_ids": repository_ids, "permissions": permissions }),
      )
      .await
  }

  /// Revoke an installation token via `DELETE /installation/token`.
  pub async fn revoke(&self, token: &str) -> GhResult<()> {
    let (status, body) = self
      .call(
        Method::DELETE,
        "/installation/token",
        "DELETE /installation/token",
        Auth::Token(token),
        None,
      )
      .await?;
    if status == StatusCode::UNAUTHORIZED {
      // Already expired or revoked.
      return Ok(());
    }
    Self::expect_ok("revoke", status, &body)
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn redirects_mean_not_installed() {
    let err = GitHubApp::expect_ok("x", StatusCode::MOVED_PERMANENTLY, &Value::Null).unwrap_err();
    assert!(matches!(err, GhError::NotInstalled(_)));
  }

  #[test]
  fn names() {
    for ok in ["Profiidev", "a.b_c-d", "x"] {
      assert!(valid_name(ok), "{ok}");
    }
    for bad in ["", ".", "..", "a/b", "a?b", "a b", &"x".repeat(101)] {
      assert!(!valid_name(bad), "{bad}");
    }
  }
}

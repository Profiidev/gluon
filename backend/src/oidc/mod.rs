//! Subject token validation.

use std::{
  collections::HashMap,
  sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
  },
  time::{Duration, Instant},
};

use jsonwebtoken::{DecodingKey, Validation, jwk::JwkSet};
use serde_json::{Map, Value};
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tracing::{instrument, warn};

use crate::config::IssuerConfig;

pub mod caller;

pub use caller::Caller;

/// Minimum time between JWKS fetches made by requests (unknown `kid` or stale cache).
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(3600);
const REPLAY_CAPACITY: usize = 500_000;

/// Seen `jti`s, shared by all issuers and kept across config reloads. Entries are
/// never evicted before the token they belong to has expired; when full, new
/// tokens are refused instead.
pub struct ReplayCache {
  seen: Mutex<HashMap<String, u64>>,
  capacity: usize,
}

pub fn replay_cache() -> ReplayCache {
  ReplayCache::new(REPLAY_CAPACITY)
}

impl ReplayCache {
  pub fn new(capacity: usize) -> ReplayCache {
    ReplayCache {
      seen: Mutex::new(HashMap::new()),
      capacity,
    }
  }

  /// Record `key` until `expires_at` (unix seconds); errors on replay or when full.
  fn insert(&self, key: String, expires_at: u64) -> Result<(), String> {
    let now = jsonwebtoken::get_current_timestamp();
    let mut seen = self.seen.lock().unwrap();
    if seen.get(&key).is_some_and(|e| *e >= now) {
      metrics::counter!("broker_replay_rejected_total").increment(1);
      return Err("replayed jti".into());
    }
    if seen.len() >= self.capacity {
      seen.retain(|_, e| *e >= now);
      if seen.len() >= self.capacity {
        return Err("replay cache full".into());
      }
    }
    seen.insert(key, expires_at);
    Ok(())
  }
}

/// Untrusted values in log messages: bounded and escaped.
fn short(s: &str) -> String {
  format!("{:?}", s.chars().take(64).collect::<String>())
}

struct JwksState {
  keys: HashMap<String, DecodingKey>,
  expires_at: Instant,
}

pub struct Issuer {
  pub config: IssuerConfig,
  http: reqwest::Client,
  jwks: RwLock<Option<JwksState>>,
  /// Single-flight guard for request-triggered fetches.
  refresh_lock: AsyncMutex<Option<Instant>>,
  fetched: AtomicBool,
}

impl Issuer {
  pub fn new(config: IssuerConfig, http: reqwest::Client) -> Issuer {
    Issuer {
      config,
      http,
      jwks: RwLock::new(None),
      refresh_lock: AsyncMutex::new(None),
      fetched: AtomicBool::new(false),
    }
  }

  /// `/readyz`: JWKS fetched at least once.
  pub fn ready(&self) -> bool {
    self.fetched.load(Ordering::Relaxed)
  }

  async fn jwks_url(&self) -> Result<String, String> {
    if let Some(url) = &self.config.jwks_url {
      return Ok(url.clone());
    }
    let discovery = format!("{}/.well-known/openid-configuration", self.config.url);
    let doc: Value = self
      .http
      .get(&discovery)
      .send()
      .await
      .and_then(|r| r.error_for_status())
      .map_err(|e| format!("discovery: {e}"))?
      .json()
      .await
      .map_err(|e| format!("discovery: {e}"))?;
    let uri = doc["jwks_uri"].as_str().ok_or("discovery: no jwks_uri")?;
    // The JWKS must live on the issuer's own origin (scheme, host and port).
    let origin = |u: &str| {
      reqwest::Url::parse(u).ok().map(|u| {
        (
          u.scheme().to_string(),
          u.host_str().map(String::from),
          u.port_or_known_default(),
        )
      })
    };
    if origin(uri).is_none() || origin(uri) != origin(&self.config.url) {
      return Err(format!(
        "discovery: jwks_uri {} is not on the issuer origin",
        short(uri)
      ));
    }
    Ok(uri.to_string())
  }

  #[instrument(skip(self), fields(issuer = %self.config.name))]
  pub async fn refresh(&self) -> Result<(), String> {
    let result = self.fetch().await;
    let label = if result.is_ok() { "ok" } else { "error" };
    metrics::counter!("broker_jwks_refresh_total", "issuer" => self.config.name.clone(), "result" => label)
      .increment(1);
    let (keys, ttl) = result?;
    *self.jwks.write().await = Some(JwksState {
      keys,
      expires_at: Instant::now() + ttl,
    });
    self.fetched.store(true, Ordering::Relaxed);
    Ok(())
  }

  async fn fetch(&self) -> Result<(HashMap<String, DecodingKey>, Duration), String> {
    let url = self.jwks_url().await?;
    let res = self
      .http
      .get(&url)
      .send()
      .await
      .and_then(|r| r.error_for_status())
      .map_err(|e| format!("jwks: {e}"))?;
    let ttl = res
      .headers()
      .get(reqwest::header::CACHE_CONTROL)
      .and_then(|v| v.to_str().ok())
      .and_then(|v| {
        v.split(',')
          .find_map(|d| d.trim().strip_prefix("max-age=")?.parse::<u64>().ok())
      })
      .map(Duration::from_secs)
      .unwrap_or(DEFAULT_JWKS_TTL)
      .clamp(Duration::from_secs(60), Duration::from_secs(24 * 3600));
    let set: JwkSet = res.json().await.map_err(|e| format!("jwks: {e}"))?;
    let mut keys = HashMap::new();
    for jwk in &set.keys {
      let Some(kid) = jwk.common.key_id.clone() else {
        continue;
      };
      match DecodingKey::from_jwk(jwk) {
        Ok(k) => {
          keys.insert(kid, k);
        }
        Err(e) => warn!("jwks: skipping key {kid}: {e}"),
      }
    }
    Ok((keys, ttl))
  }

  async fn cached(&self, kid: &str, fresh_only: bool) -> Option<DecodingKey> {
    let jwks = self.jwks.read().await;
    let state = jwks.as_ref()?;
    if fresh_only && state.expires_at <= Instant::now() {
      return None;
    }
    state.keys.get(kid).cloned()
  }

  /// Look up a key; on a miss or stale cache refetch at most once per
  /// interval, with concurrent requests sharing one fetch. Stale keys are
  /// used while the issuer is unreachable.
  async fn key(&self, kid: &str) -> Option<DecodingKey> {
    if let Some(k) = self.cached(kid, true).await {
      return Some(k);
    }
    let mut last = self.refresh_lock.lock().await;
    if let Some(k) = self.cached(kid, true).await {
      return Some(k);
    }
    if last.is_none_or(|t| t.elapsed() >= REFRESH_INTERVAL) {
      *last = Some(Instant::now());
      if let Err(e) = self.refresh().await {
        warn!("jwks refresh for {} failed: {e}", self.config.name);
      }
    }
    drop(last);
    self.cached(kid, false).await
  }
}

/// Validate a subject token against the configured issuers.
/// The error is a log-only reason.
pub async fn validate(
  issuers: &[Arc<Issuer>],
  replay: &ReplayCache,
  token: &str,
) -> Result<Caller, String> {
  let header = jsonwebtoken::decode_header(token).map_err(|e| format!("header: {e}"))?;
  let unverified: Map<String, Value> =
    jsonwebtoken::dangerous::insecure_decode_claims(token).map_err(|e| format!("claims: {e}"))?;
  let iss = unverified
    .get("iss")
    .and_then(Value::as_str)
    .ok_or("missing iss")?;
  let issuer = issuers
    .iter()
    .find(|i| i.config.url == iss.trim_end_matches('/'))
    .ok_or_else(|| format!("untrusted issuer {}", short(iss)))?;
  let cfg = &issuer.config;

  if !cfg.algorithms.contains(&header.alg) {
    return Err(format!("algorithm {:?} not allowed", header.alg));
  }
  let kid = header.kid.as_deref().ok_or("missing kid")?;
  let key = issuer
    .key(kid)
    .await
    .ok_or_else(|| format!("unknown kid {}", short(kid)))?;

  let mut validation = Validation::new(header.alg);
  validation.algorithms = vec![header.alg];
  validation.leeway = cfg.clock_skew.as_secs();
  validation.validate_exp = true;
  validation.validate_nbf = true;
  validation.set_audience(&[&cfg.audience]);
  validation.set_issuer(&[iss]);
  validation.set_required_spec_claims(&["exp", "iat", "iss", "aud"]);
  let claims = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
    .map_err(|e| format!("verify: {e}"))?
    .claims;
  // The audience must be exactly ours, not one entry of a list.
  if claims.get("aud").and_then(Value::as_str) != Some(cfg.audience.as_str()) {
    return Err("aud is not exactly the configured audience".into());
  }

  let now = jsonwebtoken::get_current_timestamp();
  let iat = claims
    .get("iat")
    .and_then(Value::as_u64)
    .ok_or("invalid iat")?;
  if iat > now + cfg.clock_skew.as_secs() {
    return Err("iat in the future".into());
  }
  if now.saturating_sub(iat) > cfg.max_token_age.as_secs() {
    return Err("token too old".into());
  }
  for claim in &cfg.required_claims {
    if claims
      .get(claim)
      .is_none_or(|v| v.is_null() || v.as_str() == Some(""))
    {
      return Err(format!("missing claim {claim}"));
    }
  }

  let caller = Caller::from_claims(cfg, claims);

  if cfg.replay_protection {
    let jti = caller.jti.as_deref().ok_or("missing jti")?;
    // Keep the entry for as long as the token could still be accepted.
    let expires_at = iat + cfg.max_token_age.as_secs() + cfg.clock_skew.as_secs();
    replay.insert(format!("{}|{jti}", cfg.url), expires_at)?;
  }
  Ok(caller)
}

#[cfg(test)]
mod test;

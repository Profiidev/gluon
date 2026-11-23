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
use moka::sync::Cache;
use serde_json::{Map, Value};
use tokio::sync::RwLock;
use tracing::{instrument, warn};

use crate::config::IssuerConfig;

pub mod caller;

pub use caller::Caller;

/// Minimum time between JWKS refetches triggered by unknown `kid`s.
const FORCED_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(3600);

/// Replay set shared by all issuers, kept across config reloads.
pub type ReplayCache = Cache<String, ()>;

pub fn replay_cache() -> ReplayCache {
  // Entries live until the longest possible token age has passed.
  Cache::builder()
    .max_capacity(1_000_000)
    .time_to_live(Duration::from_secs(3600))
    .build()
}

struct JwksState {
  keys: HashMap<String, DecodingKey>,
  expires_at: Instant,
}

pub struct Issuer {
  pub config: IssuerConfig,
  http: reqwest::Client,
  jwks: RwLock<Option<JwksState>>,
  last_forced: Mutex<Option<Instant>>,
  fetched: AtomicBool,
}

impl Issuer {
  pub fn new(config: IssuerConfig, http: reqwest::Client) -> Issuer {
    Issuer {
      config,
      http,
      jwks: RwLock::new(None),
      last_forced: Mutex::new(None),
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
    doc["jwks_uri"]
      .as_str()
      .map(String::from)
      .ok_or_else(|| "discovery: no jwks_uri".into())
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

  /// Look up a key; refetch once if unknown or stale (rate limited).
  async fn key(&self, kid: &str) -> Option<DecodingKey> {
    {
      let jwks = self.jwks.read().await;
      if let Some(state) = jwks.as_ref()
        && state.expires_at > Instant::now()
        && let Some(k) = state.keys.get(kid)
      {
        return Some(k.clone());
      }
    }
    let allowed = {
      let mut last = self.last_forced.lock().unwrap();
      let stale = self
        .jwks
        .try_read()
        .map(|j| j.as_ref().is_none_or(|s| s.expires_at <= Instant::now()))
        .unwrap_or(false);
      let ok = stale || last.is_none_or(|t| t.elapsed() >= FORCED_REFRESH_INTERVAL);
      if ok {
        *last = Some(Instant::now());
      }
      ok
    };
    if allowed && let Err(e) = self.refresh().await {
      warn!("jwks refresh for {} failed: {e}", self.config.name);
    }
    self.jwks.read().await.as_ref()?.keys.get(kid).cloned()
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
    .ok_or_else(|| format!("untrusted issuer {iss}"))?;
  let cfg = &issuer.config;

  if !cfg.algorithms.contains(&header.alg) {
    return Err(format!("algorithm {:?} not allowed", header.alg));
  }
  let kid = header.kid.as_deref().ok_or("missing kid")?;
  let key = issuer
    .key(kid)
    .await
    .ok_or_else(|| format!("unknown kid {kid}"))?;

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
    if claims.get(claim).is_none_or(Value::is_null) {
      return Err(format!("missing claim {claim}"));
    }
  }

  let caller = Caller::from_claims(cfg, claims);

  if cfg.replay_protection {
    let jti = caller.jti.as_deref().ok_or("missing jti")?;
    let entry = replay.entry(format!("{}|{jti}", cfg.url)).or_insert(());
    if !entry.is_fresh() {
      metrics::counter!("broker_replay_rejected_total").increment(1);
      return Err(format!("replayed jti {jti}"));
    }
  }
  Ok(caller)
}

#[cfg(test)]
mod test;

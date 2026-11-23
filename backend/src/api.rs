//! HTTP API and audit logging.

use std::{
  collections::{BTreeMap, BTreeSet},
  net::{IpAddr, SocketAddr},
  sync::Arc,
  time::Instant,
};

use axum::{
  Json, Router,
  body::Bytes,
  extract::{ConnectInfo, Query, State},
  http::{HeaderMap, StatusCode, header},
  response::{IntoResponse, Response},
  routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, instrument, warn};

use centaurus::backend::middleware::rate_limiter::RateLimiter;

use crate::{
  github::{GhError, GitHubApp, valid_full_name},
  oidc::{self, Caller},
  policy::{self, EvalError, Permissions, RepoRef, Resolved, TokenRequest},
  state::AppState,
};

type AppStateRef = Arc<AppState>;

/// Upper bound for `repositories` + `repository_ids` in one request.
const MAX_REQUESTED_TARGETS: usize = 20;

/// Mounted under `/api` by centaurus, which also serves `/api/health`.
pub fn router(state: AppStateRef, limiter: &mut RateLimiter) -> Router {
  Router::new()
    .route(
      "/v1/token",
      post(post_token).get(get_token).delete(delete_token),
    )
    .route("/v1/exchange", post(exchange))
    // Coarse per-IP limit in front of token validation; the per-repository
    // limit applies after it.
    .layer(limiter.create_limiter())
    .route("/readyz", get(readyz))
    .with_state(state)
}

async fn readyz(State(state): State<AppStateRef>) -> Response {
  if state.runtime.load().ready() {
    (StatusCode::OK, "OK").into_response()
  } else {
    (StatusCode::SERVICE_UNAVAILABLE, "JWKS not fetched yet").into_response()
  }
}

// ---------------------------------------------------------------------------
// Errors: generic bodies, details only in logs.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ApiError {
  pub status: StatusCode,
  pub code: &'static str,
  /// Log-only.
  pub detail: String,
}

impl ApiError {
  fn new(status: StatusCode, code: &'static str, detail: impl Into<String>) -> ApiError {
    ApiError {
      status,
      code,
      detail: detail.into(),
    }
  }
  fn invalid_request(d: impl Into<String>) -> ApiError {
    Self::new(StatusCode::BAD_REQUEST, "invalid_request", d)
  }
  fn invalid_token(d: impl Into<String>) -> ApiError {
    Self::new(StatusCode::UNAUTHORIZED, "invalid_token", d)
  }
  fn denied(d: impl Into<String>) -> ApiError {
    Self::new(StatusCode::FORBIDDEN, "access_denied", d)
  }
  fn not_installed(d: impl Into<String>) -> ApiError {
    Self::new(StatusCode::UNPROCESSABLE_ENTITY, "not_installed", d)
  }
  fn upstream(d: impl Into<String>) -> ApiError {
    Self::new(StatusCode::BAD_GATEWAY, "upstream_error", d)
  }
}

impl From<EvalError> for ApiError {
  fn from(e: EvalError) -> Self {
    match e {
      EvalError::Denied(d) => ApiError::denied(d),
      EvalError::NotInstalled(d) => ApiError::not_installed(d),
    }
  }
}

impl From<GhError> for ApiError {
  fn from(e: GhError) -> Self {
    match e {
      GhError::NotInstalled(d) => ApiError::not_installed(d),
      GhError::RateLimited => ApiError::upstream("GitHub rate limit"),
      GhError::Upstream(d) => ApiError::upstream(d),
    }
  }
}

impl IntoResponse for ApiError {
  fn into_response(self) -> Response {
    let description = match self.code {
      "invalid_request" => "The request is malformed.",
      "invalid_token" => "The subject token is invalid.",
      "access_denied" => "The request is not permitted.",
      "not_installed" => "The GitHub App cannot grant this.",
      "rate_limited" => "Too many requests.",
      "unsupported_grant_type" => "The grant type is not supported.",
      _ => "The GitHub API request failed.",
    };
    (
      self.status,
      Json(json!({ "error": self.code, "error_description": description })),
    )
      .into_response()
  }
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[derive(Serialize, Default)]
struct Audit {
  audit: bool,
  ts: String,
  action: &'static str,
  client_ip: Option<String>,
  jti: Option<String>,
  issuer: Option<String>,
  repository_id: Option<String>,
  repository: Option<String>,
  #[serde(rename = "ref")]
  ref_: Option<String>,
  job_workflow_ref: Option<String>,
  event_name: Option<String>,
  runner_environment: Option<String>,
  profile: Option<String>,
  requested_repositories: Vec<String>,
  requested_repository_ids: Vec<u64>,
  requested_permissions: Permissions,
  granted_repository_ids: Vec<u64>,
  granted_permissions: Permissions,
  rule: Option<String>,
  app: Option<String>,
  installation_id: Option<u64>,
  outcome: &'static str,
  status: u16,
  reason: Option<String>,
  expires_at: Option<String>,
  token_sha256: Option<String>,
  latency_ms: u128,
}

pub fn token_hash(token: &str) -> String {
  hex::encode(&Sha256::digest(token.as_bytes())[..8])
}

impl Audit {
  fn caller(&mut self, c: &Caller) {
    self.jti = c.jti.clone();
    self.issuer = Some(c.issuer.clone());
    self.repository_id = c.repository_id.clone();
    self.repository = c.repository.clone();
    self.ref_ = c.ref_.clone();
    self.job_workflow_ref = c.job_workflow_ref.clone();
    self.event_name = c.event_name.clone();
    self.runner_environment = c.runner_environment.clone();
  }

  fn emit(mut self, start: Instant, result: Result<(), &ApiError>) {
    self.audit = true;
    self.ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    self.latency_ms = start.elapsed().as_millis();
    match result {
      Ok(()) => {
        self.outcome = "granted";
        self.status = 200;
      }
      Err(e) => {
        self.outcome = e.code;
        self.status = e.status.as_u16();
        self.reason = Some(e.detail.clone());
      }
    }
    metrics::counter!(
      "broker_requests_total",
      "outcome" => self.outcome,
      "rule" => self.rule.clone().unwrap_or_else(|| "none".into()),
      "app" => self.app.clone().unwrap_or_else(|| "none".into())
    )
    .increment(1);
    metrics::histogram!("broker_request_duration_seconds").record(start.elapsed().as_secs_f64());
    // One JSON line per request on stdout, next to the regular logs.
    if let Ok(line) = serde_json::to_string(&self) {
      println!("{line}");
    }
  }
}

fn client_ip(state: &AppState, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
  forwarded_ip(
    &state.runtime.load().config.server.trusted_proxies,
    peer.ip(),
    headers,
  )
}

fn forwarded_ip(proxies: &[ipnet::IpNet], peer: IpAddr, headers: &HeaderMap) -> IpAddr {
  let trusted = |ip: &IpAddr| proxies.iter().any(|n| n.contains(ip));
  let mut ip = peer;
  // Proxies may append a separate header line instead of extending the first one.
  let xff = headers
    .get_all("x-forwarded-for")
    .iter()
    .filter_map(|v| v.to_str().ok())
    .collect::<Vec<_>>()
    .join(",");
  if trusted(&ip) && !xff.is_empty() {
    // Walk from the closest hop back until the first untrusted address.
    // An unparsable hop ends the walk: everything before it is client-supplied.
    for hop in xff.rsplit(',').map(|h| h.trim().parse::<IpAddr>()) {
      let Ok(hop) = hop else { break };
      ip = hop;
      if !trusted(&hop) {
        break;
      }
    }
  }
  ip
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
  headers
    .get(header::AUTHORIZATION)?
    .to_str()
    .ok()?
    .split_once(' ')
    .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
    .map(|(_, t)| t.trim())
}

// ---------------------------------------------------------------------------
// Token issuance
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct TokenResponse {
  pub token: String,
  pub expires_at: String,
  pub permissions: Permissions,
  pub repository_ids: Vec<u64>,
  pub repositories: Vec<String>,
  pub rule: String,
  pub app: String,
}

#[instrument(skip_all)]
async fn issue(
  state: &AppState,
  subject: Option<&str>,
  req: TokenRequest,
  ip: IpAddr,
  action: &'static str,
) -> Result<TokenResponse, ApiError> {
  let start = Instant::now();
  let mut audit = Audit {
    action,
    client_ip: Some(ip.to_string()),
    profile: req.profile.clone(),
    requested_repositories: req.repositories.clone(),
    requested_repository_ids: req.repository_ids.clone(),
    requested_permissions: req.permissions.clone(),
    ..Default::default()
  };
  let result = issue_inner(state, subject, &req, &mut audit).await;
  match &result {
    Ok(t) => {
      audit.expires_at = Some(t.expires_at.clone());
      audit.token_sha256 = Some(token_hash(&t.token));
      audit.emit(start, Ok(()));
    }
    Err(e) => {
      info!("token request refused: {} ({})", e.code, e.detail);
      audit.emit(start, Err(e));
    }
  }
  result
}

/// Per-repository limit. Only checked for callers a rule accepts, so the
/// limiter's key set stays bounded by the configured accounts.
fn rate_limit(
  runtime: &crate::state::Runtime,
  caller: &Caller,
  bucket: &str,
) -> Result<(), ApiError> {
  let Some(limiter) = &runtime.limiter else {
    return Ok(());
  };
  let key = format!(
    "{bucket}|{}|{}",
    caller.issuer,
    caller
      .repository_id
      .clone()
      .or(caller.sub.clone())
      .unwrap_or_default()
  );
  if limiter.check_key(&key).is_err() {
    return Err(ApiError::new(
      StatusCode::TOO_MANY_REQUESTS,
      "rate_limited",
      format!("rate limit for {key}"),
    ));
  }
  Ok(())
}

async fn issue_inner(
  state: &AppState,
  subject: Option<&str>,
  req: &TokenRequest,
  audit: &mut Audit,
) -> Result<TokenResponse, ApiError> {
  let runtime = state.runtime.load_full();
  let subject = subject.ok_or_else(|| ApiError::invalid_token("missing bearer token"))?;
  let (caller, replay_key) = oidc::validate(&runtime.issuers, subject)
    .await
    .map_err(ApiError::invalid_token)?;
  audit.caller(&caller);

  if req.repositories.len() + req.repository_ids.len() > MAX_REQUESTED_TARGETS {
    return Err(ApiError::invalid_request("too many requested targets"));
  }
  if let Some(name) = req.repositories.iter().find(|n| !valid_full_name(n)) {
    return Err(ApiError::invalid_request(format!(
      "bad repository {:?}",
      name.chars().take(100).collect::<String>()
    )));
  }

  let rule = policy::select(&caller, req, &runtime.config.policy)?;
  // Order: replays are refused before they cost quota, a rate-limited token is
  // not burned (it is only recorded after the limit), and only callers some
  // rule accepts reach the limiter and the replay store at all.
  if let Some((key, _)) = &replay_key
    && state.replay.seen(key)
  {
    return Err(ApiError::invalid_token("replayed jti"));
  }
  rate_limit(&runtime, &caller, "issue")?;
  if let Some((key, expires_at)) = replay_key {
    state
      .replay
      .insert(key, expires_at)
      .map_err(ApiError::invalid_token)?;
  }
  audit.rule = Some(rule.name.clone());
  audit.app = Some(rule.grant.app.clone());
  let app = runtime
    .apps
    .get(&rule.grant.app)
    .ok_or_else(|| ApiError::upstream("app missing from runtime"))?;

  let (installation_id, resolved) = resolve_targets(app, &caller, rule, req).await?;
  audit.installation_id = Some(installation_id);

  let installation_permissions = app.installation_permissions(installation_id).await?;
  let decision = policy::finalize(&caller, req, rule, &resolved, &installation_permissions)?;

  let minted = app
    .mint(
      installation_id,
      &decision.repository_ids,
      &decision.permissions,
    )
    .await?;
  audit.granted_repository_ids = decision.repository_ids.clone();
  audit.granted_permissions = minted.permissions.clone();

  Ok(TokenResponse {
    token: minted.token,
    expires_at: minted.expires_at,
    permissions: minted.permissions,
    repository_ids: decision.repository_ids,
    repositories: minted
      .repositories
      .into_iter()
      .map(|r| r.full_name)
      .collect(),
    rule: rule.name.clone(),
    app: rule.grant.app.clone(),
  })
}

/// Turn rule and requested targets into IDs and find the single installation they all belong to.
async fn resolve_targets(
  app: &Arc<GitHubApp>,
  caller: &Caller,
  rule: &policy::Rule,
  req: &TokenRequest,
) -> Result<(u64, Resolved), ApiError> {
  let mut installations = BTreeSet::new();
  let mut rule_ids = Vec::new();
  let mut caller_owner = None;

  let caller_github = || -> Result<(u64, u64, String), ApiError> {
    if !caller.github_ids {
      return Err(ApiError::denied("self/owner targets need a GitHub issuer"));
    }
    let parse = |v: &Option<String>| v.as_deref().and_then(|s| s.parse::<u64>().ok());
    match (
      parse(&caller.repository_id),
      parse(&caller.owner_id),
      caller.owner.clone(),
    ) {
      (Some(r), Some(o), Some(login)) => Ok((r, o, login)),
      _ => Err(ApiError::invalid_token("caller lacks repository/owner ids")),
    }
  };

  if rule.grant.target.include_self || rule.grant.target.owner_wide {
    let (repo_id, owner_id, login) = caller_github()?;
    let inst = app.installation_for_owner(owner_id, &login).await?;
    installations.insert(inst);
    caller_owner = Some(inst);
    if rule.grant.target.include_self {
      rule_ids.push(repo_id);
    }
    if rule.grant.target.owner_wide {
      rule_ids.extend(app.installation_repos(inst).await?);
    }
  }

  let mut names: BTreeMap<String, u64> = BTreeMap::new();
  let rule_names: Vec<&str> = rule
    .grant
    .target
    .repos
    .iter()
    .filter_map(|r| match r {
      RepoRef::Name(n) => Some(n.as_str()),
      RepoRef::Id(_) => None,
    })
    .collect();
  for name in rule_names {
    let info = app.resolve_repo(name).await?;
    installations.insert(info.installation_id);
    names.insert(name.to_ascii_lowercase(), info.id);
  }
  // Requested names: only look up names that can be in the grant at all, and
  // answer access_denied for unknown ones so callers learn nothing about them.
  let caller_repo = caller.repository.as_deref().map(str::to_ascii_lowercase);
  let caller_owner_name = caller.owner.as_deref().map(str::to_ascii_lowercase);
  // Installation(s) the grant itself lives in; requested names must match it.
  let mut grant_installs = installations.clone();
  let needs_lookup = rule.grant.target.owner_wide
    || rule
      .grant
      .target
      .repos
      .iter()
      .any(|r| matches!(r, RepoRef::Id(_)));
  for name in &req.repositories {
    let lower = name.to_ascii_lowercase();
    if names.contains_key(&lower) {
      continue;
    }
    if rule.grant.target.include_self && caller_repo.as_deref() == Some(lower.as_str()) {
      let (repo_id, _, _) = caller_github()?;
      names.insert(lower, repo_id);
      continue;
    }
    if !needs_lookup {
      return Err(ApiError::denied("requested repository outside the grant"));
    }
    // An owner-wide grant only covers the caller's own account.
    if rule.grant.target.owner_wide && lower.split('/').next() != caller_owner_name.as_deref() {
      return Err(ApiError::denied("requested repository outside the owner"));
    }
    if grant_installs.is_empty() {
      // ID-only grant: it lives in the caller's installation.
      let (_, owner_id, login) = caller_github()
        .map_err(|_| ApiError::invalid_request("cannot locate installation for ID-only targets"))?;
      grant_installs.insert(app.installation_for_owner(owner_id, &login).await?);
    }
    let info = app.resolve_repo(name).await.map_err(|e| match e {
      GhError::NotInstalled(d) => ApiError::denied(format!("requested repository: {d}")),
      e => e.into(),
    })?;
    // Same answer as for unknown names: nothing about other installations leaks.
    if !grant_installs.contains(&info.installation_id) {
      return Err(ApiError::denied(
        "requested repository in another installation",
      ));
    }
    installations.insert(info.installation_id);
    names.insert(lower, info.id);
  }
  for r in &rule.grant.target.repos {
    rule_ids.push(match r {
      RepoRef::Id(id) => *id,
      RepoRef::Name(n) => names[&n.to_ascii_lowercase()],
    });
  }

  let requested_targets = req.has_target().then(|| {
    req
      .repository_ids
      .iter()
      .copied()
      .chain(
        req
          .repositories
          .iter()
          .map(|n| names[&n.to_ascii_lowercase()]),
      )
      .collect()
  });

  if installations.len() > 1 {
    return Err(ApiError::invalid_request(
      "targets span more than one installation",
    ));
  }
  // Only IDs known: they must live next to the caller (mint fails otherwise).
  let installation = match installations
    .into_iter()
    .next()
    .or(caller_owner)
    .or(grant_installs.into_iter().next())
  {
    Some(i) => i,
    None => {
      let (_, owner_id, login) = caller_github()
        .map_err(|_| ApiError::invalid_request("cannot locate installation for ID-only targets"))?;
      app.installation_for_owner(owner_id, &login).await?
    }
  };

  Ok((
    installation,
    Resolved {
      rule_targets: rule_ids,
      requested_targets,
    },
  ))
}

async fn post_token(
  State(state): State<AppStateRef>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  body: Bytes,
) -> Result<Json<TokenResponse>, ApiError> {
  let req: TokenRequest = if body.iter().all(u8::is_ascii_whitespace) {
    TokenRequest::default()
  } else {
    serde_json::from_slice(&body).map_err(|e| ApiError::invalid_request(e.to_string()))?
  };
  let ip = client_ip(&state, peer, &headers);
  issue(&state, bearer(&headers), req, ip, "token")
    .await
    .map(Json)
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct TokenQuery {
  profile: Option<String>,
  /// Comma separated `owner/name`.
  repositories: Option<String>,
  /// Comma separated IDs.
  repository_ids: Option<String>,
  /// Comma separated `name:level`.
  permissions: Option<String>,
}

fn split(s: &Option<String>) -> impl Iterator<Item = &str> {
  s.as_deref()
    .unwrap_or("")
    .split(',')
    .map(str::trim)
    .filter(|s| !s.is_empty())
}

async fn get_token(
  State(state): State<AppStateRef>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  query: Result<Query<TokenQuery>, axum::extract::rejection::QueryRejection>,
) -> Result<Json<TokenResponse>, ApiError> {
  let Query(q) = query.map_err(|e| ApiError::invalid_request(e.to_string()))?;
  let mut req = TokenRequest {
    profile: q.profile.clone(),
    repositories: split(&q.repositories).map(String::from).collect(),
    ..Default::default()
  };
  for id in split(&q.repository_ids) {
    req.repository_ids.push(
      id.parse()
        .map_err(|_| ApiError::invalid_request("bad repository id"))?,
    );
  }
  for p in split(&q.permissions) {
    let (name, level) = p
      .split_once(':')
      .ok_or_else(|| ApiError::invalid_request("permissions must be name:level"))?;
    let level = serde_json::from_value(json!(level))
      .map_err(|_| ApiError::invalid_request("bad permission level"))?;
    req.permissions.insert(name.to_string(), level);
  }
  let ip = client_ip(&state, peer, &headers);
  issue(&state, bearer(&headers), req, ip, "token")
    .await
    .map(Json)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
  token: String,
}

/// Revoke a GitHub token; the caller must still present a valid subject token.
async fn delete_token(
  State(state): State<AppStateRef>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  body: Bytes,
) -> Result<StatusCode, ApiError> {
  let start = Instant::now();
  let mut audit = Audit {
    action: "revoke",
    client_ip: Some(client_ip(&state, peer, &headers).to_string()),
    ..Default::default()
  };
  let result = async {
    let runtime = state.runtime.load_full();
    let subject =
      bearer(&headers).ok_or_else(|| ApiError::invalid_token("missing bearer token"))?;
    // Revoking is idempotent, so replays are harmless here and the replay
    // store stays reserved for callers a rule accepts.
    let (caller, _) = oidc::validate(&runtime.issuers, subject)
      .await
      .map_err(ApiError::invalid_token)?;
    audit.caller(&caller);
    // Only callers some rule or profile covers may use the broker's GitHub client.
    let rule = policy::revoke_rule(&caller, &runtime.config.policy)
      .ok_or_else(|| ApiError::denied("no rule or profile covers the caller"))?;
    audit.rule = Some(rule.name.clone());
    // Own bucket: revoking never uses up the quota for issuing tokens.
    rate_limit(&runtime, &caller, "revoke")?;
    let req: RevokeRequest =
      serde_json::from_slice(&body).map_err(|e| ApiError::invalid_request(e.to_string()))?;
    audit.token_sha256 = Some(token_hash(&req.token));
    // Revocation authenticates with the token itself; the rule's app client is used.
    let app = runtime
      .apps
      .get(&rule.grant.app)
      .ok_or_else(|| ApiError::upstream("app missing from runtime"))?;
    audit.app = Some(rule.grant.app.clone());
    app.revoke(&req.token).await?;
    Ok(StatusCode::NO_CONTENT)
  }
  .await;
  audit.emit(start, result.as_ref().map(|_| ()));
  if let Err(e) = &result {
    warn!("revoke refused: {} ({})", e.code, e.detail);
  }
  result
}

// ---------------------------------------------------------------------------
// RFC 8693 token exchange
// ---------------------------------------------------------------------------

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
const ID_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id_token";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

#[derive(Deserialize)]
struct ExchangeRequest {
  grant_type: String,
  subject_token: String,
  subject_token_type: String,
  resource: Option<String>,
  scope: Option<String>,
}

async fn exchange(
  State(state): State<AppStateRef>,
  ConnectInfo(peer): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  body: Bytes,
) -> Response {
  let ip = client_ip(&state, peer, &headers);
  let json = headers
    .get(header::CONTENT_TYPE)
    .and_then(|v| v.to_str().ok())
    .is_some_and(|v| v.starts_with("application/json"));
  let parsed: Result<ExchangeRequest, String> = if json {
    serde_json::from_slice(&body).map_err(|e| e.to_string())
  } else {
    serde_urlencoded::from_bytes(&body).map_err(|e| e.to_string())
  };
  let ex = match parsed {
    Ok(ex) => ex,
    Err(e) => return ApiError::invalid_request(e).into_response(),
  };
  if ex.grant_type != GRANT_TYPE {
    return ApiError::new(
      StatusCode::BAD_REQUEST,
      "unsupported_grant_type",
      "grant_type",
    )
    .into_response();
  }
  if ex.subject_token_type != JWT_TYPE && ex.subject_token_type != ID_TOKEN_TYPE {
    return ApiError::invalid_request("subject_token_type").into_response();
  }
  let mut req = TokenRequest {
    profile: ex.scope.filter(|s| !s.is_empty()),
    ..Default::default()
  };
  match ex.resource.as_deref().map(str::trim) {
    None | Some("") => {}
    Some(r) if r.contains('/') => req.repositories.push(r.to_string()),
    // A bare owner means "the rule's own target".
    Some(r) => {
      if let Ok(id) = r.parse::<u64>() {
        req.repository_ids.push(id);
      }
    }
  }
  match issue(&state, Some(&ex.subject_token), req, ip, "exchange").await {
    Ok(t) => {
      let expires_in = chrono::DateTime::parse_from_rfc3339(&t.expires_at)
        .map(|e| (e.timestamp() - chrono::Utc::now().timestamp()).max(0))
        .unwrap_or(3600);
      Json(json!({
        "access_token": t.token,
        "issued_token_type": ACCESS_TOKEN_TYPE,
        "token_type": "Bearer",
        "expires_in": expires_in,
      }))
      .into_response()
    }
    Err(e) => e.into_response(),
  }
}

#[cfg(test)]
mod test {
  use super::*;

  #[test]
  fn forwarded_ip_walks_all_header_lines() {
    let proxies: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let proxy: IpAddr = "10.0.0.5".parse().unwrap();
    let mut headers = HeaderMap::new();
    // Client-supplied first line, proxy-added second line.
    headers.append("x-forwarded-for", "6.6.6.6".parse().unwrap());
    headers.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
    assert_eq!(
      forwarded_ip(&proxies, proxy, &headers),
      "1.2.3.4".parse::<IpAddr>().unwrap()
    );

    // An unparsable hop stops the walk at the last trusted address.
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", "6.6.6.6, unknown".parse().unwrap());
    assert_eq!(forwarded_ip(&proxies, proxy, &headers), proxy);

    // Untrusted peers are never overridden.
    let peer: IpAddr = "8.8.8.8".parse().unwrap();
    assert_eq!(forwarded_ip(&proxies, peer, &headers), peer);
  }
}

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

use crate::{
  github::{GhError, GitHubApp},
  oidc::{self, Caller},
  policy::{self, EvalError, Permissions, RepoRef, Resolved, TokenRequest},
  state::AppState,
};

type AppStateRef = Arc<AppState>;

pub fn router(state: AppStateRef) -> Router {
  Router::new()
    .route(
      "/v1/token",
      post(post_token).get(get_token).delete(delete_token),
    )
    .route("/v1/exchange", post(exchange))
    .route("/healthz", get(|| async { "OK" }))
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
  let runtime = state.runtime.load();
  let trusted = |ip: &IpAddr| {
    runtime
      .config
      .server
      .trusted_proxies
      .iter()
      .any(|n| n.contains(ip))
  };
  let mut ip = peer.ip();
  if trusted(&ip)
    && let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
  {
    // Walk from the closest hop back until the first untrusted address.
    for hop in xff
      .rsplit(',')
      .filter_map(|h| h.trim().parse::<IpAddr>().ok())
    {
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

async fn issue_inner(
  state: &AppState,
  subject: Option<&str>,
  req: &TokenRequest,
  audit: &mut Audit,
) -> Result<TokenResponse, ApiError> {
  let runtime = state.runtime.load_full();
  let subject = subject.ok_or_else(|| ApiError::invalid_token("missing bearer token"))?;
  let caller = oidc::validate(&runtime.issuers, &state.replay, subject)
    .await
    .map_err(ApiError::invalid_token)?;
  audit.caller(&caller);

  if let Some(limiter) = &runtime.limiter {
    let key = format!(
      "{}|{}",
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
  }

  for name in &req.repositories {
    if !matches!(name.split_once('/'), Some((o, r)) if !o.is_empty() && !r.is_empty() && !r.contains('/'))
    {
      return Err(ApiError::invalid_request(format!("bad repository {name}")));
    }
  }

  let rule = policy::select(&caller, req, &runtime.config.policy)?;
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
  app: &GitHubApp,
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
  let all_names = rule
    .grant
    .target
    .repos
    .iter()
    .filter_map(|r| match r {
      RepoRef::Name(n) => Some(n.clone()),
      RepoRef::Id(_) => None,
    })
    .chain(req.repositories.iter().cloned());
  for name in all_names {
    let info = app.resolve_repo(&name).await?;
    installations.insert(info.installation_id);
    names.insert(name.to_ascii_lowercase(), info.id);
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
  let installation = match installations.into_iter().next().or(caller_owner) {
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
    let caller = oidc::validate(&runtime.issuers, &state.replay, subject)
      .await
      .map_err(ApiError::invalid_token)?;
    audit.caller(&caller);
    let req: RevokeRequest =
      serde_json::from_slice(&body).map_err(|e| ApiError::invalid_request(e.to_string()))?;
    audit.token_sha256 = Some(token_hash(&req.token));
    // Revocation authenticates with the token itself; any app client works.
    let app = runtime
      .apps
      .values()
      .next()
      .ok_or_else(|| ApiError::upstream("no app configured"))?;
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

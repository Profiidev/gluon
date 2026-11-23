//! TOML configuration: raw file format plus validation/compilation into the
//! runtime [`Config`] used by the policy engine. Parsing never partially
//! applies: either the whole file compiles or an error is returned.

use std::{
  collections::{BTreeMap, HashMap, HashSet},
  path::{Path, PathBuf},
  time::Duration,
};

use ipnet::IpNet;
use serde::Deserialize;

use crate::policy::{
  DANGEROUS_PERMISSIONS, Effect, Grant, Hardening, Permissions, Policy, RepoRef, Rule, RuleKind,
  Target, matcher::Matcher,
};

pub const GITHUB_ISSUER_URL: &str = "https://token.actions.githubusercontent.com";

/// Fully validated configuration.
#[derive(Debug)]
pub struct Config {
  pub server: ServerConfig,
  pub issuers: Vec<IssuerConfig>,
  pub apps: Vec<AppConfig>,
  pub policy: Policy,
  pub limits: Option<Limits>,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
  pub trusted_proxies: Vec<IpNet>,
  pub reload_interval: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssuerKind {
  /// GitHub Actions; `repository_id` is a GitHub repository, so self-scope works.
  Github,
  /// Forgejo Actions; same claim names as GitHub, but IDs are Forgejo IDs.
  Forgejo,
  /// Anything else; claims are mapped through `claims`.
  Generic,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IssuerConfig {
  pub name: String,
  pub url: String,
  pub jwks_url: Option<String>,
  pub audience: String,
  pub kind: IssuerKind,
  pub max_token_age: Duration,
  pub clock_skew: Duration,
  pub replay_protection: bool,
  pub algorithms: Vec<jsonwebtoken::Algorithm>,
  /// Internal caller field -> claim name.
  pub claims: BTreeMap<String, String>,
  pub required_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AppConfig {
  pub name: String,
  pub client_id: String,
  pub keys: Vec<KeySource>,
  pub api_base: String,
  /// owner_id -> installation_id
  pub installations: HashMap<u64, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case", deny_unknown_fields)]
pub enum KeySource {
  File { path: PathBuf },
  SystemdCredential { name: String },
  Env { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
  pub per: Duration,
  pub count: u32,
  pub burst: u32,
}

// ---------------------------------------------------------------------------
// Raw file format
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
  #[serde(default)]
  server: RawServer,
  #[serde(default)]
  issuers: Option<Vec<RawIssuer>>,
  #[serde(default)]
  apps: Vec<RawApp>,
  #[serde(default)]
  defaults: RawDefaults,
  #[serde(default)]
  overrides: Vec<RawOverride>,
  #[serde(default)]
  profiles: Vec<RawRule>,
  #[serde(default)]
  rules: Vec<RawRule>,
  #[serde(default)]
  limits: RawLimits,
  #[serde(default)]
  repo_policies: RawRepoPolicies,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
  #[serde(default)]
  trusted_proxies: Vec<IpNet>,
  reload_interval: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIssuer {
  name: String,
  url: String,
  audience: String,
  jwks_url: Option<String>,
  kind: Option<IssuerKind>,
  max_token_age: Option<String>,
  clock_skew: Option<String>,
  replay_protection: Option<bool>,
  algorithms: Option<Vec<String>>,
  #[serde(default)]
  claims: BTreeMap<String, String>,
  required_claims: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApp {
  name: String,
  #[serde(alias = "app_id")]
  client_id: String,
  keys: Vec<KeySource>,
  api_base: Option<String>,
  #[serde(default)]
  installations: Vec<RawInstallation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInstallation {
  owner_id: u64,
  installation_id: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDefaults {
  #[serde(default)]
  self_scope: bool,
  app: Option<String>,
  issuer: Option<String>,
  #[serde(default)]
  owner_ids: Vec<u64>,
  #[serde(default)]
  permissions: Permissions,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum OverrideMode {
  #[default]
  Merge,
  Replace,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawTargetRef {
  Name { repository: String },
  Id { repository_id: u64 },
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawRepoRef {
  Id(u64),
  Name(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOverride {
  name: Option<String>,
  repository_id: u64,
  #[serde(default)]
  mode: OverrideMode,
  issuer: Option<String>,
  app: Option<String>,
  priority: Option<i64>,
  #[serde(default)]
  permissions: Permissions,
  #[serde(default)]
  extra_targets: Vec<RawTargetRef>,
  #[serde(default, rename = "match")]
  match_: BTreeMap<String, toml::Value>,
  #[serde(default)]
  allow_caller_target: bool,
  #[serde(default)]
  allow_events: Vec<String>,
  #[serde(default)]
  allow_non_branch_write: bool,
  #[serde(default)]
  allow_dangerous: bool,
}

/// Used for both `[[rules]]` and `[[profiles]]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
  name: String,
  #[serde(default)]
  effect: Effect,
  #[serde(default)]
  priority: i64,
  app: Option<String>,
  /// "self" | "owner" | "repositories"
  target: Option<String>,
  #[serde(default)]
  repositories: Vec<RawRepoRef>,
  #[serde(default)]
  permissions: Permissions,
  #[serde(default, rename = "match")]
  match_: BTreeMap<String, toml::Value>,
  #[serde(default)]
  allow_caller_target: bool,
  #[serde(default)]
  allow_owner_wide: bool,
  #[serde(default)]
  allow_events: Vec<String>,
  #[serde(default)]
  allow_non_branch_write: bool,
  #[serde(default)]
  allow_dangerous: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
  per_repository: Option<String>,
  burst: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRepoPolicies {
  #[serde(default)]
  enabled: bool,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

impl Config {
  pub fn load(path: &Path) -> Result<Config, String> {
    let text =
      std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Config::parse(&text)
  }

  pub fn parse(text: &str) -> Result<Config, String> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| e.to_string())?;
    compile(raw)
  }

  /// Files whose change should trigger a reload (config itself is added by the caller).
  pub fn watched_files(&self) -> Vec<PathBuf> {
    self
      .apps
      .iter()
      .flat_map(|a| &a.keys)
      .filter_map(|k| match k {
        KeySource::File { path } => Some(path.clone()),
        _ => None,
      })
      .collect()
  }
}

fn compile(raw: RawConfig) -> Result<Config, String> {
  if raw.repo_policies.enabled {
    return Err("repo_policies are not supported by this build".into());
  }

  let server = ServerConfig {
    trusted_proxies: raw.server.trusted_proxies,
    reload_interval: parse_duration(raw.server.reload_interval.as_deref().unwrap_or("10s"))?,
  };

  let raw_issuers = raw.issuers.unwrap_or_else(|| {
    vec![RawIssuer {
      name: "github".into(),
      url: GITHUB_ISSUER_URL.into(),
      audience: "github-token-broker".into(),
      jwks_url: None,
      kind: None,
      max_token_age: None,
      clock_skew: None,
      replay_protection: None,
      algorithms: None,
      claims: BTreeMap::new(),
      required_claims: None,
    }]
  });
  let mut issuers = Vec::new();
  for i in raw_issuers {
    issuers.push(compile_issuer(i)?);
  }
  unique(issuers.iter().map(|i| i.name.as_str()), "issuer name")?;
  unique(issuers.iter().map(|i| i.url.as_str()), "issuer url")?;
  if issuers.is_empty() {
    return Err("at least one issuer is required".into());
  }

  let mut apps = Vec::new();
  for a in raw.apps {
    if a.keys.is_empty() {
      return Err(format!("app {}: at least one key is required", a.name));
    }
    if a.client_id.is_empty() {
      return Err(format!("app {}: client_id is empty", a.name));
    }
    let mut installations = HashMap::new();
    for i in a.installations {
      if installations
        .insert(i.owner_id, i.installation_id)
        .is_some()
      {
        return Err(format!(
          "app {}: duplicate installation for owner {}",
          a.name, i.owner_id
        ));
      }
    }
    apps.push(AppConfig {
      name: a.name,
      client_id: a.client_id,
      keys: a.keys,
      api_base: a
        .api_base
        .unwrap_or_else(|| "https://api.github.com".into())
        .trim_end_matches('/')
        .to_string(),
      installations,
    });
  }
  unique(apps.iter().map(|a| a.name.as_str()), "app name")?;
  if apps.is_empty() {
    return Err("at least one [[apps]] entry is required".into());
  }

  let issuer_kinds: HashMap<&str, IssuerKind> =
    issuers.iter().map(|i| (i.name.as_str(), i.kind)).collect();
  let is_github = |issuer: &str| issuer_kinds.get(issuer) == Some(&IssuerKind::Github);
  let app_names: HashSet<&str> = apps.iter().map(|a| a.name.as_str()).collect();

  let defaults = raw.defaults;
  let default_issuer = defaults.issuer.clone().unwrap_or_else(|| "github".into());
  let default_app = match &defaults.app {
    Some(a) => Some(a.clone()),
    None if apps.len() == 1 => Some(apps[0].name.clone()),
    None => None,
  };
  let resolve_app = |app: &Option<String>, rule: &str| -> Result<String, String> {
    let app = app
      .clone()
      .or_else(|| default_app.clone())
      .ok_or_else(|| format!("{rule}: no app given and no default app"))?;
    if !app_names.contains(app.as_str()) {
      return Err(format!("{rule}: unknown app {app}"));
    }
    Ok(app)
  };
  let check_issuer = |issuer: &str, rule: &str| -> Result<(), String> {
    if issuer_kinds.contains_key(issuer) {
      Ok(())
    } else {
      Err(format!("{rule}: unknown issuer {issuer}"))
    }
  };

  let mut rules = Vec::new();
  let mut names = HashSet::new();
  let mut add_name = |name: &str| -> Result<(), String> {
    if names.insert(name.to_string()) {
      Ok(())
    } else {
      Err(format!("duplicate rule name {name}"))
    }
  };

  // Bind a rule to defaults.owner_ids. These are GitHub account IDs, so only
  // GitHub issuers get them; an existing owner_id condition is kept.
  let owner_cond = |m: &mut BTreeMap<String, toml::Value>, issuer: &str| {
    if is_github(issuer) && !defaults.owner_ids.is_empty() && !m.contains_key("owner_id") {
      m.insert(
        "owner_id".into(),
        toml::Value::Array(
          defaults
            .owner_ids
            .iter()
            .map(|id| toml::Value::Integer(*id as i64))
            .collect(),
        ),
      );
    }
  };

  // Built-in default rule.
  if defaults.self_scope {
    check_issuer(&default_issuer, "defaults")?;
    if !is_github(&default_issuer) {
      return Err("defaults.self_scope needs a GitHub issuer".into());
    }
    if defaults.owner_ids.is_empty() {
      return Err("defaults.self_scope requires defaults.owner_ids".into());
    }
    let mut m = BTreeMap::new();
    m.insert("issuer".into(), toml::Value::String(default_issuer.clone()));
    owner_cond(&mut m, &default_issuer);
    add_name("default-self")?;
    rules.push(Rule {
      name: "default-self".into(),
      priority: 0,
      effect: Effect::Allow,
      kind: RuleKind::Default,
      matcher: Matcher::compile(&m).map_err(|e| format!("defaults: {e}"))?,
      grant: Grant {
        app: resolve_app(&defaults.app, "defaults")?,
        target: Target::self_only(),
        permissions: defaults.permissions.clone(),
        allow_caller_target: false,
      },
      hardening: Hardening::default(),
    });
  }

  // Per-repository overrides.
  let mut replace_repos = HashSet::new();
  for o in raw.overrides {
    let name = o
      .name
      .clone()
      .unwrap_or_else(|| format!("override-{}", o.repository_id));
    add_name(&name)?;
    let issuer = o.issuer.clone().unwrap_or_else(|| default_issuer.clone());
    check_issuer(&issuer, &name)?;
    for key in ["issuer", "repository_id"] {
      if o.match_.contains_key(key) {
        return Err(format!("{name}: match.{key} is implied by the override"));
      }
    }
    // A negated or pattern owner_id would replace the owner binding below.
    if o.match_.contains_key("owner_id") && !binds(&o.match_, "owner_id") {
      return Err(format!("{name}: match.owner_id must use eq/in"));
    }
    let mut m = o.match_.clone();
    m.insert("issuer".into(), toml::Value::String(issuer.clone()));
    m.insert(
      "repository_id".into(),
      toml::Value::Integer(o.repository_id as i64),
    );
    // Guards against ID typos and repositories transferred to another account.
    owner_cond(&mut m, &issuer);
    let permissions = match o.mode {
      OverrideMode::Merge => {
        let mut p = defaults.permissions.clone();
        p.extend(o.permissions.clone());
        p
      }
      OverrideMode::Replace => {
        replace_repos.insert((issuer.clone(), o.repository_id.to_string()));
        o.permissions.clone()
      }
    };
    let mut target = Target::self_only();
    for t in o.extra_targets {
      target.repos.push(match t {
        RawTargetRef::Name { repository } => RepoRef::Name(parse_repo_name(&repository, &name)?),
        RawTargetRef::Id { repository_id } => RepoRef::Id(repository_id),
      });
    }
    rules.push(Rule {
      priority: o.priority.unwrap_or(10),
      effect: Effect::Allow,
      kind: RuleKind::Override,
      matcher: Matcher::compile(&m).map_err(|e| format!("{name}: {e}"))?,
      grant: Grant {
        app: resolve_app(&o.app, &name)?,
        target,
        permissions,
        allow_caller_target: o.allow_caller_target,
      },
      hardening: Hardening {
        allow_events: o.allow_events,
        allow_non_branch_write: o.allow_non_branch_write,
        allow_dangerous: o.allow_dangerous,
      },
      name,
    });
  }

  // General rules and profiles.
  let mut compile_rule = |r: RawRule, kind: RuleKind| -> Result<Rule, String> {
    let name = r.name.clone();
    add_name(&name)?;
    if kind == RuleKind::Profile && r.effect == Effect::Deny {
      return Err(format!("profile {name}: profiles cannot deny"));
    }
    let mut m = r.match_.clone();
    if r.effect == Effect::Allow {
      // Fail safe: an allow rule is always bound to an issuer and an account.
      let issuer = match m.get("issuer") {
        Some(toml::Value::String(s)) => s.clone(),
        Some(_) => return Err(format!("{name}: match.issuer must be a string")),
        None => {
          m.insert("issuer".into(), toml::Value::String(default_issuer.clone()));
          default_issuer.clone()
        }
      };
      check_issuer(&issuer, &name)?;
      if !binds(&m, "owner_id") && !binds(&m, "repository_id") {
        if !is_github(&issuer) || defaults.owner_ids.is_empty() || m.contains_key("owner_id") {
          return Err(format!(
            "{name}: allow rules must restrict owner_id or repository_id with eq/in"
          ));
        }
        owner_cond(&mut m, &issuer);
      }
    }
    let target = match (r.target.as_deref(), r.repositories.is_empty()) {
      (None | Some("self"), true) => Target::self_only(),
      (None | Some("repositories"), false) => {
        let mut repos = Vec::new();
        for repo in r.repositories {
          repos.push(match repo {
            RawRepoRef::Id(id) => RepoRef::Id(id),
            RawRepoRef::Name(n) => RepoRef::Name(parse_repo_name(&n, &name)?),
          });
        }
        Target {
          include_self: false,
          repos,
          owner_wide: false,
        }
      }
      (Some("owner"), true) => {
        if !r.allow_owner_wide {
          return Err(format!(
            "{name}: target = \"owner\" requires allow_owner_wide = true"
          ));
        }
        Target {
          include_self: false,
          repos: vec![],
          owner_wide: true,
        }
      }
      (Some(t), _) => return Err(format!("{name}: invalid target {t:?} for this rule")),
    };
    let grant = if r.effect == Effect::Allow {
      Grant {
        app: resolve_app(&r.app, &name)?,
        target,
        permissions: r.permissions,
        allow_caller_target: r.allow_caller_target,
      }
    } else {
      Grant {
        app: String::new(),
        target,
        permissions: Permissions::new(),
        allow_caller_target: false,
      }
    };
    Ok(Rule {
      priority: r.priority,
      effect: r.effect,
      kind,
      matcher: Matcher::compile(&m).map_err(|e| format!("{name}: {e}"))?,
      grant,
      hardening: Hardening {
        allow_events: r.allow_events,
        allow_non_branch_write: r.allow_non_branch_write,
        allow_dangerous: r.allow_dangerous,
      },
      name,
    })
  };

  for r in raw.rules {
    rules.push(compile_rule(r, RuleKind::Rule)?);
  }
  let mut profiles = HashMap::new();
  for p in raw.profiles {
    let rule = compile_rule(p, RuleKind::Profile)?;
    profiles.insert(rule.name.clone(), rule);
  }

  // Dangerous permissions need an explicit opt-in.
  for rule in rules.iter().chain(profiles.values()) {
    if rule.effect == Effect::Allow
      && !rule.hardening.allow_dangerous
      && let Some(p) = rule
        .grant
        .permissions
        .keys()
        .find(|p| DANGEROUS_PERMISSIONS.contains(&p.as_str()))
    {
      return Err(format!(
        "{}: permission {p} is dangerous and needs allow_dangerous = true",
        rule.name
      ));
    }
    if rule.effect == Effect::Allow && rule.grant.permissions.is_empty() {
      return Err(format!("{}: grant has no permissions", rule.name));
    }
  }

  let limits = match raw.limits.per_repository {
    Some(rate) => {
      let (count, per) = parse_rate(&rate)?;
      Some(Limits {
        per,
        count,
        burst: raw.limits.burst.unwrap_or(count).max(1),
      })
    }
    None => None,
  };

  Ok(Config {
    server,
    issuers,
    apps,
    policy: Policy {
      rules,
      profiles,
      replace_repos,
    },
    limits,
  })
}

fn compile_issuer(i: RawIssuer) -> Result<IssuerConfig, String> {
  let ctx = |e: String| format!("issuer {}: {e}", i.name);
  let kind = i.kind.unwrap_or(if i.url == GITHUB_ISSUER_URL {
    IssuerKind::Github
  } else {
    IssuerKind::Generic
  });
  // Plain http lets anyone on the path swap the signing keys; only loopback
  // (tests, local development) is exempt.
  for url in std::iter::once(&i.url).chain(i.jwks_url.as_ref()) {
    if !secure_url(url) {
      return Err(ctx(format!("{url} must use https")));
    }
  }
  if i.audience.is_empty() {
    return Err(ctx("audience is empty".into()));
  }
  // GitHub's default audience is the owner URL; it must never be accepted.
  if i.audience.starts_with("https://github.com") {
    return Err(ctx(
      "audience must not be GitHub's default owner URL".into(),
    ));
  }
  let mut algorithms = Vec::new();
  for a in i.algorithms.unwrap_or_else(|| vec!["RS256".into()]) {
    let alg: jsonwebtoken::Algorithm = a
      .parse()
      .map_err(|_| ctx(format!("unknown algorithm {a}")))?;
    if matches!(
      alg,
      jsonwebtoken::Algorithm::HS256
        | jsonwebtoken::Algorithm::HS384
        | jsonwebtoken::Algorithm::HS512
    ) {
      return Err(ctx(format!("algorithm {a} is not allowed")));
    }
    algorithms.push(alg);
  }
  if algorithms.is_empty() {
    return Err(ctx("algorithms is empty".into()));
  }
  for field in i.claims.keys() {
    if !crate::oidc::caller::FIELDS.contains(&field.as_str()) {
      return Err(ctx(format!("unknown caller field {field} in claims")));
    }
  }
  let required_claims = i.required_claims.unwrap_or_else(|| match kind {
    IssuerKind::Github | IssuerKind::Forgejo => [
      "repository",
      "repository_id",
      "repository_owner",
      "repository_owner_id",
      "ref",
      "sub",
      "jti",
    ]
    .map(String::from)
    .to_vec(),
    IssuerKind::Generic => vec!["sub".into()],
  });
  let max_token_age = parse_duration(i.max_token_age.as_deref().unwrap_or("5m")).map_err(ctx)?;
  // Bounds how long replay entries (and their memory) are kept.
  if max_token_age > Duration::from_secs(3600) {
    return Err(ctx("max_token_age must be at most 1h".into()));
  }
  Ok(IssuerConfig {
    max_token_age,
    clock_skew: parse_duration(i.clock_skew.as_deref().unwrap_or("60s")).map_err(ctx)?,
    replay_protection: i.replay_protection.unwrap_or(true),
    url: i.url.trim_end_matches('/').to_string(),
    name: i.name,
    jwks_url: i.jwks_url,
    audience: i.audience,
    kind,
    algorithms,
    claims: i.claims,
    required_claims,
  })
}

fn secure_url(url: &str) -> bool {
  match reqwest::Url::parse(url) {
    Ok(u) if u.scheme() == "https" => true,
    Ok(u) if u.scheme() == "http" => {
      matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
    }
    _ => false,
  }
}

/// A positive `eq`/`in` condition on `key`; negated or pattern conditions do not bind.
fn binds(m: &BTreeMap<String, toml::Value>, key: &str) -> bool {
  match m.get(key) {
    None => false,
    Some(toml::Value::Table(t)) => !t.is_empty() && t.keys().all(|k| k == "eq" || k == "in"),
    Some(_) => true,
  }
}

fn unique<'a>(items: impl Iterator<Item = &'a str>, what: &str) -> Result<(), String> {
  let mut seen = HashSet::new();
  for i in items {
    if !seen.insert(i) {
      return Err(format!("duplicate {what} {i}"));
    }
  }
  Ok(())
}

fn parse_repo_name(name: &str, rule: &str) -> Result<String, String> {
  match name.split_once('/') {
    Some((o, r)) if !o.is_empty() && !r.is_empty() && !r.contains('/') => Ok(name.to_string()),
    _ => Err(format!("{rule}: repository {name:?} must be owner/name")),
  }
}

/// `"500ms"`, `"60s"`, `"5m"`, `"1h"`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
  let s = s.trim();
  let split = s
    .find(|c: char| !c.is_ascii_digit())
    .ok_or_else(|| format!("duration {s:?} needs a unit (ms, s, m, h)"))?;
  let (n, unit) = s.split_at(split);
  let n: u64 = n.parse().map_err(|_| format!("invalid duration {s:?}"))?;
  Ok(match unit {
    "ms" => Duration::from_millis(n),
    "s" => Duration::from_secs(n),
    "m" => Duration::from_secs(n * 60),
    "h" => Duration::from_secs(n * 3600),
    _ => return Err(format!("invalid duration unit in {s:?}")),
  })
}

/// `"30/min"` -> (30, 60s)
pub fn parse_rate(s: &str) -> Result<(u32, Duration), String> {
  let (n, per) = s
    .split_once('/')
    .ok_or_else(|| format!("rate {s:?} must look like 30/min"))?;
  let n: u32 = n
    .trim()
    .parse()
    .map_err(|_| format!("invalid rate {s:?}"))?;
  if n == 0 {
    return Err(format!("rate {s:?} must be > 0"));
  }
  let per = match per.trim() {
    "s" | "sec" | "second" => Duration::from_secs(1),
    "m" | "min" | "minute" => Duration::from_secs(60),
    "h" | "hour" => Duration::from_secs(3600),
    p => return Err(format!("invalid rate unit {p:?}")),
  };
  Ok((n, per))
}

#[cfg(test)]
mod test {
  use super::*;

  pub const EXAMPLE: &str = include_str!("../config.example.toml");

  #[test]
  fn example_config_is_valid() {
    let c = Config::parse(EXAMPLE).unwrap();
    assert_eq!(c.issuers[0].kind, IssuerKind::Github);
    assert!(c.policy.rules.iter().any(|r| r.name == "default-self"));
    assert!(c.policy.profiles.contains_key("release"));
    assert_eq!(c.limits.unwrap().count, 30);
  }

  #[test]
  fn durations_and_rates() {
    assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
    assert!(parse_duration("5").is_err());
    assert!(parse_duration("5d").is_err());
    assert_eq!(parse_rate("30/min").unwrap(), (30, Duration::from_secs(60)));
    assert!(parse_rate("0/min").is_err());
    assert!(parse_rate("30").is_err());
  }

  const BASE: &str = r#"
[[apps]]
name = "main"
client_id = "Iv1"
keys = [{ source = "env", name = "KEY" }]
[defaults]
self_scope = true
owner_ids = [1]
permissions = { contents = "read" }
"#;

  /// Every one of these must be rejected as a whole.
  #[test]
  fn invalid_configs_are_rejected() {
    let cases: &[(&str, &str)] = &[
      ("unknown top-level key", "bogus = 1"),
      ("garbage", "[[[["),
      (
        "hs256",
        "[[issuers]]\nname='x'\nurl='https://x'\naudience='a'\nalgorithms=['HS256']",
      ),
      (
        "github default aud",
        "[[issuers]]\nname='github'\nurl='https://x'\naudience='https://github.com/me'",
      ),
      (
        "bad regex",
        "[[rules]]\nname='r'\neffect='deny'\nmatch={ref={regex='('}}",
      ),
      (
        "bad cel",
        "[[rules]]\nname='r'\neffect='deny'\nmatch={expr='caller.'}",
      ),
      (
        "unknown field",
        "[[rules]]\nname='r'\neffect='deny'\nmatch={nope={eq='x'}}",
      ),
      (
        "unknown op",
        "[[rules]]\nname='r'\neffect='deny'\nmatch={ref={contains='x'}}",
      ),
      (
        "dangerous",
        "[[profiles]]\nname='p'\npermissions={administration='write'}",
      ),
      (
        "owner wide w/o flag",
        "[[profiles]]\nname='p'\ntarget='owner'\npermissions={contents='read'}",
      ),
      ("dup name", "[[rules]]\nname='default-self'\neffect='deny'"),
      (
        "unknown app",
        "[[profiles]]\nname='p'\napp='nope'\npermissions={contents='read'}",
      ),
      (
        "bad level",
        "[[profiles]]\nname='p'\npermissions={contents='root'}",
      ),
      (
        "bad repo name",
        "[[profiles]]\nname='p'\nrepositories=['foo']\npermissions={contents='read'}",
      ),
      ("repo policies", "[repo_policies]\nenabled=true"),
      ("bad rate", "[limits]\nper_repository='lots'"),
      ("profile deny", "[[profiles]]\nname='p'\neffect='deny'"),
      ("empty grant", "[[profiles]]\nname='p'"),
      (
        "override negated owner",
        "[[overrides]]\nrepository_id=1\nmode='replace'\npermissions={contents='read'}\nmatch={owner_id={not_eq=2}}",
      ),
      (
        "http issuer",
        "[[issuers]]\nname='github'\nurl='http://token.example.com'\naudience='a'",
      ),
      (
        "http jwks",
        "[[issuers]]\nname='github'\nurl='https://token.example.com'\njwks_url='http://token.example.com/jwks'\naudience='a'",
      ),
      (
        "override implied key",
        "[[overrides]]\nrepository_id=1\nmatch={repository_id={eq=2}}",
      ),
      (
        "glob owner binding",
        "[[profiles]]\nname='p'\nrepositories=[5]\npermissions={contents='read'}\nmatch={owner_id={glob='*'}}",
      ),
      (
        "environments is dangerous",
        "[[profiles]]\nname='p'\npermissions={environments='write'}",
      ),
    ];
    for (what, extra) in cases {
      let text = format!("{BASE}\n{extra}");
      assert!(Config::parse(&text).is_err(), "{what} should fail");
    }
    assert!(Config::parse(BASE).is_ok());
    // No apps at all.
    assert!(Config::parse("").is_err());
    // A negated repository condition does not count as an account binding:
    // the rule gets bound to defaults.owner_ids instead.
    let negated = format!(
      "{BASE}\n[[profiles]]\nname='p'\nrepositories=[5]\npermissions={{contents='read'}}\nmatch={{repository_id={{not_in=[5]}}}}"
    );
    let cfg = Config::parse(&negated).unwrap();
    let rule = &cfg.policy.profiles["p"];
    let foreign = crate::oidc::Caller::test("evil/repo", 9, 999);
    assert!(!rule.matcher.matches(&foreign));
    assert!(
      rule
        .matcher
        .matches(&crate::oidc::Caller::test("me/repo", 9, 1))
    );

    // Non-GitHub issuers are never bound to the GitHub owner_ids implicitly.
    let forgejo = format!(
      "{BASE}\n[[issuers]]\nname='github'\nurl='https://token.actions.githubusercontent.com'\naudience='a'\n[[issuers]]\nname='fj'\nurl='https://git.example.com'\nkind='forgejo'\naudience='a'\n[[profiles]]\nname='p'\nrepositories=['o/r']\npermissions={{contents='read'}}\nmatch={{issuer='fj'}}"
    );
    assert!(
      Config::parse(&forgejo)
        .unwrap_err()
        .contains("must restrict")
    );
    assert!(
      Config::parse(&forgejo.replace(
        "match={issuer='fj'}",
        "match={issuer='fj', repository_id=7}"
      ))
      .is_ok()
    );
  }
}

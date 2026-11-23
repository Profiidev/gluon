//! Policy evaluation (§5.6). Pure functions of caller, request, config and
//! installation permissions; network lookups happen between [`select`] and
//! [`finalize`] in the API layer.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::oidc::caller::Caller;

pub mod matcher;

/// H4
pub const DANGEROUS_PERMISSIONS: &[&str] = &[
  "administration",
  "workflows",
  "secrets",
  "members",
  "organization_administration",
];

/// H1
const HARDENED_EVENTS: &[&str] = &["pull_request_target", "workflow_run"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
  Read,
  Write,
  Admin,
}

pub type Permissions = BTreeMap<String, Level>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
  #[default]
  Allow,
  Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleKind {
  Default,
  Rule,
  Override,
  Profile,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RepoRef {
  Id(u64),
  /// `owner/name`
  Name(String),
}

#[derive(Debug, Clone, Default)]
pub struct Target {
  pub include_self: bool,
  pub repos: Vec<RepoRef>,
  pub owner_wide: bool,
}

impl Target {
  pub fn self_only() -> Target {
    Target {
      include_self: true,
      ..Default::default()
    }
  }
}

#[derive(Debug)]
pub struct Grant {
  pub app: String,
  pub target: Target,
  /// Ceiling.
  pub permissions: Permissions,
  pub allow_caller_target: bool,
}

#[derive(Debug, Default)]
pub struct Hardening {
  /// H1 opt-in for `pull_request_target` / `workflow_run`.
  pub allow_events: Vec<String>,
  /// H2 opt-out.
  pub allow_non_branch_write: bool,
  /// H4 opt-in.
  pub allow_dangerous: bool,
}

#[derive(Debug)]
pub struct Rule {
  pub name: String,
  pub priority: i64,
  pub effect: Effect,
  pub kind: RuleKind,
  pub matcher: matcher::Matcher,
  pub grant: Grant,
  pub hardening: Hardening,
}

#[derive(Debug, Default)]
pub struct Policy {
  /// Default rule, overrides and `[[rules]]`.
  pub rules: Vec<Rule>,
  pub profiles: HashMap<String, Rule>,
  /// (issuer, repository_id) with a `replace` override: the default rule never applies.
  pub replace_repos: HashSet<(String, String)>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TokenRequest {
  pub repositories: Vec<String>,
  pub repository_ids: Vec<u64>,
  pub permissions: Permissions,
  pub profile: Option<String>,
}

impl TokenRequest {
  pub fn has_target(&self) -> bool {
    !self.repositories.is_empty() || !self.repository_ids.is_empty()
  }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EvalError {
  /// 403 access_denied
  Denied(String),
  /// 422 not_installed
  NotInstalled(String),
}

fn denied<T>(msg: impl Into<String>) -> Result<T, EvalError> {
  Err(EvalError::Denied(msg.into()))
}

/// Whether an allow rule applies, including H1.
fn allow_matches(rule: &Rule, caller: &Caller) -> bool {
  if let Some(event) = caller.event_name.as_deref()
    && HARDENED_EVENTS.contains(&event)
    && !rule.hardening.allow_events.iter().any(|e| e == event)
  {
    return false;
  }
  rule.matcher.matches(caller)
}

/// §5.6 steps 1-3: pick the rule.
pub fn select<'a>(
  caller: &Caller,
  req: &TokenRequest,
  policy: &'a Policy,
) -> Result<&'a Rule, EvalError> {
  let profile = match &req.profile {
    Some(name) => match policy.profiles.get(name) {
      Some(p) => Some(p),
      None => return denied(format!("unknown profile {name}")),
    },
    None => None,
  };

  if let Some(rule) = policy
    .rules
    .iter()
    .find(|r| r.effect == Effect::Deny && r.matcher.matches(caller))
  {
    return denied(format!("deny rule {} matched", rule.name));
  }

  if let Some(profile) = profile {
    return if allow_matches(profile, caller) {
      Ok(profile)
    } else {
      denied(format!("profile {} does not match", profile.name))
    };
  }

  let replaced = caller.repository_id.as_ref().is_some_and(|id| {
    policy
      .replace_repos
      .contains(&(caller.issuer.clone(), id.clone()))
  });

  policy
    .rules
    .iter()
    .filter(|r| r.effect == Effect::Allow)
    .filter(|r| !(replaced && r.kind == RuleKind::Default))
    .filter(|r| allow_matches(r, caller))
    // Deterministic: priority, then overrides > rules > default, then name.
    .max_by(|a, b| {
      (a.priority, a.kind)
        .cmp(&(b.priority, b.kind))
        .then_with(|| b.name.cmp(&a.name))
    })
    .ok_or_else(|| EvalError::Denied("no rule matched".into()))
}

/// Network-derived inputs for [`finalize`].
#[derive(Debug, Default)]
pub struct Resolved {
  /// Rule target as repository IDs (self, names and owner-wide already expanded).
  pub rule_targets: Vec<u64>,
  /// Requested targets as IDs; `None` when the caller asked for none.
  pub requested_targets: Option<Vec<u64>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
  pub repository_ids: Vec<u64>,
  pub permissions: Permissions,
}

/// H2: is the caller on something other than a branch or tag?
fn is_non_branch_ref(caller: &Caller) -> bool {
  let ref_ok = matches!(caller.ref_type.as_deref(), Some("branch" | "tag"));
  let pr_ref = caller
    .ref_
    .as_deref()
    .is_some_and(|r| r.starts_with("refs/pull/"));
  !ref_ok || pr_ref
}

/// §5.6 steps 4-6.
pub fn finalize(
  caller: &Caller,
  req: &TokenRequest,
  rule: &Rule,
  resolved: &Resolved,
  installation_permissions: &Permissions,
) -> Result<Decision, EvalError> {
  let rule_set: BTreeSet<u64> = resolved.rule_targets.iter().copied().collect();
  if rule_set.is_empty() {
    return denied("rule target is empty");
  }
  let targets = match &resolved.requested_targets {
    None => rule_set,
    Some(requested) => {
      let requested: BTreeSet<u64> = requested.iter().copied().collect();
      if !requested.is_subset(&rule_set) {
        return denied("requested target outside the grant");
      }
      // Asking for exactly the grant is not narrowing, so it is always fine.
      if requested != rule_set && !rule.grant.allow_caller_target {
        return denied("rule does not allow caller-selected targets");
      }
      requested
    }
  };

  let mut ceiling = rule.grant.permissions.clone();
  if is_non_branch_ref(caller) && !rule.hardening.allow_non_branch_write {
    for level in ceiling.values_mut() {
      *level = Level::Read;
    }
  }

  let permissions = if req.permissions.is_empty() {
    let p: Permissions = ceiling
      .iter()
      .filter_map(|(name, level)| {
        installation_permissions
          .get(name)
          .map(|i| (name.clone(), (*level).min(*i)))
      })
      .collect();
    if p.is_empty() {
      return Err(EvalError::NotInstalled(
        "installation has none of the granted permissions".into(),
      ));
    }
    p
  } else {
    for (name, level) in &req.permissions {
      match ceiling.get(name) {
        Some(c) if level <= c => {}
        _ => return denied(format!("permission {name}:{level:?} exceeds the grant")),
      }
      match installation_permissions.get(name) {
        Some(i) if level <= i => {}
        _ => {
          return Err(EvalError::NotInstalled(format!(
            "installation lacks {name}:{level:?}"
          )));
        }
      }
    }
    req.permissions.clone()
  };

  Ok(Decision {
    repository_ids: targets.into_iter().collect(),
    permissions,
  })
}

#[cfg(test)]
mod test;

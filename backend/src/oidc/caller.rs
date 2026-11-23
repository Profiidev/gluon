//! Internal caller model and issuer-specific claim mapping.

use serde::Serialize;
use serde_json::{Map, Value};

use crate::config::{IssuerConfig, IssuerKind};

/// Caller fields usable in `match` and in `[[issuers]].claims`.
pub const FIELDS: &[&str] = &[
  "issuer",
  "owner",
  "owner_id",
  "repository",
  "repository_id",
  "ref",
  "ref_type",
  "sha",
  "event_name",
  "workflow_ref",
  "job_workflow_ref",
  "environment",
  "runner_environment",
  "actor",
  "actor_id",
  "sub",
];

#[derive(Debug, Clone, Default, Serialize)]
pub struct Caller {
  /// Issuer name from config.
  pub issuer: String,
  /// Only GitHub issuers carry GitHub repository IDs, so only they can use self-scope.
  #[serde(skip)]
  pub github_ids: bool,
  pub owner: Option<String>,
  pub owner_id: Option<String>,
  pub repository: Option<String>,
  pub repository_id: Option<String>,
  #[serde(rename = "ref")]
  pub ref_: Option<String>,
  pub ref_type: Option<String>,
  pub sha: Option<String>,
  pub event_name: Option<String>,
  pub workflow_ref: Option<String>,
  pub job_workflow_ref: Option<String>,
  pub environment: Option<String>,
  pub runner_environment: Option<String>,
  pub actor: Option<String>,
  pub actor_id: Option<String>,
  pub sub: Option<String>,
  pub jti: Option<String>,
  pub claims: Map<String, Value>,
}

fn claim_string(v: &Value) -> Option<String> {
  match v {
    Value::Null => None,
    Value::String(s) => Some(s.clone()),
    v => Some(v.to_string()),
  }
}

/// Claim name for a caller field on GitHub-style issuers.
fn default_claim(field: &str) -> &str {
  match field {
    "owner" => "repository_owner",
    "owner_id" => "repository_owner_id",
    f => f,
  }
}

impl Caller {
  pub fn from_claims(issuer: &IssuerConfig, claims: Map<String, Value>) -> Caller {
    let get = |field: &str| -> Option<String> {
      let claim = issuer
        .claims
        .get(field)
        .map(String::as_str)
        .unwrap_or_else(|| default_claim(field));
      claims.get(claim).and_then(claim_string)
    };
    let mut c = Caller {
      issuer: issuer.name.clone(),
      github_ids: issuer.kind == IssuerKind::Github,
      owner: get("owner"),
      owner_id: get("owner_id"),
      repository: get("repository"),
      repository_id: get("repository_id"),
      ref_: get("ref"),
      ref_type: get("ref_type"),
      sha: get("sha"),
      event_name: get("event_name"),
      workflow_ref: get("workflow_ref"),
      job_workflow_ref: get("job_workflow_ref"),
      environment: get("environment"),
      runner_environment: get("runner_environment"),
      actor: get("actor"),
      actor_id: get("actor_id"),
      sub: get("sub"),
      jti: claims.get("jti").and_then(claim_string),
      claims: Map::new(),
    };
    // Older issuers omit ref_type; derive it so the non-branch write downgrade still works.
    if c.ref_type.is_none() {
      c.ref_type = c.ref_.as_deref().and_then(|r| {
        if r.starts_with("refs/heads/") {
          Some("branch".to_string())
        } else if r.starts_with("refs/tags/") {
          Some("tag".to_string())
        } else {
          None
        }
      });
    }
    c.claims = claims;
    c
  }

  pub fn get(&self, field: &str) -> Option<String> {
    if let Some(claim) = field.strip_prefix("claims.") {
      return self.claims.get(claim).and_then(claim_string);
    }
    match field {
      "issuer" => Some(self.issuer.clone()),
      "owner" => self.owner.clone(),
      "owner_id" => self.owner_id.clone(),
      "repository" => self.repository.clone(),
      "repository_id" => self.repository_id.clone(),
      "ref" => self.ref_.clone(),
      "ref_type" => self.ref_type.clone(),
      "sha" => self.sha.clone(),
      "event_name" => self.event_name.clone(),
      "workflow_ref" => self.workflow_ref.clone(),
      "job_workflow_ref" => self.job_workflow_ref.clone(),
      "environment" => self.environment.clone(),
      "runner_environment" => self.runner_environment.clone(),
      "actor" => self.actor.clone(),
      "actor_id" => self.actor_id.clone(),
      "sub" => self.sub.clone(),
      _ => None,
    }
  }

  /// A GitHub Actions caller on `refs/heads/main`, push event, github-hosted.
  #[cfg(test)]
  pub fn test(repository: &str, repository_id: u64, owner_id: u64) -> Caller {
    Caller {
      issuer: "github".into(),
      github_ids: true,
      owner: repository.split('/').next().map(String::from),
      owner_id: Some(owner_id.to_string()),
      repository: Some(repository.into()),
      repository_id: Some(repository_id.to_string()),
      ref_: Some("refs/heads/main".into()),
      ref_type: Some("branch".into()),
      event_name: Some("push".into()),
      runner_environment: Some("github-hosted".into()),
      sub: Some(format!("repo:{repository}:ref:refs/heads/main")),
      ..Default::default()
    }
  }
}

#[cfg(test)]
mod test {
  use super::*;
  use crate::config::Config;

  #[test]
  fn maps_github_and_custom_claims() {
    let cfg = Config::parse(
      r#"
[[issuers]]
name = "github"
url = "https://token.actions.githubusercontent.com"
audience = "a"
[[issuers]]
name = "gitlab"
url = "https://gitlab.example.com"
audience = "a"
claims = { repository = "project_path", repository_id = "project_id", owner = "namespace_path" }
[[apps]]
name = "main"
client_id = "x"
keys = [{ source = "env", name = "K" }]
"#,
    )
    .unwrap();
    let claims: Map<String, Value> = serde_json::from_value(serde_json::json!({
      "repository": "a/b", "repository_id": "5", "repository_owner": "a",
      "repository_owner_id": 7, "ref": "refs/tags/v1", "custom": "x",
    }))
    .unwrap();
    let c = Caller::from_claims(&cfg.issuers[0], claims);
    assert!(c.github_ids);
    assert_eq!(c.owner_id.as_deref(), Some("7"));
    assert_eq!(c.ref_type.as_deref(), Some("tag"));
    assert_eq!(c.get("claims.custom").as_deref(), Some("x"));

    let claims: Map<String, Value> = serde_json::from_value(serde_json::json!({
      "project_path": "grp/proj", "project_id": "9", "namespace_path": "grp",
    }))
    .unwrap();
    let c = Caller::from_claims(&cfg.issuers[1], claims);
    assert!(!c.github_ids);
    assert_eq!(c.repository.as_deref(), Some("grp/proj"));
    assert_eq!(c.repository_id.as_deref(), Some("9"));
    assert_eq!(c.owner.as_deref(), Some("grp"));
  }
}

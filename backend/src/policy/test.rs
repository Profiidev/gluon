//! Table-driven policy evaluation tests.

use super::*;
use crate::config::Config;

const OWNER: u64 = 100;

const CONFIG: &str = r#"
[[apps]]
name = "main"
client_id = "Iv1"
keys = [{ source = "env", name = "K" }]

[[apps]]
name = "renovate"
client_id = "Iv2"
keys = [{ source = "env", name = "K" }]

[defaults]
self_scope = true
app = "main"
owner_ids = [100]
permissions = { contents = "write", metadata = "read", pull_requests = "write" }

# merge: adds packages, only from main
[[overrides]]
repository_id = 11
mode = "merge"
permissions = { packages = "write" }
match = { ref = { glob = "refs/heads/main" } }

# replace: read-only repo, only from main
[[overrides]]
repository_id = 12
mode = "replace"
permissions = { contents = "read" }
match = { ref = "refs/heads/main" }

# cross-repo grant with caller-selectable subset
[[overrides]]
repository_id = 13
mode = "merge"
extra_targets = [{ repository_id = 99 }, { repository_id = 98 }]
permissions = { contents = "write" }
allow_caller_target = true

[[overrides]]
repository_id = 14
allow_events = ["workflow_run"]

[[overrides]]
repository_id = 15
allow_non_branch_write = true

[[profiles]]
name = "release"
permissions = { contents = "write", packages = "write" }
match = { ref_type = { eq = "tag" } }

[[profiles]]
name = "admin"
permissions = { administration = "write" }
allow_dangerous = true

[[rules]]
name = "renovate"
app = "renovate"
priority = 50
repositories = [77]
permissions = { contents = "write" }
match = { repository_id = 16 }

[[rules]]
name = "no-self-hosted"
effect = "deny"
priority = 100
match = { runner_environment = "self-hosted", repository_id = [17] }
"#;

fn policy() -> Policy {
  Config::parse(CONFIG).unwrap().policy
}

fn install_all() -> Permissions {
  [
    ("contents", Level::Admin),
    ("metadata", Level::Read),
    ("pull_requests", Level::Write),
    ("packages", Level::Write),
    ("administration", Level::Write),
  ]
  .into_iter()
  .map(|(k, v)| (k.to_string(), v))
  .collect()
}

fn perms(p: &[(&str, Level)]) -> Permissions {
  p.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

/// Self/IDs only, no names: mirrors what the API layer resolves.
fn resolve(rule: &Rule, caller: &Caller, req: &TokenRequest) -> Resolved {
  let mut rule_targets = Vec::new();
  if rule.grant.target.include_self {
    rule_targets.push(caller.repository_id.as_ref().unwrap().parse().unwrap());
  }
  for r in &rule.grant.target.repos {
    if let RepoRef::Id(id) = r {
      rule_targets.push(*id);
    }
  }
  Resolved {
    rule_targets,
    requested_targets: req.has_target().then(|| req.repository_ids.clone()),
  }
}

fn eval(
  caller: &Caller,
  req: &TokenRequest,
  install: &Permissions,
) -> Result<(String, Decision), EvalError> {
  let policy = policy();
  let rule = select(caller, req, &policy)?;
  let resolved = resolve(rule, caller, req);
  finalize(caller, req, rule, &resolved, install).map(|d| (rule.name.clone(), d))
}

struct Case {
  name: &'static str,
  caller: Caller,
  req: TokenRequest,
  expect: Result<(&'static str, Vec<u64>, Permissions), EvalError>,
}

fn caller(repo_id: u64) -> Caller {
  Caller::test(&format!("Profiidev/r{repo_id}"), repo_id, OWNER)
}

fn with(mut c: Caller, f: impl FnOnce(&mut Caller)) -> Caller {
  f(&mut c);
  c
}

fn denied_any() -> EvalError {
  EvalError::Denied(String::new())
}

#[test]
fn table() {
  let default_perms = perms(&[
    ("contents", Level::Write),
    ("metadata", Level::Read),
    ("pull_requests", Level::Write),
  ]);
  let cases = vec![
    Case {
      name: "self-scope default",
      caller: caller(1),
      req: TokenRequest::default(),
      expect: Ok(("default-self", vec![1], default_perms.clone())),
    },
    Case {
      name: "foreign owner gets nothing",
      caller: with(caller(1), |c| c.owner_id = Some("999".into())),
      req: TokenRequest::default(),
      expect: Err(denied_any()),
    },
    Case {
      name: "other issuer never matches default",
      caller: with(caller(1), |c| c.issuer = "forgejo".into()),
      req: TokenRequest::default(),
      expect: Err(denied_any()),
    },
    Case {
      name: "merge override on main",
      caller: caller(11),
      req: TokenRequest::default(),
      expect: Ok((
        "override-11",
        vec![11],
        perms(&[
          ("contents", Level::Write),
          ("metadata", Level::Read),
          ("packages", Level::Write),
          ("pull_requests", Level::Write),
        ]),
      )),
    },
    Case {
      name: "merge override off main falls back to default",
      caller: with(caller(11), |c| c.ref_ = Some("refs/heads/dev".into())),
      req: TokenRequest::default(),
      expect: Ok(("default-self", vec![11], default_perms.clone())),
    },
    Case {
      name: "replace override on main",
      caller: caller(12),
      req: TokenRequest::default(),
      expect: Ok(("override-12", vec![12], perms(&[("contents", Level::Read)]))),
    },
    Case {
      name: "replace override off main denies",
      caller: with(caller(12), |c| c.ref_ = Some("refs/heads/dev".into())),
      req: TokenRequest::default(),
      expect: Err(denied_any()),
    },
    Case {
      name: "cross-repo grant, full target",
      caller: caller(13),
      req: TokenRequest::default(),
      expect: Ok((
        "override-13",
        vec![13, 98, 99],
        perms(&[
          ("contents", Level::Write),
          ("metadata", Level::Read),
          ("pull_requests", Level::Write),
        ]),
      )),
    },
    Case {
      name: "cross-repo grant, caller subset",
      caller: caller(13),
      req: TokenRequest {
        repository_ids: vec![99],
        permissions: perms(&[("contents", Level::Write)]),
        ..Default::default()
      },
      expect: Ok((
        "override-13",
        vec![99],
        perms(&[("contents", Level::Write)]),
      )),
    },
    Case {
      name: "target outside grant",
      caller: caller(13),
      req: TokenRequest {
        repository_ids: vec![500],
        ..Default::default()
      },
      expect: Err(denied_any()),
    },
    Case {
      name: "subset without allow_caller_target",
      caller: caller(1),
      req: TokenRequest {
        repository_ids: vec![2],
        ..Default::default()
      },
      expect: Err(denied_any()),
    },
    Case {
      name: "requesting exactly self is fine",
      caller: caller(1),
      req: TokenRequest {
        repository_ids: vec![1],
        ..Default::default()
      },
      expect: Ok(("default-self", vec![1], default_perms.clone())),
    },
    Case {
      name: "requested permission above grant",
      caller: caller(1),
      req: TokenRequest {
        permissions: perms(&[("contents", Level::Admin)]),
        ..Default::default()
      },
      expect: Err(denied_any()),
    },
    Case {
      name: "requested permission not in grant",
      caller: caller(1),
      req: TokenRequest {
        permissions: perms(&[("issues", Level::Read)]),
        ..Default::default()
      },
      expect: Err(denied_any()),
    },
    Case {
      name: "requested permission subset",
      caller: caller(1),
      req: TokenRequest {
        permissions: perms(&[("contents", Level::Read)]),
        ..Default::default()
      },
      expect: Ok(("default-self", vec![1], perms(&[("contents", Level::Read)]))),
    },
    Case {
      name: "deny rule wins over default",
      caller: with(caller(17), |c| {
        c.runner_environment = Some("self-hosted".into())
      }),
      req: TokenRequest::default(),
      expect: Err(denied_any()),
    },
    Case {
      name: "deny rule does not hit github-hosted",
      caller: caller(17),
      req: TokenRequest::default(),
      expect: Ok(("default-self", vec![17], default_perms.clone())),
    },
    Case {
      name: "deny rule beats a profile",
      caller: with(caller(17), |c| {
        c.runner_environment = Some("self-hosted".into());
        c.ref_type = Some("tag".into());
        c.ref_ = Some("refs/tags/v1".into());
      }),
      req: TokenRequest {
        profile: Some("release".into()),
        ..Default::default()
      },
      expect: Err(denied_any()),
    },
    Case {
      name: "priority rule picks other app and target",
      caller: caller(16),
      req: TokenRequest::default(),
      expect: Ok(("renovate", vec![77], perms(&[("contents", Level::Write)]))),
    },
    Case {
      name: "profile on tag",
      caller: with(caller(1), |c| {
        c.ref_type = Some("tag".into());
        c.ref_ = Some("refs/tags/v1".into());
      }),
      req: TokenRequest {
        profile: Some("release".into()),
        ..Default::default()
      },
      expect: Ok((
        "release",
        vec![1],
        perms(&[("contents", Level::Write), ("packages", Level::Write)]),
      )),
    },
    Case {
      name: "profile match fails on branch",
      caller: caller(1),
      req: TokenRequest {
        profile: Some("release".into()),
        ..Default::default()
      },
      expect: Err(denied_any()),
    },
    Case {
      name: "unknown profile",
      caller: caller(1),
      req: TokenRequest {
        profile: Some("nope".into()),
        ..Default::default()
      },
      expect: Err(denied_any()),
    },
    Case {
      name: "profile still bound to owner",
      caller: with(caller(1), |c| {
        c.owner_id = Some("999".into());
        c.ref_type = Some("tag".into());
      }),
      req: TokenRequest {
        profile: Some("release".into()),
        ..Default::default()
      },
      expect: Err(denied_any()),
    },
    Case {
      name: "workflow_run denied by default",
      caller: with(caller(1), |c| c.event_name = Some("workflow_run".into())),
      req: TokenRequest::default(),
      expect: Err(denied_any()),
    },
    Case {
      name: "pull_request_target denied by default",
      caller: with(caller(1), |c| {
        c.event_name = Some("pull_request_target".into())
      }),
      req: TokenRequest::default(),
      expect: Err(denied_any()),
    },
    Case {
      name: "opt-in per rule",
      caller: with(caller(14), |c| c.event_name = Some("workflow_run".into())),
      req: TokenRequest::default(),
      expect: Ok(("override-14", vec![14], default_perms.clone())),
    },
    Case {
      name: "PR ref downgrades to read",
      caller: with(caller(1), |c| {
        c.ref_ = Some("refs/pull/5/merge".into());
        c.ref_type = None;
        c.event_name = Some("pull_request".into());
      }),
      req: TokenRequest::default(),
      expect: Ok((
        "default-self",
        vec![1],
        perms(&[
          ("contents", Level::Read),
          ("metadata", Level::Read),
          ("pull_requests", Level::Read),
        ]),
      )),
    },
    Case {
      name: "explicit write on PR ref is 403",
      caller: with(caller(1), |c| {
        c.ref_ = Some("refs/pull/5/merge".into());
        c.ref_type = None;
      }),
      req: TokenRequest {
        permissions: perms(&[("contents", Level::Write)]),
        ..Default::default()
      },
      expect: Err(denied_any()),
    },
    Case {
      name: "opt-out keeps write",
      caller: with(caller(15), |c| {
        c.ref_ = Some("refs/pull/5/merge".into());
        c.ref_type = None;
      }),
      req: TokenRequest::default(),
      expect: Ok(("override-15", vec![15], default_perms.clone())),
    },
    Case {
      name: "dangerous only via opted-in profile",
      caller: caller(1),
      req: TokenRequest {
        profile: Some("admin".into()),
        ..Default::default()
      },
      expect: Ok(("admin", vec![1], perms(&[("administration", Level::Write)]))),
    },
    Case {
      name: "dangerous permission request on default is 403",
      caller: caller(1),
      req: TokenRequest {
        permissions: perms(&[("administration", Level::Write)]),
        ..Default::default()
      },
      expect: Err(denied_any()),
    },
  ];

  for case in cases {
    let got = eval(&case.caller, &case.req, &install_all());
    match (&case.expect, got) {
      (Ok((rule, ids, p)), Ok((got_rule, d))) => {
        assert_eq!(&got_rule, rule, "{}", case.name);
        assert_eq!(&d.repository_ids, ids, "{}", case.name);
        assert_eq!(&d.permissions, p, "{}", case.name);
      }
      (Err(EvalError::Denied(_)), Err(EvalError::Denied(_))) => {}
      (Err(EvalError::NotInstalled(_)), Err(EvalError::NotInstalled(_))) => {}
      (expect, got) => panic!("{}: expected {expect:?}, got {got:?}", case.name),
    }
  }
}

#[test]
fn installation_permissions_cap_the_grant() {
  // Installation only has contents:read.
  let install = perms(&[("contents", Level::Read)]);
  let (_, d) = eval(&caller(1), &TokenRequest::default(), &install).unwrap();
  assert_eq!(d.permissions, perms(&[("contents", Level::Read)]));

  let req = TokenRequest {
    permissions: perms(&[("contents", Level::Write)]),
    ..Default::default()
  };
  assert!(matches!(
    eval(&caller(1), &req, &install),
    Err(EvalError::NotInstalled(_))
  ));
  assert!(matches!(
    eval(&caller(1), &TokenRequest::default(), &Permissions::new()),
    Err(EvalError::NotInstalled(_))
  ));
}

#[test]
fn rule_choice_is_deterministic() {
  let cfg = format!(
    "{CONFIG}\n[[rules]]\nname = \"a-tie\"\npriority = 50\nrepositories = [1]\npermissions = {{ contents = \"read\" }}\nmatch = {{ repository_id = 16 }}\n"
  );
  let policy = Config::parse(&cfg).unwrap().policy;
  for _ in 0..10 {
    let rule = select(&caller(16), &TokenRequest::default(), &policy).unwrap();
    assert_eq!(rule.name, "a-tie");
  }
}

/// The CI profiles from config.example.toml (used to replace commit-bot secrets).
mod ci_profiles {
  use super::*;

  const EXAMPLE: &str = include_str!("../../config.example.toml");
  const OWNER: u64 = 92174452;
  const HELM_CHARTS: u64 = 500;

  fn ci(workflow: &str, git_ref: &str, event: &str) -> Caller {
    let mut c = Caller::test("Profiidev/app", 7, OWNER);
    c.ref_ = Some(git_ref.into());
    c.ref_type = if git_ref.starts_with("refs/heads/") {
      Some("branch".into())
    } else if git_ref.starts_with("refs/tags/") {
      Some("tag".into())
    } else {
      None
    };
    c.event_name = Some(event.into());
    c.job_workflow_ref = Some(format!(
      "Profiidev/app/.github/workflows/{workflow}@{git_ref}"
    ));
    c
  }

  fn run(c: &Caller, profile: &str) -> Result<Decision, EvalError> {
    let policy = Config::parse(EXAMPLE).unwrap().policy;
    let req = TokenRequest {
      profile: Some(profile.into()),
      ..Default::default()
    };
    let rule = select(c, &req, &policy)?;
    let mut rule_targets = Vec::new();
    if rule.grant.target.include_self {
      rule_targets.push(7);
    }
    // Only named target in these profiles is helm-charts.
    rule_targets.extend(rule.grant.target.repos.iter().map(|_| HELM_CHARTS));
    let all: Permissions = [
      "contents",
      "checks",
      "pull_requests",
      "issues",
      "statuses",
      "workflows",
      "vulnerability_alerts",
    ]
    .into_iter()
    .map(|p| (p.to_string(), Level::Write))
    .collect();
    finalize(
      c,
      &req,
      rule,
      &Resolved {
        rule_targets,
        requested_targets: None,
      },
      &all,
    )
  }

  #[test]
  fn lint() {
    let d = run(
      &ci("checks.yml", "refs/pull/3/merge", "pull_request"),
      "lint",
    )
    .unwrap();
    assert_eq!(d.repository_ids, vec![7]);
    assert_eq!(d.permissions["contents"], Level::Write);
    assert_eq!(d.permissions["checks"], Level::Write);
    assert!(
      run(
        &ci("other.yml", "refs/pull/3/merge", "pull_request"),
        "lint"
      )
      .is_err()
    );
  }

  #[test]
  fn publish() {
    let d = run(
      &ci("checks-publish.yml", "refs/heads/main", "workflow_run"),
      "publish",
    )
    .unwrap();
    assert_eq!(d.permissions["checks"], Level::Write);
    assert_eq!(d.permissions["contents"], Level::Read);
    run(
      &ci("tests-publish.yml", "refs/heads/main", "workflow_run"),
      "publish",
    )
    .unwrap();
    assert!(
      run(
        &ci("checks-publish.yml", "refs/heads/dev", "workflow_run"),
        "publish"
      )
      .is_err()
    );
    assert!(
      run(
        &ci("checks-publish.yml", "refs/heads/main", "push"),
        "publish"
      )
      .is_err()
    );
    // workflow_run stays denied for the default rule.
    let c = ci("checks-publish.yml", "refs/heads/main", "workflow_run");
    let policy = Config::parse(EXAMPLE).unwrap().policy;
    assert!(select(&c, &TokenRequest::default(), &policy).is_err());
  }

  #[test]
  fn chart_bump() {
    let d = run(&ci("release.yml", "refs/tags/v1.2.3", "push"), "chart-bump").unwrap();
    assert_eq!(d.repository_ids, vec![HELM_CHARTS]);
    assert_eq!(d.permissions, perms(&[("contents", Level::Write)]));
    assert!(run(&ci("release.yml", "refs/heads/main", "push"), "chart-bump").is_err());
    assert!(run(&ci("checks.yml", "refs/tags/v1.2.3", "push"), "chart-bump").is_err());
  }

  #[test]
  fn renovate() {
    let d = run(
      &ci("renovate.yml", "refs/heads/main", "schedule"),
      "renovate",
    )
    .unwrap();
    assert_eq!(d.permissions["workflows"], Level::Write);
    let d = run(
      &ci("renovate.yml", "refs/pull/9/merge", "pull_request"),
      "renovate",
    )
    .unwrap();
    assert_eq!(d.permissions["workflows"], Level::Write);
    assert!(run(&ci("renovate.yml", "refs/heads/dev", "push"), "renovate").is_err());
    assert!(run(&ci("checks.yml", "refs/heads/main", "push"), "renovate").is_err());
  }
}

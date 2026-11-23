//! T4: `--check` and atomic reload.

mod common;

use std::process::Command;

use common::*;
use serde_json::json;

fn check(text: &str) -> bool {
  let dir = tempfile::tempdir().unwrap();
  let path = dir.path().join("config.toml");
  std::fs::write(&path, text).unwrap();
  Command::new(env!("CARGO_BIN_EXE_backend"))
    .args(["--check", "--config", path.to_str().unwrap()])
    .output()
    .unwrap()
    .status
    .success()
}

#[test]
fn check_flag() {
  assert!(check(include_str!("../config.example.toml")));
  assert!(!check("not toml ["));
  assert!(!check("[[apps]]\nname='a'\nclient_id='x'\nkeys=[]"));
  // A single bad rule fails the whole file.
  let bad = format!(
    "{}\n[[rules]]\nname='x'\neffect='deny'\nmatch={{ref={{regex='('}}}}",
    include_str!("../config.example.toml")
  );
  assert!(!check(&bad));
}

#[tokio::test]
async fn invalid_reload_keeps_old_config() {
  let s = TestServer::start().await;
  let path = s.config_path();
  let good = std::fs::read_to_string(&path).unwrap();
  let before = s.app_state.runtime.load_full();

  // Valid TOML, but one rule is broken: nothing may be applied.
  std::fs::write(
    &path,
    good.replace(
      "[[profiles]]\nname = \"release\"",
      "[[rules]]\nname = \"broken\"\neffect = \"deny\"\nmatch = { ref = { regex = \"(\" } }\n\n[[profiles]]\nname = \"release\"",
    ),
  )
  .unwrap();
  assert!(s.app_state.reload().is_err());
  assert!(std::sync::Arc::ptr_eq(
    &before,
    &s.app_state.runtime.load_full()
  ));

  // Missing key file fails too.
  std::fs::write(&path, good.replace("app-key.pem", "missing.pem")).unwrap();
  assert!(s.app_state.reload().is_err());
  assert!(std::sync::Arc::ptr_eq(
    &before,
    &s.app_state.runtime.load_full()
  ));

  // Still serving with the old config.
  let (status, _) = s
    .post_token(&s.token("Profiidev/nix", 42, OWNER_ID), json!({}))
    .await;
  assert_eq!(status, 200);

  // A valid change applies: disable self-scope, now everything is denied.
  std::fs::write(
    &path,
    good.replace("self_scope = true", "self_scope = false"),
  )
  .unwrap();
  s.app_state.reload().unwrap();
  assert!(
    s.app_state.runtime.load().ready(),
    "issuer JWKS kept across reload"
  );
  let (status, _) = s
    .post_token(&s.token("Profiidev/nix", 42, OWNER_ID), json!({}))
    .await;
  assert_eq!(status, 403);
}

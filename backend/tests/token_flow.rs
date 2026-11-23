//! End-to-end token flows against a mocked GitHub API.

mod common;

use common::*;
use serde_json::{Value, json};

/// Every mint is scoped by repositories and permissions.
fn assert_mints_scoped(server: &TestServer) {
  let mints = server.mint_bodies();
  assert!(!mints.is_empty());
  for body in mints {
    let perms = body["permissions"]
      .as_object()
      .expect("permissions present");
    assert!(!perms.is_empty(), "permissions non-empty: {body}");
    let ids = body["repository_ids"].as_array().map(Vec::len).unwrap_or(0);
    let names = body["repositories"].as_array().map(Vec::len).unwrap_or(0);
    assert!(ids + names > 0, "repository scope present: {body}");
  }
}

/// The token a caller receives always comes from a repository_ids mint.
fn last_caller_mint(server: &TestServer) -> Value {
  server
    .mint_bodies()
    .into_iter()
    .rev()
    .find(|b| b.get("repository_ids").is_some())
    .unwrap()
}

#[tokio::test]
async fn self_scope_default() {
  let s = TestServer::start().await;
  let (status, body) = s
    .post_token(&s.token("Profiidev/nix", 42, OWNER_ID), json!({}))
    .await;
  assert_eq!(status, 200, "{body}");
  assert_eq!(body["repository_ids"], json!([42]));
  assert_eq!(body["repositories"], json!(["Profiidev/nix"]));
  assert_eq!(body["rule"], "default-self");
  assert_eq!(body["app"], "main");
  assert_eq!(
    body["permissions"],
    json!({ "contents": "write", "metadata": "read", "pull_requests": "write" })
  );
  assert!(body["token"].as_str().unwrap().starts_with("ghs_"));
  let mint = last_caller_mint(&s);
  assert_eq!(mint["repository_ids"], json!([42]));
  assert_mints_scoped(&s);
}

#[tokio::test]
async fn empty_body_and_get_variant() {
  let s = TestServer::start().await;
  let res = s
    .client
    .post(format!("{}/api/v1/token", s.url))
    .bearer_auth(s.token("Profiidev/nix", 42, OWNER_ID))
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), 200);

  let res = s
    .client
    .get(format!("{}/api/v1/token?permissions=contents:read", s.url))
    .bearer_auth(s.token("Profiidev/nix", 42, OWNER_ID))
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), 200);
  let body: Value = res.json().await.unwrap();
  assert_eq!(body["permissions"], json!({ "contents": "read" }));
}

#[tokio::test]
async fn cross_repo_by_name_and_subset() {
  let s = TestServer::start().await;
  let (status, body) = s
    .post_token(&s.token("Profiidev/foo", 1, OWNER_ID), json!({}))
    .await;
  assert_eq!(status, 200, "{body}");
  assert_eq!(body["repository_ids"], json!([1, 42, 43]));

  let (status, body) = s
    .post_token(
      &s.token("Profiidev/foo", 1, OWNER_ID),
      json!({ "repositories": ["Profiidev/nix"], "permissions": { "contents": "write" } }),
    )
    .await;
  assert_eq!(status, 200, "{body}");
  assert_eq!(body["repository_ids"], json!([42]));
  assert_eq!(
    last_caller_mint(&s)["permissions"],
    json!({ "contents": "write" })
  );
  assert_mints_scoped(&s);
}

#[tokio::test]
async fn denials() {
  let s = TestServer::start().await;
  // Not in the cross-repo grant.
  let (status, body) = s
    .post_token(
      &s.token("Profiidev/nix", 42, OWNER_ID),
      json!({ "repositories": ["Profiidev/foo"] }),
    )
    .await;
  assert_eq!(status, 403);
  assert_eq!(body["error"], "access_denied");
  // No rule detail leaks.
  assert!(!body.to_string().contains("default-self"));

  // Requested permission above the grant.
  let (status, _) = s
    .post_token(
      &s.token("Profiidev/nix", 42, OWNER_ID),
      json!({ "permissions": { "contents": "admin" } }),
    )
    .await;
  assert_eq!(status, 403);

  // Owner not in owner_ids.
  let (status, _) = s
    .post_token(&s.token("Stranger/x", 9, 999), json!({}))
    .await;
  assert_eq!(status, 403);

  // Profile that does not match (branch, not tag).
  let (status, _) = s
    .post_token(
      &s.token("Profiidev/nix", 42, OWNER_ID),
      json!({ "profile": "release" }),
    )
    .await;
  assert_eq!(status, 403);
}

#[tokio::test]
async fn profile_on_tag() {
  let s = TestServer::start().await;
  let token = s.token_with("Profiidev/nix", 42, OWNER_ID, |c| {
    c["ref"] = json!("refs/tags/v1.0.0");
    c["ref_type"] = json!("tag");
  });
  let (status, body) = s.post_token(&token, json!({ "profile": "release" })).await;
  assert_eq!(status, 200, "{body}");
  assert_eq!(body["rule"], "release");
  assert_eq!(
    body["permissions"],
    json!({ "contents": "write", "packages": "write" })
  );
}

#[tokio::test]
async fn token_errors() {
  let s = TestServer::start().await;
  let res = s
    .client
    .post(format!("{}/api/v1/token", s.url))
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), 401);

  let (status, body) = s.post_token("not.a.jwt", json!({})).await;
  assert_eq!(status, 401);
  assert_eq!(body["error"], "invalid_token");

  // Replay over HTTP.
  let token = s.token("Profiidev/nix", 42, OWNER_ID);
  assert_eq!(s.post_token(&token, json!({})).await.0, 200);
  assert_eq!(s.post_token(&token, json!({})).await.0, 401);

  // Malformed body.
  let (status, body) = s
    .post_token(
      &s.token("Profiidev/nix", 42, OWNER_ID),
      json!({ "bogus": 1 }),
    )
    .await;
  assert_eq!(status, 400);
  assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn not_installed_and_upstream_errors() {
  let s = TestServer::start().await;
  let (status, body) = s
    .post_token(&s.token("NotInstalled/x", 5, 200), json!({}))
    .await;
  assert_eq!(status, 422, "{body}");
  assert_eq!(body["error"], "not_installed");

  let (status, body) = s.post_token(&s.token("Broken/x", 6, 300), json!({})).await;
  assert_eq!(status, 502, "{body}");
  assert_eq!(body["error"], "upstream_error");

  // Repo id the installation does not contain: GitHub refuses the mint.
  let (status, _) = s
    .post_token(&s.token("Profiidev/ghost", 999, OWNER_ID), json!({}))
    .await;
  assert_eq!(status, 422);
}

#[tokio::test]
async fn targets_in_two_installations() {
  let s = TestServer::start().await;
  let (status, body) = s
    .post_token(
      &s.token("Profiidev/nix", 42, OWNER_ID),
      json!({ "profile": "cross-install" }),
    )
    .await;
  assert_eq!(status, 400, "{body}");
  assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn rfc8693_exchange() {
  let s = TestServer::start().await;
  let res = s
    .client
    .post(format!("{}/api/v1/exchange", s.url))
    .form(&[
      (
        "grant_type",
        "urn:ietf:params:oauth:grant-type:token-exchange",
      ),
      ("subject_token", &s.token("Profiidev/foo", 1, OWNER_ID)),
      ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
      ("resource", "Profiidev/nix"),
    ])
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), 200);
  let body: Value = res.json().await.unwrap();
  assert_eq!(body["token_type"], "Bearer");
  assert_eq!(
    body["issued_token_type"],
    "urn:ietf:params:oauth:token-type:access_token"
  );
  assert!(body["access_token"].as_str().unwrap().starts_with("ghs_"));
  assert!(body["expires_in"].as_i64().unwrap() > 0);
  assert_eq!(last_caller_mint(&s)["repository_ids"], json!([42]));

  let res = s
    .client
    .post(format!("{}/api/v1/exchange", s.url))
    .json(&json!({
      "grant_type": "password",
      "subject_token": "x",
      "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    }))
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn revoke() {
  let s = TestServer::start().await;
  let res = s
    .client
    .delete(format!("{}/api/v1/token", s.url))
    .bearer_auth(s.token("Profiidev/nix", 42, OWNER_ID))
    .json(&json!({ "token": "ghs_abc" }))
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), 204);
  let revoked = s
    .mock
    .received_requests()
    .await
    .unwrap()
    .into_iter()
    .any(|r| {
      r.method == wiremock::http::Method::DELETE
        && r.headers.get("authorization").unwrap().to_str().unwrap() == "Bearer ghs_abc"
    });
  assert!(revoked);

  // Without a subject token.
  let res = s
    .client
    .delete(format!("{}/api/v1/token", s.url))
    .json(&json!({ "token": "ghs_abc" }))
    .send()
    .await
    .unwrap();
  assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn rate_limit_per_repository() {
  let s = TestServer::start_with("[limits]\nper_repository = \"2/min\"\nburst = 2").await;
  async fn call(s: &TestServer) -> (u16, Value) {
    s.post_token(&s.token("Profiidev/nix", 42, OWNER_ID), json!({}))
      .await
  }
  assert_eq!(call(&s).await.0, 200);
  assert_eq!(call(&s).await.0, 200);
  let (status, body) = call(&s).await;
  assert_eq!(status, 429);
  assert_eq!(body["error"], "rate_limited");
  // Another repository has its own bucket.
  assert_eq!(
    s.post_token(&s.token("Profiidev/foo", 1, OWNER_ID), json!({}))
      .await
      .0,
    200
  );
}

#[tokio::test]
async fn health_and_metrics() {
  let s = TestServer::start().await;
  for p in ["/api/health", "/api/readyz"] {
    assert_eq!(
      s.client
        .get(format!("{}{p}", s.url))
        .send()
        .await
        .unwrap()
        .status(),
      200
    );
  }
  s.post_token(&s.token("Profiidev/nix", 42, OWNER_ID), json!({}))
    .await;
  let metrics = s
    .client
    .get(format!("{}/api/metrics", s.url))
    .send()
    .await
    .unwrap()
    .text()
    .await
    .unwrap();
  for name in [
    "broker_requests_total",
    "broker_request_duration_seconds",
    "broker_github_requests_total",
    "broker_jwks_refresh_total",
  ] {
    assert!(metrics.contains(name), "{name} missing:\n{metrics}");
  }
}

#[tokio::test]
async fn requested_names_are_checked_before_lookup() {
  let s = TestServer::start().await;
  let before = s.mock.received_requests().await.unwrap().len();
  // Default grant is self only: a foreign name is refused without asking GitHub.
  let (status, body) = s
    .post_token(
      &s.token("Profiidev/nix", 42, OWNER_ID),
      json!({ "repositories": ["Profiidev/secret-thing"] }),
    )
    .await;
  assert_eq!(status, 403, "{body}");
  let calls = s.mock.received_requests().await.unwrap();
  assert!(
    !calls[before..]
      .iter()
      .any(|r| r.url.path().contains("secret-thing")),
    "looked up an unrelated repository"
  );

  // Asking for yourself by name needs no lookup either.
  let (status, body) = s
    .post_token(
      &s.token("Profiidev/nix", 42, OWNER_ID),
      json!({ "repositories": ["profiidev/NIX"] }),
    )
    .await;
  assert_eq!(status, 200, "{body}");

  // Unknown names inside a lookup-capable grant answer access_denied, not not_installed.
  let (status, body) = s
    .post_token(
      &s.token("Profiidev/foo", 1, OWNER_ID),
      json!({ "repositories": ["Profiidev/ghost"] }),
    )
    .await;
  assert_eq!(status, 403, "{body}");
}

#[tokio::test]
async fn request_limits_and_name_validation() {
  let s = TestServer::start().await;
  let many: Vec<u64> = (0..21).collect();
  let (status, _) = s
    .post_token(
      &s.token("Profiidev/nix", 42, OWNER_ID),
      json!({ "repository_ids": many }),
    )
    .await;
  assert_eq!(status, 400);
  for bad in ["Profiidev/..", "Profiidev/x?y", "../app/x", "a/b/c"] {
    let (status, _) = s
      .post_token(
        &s.token("Profiidev/nix", 42, OWNER_ID),
        json!({ "repositories": [bad] }),
      )
      .await;
    assert_eq!(status, 400, "{bad}");
  }
}

#[tokio::test]
async fn secondary_rate_limit_backs_off() {
  use wiremock::{
    Mock, ResponseTemplate,
    matchers::{method, path},
  };
  let s = TestServer::start().await;
  Mock::given(method("GET"))
    .and(path("/users/Limited/installation"))
    .respond_with(
      ResponseTemplate::new(403)
        .set_body_json(json!({ "message": "You have exceeded a secondary rate limit" })),
    )
    .mount(&s.mock)
    .await;
  let (status, _) = s.post_token(&s.token("Limited/x", 8, 300), json!({})).await;
  assert_eq!(status, 502);
  let count = |reqs: &[wiremock::Request]| {
    reqs
      .iter()
      .filter(|r| r.url.path() == "/users/Limited/installation")
      .count()
  };
  let first = count(&s.mock.received_requests().await.unwrap());
  // Backing off: the next call does not reach GitHub.
  let (status, _) = s.post_token(&s.token("Limited/x", 8, 300), json!({})).await;
  assert_eq!(status, 502);
  assert_eq!(count(&s.mock.received_requests().await.unwrap()), first);
}

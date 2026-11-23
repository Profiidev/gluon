//! Shared harness: one wiremock server plays both the OIDC issuer and the
//! GitHub API; the broker runs for real on an OS-assigned port.
#![allow(dead_code)]

use std::{
  io::Write,
  os::unix::fs::PermissionsExt,
  sync::{Arc, Mutex},
};

use backend::App;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tempfile::TempDir;
use wiremock::{
  Mock, MockServer, Request, Respond, ResponseTemplate,
  matchers::{method, path, path_regex},
};

pub const OIDC_KEY: &[u8] = include_bytes!("fixtures/oidc-key.pem");
pub const APP_KEY: &str = include_str!("fixtures/app-key.pem");
pub const JWKS: &str = include_str!("fixtures/jwks.json");

pub const OWNER_ID: u64 = 100;
pub const INSTALLATION: u64 = 555;

/// Repos GitHub knows about: (id, full_name, installation).
pub const REPOS: &[(u64, &str, u64)] = &[
  (1, "Profiidev/foo", 555),
  (42, "Profiidev/nix", 555),
  (43, "Profiidev/other", 555),
  (77, "OtherOrg/lib", 556),
];

pub struct TestServer {
  pub url: String,
  pub mock: MockServer,
  pub client: reqwest::Client,
  pub dir: TempDir,
  pub app_state: Arc<backend::AppState>,
  pub mints: Arc<Mutex<Vec<Value>>>,
}

/// Echo the mint body back as GitHub would, recording every request.
struct MintResponder {
  installation: u64,
  mints: Arc<Mutex<Vec<Value>>>,
}

impl Respond for MintResponder {
  fn respond(&self, req: &Request) -> ResponseTemplate {
    let body: Value = serde_json::from_slice(&req.body).unwrap();
    self.mints.lock().unwrap().push(body.clone());
    let in_installation = |r: &&(u64, &str, u64)| r.2 == self.installation;
    let mut repos = Vec::new();
    if let Some(ids) = body["repository_ids"].as_array() {
      for id in ids {
        match REPOS
          .iter()
          .filter(in_installation)
          .find(|r| Some(r.0) == id.as_u64())
        {
          Some(r) => repos.push(json!({ "id": r.0, "full_name": r.1 })),
          None => {
            return ResponseTemplate::new(422)
              .set_body_json(json!({ "message": "There is at least one repository that does not exist or is not accessible" }));
          }
        }
      }
    }
    if let Some(names) = body["repositories"].as_array() {
      for n in names {
        match REPOS
          .iter()
          .filter(in_installation)
          .find(|r| r.1.split('/').nth(1) == n.as_str())
        {
          Some(r) => repos.push(json!({ "id": r.0, "full_name": r.1 })),
          None => return ResponseTemplate::new(422).set_body_json(json!({ "message": "nope" })),
        }
      }
    }
    ResponseTemplate::new(201).set_body_json(json!({
      "token": format!("ghs_test{}", self.mints.lock().unwrap().len()),
      "expires_at": "2099-01-01T00:00:00Z",
      "permissions": body["permissions"],
      "repositories": repos,
    }))
  }
}

pub fn config(mock: &str, extra: &str) -> String {
  format!(
    r#"
[server]
reload_interval = "0s"

[[issuers]]
name = "github"
url = "{mock}"
kind = "github"
audience = "github-token-broker"

[[apps]]
name = "main"
client_id = "Iv1.test"
api_base = "{mock}"
keys = [{{ source = "file", path = "KEYPATH" }}]

[defaults]
self_scope = true
app = "main"
owner_ids = [100, 200, 300]
permissions = {{ contents = "write", metadata = "read", pull_requests = "write" }}

[[overrides]]
repository_id = 1
mode = "merge"
extra_targets = [{{ repository = "Profiidev/nix" }}, {{ repository = "Profiidev/other" }}]
allow_caller_target = true
permissions = {{ contents = "write" }}

[[profiles]]
name = "release"
permissions = {{ contents = "write", packages = "write" }}
match = {{ ref_type = "tag" }}

[[profiles]]
name = "cross-install"
repositories = ["Profiidev/nix", "OtherOrg/lib"]
permissions = {{ contents = "read" }}

{extra}
"#
  )
}

impl TestServer {
  pub async fn start() -> TestServer {
    TestServer::start_with("").await
  }

  pub async fn start_with(extra: &str) -> TestServer {
    let mock = MockServer::start().await;
    let mints = Arc::new(Mutex::new(Vec::new()));
    mount_github(&mock, mints.clone()).await;

    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("app-key.pem");
    let mut f = std::fs::File::create(&key_path).unwrap();
    f.write_all(APP_KEY.as_bytes()).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o400)).unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(
      &config_path,
      config(&mock.uri(), extra).replace("KEYPATH", key_path.to_str().unwrap()),
    )
    .unwrap();

    // Random port; metrics on the main listener under /api/metrics.
    unsafe {
      std::env::set_var("PORT", "0");
      std::env::set_var("LOG_LEVEL", "off");
      std::env::set_var("METRICS_ENABLED", "true");
      std::env::remove_var("METRICS_PORT");
    }
    let app = App::new(backend::Settings::parse(), config_path)
      .await
      .expect("app starts");
    let url = format!("http://127.0.0.1:{}", app.port());
    let app_state = app.state.clone();
    tokio::spawn(app.run());

    let client = reqwest::Client::new();
    for _ in 0..100 {
      if let Ok(r) = client.get(format!("{url}/api/readyz")).send().await
        && r.status() == 200
      {
        break;
      }
      tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    TestServer {
      url,
      mock,
      client,
      dir,
      app_state,
      mints,
    }
  }

  pub fn config_path(&self) -> std::path::PathBuf {
    self.dir.path().join("config.toml")
  }

  /// A fresh, valid GitHub-style token for `repository` (owner derived from the name).
  pub fn token(&self, repository: &str, repository_id: u64, owner_id: u64) -> String {
    self.token_with(repository, repository_id, owner_id, |_| {})
  }

  pub fn token_with(
    &self,
    repository: &str,
    repository_id: u64,
    owner_id: u64,
    f: impl FnOnce(&mut Value),
  ) -> String {
    let now = jsonwebtoken::get_current_timestamp();
    let owner = repository.split('/').next().unwrap();
    let nanos = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    let mut claims = json!({
      "iss": self.mock.uri(),
      "aud": "github-token-broker",
      "iat": now, "nbf": now, "exp": now + 300,
      "jti": format!("jti-{nanos}"),
      "sub": format!("repo:{repository}:ref:refs/heads/main"),
      "repository": repository,
      "repository_id": repository_id.to_string(),
      "repository_owner": owner,
      "repository_owner_id": owner_id.to_string(),
      "ref": "refs/heads/main",
      "ref_type": "branch",
      "event_name": "push",
      "runner_environment": "github-hosted",
      "job_workflow_ref": format!("{repository}/.github/workflows/ci.yml@refs/heads/main"),
    });
    f(&mut claims);
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-kid".into());
    jsonwebtoken::encode(
      &header,
      &claims,
      &EncodingKey::from_rsa_pem(OIDC_KEY).unwrap(),
    )
    .unwrap()
  }

  pub async fn post_token(&self, bearer: &str, body: Value) -> (u16, Value) {
    let res = self
      .client
      .post(format!("{}/api/v1/token", self.url))
      .bearer_auth(bearer)
      .json(&body)
      .send()
      .await
      .unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(Value::Null))
  }

  pub fn mint_bodies(&self) -> Vec<Value> {
    self.mints.lock().unwrap().clone()
  }
}

async fn mount_github(mock: &MockServer, mints: Arc<Mutex<Vec<Value>>>) {
  Mock::given(method("GET"))
    .and(path("/.well-known/openid-configuration"))
    .respond_with(
      ResponseTemplate::new(200)
        .set_body_json(json!({ "jwks_uri": format!("{}/jwks", mock.uri()) })),
    )
    .mount(mock)
    .await;
  Mock::given(method("GET"))
    .and(path("/jwks"))
    .respond_with(ResponseTemplate::new(200).set_body_raw(JWKS, "application/json"))
    .mount(mock)
    .await;

  // Owner 100 = Profiidev (installation 555), 200 = NotInstalled, 300 = Broken (557).
  Mock::given(method("GET"))
    .and(path("/users/Profiidev/installation"))
    .respond_with(
      ResponseTemplate::new(200).set_body_json(json!({ "id": 555, "account": { "id": 100 } })),
    )
    .mount(mock)
    .await;
  Mock::given(method("GET"))
    .and(path("/users/NotInstalled/installation"))
    .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "message": "Not Found" })))
    .mount(mock)
    .await;
  Mock::given(method("GET"))
    .and(path("/users/Broken/installation"))
    .respond_with(
      ResponseTemplate::new(200).set_body_json(json!({ "id": 557, "account": { "id": 300 } })),
    )
    .mount(mock)
    .await;
  for (_, name, inst) in REPOS {
    let account = if *inst == 555 { 100 } else { 400 };
    Mock::given(method("GET"))
      .and(path(format!("/repos/{name}/installation")))
      .respond_with(
        ResponseTemplate::new(200)
          .set_body_json(json!({ "id": inst, "account": { "id": account } })),
      )
      .mount(mock)
      .await;
  }
  for inst in [555u64, 556] {
    Mock::given(method("GET"))
      .and(path(format!("/app/installations/{inst}")))
      .respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "id": inst,
        "permissions": { "contents": "write", "metadata": "read", "pull_requests": "write", "packages": "write" }
      })))
      .mount(mock)
      .await;
    Mock::given(method("POST"))
      .and(path(format!("/app/installations/{inst}/access_tokens")))
      .respond_with(MintResponder {
        installation: inst,
        mints: mints.clone(),
      })
      .mount(mock)
      .await;
  }
  Mock::given(method("GET"))
    .and(path("/app/installations/557"))
    .respond_with(ResponseTemplate::new(500).set_body_json(json!({ "message": "boom" })))
    .mount(mock)
    .await;
  Mock::given(method("DELETE"))
    .and(path("/installation/token"))
    .respond_with(ResponseTemplate::new(204))
    .mount(mock)
    .await;
  Mock::given(method("GET"))
    .and(path_regex("^/never$"))
    .respond_with(ResponseTemplate::new(500))
    .mount(mock)
    .await;
}

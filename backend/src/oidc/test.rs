//! T2: subject token validation.

use std::sync::Arc;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use wiremock::{
  Mock, MockServer, ResponseTemplate,
  matchers::{method, path},
};

use super::*;
use crate::config::Config;

const OIDC_KEY: &[u8] = include_bytes!("../../tests/fixtures/oidc-key.pem");
const OTHER_KEY: &[u8] = include_bytes!("../../tests/fixtures/other-key.pem");
const OIDC_PUB: &[u8] = include_bytes!("../../tests/fixtures/oidc-pub.pem");
const JWKS: &str = include_str!("../../tests/fixtures/jwks.json");

struct Env {
  server: MockServer,
  issuer: Arc<Issuer>,
  replay: ReplayCache,
}

async fn env() -> Env {
  let server = MockServer::start().await;
  Mock::given(method("GET"))
    .and(path("/.well-known/openid-configuration"))
    .respond_with(
      ResponseTemplate::new(200)
        .set_body_json(json!({ "jwks_uri": format!("{}/jwks", server.uri()) })),
    )
    .mount(&server)
    .await;
  Mock::given(method("GET"))
    .and(path("/jwks"))
    .respond_with(
      ResponseTemplate::new(200)
        .insert_header("cache-control", "max-age=600")
        .set_body_raw(JWKS, "application/json"),
    )
    .mount(&server)
    .await;
  let cfg = Config::parse(&format!(
    r#"
[[issuers]]
name = "github"
url = "{}"
kind = "github"
audience = "github-token-broker"
[[apps]]
name = "main"
client_id = "x"
keys = [{{ source = "env", name = "K" }}]
"#,
    server.uri()
  ))
  .unwrap();
  let issuer = Arc::new(Issuer::new(cfg.issuers[0].clone(), reqwest::Client::new()));
  Env {
    server,
    issuer,
    replay: replay_cache(),
  }
}

fn claims(iss: &str) -> Value {
  let now = jsonwebtoken::get_current_timestamp();
  json!({
    "iss": iss,
    "aud": "github-token-broker",
    "iat": now,
    "nbf": now,
    "exp": now + 300,
    "jti": format!("jti-{}", rand_suffix()),
    "sub": "repo:Profiidev/foo:ref:refs/heads/main",
    "repository": "Profiidev/foo",
    "repository_id": "1",
    "repository_owner": "Profiidev",
    "repository_owner_id": "100",
    "ref": "refs/heads/main",
    "ref_type": "branch",
  })
}

fn rand_suffix() -> u128 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos()
}

fn sign_with(claims: &Value, key: &[u8], kid: &str) -> String {
  let mut header = Header::new(Algorithm::RS256);
  header.kid = Some(kid.into());
  jsonwebtoken::encode(&header, claims, &EncodingKey::from_rsa_pem(key).unwrap()).unwrap()
}

fn sign(claims: &Value) -> String {
  sign_with(claims, OIDC_KEY, "test-kid")
}

async fn check(env: &Env, token: &str) -> Result<Caller, String> {
  validate(std::slice::from_ref(&env.issuer), &env.replay, token).await
}

#[tokio::test]
async fn valid_token() {
  let env = env().await;
  let caller = check(&env, &sign(&claims(&env.server.uri())))
    .await
    .unwrap();
  assert_eq!(caller.repository.as_deref(), Some("Profiidev/foo"));
  assert!(env.issuer.ready());
}

#[tokio::test]
async fn rejects_bad_tokens() {
  let env = env().await;
  let iss = env.server.uri();
  let now = jsonwebtoken::get_current_timestamp();

  let mut c = claims(&iss);
  c["aud"] = json!("https://github.com/Profiidev");
  assert!(
    check(&env, &sign(&c)).await.unwrap_err().contains("verify"),
    "wrong aud"
  );

  let c = claims("https://evil.example.com");
  assert!(
    check(&env, &sign(&c))
      .await
      .unwrap_err()
      .contains("untrusted issuer"),
    "wrong iss"
  );

  let mut c = claims(&iss);
  c["exp"] = json!(now - 120);
  c["iat"] = json!(now - 200);
  c["nbf"] = json!(now - 200);
  assert!(check(&env, &sign(&c)).await.is_err(), "expired");

  let mut c = claims(&iss);
  c["iat"] = json!(now - 600);
  c["nbf"] = json!(now - 600);
  c["exp"] = json!(now + 600);
  assert!(
    check(&env, &sign(&c))
      .await
      .unwrap_err()
      .contains("too old"),
    "too old"
  );

  let mut c = claims(&iss);
  c["iat"] = json!(now + 600);
  assert!(check(&env, &sign(&c)).await.is_err(), "iat in future");

  let mut c = claims(&iss);
  c.as_object_mut().unwrap().remove("repository_id");
  assert!(
    check(&env, &sign(&c))
      .await
      .unwrap_err()
      .contains("missing claim"),
    "missing claim"
  );

  let c = claims(&iss);
  assert!(
    check(&env, &sign_with(&c, OTHER_KEY, "test-kid"))
      .await
      .unwrap_err()
      .contains("verify"),
    "wrong signature"
  );
}

#[tokio::test]
async fn unknown_kid_refetches_once_then_fails() {
  let env = env().await;
  let c = claims(&env.server.uri());
  let err = check(&env, &sign_with(&c, OTHER_KEY, "rotated"))
    .await
    .unwrap_err();
  assert!(err.contains("unknown kid"));
  let fetches =
    |reqs: &[wiremock::Request]| reqs.iter().filter(|r| r.url.path() == "/jwks").count();
  let first = fetches(&env.server.received_requests().await.unwrap());
  // Second unknown kid inside the refetch interval must not hit the issuer again.
  let c = claims(&env.server.uri());
  assert!(
    check(&env, &sign_with(&c, OTHER_KEY, "rotated-2"))
      .await
      .is_err()
  );
  assert_eq!(
    fetches(&env.server.received_requests().await.unwrap()),
    first
  );
}

#[tokio::test]
async fn alg_none_and_hs256_are_rejected() {
  let env = env().await;
  let c = claims(&env.server.uri());
  let b64 = |v: &Value| {
    use base64_url::encode;
    encode(&serde_json::to_vec(v).unwrap())
  };

  // alg=none, no signature.
  let none = format!(
    "{}.{}.",
    b64(&json!({ "alg": "none", "typ": "JWT", "kid": "test-kid" })),
    b64(&c)
  );
  assert!(check(&env, &none).await.is_err());

  // HS256 "signed" with the RSA public key (key confusion).
  let mut header = Header::new(Algorithm::HS256);
  header.kid = Some("test-kid".into());
  let hs = jsonwebtoken::encode(&header, &c, &EncodingKey::from_secret(OIDC_PUB).unwrap()).unwrap();
  assert!(check(&env, &hs).await.unwrap_err().contains("not allowed"));
}

#[tokio::test]
async fn replayed_jti_is_rejected() {
  let env = env().await;
  let token = sign(&claims(&env.server.uri()));
  check(&env, &token).await.unwrap();
  assert!(check(&env, &token).await.unwrap_err().contains("replayed"));
}

/// Tiny base64url encoder for crafting raw tokens.
mod base64_url {
  pub fn encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
      let b = [
        chunk[0],
        *chunk.get(1).unwrap_or(&0),
        *chunk.get(2).unwrap_or(&0),
      ];
      let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
      for i in 0..=chunk.len() {
        out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
      }
    }
    out
  }
}

# gluon

A self-hosted GitHub App token broker. A CI job sends its OIDC token and gets back a short-lived GitHub App installation token with a narrow scope.

- **Self-scope by default.** A workflow in repo A gets a token for repo A only. No repository needs any configuration.
- **Keys stay in the broker.** No CI secret holds a private key.
- **Central policy.** One TOML file holds overrides, cross-repo grants, profiles and deny rules.
- **Stateless.** Caches (JWKS, installations, repo IDs, replay set) live in memory.

## Use it in a workflow

```yaml
permissions:
  id-token: write

steps:
  - uses: profiidev/gluon@v1
    id: gluon
    with:
      url: https://gluon.profidev.io
      # optional:
      # repositories: Profiidev/other, 123456
      # permissions: contents:write, pull_requests:read
      # profile: release
  - run: gh pr list
    env:
      GH_TOKEN: ${{ steps.gluon.outputs.token }}
```

Inputs:

| Input            | Default                 |
| ---------------- | ----------------------- |
| `url`            | required                |
| `audience`       | `github-token-broker`   |
| `repositories`   | –                       |
| `permissions`    | –                       |
| `profile`        | –                       |
| `skip-revoke`    | `false`                 |
| `github-api-url` | `${{ github.api_url }}` |

Outputs: `token` (masked) and `expires_at`. The post step revokes the token unless `skip-revoke: true`.

Without the action:

```sh
OIDC=$(curl -sH "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=github-token-broker" | jq -r .value)
GH_TOKEN=$(curl -sf -X POST -H "Authorization: Bearer $OIDC" \
  https://gluon.profidev.io/v1/token | jq -r .token)
echo "::add-mask::$GH_TOKEN"
```

## API

Every endpoint except `/healthz`, `/readyz` and `/metrics` needs `Authorization: Bearer <OIDC token>`.

| Endpoint            | Purpose                                                                                                                                                                                                                             |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/token`    | Body (all optional): `{"repositories": ["o/n"], "repository_ids": [1], "permissions": {"contents": "write"}, "profile": "release"}`. Returns `token`, `expires_at`, `permissions`, `repository_ids`, `repositories`, `rule`, `app`. |
| `GET /v1/token`     | Same, with query parameters `profile`, `repositories=o/n,o/m`, `repository_ids=1,2`, `permissions=contents:write,issues:read`.                                                                                                      |
| `DELETE /v1/token`  | Body `{"token": "ghs_…"}`. Revokes the token through `DELETE /installation/token`.                                                                                                                                                  |
| `POST /v1/exchange` | RFC 8693, form or JSON. `subject_token` is in the body. `resource` is `owner/name`, an ID, or an owner (the owner form means "the grant's target"). `scope` is a profile.                                                           |
| `GET /healthz`      | Liveness.                                                                                                                                                                                                                           |
| `GET /readyz`       | The config is loaded, the keys are readable and every issuer's JWKS was fetched at least once.                                                                                                                                      |
| `GET /metrics`      | Prometheus metrics. Served on `server.metrics_listen` when that is set, otherwise on the main listener.                                                                                                                             |

Error bodies are `{"error": "<code>", "error_description": "<generic text>"}`. They never reveal policy details. Codes: `invalid_request` (400), `invalid_token` (401), `access_denied` (403), `not_installed` (422), `rate_limited` (429), `upstream_error` (502).

## Configuration

`CONFIG_PATH` (default `/etc/gluon/config.toml`) or `--config <path>` points at a TOML file. `LOG_LEVEL` sets the log level (default `info`).

`gluon --check [--config path]` validates the file and exits.

The config and key files are reloaded atomically:

- on `SIGHUP`,
- when their mtime changes, checked every `server.reload_interval` (default `10s`, `0s` disables this).

An invalid config or an unreadable key keeps the old configuration active. A change to a listen address needs a restart.

See [`backend/config.example.toml`](backend/config.example.toml) for a full example.

### `[server]`

`listen` (default `0.0.0.0:8000`), `metrics_listen`, `trusted_proxies` (CIDRs whose `X-Forwarded-For` is trusted for the audit log client IP), `reload_interval`.

### `[[issuers]]`

`name`, `url`, `audience`, plus optional:

- `jwks_url` (default: OIDC discovery)
- `kind`: `github` / `forgejo` / `generic`
- `max_token_age` (default `5m`, at most `1h`)
- `clock_skew` (default `60s`)
- `replay_protection` (default `true`, needs `jti`)
- `algorithms` (default `["RS256"]`; HMAC algorithms are rejected)
- `claims` (map a caller field to a claim name)
- `required_claims`

If `[[issuers]]` is left out, the GitHub Actions issuer is configured with audience `github-token-broker`.

- `github`: claims as GitHub sends them. Only this kind supports `self` and `owner` targets, because only its IDs are GitHub repository IDs.
- `forgejo`: same claim names as GitHub. Use it with explicit `repositories` targets.
- `generic`: anything else. Map fields with `claims = { repository = "project_path", owner = "namespace_path" }`.

Caller fields you can use in `match`: `issuer`, `owner`, `owner_id`, `repository`, `repository_id`, `ref`, `ref_type`, `sha`, `event_name`, `workflow_ref`, `job_workflow_ref`, `environment`, `runner_environment`, `actor`, `actor_id`, `sub`, and `claims.<name>` for any raw claim.

### `[[apps]]`

`name`, `client_id` (or the app ID), `keys` and `api_base` (default `https://api.github.com`, set it for GHES).

`keys` is a list of sources, tried in order:

- `{ source = "file", path = ".." }`: the file must not be group-writable or world-accessible. 0400 is best; 0440 is accepted for Kubernetes `fsGroup`.
- `{ source = "systemd-credential", name = ".." }`
- `{ source = "env", name = ".." }`

Signing uses the first key that works. If GitHub answers 401, the next key is tried.

`[[apps.installations]] owner_id/installation_id` pins installations. Without it, the installation is looked up and cached.

### Policy

| Section         | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `[defaults]`    | `self_scope = true` enables the built-in rule `default-self`: issuer `github` (or `defaults.issuer`), `owner_id ∈ owner_ids`, target self, permissions `defaults.permissions`, app `defaults.app` (or the only app).                                                                                                                                                                                                                                    |
| `[[overrides]]` | Keyed by `repository_id`. `mode = "merge"` adds `permissions` on top of the defaults and keeps the default owner check. `mode = "replace"` grants only its own `permissions`, **and the default rule never applies to that repo**: if the override's `match` fails, the request is denied. `extra_targets = [{ repository = "o/n" } \| { repository_id = 1 }]` adds cross-repo targets. Priority defaults to 10, so an override beats the default rule. |
| `[[profiles]]`  | A named grant, selected with `profile=<name>`. Its `match` must still hold.                                                                                                                                                                                                                                                                                                                                                                             |
| `[[rules]]`     | General `allow`/`deny` rules with a `priority`. Any matching deny wins, profiles included.                                                                                                                                                                                                                                                                                                                                                              |

Rules and profiles take `target = "self" \| "owner" \| "repositories"`, `repositories = [id \| "o/n"]`, `permissions`, `app` and `match`. Allow rules without an `owner_id` or `repository_id` condition are automatically bound to `defaults.owner_ids`. Without owner IDs they are rejected.

`match` is a table of conditions, and all of them must hold:

- `field = "x"` (eq)
- `field = [..]` (in)
- `field = { eq, in, glob, regex, not_eq, not_in, not_glob, not_regex }`
- `expr = "<CEL over caller>"`

Regexes are anchored. In globs, `*` does not cross `/`; use `**` for that.

Per-rule flags:

| Flag                     | Effect                                                                                                                                                                             |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allow_caller_target`    | The caller may request a subset of the target. Asking for exactly the target always works.                                                                                         |
| `allow_owner_wide`       | Required for `target = "owner"`.                                                                                                                                                   |
| `allow_events = [..]`    | H1: `pull_request_target` and `workflow_run` are denied unless listed here.                                                                                                        |
| `allow_non_branch_write` | H2: on refs that are not a branch or tag (for example `refs/pull/*`), unrequested write permissions become read, and an explicit write request gets 403. This flag turns that off. |
| `allow_dangerous`        | H4: required for `administration`, `workflows`, `secrets`, `members` and `organization_administration`.                                                                            |

A token never exceeds `requested ∩ rule ∩ installation`. An explicitly requested permission above the rule gets 403. One above what the installation has gets 422. All targets must be in one installation, otherwise 400.

### `[limits]`

`per_repository = "30/min"` (also `/s`, `/h`) and `burst`. The limit is kept per issuer and repository, in memory.

## Operations

- Audit log: one JSON line on stdout per request (`"audit": true`). It holds the caller claims, the requested and granted targets and permissions, rule, app, installation, outcome, reason, expiry, latency and a SHA-256 prefix of the issued token. The subject token, the GitHub token and key material are never logged.
- Metrics:
  - `broker_requests_total{outcome,rule,app}`
  - `broker_request_duration_seconds`
  - `broker_github_requests_total{endpoint,status}`
  - `broker_github_ratelimit_remaining{app,installation}`
  - `broker_jwks_refresh_total{issuer,result}`
  - `broker_config_reload_total{result}`
  - `broker_replay_rejected_total`
- Replay protection and rate limits are per process. Run a single replica.
- Expose only `/v1/*` publicly. The chart's ingress does that.

## Deployment

The image is `ghcr.io/profiidev/gluon/gluon` (scratch, non-root). The chart is `gluon` in `profiidev/helm-charts`, and the ArgoCD app is `terraform/apps/gluon.tf` in server-config.

Before the first sync:

1. Store the GitHub App private key in Vault at `tools/gluon`, field `main-key.pem`.
2. Release a version: run the `Release Version` workflow. The resulting tag builds the image and bumps the chart.

## Development

```sh
cargo nextest run                 # backend tests (no Docker needed)
cargo run -- --check --config backend/config.example.toml
npm ci && cd action && npm test && npm run build
```

Not implemented from the spec:

- in-repo `.sts` policies and `/sts/exchange`
- external signers (KMS, PKCS#11, Transit)
- a shared replay store (Redis)
- a NixOS module
- OpenTelemetry/Sentry export (only `tracing` spans exist)

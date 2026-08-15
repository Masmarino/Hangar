# Test hardening: HTTP remote registry error mapping (npm + Docker)

Scope: `crates/hangar-infrastructure/src/http_remote_npm_registry.rs` and
`crates/hangar-infrastructure/src/http_remote_docker_registry.rs`. Both proxy to real
remote registries; before this pass their non-2xx/parse/body-read error-mapping code was
exercised only by an `#[ignore]`d real-network test and a redirect-not-followed test —
nothing hit it against a controlled server.

## SSRF guard check (done first, per instructions)

Read `crates/hangar-infrastructure/src/ssrf_guard.rs`. `ensure_public_host` unconditionally
rejects loopback (`is_loopback()`), RFC1918, link-local, etc., with no test-only bypass, no
env var, no injectable allow-list. Its own tests (`rejects_a_url_whose_literal_host_is_a_private_ip`,
`rejects_a_url_pointing_at_localhost_by_name`) confirm this and show no precedent for
testing through it — they test the guard itself, not a way around it.

`wiremock::MockServer` always binds to `127.0.0.1`, so **any** `base_url` that reaches a
wiremock server is a loopback address, which `ensure_public_host` will always reject before
a request is ever sent. A test that drives `fetch_metadata`/`fetch_tarball`/`fetch_manifest`/
`fetch_blob` end-to-end against wiremock is therefore not possible without weakening the
guard — which is out of scope and explicitly prohibited for production code.

## Approach used: extraction, per the task's documented fallback

Following the precedent in `docs/superpowers/test-hardening-ldap-smtp-report.md`
(pure-logic extraction, e.g. `extract_single_match` in `ldap3_auth_adapter.rs`), the
response-handling code in both files — status mapping, JSON parsing, body-read mapping —
was extracted into small free functions that take an **already-fetched** `reqwest::Response`
(or `Option<reqwest::Response>`, matching the existing `Option`-returning shape for Docker's
404-as-`None` convention). None of these functions call `ensure_public_host`, so a test can
obtain a genuine `reqwest::Response` by sending a plain `reqwest::Client` request straight to
a `wiremock::MockServer` (no SSRF check in that path — the test never calls the adapter's own
SSRF-guarded `send`) and feed it into the extracted function. The adapter's real public
methods still call `ensure_public_host` exactly where they did before, then call the send,
then delegate to the extracted function — production request flow and every check on every
hostname (including the Docker challenge realm) is unchanged.

This was applied uniformly to both files rather than needing a different strategy per file,
since both had the same shape of problem (response-handling reachable only after an
SSRF-guarded send).

### `http_remote_npm_registry.rs`

Extracted:
- `map_metadata_response(response, url) -> Result<serde_json::Value, DomainError>` — the
  status check + `.json()` call previously inline in `fetch_metadata`.
- `map_tarball_response(response, url) -> Result<Vec<u8>, DomainError>` — the status check +
  `.bytes()` call previously inline in `fetch_tarball`.

Both functions' bodies are the exact original inline code, moved verbatim (same error
message formats, same order of operations).

### `http_remote_docker_registry.rs`

Extracted:
- `extract_challenge_or_error(response: &reqwest::Response, url) -> Result<BearerChallenge, DomainError>`
  — the `www-authenticate` header lookup + `parse_bearer_challenge` + `ok_or_else` previously
  inline in `get_with_bearer_challenge`. This closes a real, previously-untested error path:
  a 401 with no `WWW-Authenticate` header, or a non-Bearer one, mapping to
  `"{url} returned 401 without a Bearer challenge"`.
- `parse_token_response(response, realm) -> Result<TokenResponse, DomainError>` — the
  `.json::<TokenResponse>()` call (with its own error mapping) previously inline after the
  token-endpoint's `require_success` check.
- `map_manifest_response(response: Option<reqwest::Response>, url) -> Result<Option<(Vec<u8>, String)>, DomainError>`
  — the `Option` short-circuit, content-type header extraction, and body-read mapping
  previously inline in `fetch_manifest`.
- `map_blob_response(response: Option<reqwest::Response>, url) -> Result<Option<Vec<u8>>, DomainError>`
  — same idea for `fetch_blob`.

`require_success` (an existing private associated fn) was **not modified** — it already had
the right shape (takes an already-fetched `reqwest::Response`, no SSRF call inside), so it
was directly testable as-is; tests call `HttpRemoteDockerRegistry::require_success(...)`.

Two incidental `#[derive(Debug)]` additions were needed purely so `.unwrap_err()` compiles in
tests (`Result::unwrap_err` requires the `Ok` variant to implement `Debug`): `TokenResponse`
and `BearerChallenge`. These are additive derives with zero effect on runtime behavior.

**Behavior-preserving**: every extracted function's body is the original inline code moved
verbatim — same error message text, same order of checks, same success/failure shape. The
call sites (`fetch_metadata`, `fetch_tarball`, `get_with_bearer_challenge`, `fetch_manifest`,
`fetch_blob`) now delegate to the extracted function instead of inlining the logic, but do so
at the exact same point in the control flow, with the exact same inputs. All pre-existing
tests in both files pass unchanged, and the crate builds/clippies clean.

## `Cargo.toml`

Added `wiremock = "0.6"` under `[dev-dependencies]` only (resolved to `wiremock 0.6.5`,
pulling in a handful of transitive dev-only deps — `hyper 1.11.0` was already present in the
lockfile via `openidconnect`, so no new major HTTP stack was introduced). No production
dependency changed.

## New tests

### `http_remote_npm_registry.rs` (+7)

- `maps_a_404_metadata_response_to_a_domain_error_naming_the_status`
- `maps_a_500_metadata_response_to_a_domain_error_naming_the_status`
- `maps_a_200_response_with_a_non_json_body_to_a_parse_error`
- `maps_a_200_response_with_a_valid_body_to_the_parsed_json`
- `maps_a_404_tarball_response_to_a_domain_error_naming_the_status`
- `maps_a_500_tarball_response_to_a_domain_error_naming_the_status`
- `maps_a_200_tarball_response_to_its_raw_bytes`

### `http_remote_docker_registry.rs` (+12)

- `require_success_maps_a_404_response_to_a_domain_error_naming_the_status`
- `require_success_maps_a_500_response_to_a_domain_error_naming_the_status`
- `require_success_passes_through_a_200_response`
- `extract_challenge_or_error_rejects_a_401_with_no_www_authenticate_header`
- `extract_challenge_or_error_rejects_a_401_with_a_non_bearer_challenge`
- `extract_challenge_or_error_parses_a_valid_bearer_challenge`
- `parse_token_response_rejects_a_non_json_body`
- `parse_token_response_accepts_a_valid_body`
- `map_manifest_response_passes_none_through_unchanged`
- `map_manifest_response_returns_bytes_and_content_type_for_a_200_response`
- `map_blob_response_passes_none_through_unchanged`
- `map_blob_response_returns_bytes_for_a_200_response`

All new tests use `wiremock::MockServer::start().await` + `Mock::given(...).respond_with(...)`
and a plain `reqwest::Client` to fetch a real response from it, then feed that response into
the extracted function under test — genuine HTTP round trips, not hand-built `Response`
objects.

## Disclosed gap (not attempted to close)

The full two-hop Docker Bearer-challenge dance (401 → fetch token from `realm` → retry
original URL with the token) is not tested end-to-end, because both the original `url` and
the challenge's `realm` are independently checked by `ensure_public_host`, and a wiremock
server can only ever be reached at a loopback address that check will always reject. Testing
around this would require either weakening the SSRF guard (explicitly prohibited) or adding
a second bypass seam beyond the response-mapping extraction (feels like it starts eroding the
guard's coverage for a security-relevant check — realm is remote-attacker-controlled input,
per the file's own comment). Instead, each stage's error-mapping was tested independently
(`extract_challenge_or_error` for the 401/header stage, `parse_token_response` for the
token-body stage, `require_success` for both requests' status checks) — this covers all the
error-mapping logic without touching the SSRF guard.

## Full test suite result

`cargo build --workspace` baseline (before any change): clean.

`DATABASE_URL=postgres://hangar:change-me@localhost:5432/hangar cargo test --workspace`:

```
test result: ok. 229 passed; 0 failed; 1 ignored   (hangar-api)
test result: ok. 262 passed; 0 failed; 0 ignored   (hangar-application)
test result: ok. 72  passed; 0 failed; 0 ignored   (hangar-docker)
test result: ok. 50  passed; 0 failed; 0 ignored   (hangar-domain)
test result: ok. 223 passed; 0 failed; 5 ignored   (hangar-infrastructure)
test result: ok. 33  passed; 0 failed; 0 ignored   (hangar-npm)
+ 5x doc-tests: 0 passed; 0 failed
```

Zero failures anywhere in the workspace. `hangar-infrastructure` went from 204 to 223
passing tests (+19: 7 new in `http_remote_npm_registry.rs`, 12 new in
`http_remote_docker_registry.rs`). `cargo clippy -p hangar-infrastructure --lib --tests`
reports no new warnings in either changed file (pre-existing warnings elsewhere in the crate
are untouched).

## Files changed

- `crates/hangar-infrastructure/src/http_remote_npm_registry.rs`
- `crates/hangar-infrastructure/src/http_remote_docker_registry.rs`
- `crates/hangar-infrastructure/Cargo.toml` (added `wiremock = "0.6"` dev-dependency)
- `Cargo.lock` (lockfile update for the new dev-dependency)

# Test hardening: hangar-docker tier-1 (authz, tenant resolution, token auth)

Scope: `crates/hangar-docker/src/authz.rs`, `crates/hangar-docker/src/organization_resolution.rs`,
`crates/hangar-docker/src/auth.rs`. Test-only additions, no production code changed (every
mutation used for evidence below was reverted immediately after observing the expected
failure). No bugs found — all three files behave correctly.

Baseline: `cargo build --workspace` succeeded cleanly before any change.

## 1. `authz.rs`

`require_granted_action` already had 2 tests (untouched, still passing, assertions unchanged).
`require_same_organization`, `require_docker_repository`, and `require_hosted` had zero tests;
`require_repository_by_name` (the function that ties `find_by_org_and_name` to
`require_same_organization`) also had none.

### What was tested and why

- **`require_same_organization`** — the core cross-tenant boundary, byte-identical logic to
  `hangar_npm::authz::require_same_organization` (`user.is_super_admin ||
  user.organization_id == organization_id`, else `StatusCode::NOT_FOUND`). Confirmed this
  crate uses the same 404-not-403 convention as both `hangar_api::authz` and the npm crate's
  copy.
  - `a_member_of_the_same_organization_passes`
  - `a_super_admin_passes_for_a_different_organization`
  - `a_member_of_a_different_organization_is_rejected_with_not_found`

- **`require_docker_repository`** (this crate's equivalent of npm's
  `require_npm_hosted_repository`) — a non-docker-format repository (Npm) must be unreachable
  through any docker route, 404.
  - `a_docker_format_repository_passes_require_docker_repository`
  - `an_npm_format_repository_is_unreachable_through_docker_routes`

- **`require_hosted`** — writes only make sense against a hosted repository; proxy/group
  repositories have no local storage, rejected with 405. Same three `RepositoryType`
  variants (`Hosted`/`Proxy`/`Group`) as the npm crate.
  - `a_hosted_repository_passes_require_hosted`
  - `a_proxy_repository_is_rejected_by_require_hosted`
  - `a_group_repository_is_rejected_by_require_hosted`

- **`require_repository_by_name`** — the two-step isolation model: (1) lookup scoped by the
  caller-supplied `organization_id` (the Host-resolved org), (2) the caller's own organization
  must independently match the repository's. DB-backed (`#[sqlx::test]`), using this crate's
  own `route_test_support::{test_state, seed_repository}` (unlike the npm crate, which had to
  duplicate a state builder inline — `hangar-docker` already has a shared test-support module).
  - `db::a_repository_in_the_callers_own_organization_is_returned`
  - `db::a_nonexistent_repository_is_not_found`
  - `db::a_caller_from_a_different_organization_is_rejected_even_though_the_repository_exists`
    — the direct unit-level equivalent of `routes/catalog.rs`'s own cross-organization
    isolation tests, isolated to just this function.
  - `db::a_super_admin_can_reach_a_repository_outside_their_own_organization`

### Differences from the npm crate's equivalent

None in this function's logic — `require_same_organization`, `require_docker_repository` (vs
`require_npm_hosted_repository`), `require_hosted`, and `require_repository_by_name` are
structurally identical to the npm crate's copies, just format-swapped (`Docker` vs `Npm`). The
one real difference in this file is `require_granted_action` (JWT scope-vs-resolved-repository-id
check), which has no npm equivalent at all — npm tokens are plain opaque bearer tokens with no
embedded scope, so there is nothing analogous to check. That function's 2 pre-existing tests were
left untouched.

### Mutation-testing evidence

Mutated `require_same_organization`'s guard from `user.is_super_admin ||
user.organization_id == organization_id` to `user.is_super_admin || true`:

```
thread 'authz::tests::a_member_of_a_different_organization_is_rejected_with_not_found' panicked:
called `Result::unwrap_err()` on an `Ok` value: ()

thread 'authz::tests::db::a_caller_from_a_different_organization_is_rejected_even_though_the_repository_exists' panicked:
called `Result::unwrap_err()` on an `Ok` value: PackageRepositorySummary { ... }

test result: FAILED. 12 passed; 2 failed; 0 ignored; 0 measured; 58 filtered out
```

Exactly the two cross-org tests (one pure-unit, one DB-backed) failed; all 12 others in the
file were unaffected. Reverted; confirmed 14/14 (authz.rs alone) and 32/32 (all three files)
passing again.

## 2. `organization_resolution.rs`

Had **zero** tests before this change. The `ResolvedOrganization` `FromRequestParts<DockerState>`
extractor's logic was read directly and found to be **byte-identical** to
`hangar_npm::organization_resolution::ResolvedOrganization`'s copy (both are explicitly
documented as verbatim copies of `hangar_api::organization_middleware::ResolvedOrganization`,
adapted only to each crate's own state type): strip port, lowercase, strip `.{base_domain}`
suffix via `strip_suffix`, `""`/`"www"` label → public org, else exact-slug DB lookup via
`OrganizationSlug::parse` + `find_by_slug`.

### What was tested and why

Same scenario class as the npm crate's equivalent report, adapted to `DockerState` and a
locally-built minimal router (this file had no router of its own, so one was added inside the
test module, following the npm crate's and this crate's own `route_test_support` conventions):

- `a_plain_base_domain_host_resolves_to_the_public_organization` (`hangar.localhost`)
- `a_www_host_label_resolves_to_the_public_organization` (`www.hangar.localhost`)
- `a_slug_dot_base_domain_host_resolves_to_that_organization` (`acme.hangar.localhost`)
- `a_port_suffix_on_the_host_header_is_stripped` (`hangar.localhost:8080`)
- `a_port_suffix_on_an_organization_subdomain_is_stripped` (`acme.hangar.localhost:8080`)
- `an_uppercase_host_header_still_resolves_the_organization` (`ACME.HANGAR.LOCALHOST`)
- `an_unknown_organization_slug_is_not_found` (`nope.hangar.localhost` → 404)
- `a_host_that_merely_contains_another_organizations_slug_is_not_confused_with_it` — the
  exact risk named in the brief: `evilacme.hangar.localhost` strips to label `"evilacme"`, a
  distinct string from `"acme"`, and `PostgresOrganizationRepository::find_by_slug` does an
  exact-equality SQL lookup (same adapter the npm crate uses — `state.organizations` in
  `route_test_support::test_state` is the identical
  `PostgresOrganizationRepository`) — so no substring/suffix confusion is possible. Confirmed
  404, not a match.
- `a_host_where_the_base_domain_appears_as_a_substring_but_not_as_the_final_label_does_not_match`
  — the stricter vhost-confusion variant: `acme.hangar.localhost.evil.com`. Must fall back to
  public, not match "acme".
- `a_host_that_does_not_end_with_the_base_domain_falls_back_to_the_public_organization` —
  documents the fallback behavior for an unrelated/malformed host (least-privileged tenant,
  not an arbitrary one).

**No bug found.** Independently verified (not assumed from the npm crate's report) that the
same reasoning holds here: the dot-anchored `strip_suffix` plus exact-equality slug lookup
together make the "evilacme matches acme" and vhost-suffix-confusion bug classes
architecturally impossible in this crate's current code, exactly as in the npm crate.

### Differences from the npm crate's equivalent

None found — the extractor logic is verbatim-identical (confirmed by direct comparison of the
full function body), differing only in the state type it's generic over (`DockerState` vs
`NpmState`).

### Mutation-testing evidence

Mutated the label extraction from anchored `strip_suffix(".{base_domain}")` to an
un-anchored, first-occurrence `find`-based match:

```rust
// before
let label = host_without_port.strip_suffix(&format!(".{}", state.hangar_base_domain)).unwrap_or("");
// mutated to
let needle = format!(".{}", state.hangar_base_domain);
let label = match host_without_port.find(&needle) {
    Some(idx) => &host_without_port[..idx],
    None => "",
};
```

Result:

```
thread 'organization_resolution::tests::a_host_where_the_base_domain_appears_as_a_substring_but_not_as_the_final_label_does_not_match' panicked:
assertion `left == right` failed: the base domain appearing mid-host (not as the final label) must fall back to public, never match "acme"
  left: b"acme"
 right: [112, 117, 98, 108, 105, 99]   // "public"

test result: FAILED. 9 passed; 1 failed; 0 ignored; 0 measured; 62 filtered out
```

Exactly the one test designed to catch this reproduced the leak (`acme.hangar.localhost.evil.com`
would have resolved to acme's own organization instead of falling back to public); all 9 other
tests still passed. Reverted; confirmed 10/10 passing again.

## 3. `auth.rs`

The `DockerAuthUser` `FromRequestParts<DockerState>` extractor. This is architecturally
different from the npm crate's `NpmAuthUser`, exactly as the brief anticipated: Docker registry
auth uses short-lived, self-contained **JWT bearer tokens** signed by `JwtDockerTokenIssuer`
(`state.token_issuer`), not a DB-backed opaque-token lookup. `from_request_parts` does:

1. `scope_hint` — best-effort `Path` extraction to build a `WWW-Authenticate` challenge scope
   for the 401 case (no DB, no bearing on authentication itself).
2. Extract `Authorization: Bearer <token>` (fails → 401 with challenge).
3. `state.token_issuer.verify(token)` — JWT signature + `typ` claim check (fails → 401 with
   challenge). No DB call at all — the token is self-contained.
4. Map the returned `DockerAccessClaims` (`user_id`, `organization_id`, `is_super_admin`,
   `granted_scope`) directly onto `DockerAuthUser`.

There is **no revocation/active-token check** in this file (unlike npm's `NpmAuthUser`, which
does a live `find_by_hash` + `is_active()` DB check) — that's an intentional design difference
documented in the struct's own doc comment ("this token is short-lived and self-contained by
design ... never re-checked live against the database"), not a gap. The actual signature/claims
verification (`typ` check, expiry, HMAC) lives in `JwtDockerTokenIssuer::verify` inside
`hangar-infrastructure`, which already has its own unit tests (`jwt_docker_token_issuer.rs`,
untouched, out of this task's 3-file scope) — this file's own job is just "extract header, call
verify, map errors to 401, map success onto the struct," so that's what was tested here at the
HTTP-extractor boundary (as opposed to re-testing the issuer's internals).

**Scope-vs-repository enforcement does NOT live in this file.** Per the brief's own caveat: the
brief asked to test scope-repository-mismatch logic "if such a check exists in this file
specifically." It doesn't — `auth.rs` only carries `granted_scope` through unmodified;
the actual enforcement (`resolved_repository_id` vs `scope.granted_repository_id`) is
`require_granted_action` in `authz.rs`, which already had 2 pre-existing tests (left
untouched). This file was tested only for correctly carrying the scope through, not for
enforcing it.

### What was tested and why

Used a locally-built minimal router (mirroring both the npm crate's `auth.rs` test convention
and this crate's own `route_test_support::test_state`), reusing the `/_catalog`-style
no-path-param route shape so `scope_hint` takes its documented `None` path deterministically.

- `a_valid_docker_access_token_authenticates_and_maps_claims_correctly` — issues a token via
  the real `state.token_issuer`, asserts the extractor correctly maps `user_id`,
  `organization_id`, and `is_super_admin` onto `DockerAuthUser` (200, JSON body checked field
  by field).
- `a_valid_token_carries_its_granted_scope_through_the_extractor` — a token issued with a
  `DockerGrantedScope` round-trips `granted_scope.name` through the extractor unchanged.
- `a_missing_authorization_header_is_rejected` — 401.
- `a_malformed_authorization_header_is_rejected` — wrong scheme (`Basic ...` instead of
  `Bearer`) — 401.
- `a_garbage_bearer_token_is_rejected` — a string that isn't a JWT at all — 401.
- `a_token_signed_with_a_different_secret_is_rejected` — a structurally valid, correctly
  self-consistent JWT signed with a secret this server doesn't recognize (e.g. a stale secret
  from before a rotation) — 401.
- `a_token_with_a_tampered_signature_is_rejected` — a real, validly-issued token with one
  character of its signature flipped — 401.
- `a_session_login_token_is_rejected_as_a_docker_access_token` — the specific shared-secret
  risk documented in `JwtDockerTokenIssuer`'s own comment: the session-login issuer
  (`JwtTokenIssuer`) and the Docker access-token issuer sign with the same secret in
  production, so only the `typ` claim keeps them apart. Proves this is actually wired up at
  the HTTP boundary in `hangar-docker`, not just inside the issuer's own unit test
  (`jwt_docker_token_issuer.rs::a_session_token_is_rejected_by_the_docker_token_issuer`,
  which tests the issuer directly, not this extractor).

**Adjustment from the brief — expiry could not be tested at this boundary.** The brief asked
for an "expired JWT rejected" test. `JwtDockerTokenIssuer::new` hardcodes a 5-minute TTL with
no test-only override — unlike the sibling session-token issuer `JwtTokenIssuer`, which exposes
a `set_ttl` method specifically for this purpose
(`jwt_token_issuer.rs::set_ttl_changes_the_expiry_of_newly_issued_tokens`). Producing a
genuinely-expired-but-validly-signed Docker access token requires either (a) modifying
`JwtDockerTokenIssuer` in `hangar-infrastructure` to add a similar test-only `set_ttl` — outside
this task's 3-file scope — or (b) adding a direct `jsonwebtoken` dependency to
`hangar-docker`'s `Cargo.toml` to hand-construct claims — prohibited ("do not add new external
dependencies", and Cargo.toml is outside the 3-file scope). Given both routes are out of
scope, this specific case was not tested directly; the tampered-signature and wrong-secret
tests exercise the identical code path (`verify()` returning `Err` → 401) that an expired
token would also take, so the extractor's error-handling itself is still covered. Flagging
this gap explicitly rather than silently skipping it.

**No bug found.**

### Mutation-testing evidence

Mutated the verification step from propagating `verify()`'s error to swallowing it and
substituting a default-successful claims value:

```rust
// before
let claims = state.token_issuer.verify(bearer.token()).map_err(|_| unauthorized(state, scope.as_deref()))?;
// mutated to
let claims = state.token_issuer.verify(bearer.token()).unwrap_or(hangar_domain::docker_registry::DockerAccessClaims {
    user_id: Uuid::nil(), organization_id: Uuid::nil(), is_super_admin: false, granted_scope: None,
});
```

Result:

```
test auth::tests::a_garbage_bearer_token_is_rejected ... FAILED (200, expected 401)
test auth::tests::a_token_signed_with_a_different_secret_is_rejected ... FAILED (200, expected 401)
test auth::tests::a_session_login_token_is_rejected_as_a_docker_access_token ... FAILED (200, expected 401)
test auth::tests::a_token_with_a_tampered_signature_is_rejected ... FAILED (200, expected 401)
test auth::tests::a_valid_token_carries_its_granted_scope_through_the_extractor ... ok
test auth::tests::a_valid_docker_access_token_authenticates_and_maps_claims_correctly ... ok
test auth::tests::a_malformed_authorization_header_is_rejected ... ok
test auth::tests::a_missing_authorization_header_is_rejected ... ok

test result: FAILED. 4 passed; 4 failed; 0 ignored; 0 measured; 64 filtered out
```

Exactly the four invalid-token tests failed (all previously-invalid tokens now silently
authenticated); the two valid-header tests (missing/malformed) and the two valid-token tests
were unaffected, as expected — this mutation only bypasses signature verification, not header
extraction. Reverted; confirmed 8/8 (auth.rs alone) and 32/32 (all three files) passing again.

## Bugs or gaps found

No behavioral bugs. One test-coverage gap, disclosed above: expired-JWT rejection could not be
tested at the `auth.rs` HTTP boundary without either modifying `hangar-infrastructure` (out of
this task's 3-file scope) or adding a new direct dependency (prohibited). The underlying
expiry-checking mechanism itself (`jsonwebtoken`'s `Validation::default()`, which checks `exp`)
is standard library behavior, not custom code in this crate.

## Full test suite result

`DATABASE_URL=postgres://hangar:change-me@localhost:5432/hangar cargo test --workspace`:

```
217 passed (hangar-api, 1 ignored)
262 passed (hangar-application)
72 passed (hangar-docker)   <- was 40 before this change
50 passed (hangar-domain)
193 passed (hangar-infrastructure, 5 ignored)
33 passed (hangar-npm)
0 failed across the whole workspace
```

No regressions anywhere in the workspace. `cargo clippy -p hangar-docker --tests --all-targets`
shows only 4 pre-existing warnings in unrelated files (`blobs.rs`, `manifests.rs`) — none
introduced by this change.

## New test names (32 total)

**`authz.rs`** (12):
- `a_member_of_the_same_organization_passes`
- `a_super_admin_passes_for_a_different_organization`
- `a_member_of_a_different_organization_is_rejected_with_not_found`
- `a_docker_format_repository_passes_require_docker_repository`
- `an_npm_format_repository_is_unreachable_through_docker_routes`
- `a_hosted_repository_passes_require_hosted`
- `a_proxy_repository_is_rejected_by_require_hosted`
- `a_group_repository_is_rejected_by_require_hosted`
- `db::a_repository_in_the_callers_own_organization_is_returned`
- `db::a_nonexistent_repository_is_not_found`
- `db::a_caller_from_a_different_organization_is_rejected_even_though_the_repository_exists`
- `db::a_super_admin_can_reach_a_repository_outside_their_own_organization`

**`organization_resolution.rs`** (10):
- `a_plain_base_domain_host_resolves_to_the_public_organization`
- `a_www_host_label_resolves_to_the_public_organization`
- `a_slug_dot_base_domain_host_resolves_to_that_organization`
- `a_port_suffix_on_the_host_header_is_stripped`
- `a_port_suffix_on_an_organization_subdomain_is_stripped`
- `an_uppercase_host_header_still_resolves_the_organization`
- `an_unknown_organization_slug_is_not_found`
- `a_host_that_merely_contains_another_organizations_slug_is_not_confused_with_it`
- `a_host_where_the_base_domain_appears_as_a_substring_but_not_as_the_final_label_does_not_match`
- `a_host_that_does_not_end_with_the_base_domain_falls_back_to_the_public_organization`

**`auth.rs`** (8):
- `a_valid_docker_access_token_authenticates_and_maps_claims_correctly`
- `a_valid_token_carries_its_granted_scope_through_the_extractor`
- `a_missing_authorization_header_is_rejected`
- `a_malformed_authorization_header_is_rejected`
- `a_garbage_bearer_token_is_rejected`
- `a_token_signed_with_a_different_secret_is_rejected`
- `a_token_with_a_tampered_signature_is_rejected`
- `a_session_login_token_is_rejected_as_a_docker_access_token`

## Files changed

- `crates/hangar-docker/src/authz.rs` (test module extended, no production code changed; the
  2 pre-existing `require_granted_action` tests are untouched)
- `crates/hangar-docker/src/organization_resolution.rs` (test module added, no production code
  changed)
- `crates/hangar-docker/src/auth.rs` (test module added, no production code changed)

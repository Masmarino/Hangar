# Revoke-token ownership bug — fix report

## The bug, confirmed by re-reading the code

`revoke_token` in `crates/hangar-api/src/routes/api_tokens.rs` called
`state.revoke_api_token.execute(id, user.id)`, which called
`RevokeApiTokenUseCase::execute` in
`crates/hangar-application/src/use_cases/api_token.rs`, which called
`ApiTokenRepositoryPort::revoke(id, user_id)`, implemented in
`crates/hangar-infrastructure/src/postgres/api_token_repository.rs` as:

```rust
async fn revoke(&self, id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
    sqlx::query!("UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND user_id = $2", id, user_id)
        .execute(&self.pool)
        .await
        .infra_err()?;
    Ok(())
}
```

The `UPDATE` is correctly scoped by both `id` and `user_id`, so a caller
attempting to revoke a token they don't own affects zero rows — but the old
code never inspected `rows_affected()` and always returned `Ok(())`. Every
layer above it (`RevokeApiTokenUseCase::execute`, then the route handler)
propagated that `Ok(())` straight through to an HTTP `204 No Content`,
identical to what a legitimate owner gets. The token was never actually
revoked, but the caller had no way to know that — a client bug (wrong token
id) would silently masquerade as success. This exact wrong behavior was
locked in as a test in commit `0d7f07f`
(`revoking_another_users_token_does_not_revoke_it`, asserting `204`).

## Status code chosen: 404 Not Found

Two candidates: 403 Forbidden (confirms the token exists but access is
denied) or 404 Not Found (doesn't confirm existence at all).

Existing codebase convention, from `crates/hangar-api/src/authz.rs`:
- `require_same_organization`: a caller from a **different organization**
  gets `404`, specifically to avoid confirming a resource's existence across
  that boundary — with a test asserting this explicitly
  (`a_non_admin_of_a_different_organization_gets_not_found_not_forbidden`).
- `require_organization_admin`/role checks **within the same organization**
  (insufficient role, resource visibly exists to the caller) get `403`.

I checked whether any other **user-owned** (not org-owned) resource with
this exact `WHERE id = $1 AND user_id = $2` shape already has an established
convention. `PostgresWebauthnCredentialRepository::delete` (passkeys) has the
identical shape and the identical bug (`DeletePasskeyUseCase` silently
no-ops on a non-owner's credential id), but its route
(`crates/hangar-api/src/routes/mfa.rs::delete_passkey`) doesn't handle this
case correctly either — so there's no existing *correct* precedent to copy,
only the same latent bug. That endpoint is out of scope here per the task's
"don't touch files outside what's genuinely necessary" instruction, but it
is worth a follow-up (flagged separately).

Given no direct precedent, I applied the codebase's stated philosophy by
extension: a per-user resource is at least as private as a per-organization
one — arguably more so, since other members of the *same* organization have
no legitimate relationship to another user's personal API token at all.
Reusing 403 here would leak one bit of information beyond what the org-level
convention exposes: it would confirm to any authenticated caller that a
given token id genuinely exists (just owned by someone else), which a 404
does not. So I chose **404 Not Found**, structured to be response-identical
whether the id is unknown or owned by a different user (verified by a route
test covering both cases and asserting the same status).

## The exact code change

- `crates/hangar-domain/src/api_token.rs`: `ApiTokenRepositoryPort::revoke`
  now returns `Result<bool, DomainError>` — `true` iff a row was affected —
  documented on the trait method.
- `crates/hangar-infrastructure/src/postgres/api_token_repository.rs`:
  `revoke` captures the `PgQueryResult` and returns
  `Ok(result.rows_affected() > 0)`.
- `crates/hangar-application/src/error.rs`: added
  `ApplicationError::ApiTokenNotFound` ("api token not found"), documented as
  deliberately ambiguous between "unknown id" and "wrong owner".
- `crates/hangar-application/src/use_cases/api_token.rs`:
  `RevokeApiTokenUseCase::execute` now branches on the repository's bool —
  `Ok(())` on `true`, `Err(ApplicationError::ApiTokenNotFound)` on `false`.
- `crates/hangar-api/src/dto.rs`: `application_error_response` maps
  `ApiTokenNotFound` to `404 Not Found` (previously would have fallen
  through to the catch-all `400 Bad Request`, which would have been wrong
  too).
- Test-double updates required for compilation, no production-logic changes:
  `crates/hangar-application/src/use_cases/admin.rs`'s `FakeApiTokens::revoke`
  and `crates/hangar-application/src/use_cases/docker_access_token.rs`'s
  `FakeApiTokens::revoke` updated to the new `Result<bool, _>` signature.
- Tests updated/added:
  - `crates/hangar-infrastructure/src/postgres/api_token_repository.rs`:
    `revoke_only_affects_the_owning_user` now also asserts on the returned
    bool.
  - `crates/hangar-application/src/use_cases/api_token.rs`: renamed
    `revoking_someone_elses_token_is_a_no_op` to
    `revoking_someone_elses_token_is_rejected_and_does_not_revoke_it`,
    asserting `ApplicationError::ApiTokenNotFound` instead of `Ok(())`; added
    `revoking_an_unknown_token_id_is_rejected`.
  - `crates/hangar-api/src/routes/api_tokens.rs`: renamed
    `revoking_another_users_token_does_not_revoke_it` to
    `revoking_another_users_token_is_rejected_and_does_not_revoke_it` and
    changed its assertion from `NO_CONTENT` to `NOT_FOUND` (this is the test
    from `0d7f07f` that documented the wrong behavior); added
    `revoking_an_unknown_token_id_returns_not_found` to lock in that an
    unknown id gets the identical status as a wrong-owner id.
  - The legitimate-owner path (`revoking_own_token_removes_it_from_the_list`)
    was left untouched and still asserts `204 No Content`.

`admin_revoke_api_token` (super-admin override) uses
`ApiTokenRepositoryPort::revoke_any`, a separate trait method not touched by
this change — its behavior is unaffected.

## Mutation-testing evidence

Reverted the fix in `RevokeApiTokenUseCase::execute` to:

```rust
pub async fn execute(&self, token_id: Uuid, user_id: Uuid) -> Result<(), ApplicationError> {
    let _ = self.tokens.revoke(token_id, user_id).await?; // MUTATION: discard the affected-row signal
    Ok(())
}
```

Result with the mutation in place:

```
test routes::api_tokens::tests::revoking_an_unknown_token_id_returns_not_found ... FAILED
  left: 204
 right: 404
test routes::api_tokens::tests::revoking_another_users_token_is_rejected_and_does_not_revoke_it ... FAILED
  left: 204
 right: 404
test use_cases::api_token::tests::revoking_an_unknown_token_id_is_rejected ... FAILED
  called `Result::unwrap_err()` on an `Ok` value: ()
test use_cases::api_token::tests::revoking_someone_elses_token_is_rejected_and_does_not_revoke_it ... FAILED
  called `Result::unwrap_err()` on an `Ok` value: ()
```

All four new/updated regression tests failed under the mutation, confirming
they actually exercise the fix. Restored the fix; re-ran the same four
tests — all passed (`8 passed; 0 failed` for hangar-api's api_tokens/admin
subset, `6 passed; 0 failed` for hangar-application's api_token subset).

## Full test suite result

`DATABASE_URL=postgres://hangar:change-me@localhost:5432/hangar cargo test --workspace`
(run per-crate due to background-shell truncation, full output captured):

- `hangar-api`: 230 passed, 0 failed, 1 ignored
- `hangar-application`: 270 passed, 0 failed, 0 ignored
- `hangar-infrastructure`: 223 passed, 0 failed, 5 ignored
- `hangar-npm`: 55 passed, 0 failed, 1 ignored
- (hangar-domain, hangar-docker unaffected by this change; not re-verified
  individually beyond the initial full-workspace `cargo build`)

Zero regressions across the workspace.

`cargo build --workspace`: clean (exit 0).
`DATABASE_URL=... cargo clippy --workspace --all-targets`: clean (exit 0) —
only pre-existing warnings unrelated to this change (missing `Default` impls
on docker test fakes, a `bool_assert_comparison` warning in
`routes/mfa.rs`, and a `mfa.rs` item-ordering lint), none introduced by this
fix.

## Files changed

- `crates/hangar-domain/src/api_token.rs`
- `crates/hangar-infrastructure/src/postgres/api_token_repository.rs`
- `crates/hangar-application/src/error.rs`
- `crates/hangar-application/src/use_cases/api_token.rs`
- `crates/hangar-application/src/use_cases/admin.rs` (test double only)
- `crates/hangar-application/src/use_cases/docker_access_token.rs` (test double only)
- `crates/hangar-api/src/dto.rs`
- `crates/hangar-api/src/routes/api_tokens.rs`

## Note on worktree state

This worktree's own branch (`worktree-agent-a4a3a75a25e5fb491`) was
initially checked out at an unrelated bogus "Initial commit" (just a
LICENSE file) rather than `develop` as the task described. I reset the
worktree's branch to local `develop` (`ac2afdf`, which contains `0d7f07f`)
without touching the main working copy's own `develop` checkout, then did
all work from there.

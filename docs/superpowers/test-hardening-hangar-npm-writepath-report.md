# Test hardening: hangar-npm write-path routes (publish, unpublish, dist-tags)

Scope: `crates/hangar-npm/src/routes/publish.rs`, `crates/hangar-npm/src/routes/unpublish.rs`,
`crates/hangar-npm/src/routes/dist_tags.rs`. Test-only additions (each file's own `#[cfg(test)]
mod tests`), following the HTTP-router test convention already established in
`routes/metadata.rs` (`test_state`/`seed_repository`/`seed_user_with_active_token`/
`seed_permission` helpers, `#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]`,
`tower::ServiceExt::oneshot` against the real `crate::router(state)`). No shared test-support
module exists in this crate, so each file's test module duplicates its own copy of the
helpers, matching the precedent already set by `authz.rs`'s `db` submodule and `metadata.rs`.

**One real, unfixed bug found** — see "Bugs found" below. Production code was NOT modified to
fix it, per instructions; every mutation used for evidence was reverted immediately after
observing the expected test failure (confirmed via `git diff --stat`, which shows only pure
test-module additions in both `publish.rs` and `unpublish.rs`).

## 1. `publish.rs`

Zero tests existed for the single most security/correctness-sensitive npm WRITE path. Read
the handler in full (`crates/hangar-npm/src/routes/publish.rs`) and the underlying
`PublishNpmPackageUseCase` (already well unit-tested at the application layer, so route-layer
tests focus on wiring, parsing, and branching rather than re-proving publish semantics).

### What was tested and why

- **A valid publish with a tarball succeeds** (`a_valid_publish_with_a_tarball_succeeds`) — no
  happy-path HTTP-layer test existed; confirms 201 Created and the `{ok, id}` response shape.
- **No-attachments = deprecate-only vs has-attachment = real publish, tested distinctly**
  (`a_publish_document_with_no_attachments_only_deprecates_and_does_not_create_a_version`) —
  publishes a real version first, then PUTs a document with the SAME version's manifest
  carrying a `deprecated` message and NO `_attachments` key (the real `npm deprecate` wire
  format). Confirms 200 (not 201) and that the version's `deprecated` field is set via a
  follow-up metadata fetch, not just that the response looked right.
- **Invalid package name** (`publishing_with_an_invalid_package_name_is_rejected`) — 400.
- **Invalid version string** (`publishing_with_an_invalid_version_string_is_rejected`) — 400.
- **Invalid base64 tarball attachment** (`publishing_with_invalid_base64_tarball_data_is_rejected`)
  — 400.
- **Non-hosted (proxy) repository rejected, wired at the route** — the brief's specific
  concern: `require_hosted` was already unit-tested in isolation in the tier-1 pass, but never
  proven to be genuinely *called* by this route. `publishing_against_a_proxy_repository_is_rejected`
  fires a real HTTP PUT against a proxy-type repository and asserts 405 — see mutation
  evidence below proving this would catch a route that forgot the call.
- **Cross-organization caller rejected, wired at the route** — same "wired, not just unit
  tested" concern for `require_repository_by_name`'s organization check.
  `publishing_by_a_caller_from_a_different_organization_is_rejected` seeds a caller in a
  different organization holding an explicit (stale-grant-style) write permission on the
  target repository, and asserts 404 through the real route — see mutation evidence below.

### New tests (7)

- `a_valid_publish_with_a_tarball_succeeds`
- `a_publish_document_with_no_attachments_only_deprecates_and_does_not_create_a_version`
- `publishing_with_an_invalid_package_name_is_rejected`
- `publishing_with_an_invalid_version_string_is_rejected`
- `publishing_with_invalid_base64_tarball_data_is_rejected`
- `publishing_against_a_proxy_repository_is_rejected`
- `publishing_by_a_caller_from_a_different_organization_is_rejected`

## 2. `unpublish.rs`

Zero tests existed for any of the 3 handlers (`unpublish_package`, `unpublish_via_document_put`,
`unpublish_version`).

### What was tested and why

- **Whole-package DELETE succeeds** (`unpublishing_the_whole_package_deletes_it`) — 200, and
  the package is genuinely gone afterward (confirmed via a metadata fetch, not just the HTTP
  status).
- **Single-version DELETE (tarball route) succeeds**
  (`unpublishing_a_single_existing_version_via_the_tarball_route_succeeds`) — publishes two
  versions, deletes one via the `/-/  :filename/-rev/:rev` route, confirms exactly that one is
  gone and the other survives.
- **Diff logic: removing exactly the missing versions**
  (`putting_back_a_packument_missing_one_version_removes_only_that_version`) — a realistic
  3-version packument (1.0.0, 2.0.0, 3.0.0), client PUTs back a document missing 2.0.0 only.
  Confirms 1.0.0 and 3.0.0 both survive and 2.0.0 alone is removed — this is the core
  correctness risk for the diff-based reimplementation of real `npm unpublish <pkg>@<version>`.
  See mutation evidence below.
- **Diff logic: same version list is a true no-op**
  (`putting_back_the_same_version_list_removes_nothing`) — posting back the exact stored
  version list removes nothing.
- **The plain DELETE route's actual (non-idempotent) behavior for a nonexistent version**
  (`unpublishing_a_nonexistent_version_via_the_delete_route_is_a_404_not_a_silent_success`) —
  the brief asked to test "unpublishing a version that doesn't exist" and confirm genuine
  idempotency, not a silently masked problem. Investigation found this applies asymmetrically
  across `unpublish.rs`'s two mechanisms: `unpublish_version` (the plain per-version DELETE)
  has NO idempotency handling — it propagates `NpmVersionNotFound` straight through
  `npm_error_response` as a 404. This is documented, expected behavior (not a bug) — the
  DELETE route deliberately targets one version by exact tarball filename and should say so
  if it's gone. Only `unpublish_via_document_put`'s loop has the explicit
  NpmPackageNotFound/NpmVersionNotFound-as-non-error idempotency handling, because it's
  reasoning over a diff snapshot that could legitimately race with a concurrent request; see
  next section.
- **The diff-route's idempotency handling under a genuine concurrent race** — see "Bugs
  found" below; this is where the one real bug in this pass was discovered.
- **Non-hosted (proxy) repository rejected, wired at the route**
  (`unpublishing_against_a_proxy_repository_is_rejected`) — 405, mirroring the publish.rs
  concern for this route family.
- **Cross-organization caller rejected, wired at the route**
  (`unpublishing_by_a_caller_from_a_different_organization_is_rejected`) — 404.

### New tests (8, 1 marked `#[ignore]`)

- `unpublishing_the_whole_package_deletes_it`
- `unpublishing_a_single_existing_version_via_the_tarball_route_succeeds`
- `putting_back_a_packument_missing_one_version_removes_only_that_version`
- `putting_back_the_same_version_list_removes_nothing`
- `a_concurrent_duplicate_diff_request_is_tolerated_not_surfaced_as_an_error` — **`#[ignore]`d**,
  see "Bugs found" below
- `unpublishing_a_nonexistent_version_via_the_delete_route_is_a_404_not_a_silent_success`
- `unpublishing_against_a_proxy_repository_is_rejected`
- `unpublishing_by_a_caller_from_a_different_organization_is_rejected`

### An investigation dead-end worth recording

My first attempt at testing the diff loop's `NpmPackageNotFound`/`NpmVersionNotFound`
idempotency handling was to PUT the same "missing 2.0.0" diff document twice in a row
(sequentially) and expect the second call to hit the not-found branch. This is **logically
impossible to trigger this way**: `unpublish_via_document_put` always recomputes
`current_versions` fresh from the live packument at the START of each request, so a version
that's already gone from a prior request can never appear in a later request's own diff — the
diff, by construction, only ever contains versions the SAME request's own snapshot still
shows as present. The only way `execute_version` can actually return
`NpmPackageNotFound`/`NpmVersionNotFound` mid-loop (the thing the surrounding code comment
explicitly guards against) is a genuine race between two concurrent requests that both
computed the same diff before either finished. I rewrote the test as a real concurrency test
(`tokio::join!` on two identical diff-PUTs) — this is what surfaced the bug below.

## 3. `dist_tags.rs`

Zero tests existed for `list_tags`/`set_tag`/`delete_tag`, including the hand-rolled
`body.trim().trim_matches('"')` raw-string parsing in `set_tag`.

### What was tested and why

- **Setting a dist-tag to a valid version succeeds** (`setting_a_dist_tag_to_a_valid_version_succeeds`)
  — bare version string body, 200, confirmed via `list_dist_tags`.
- **JSON-string-quoted version body is correctly unquoted**
  (`setting_a_dist_tag_with_a_json_quoted_version_is_correctly_unquoted`) — `"1.0.0"` (npm's
  actual wire format, not an edge case) is correctly parsed after `trim_matches('"')`.
- **Whitespace around the body is trimmed**
  (`setting_a_dist_tag_with_surrounding_whitespace_is_trimmed`) — `"  \"1.0.0\"  \n"`.
- **Listing dist-tags** (`listing_dist_tags_returns_previously_set_tags`) — confirms both
  publish's own automatic `latest` tag and a manually-set `beta` tag are both visible.
- **Deleting a dist-tag** (`deleting_a_dist_tag_removes_it`).
- **Setting a dist-tag to a version that was never published — the brief's specific concern**
  (`setting_a_dist_tag_to_a_nonexistent_version_is_rejected_not_silently_accepted`) —
  investigated whether this could let e.g. `latest` point at a version that doesn't exist.
  **Confirmed rejected, not a bug**: `SetDistTagUseCase::execute`
  (`crates/hangar-application/src/use_cases/npm_dist_tags.rs:19-38`) calls
  `self.packages.find_version(package.id, version)` and returns `NpmVersionNotFound` before
  ever calling `set_dist_tag` if the version doesn't exist; `npm_error_response` maps that to
  404. The route test drives this through the real HTTP PUT and also confirms the tag was NOT
  moved in the database.
- **Non-hosted (proxy) repository rejected, wired at the route**
  (`setting_a_dist_tag_against_a_proxy_repository_is_rejected`) — 405.
- **Cross-organization caller rejected, wired at the route**
  (`setting_a_dist_tag_by_a_caller_from_a_different_organization_is_rejected`) — 404.

### New tests (8)

- `setting_a_dist_tag_to_a_valid_version_succeeds`
- `setting_a_dist_tag_with_a_json_quoted_version_is_correctly_unquoted`
- `setting_a_dist_tag_with_surrounding_whitespace_is_trimmed`
- `listing_dist_tags_returns_previously_set_tags`
- `deleting_a_dist_tag_removes_it`
- `setting_a_dist_tag_to_a_nonexistent_version_is_rejected_not_silently_accepted`
- `setting_a_dist_tag_against_a_proxy_repository_is_rejected`
- `setting_a_dist_tag_by_a_caller_from_a_different_organization_is_rejected`

## Bugs found

### Real, unfixed bug: a TOCTOU race in `UnpublishNpmPackageUseCase::execute_version` can surface a raw 500 instead of the idempotent success the surrounding code promises

**File:** `crates/hangar-application/src/use_cases/npm_unpublish.rs`, `execute_version`
(lines 21-57), specifically the sequence:

```rust
let npm_version = self.packages.find_version(package.id, version).await?.ok_or(ApplicationError::NpmVersionNotFound)?;
self.storage.delete(repository_id, &npm_version.tarball_storage_key).await?;   // <-- races here
self.packages.delete_version(package.id, version).await?;
```

and `FilesystemStorageBackend::delete` (`crates/hangar-infrastructure/src/filesystem_storage.rs:63-66`):

```rust
async fn delete(&self, repository_id: Uuid, path: &str) -> Result<(), StorageError> {
    let target = self.object_path(repository_id, path)?;
    fs::remove_file(&target).await.map_err(|e| StorageError::Io(e.to_string()))
}
```

**How it was found:** `routes/unpublish.rs`'s `unpublish_via_document_put` has an explicit
idempotency comment: "a version already gone (e.g. cascade-deleted with the last surviving
version) is not an error", and catches `NpmPackageNotFound`/`NpmVersionNotFound` from
`execute_version` as non-errors. Testing this required a genuine concurrency scenario (see
"investigation dead-end" above). I wrote
`a_concurrent_duplicate_diff_request_is_tolerated_not_surfaced_as_an_error`: two identical
diff-PUT requests, both dropping the same version (2.0.0), fired concurrently via
`tokio::join!`. Run in a loop of ~30 attempts, this failed intermittently (roughly 1 run in
5-6) with:

```
left: 500
right: 200
assertion `left == right` failed: neither concurrent request may surface the race as an error
```

Captured response body on failure:

```json
{"error":"storage io failure: No such file or directory (os error 2)"}
```

**Root cause:** the idempotency catch in `unpublish_via_document_put` only covers the case
where `execute_version`'s own `find_package`/`find_version` checks return None (i.e. the
version was already gone before this call even started). It does NOT cover a second, narrower
race entirely inside `execute_version` itself: two concurrent callers can both pass
`find_version` (neither has deleted anything yet, so both see the version as present), then
both call `self.storage.delete(repository_id, &npm_version.tarball_storage_key)` on the SAME
tarball key. The first succeeds; the second's `fs::remove_file` hits ENOENT, which
`FilesystemStorageBackend::delete` wraps as `StorageError::Io` — a variant that is not
`NpmPackageNotFound` or `NpmVersionNotFound`, so it is NOT caught by the
`unpublish_via_document_put` match arms and propagates as a raw 500 instead of the intended
idempotent success (or, arguably more correctly, a clean 404/409).

**Impact:** two overlapping `npm unpublish` retries (or two automation jobs racing) against
the same version can non-deterministically produce a 500 with a filesystem-internals error
message leaked to the client, instead of both succeeding as the surrounding code's own
comment promises. This is a genuine, if narrow-window, correctness/robustness gap — not a
security/tenant-isolation issue, and not something I fixed (per instructions: production code
was not touched to address this).

**Disposition:** Per instructions not to fix production code, this is reported rather than
patched. The reproducing test
(`a_concurrent_duplicate_diff_request_is_tolerated_not_surfaced_as_an_error` in
`crates/hangar-npm/src/routes/unpublish.rs`) is marked `#[ignore]` (with a doc comment and the
`ignore` reason string both explaining why) rather than left in the default suite, because it
is measurably flaky (fails ~15-20% of the time) and a flaky test in the default `cargo test`
run is worse than no test — it would fail CI nondeterministically for reasons unrelated to
whatever change triggered that CI run. It remains in the codebase as living reproduction
evidence and a regression check: once `execute_version` is made TOCTOU-safe (e.g. treat a
storage-delete-not-found as tolerable, or serialize per-version deletes), removing the
`#[ignore]` attribute should make it pass reliably.

**Not a bug:** the dist-tag-to-nonexistent-version case the brief specifically flagged as a
possible concern (`SetDistTagUseCase` rejects it, confirmed above) — no dist-tag can be
pointed at a version that doesn't exist.

**Not a bug:** the asymmetry between `unpublish_version`'s plain 404-on-missing behavior and
`unpublish_via_document_put`'s idempotent-on-missing behavior — these are two intentionally
different mechanisms (one targets one version by name and should error if it's not there; the
other reasons over a diff snapshot that can legitimately race).

## Mutation-testing evidence

All three mutations below were applied, run, observed to fail exactly the targeted test(s)
while leaving all others green, then reverted. `git diff --stat` after every revert confirmed
production files carry zero net changes (all diffs are pure test-module additions).

### 1. `publish.rs` — cross-organization rejection wired at the route (not just unit-tested)

Mutated the route to bypass `require_repository_by_name`'s organization check, replacing it
with a raw `find_by_org_and_name` call (simulating a route author who forgot to call the
guard):

```
thread 'routes::publish::tests::publishing_by_a_caller_from_a_different_organization_is_rejected' panicked:
assertion `left == right` failed: a valid write-role grant on a repository in a DIFFERENT organization must not let a publish through the actual route
  left: 201
 right: 404

test result: FAILED. 6 passed; 1 failed; 0 ignored; 0 measured; 49 filtered out
```

Exactly the targeted test failed; the other 6 `publish.rs` tests were unaffected. Reverted.

### 2. `publish.rs` — non-hosted (proxy) rejection wired at the route

Mutated the route to skip the `require_hosted(&repo)?` call entirely:

```
thread 'routes::publish::tests::publishing_against_a_proxy_repository_is_rejected' panicked:
assertion `left == right` failed: publish must be rejected on a proxy repository at the route level, not just in the unit-tested require_hosted() itself
  left: 201
 right: 405

test result: FAILED. 6 passed; 1 failed; 0 ignored; 0 measured; 49 filtered out
```

Exactly the targeted test failed. Reverted.

### 3. `unpublish.rs` — the diff logic itself

Mutated `unpublish_via_document_put`'s `current_versions.difference(&surviving_versions)` to
`current_versions.union(&surviving_versions)` (i.e. "remove everything mentioned by either
side" instead of "remove only what's missing"):

```
thread 'routes::unpublish::tests::putting_back_a_packument_missing_one_version_removes_only_that_version' panicked:
called `Option::unwrap()` on a `None` value

thread 'routes::unpublish::tests::putting_back_the_same_version_list_removes_nothing' panicked:
called `Option::unwrap()` on a `None` value

test result: FAILED. 5 passed; 2 failed; 1 ignored; 0 measured; 48 filtered out
```

Both tests that exercise the diff correctness failed — the union mutation over-deletes to the
point of wiping out the whole package (both versions removed, package cascade-deleted), so a
subsequent metadata fetch returns `None` and `.unwrap()` panics. This is a strong, unambiguous
signal: a broken diff computation is caught immediately. The other 5 (non-diff-logic)
`unpublish.rs` tests were unaffected. Reverted.

## Full test suite result

`DATABASE_URL=postgres://hangar:change-me@localhost:5432/hangar cargo test --workspace`:

```
229 passed (hangar-api, 1 ignored)
269 passed (hangar-docker)
72 passed (hangar-application)
61 passed (hangar-domain)
223 passed (hangar-infrastructure, 5 ignored)
55 passed (hangar-npm, 1 ignored)   <- was 33 before this change
0 failed across the whole workspace
```

`cargo test -p hangar-npm` alone: `running 56 tests ... test result: ok. 55 passed; 0 failed;
1 ignored`. Re-ran the full `hangar-npm` suite 3 times consecutively to confirm the only
non-deterministic test is the intentionally-`#[ignore]`d one; everything else is stable.

## Files changed

- `crates/hangar-npm/src/routes/publish.rs` (test module added, no production code changed)
- `crates/hangar-npm/src/routes/unpublish.rs` (test module added, no production code changed;
  one new test is marked `#[ignore]` as a documented reproduction of a real, unfixed bug in
  `crates/hangar-application/src/use_cases/npm_unpublish.rs` — see "Bugs found")
- `crates/hangar-npm/src/routes/dist_tags.rs` (test module added, no production code changed)

No files outside these three were modified.

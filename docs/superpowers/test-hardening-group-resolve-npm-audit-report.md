# Test hardening: group-resolution cycle guard and npm advisory parsing

Scope: two pure-logic files, no I/O, no production behavior changes.

- `crates/hangar-application/src/use_cases/group_resolve.rs` — `resolve_in_group`
- `crates/hangar-domain/src/npm_audit.rs` — `parse_advisories` / `parse_one_advisory`

## 1. `group_resolve.rs`

### Risk being tested

`resolve_in_group` is a shared recursive "try hosted, else recurse into group
members" walker used by 4 GET use cases (docker manifest/blob, npm
metadata/download). It carries its own `visited: HashSet<Uuid>` cycle guard,
and its own doc comment warns that "two groups can still form one [cycle]" —
i.e. direct self-membership is blocked at the domain layer
(`DomainError::SelfGroupMembership`, enforced in
`use_cases/package_repository.rs`), but a mutual reference between two
*different* groups (A contains B, B contains A) is not preventable at
creation time and relies entirely on this function's own guard at read time.
Before this change there were zero direct tests of this function, and none
of its four callers exercised the cyclic-group case.

### What I verified by reading the code first

- `visited.insert(repository_id)` happens *before* the repository is looked
  up. If the insert reports the id was already present, the function returns
  `Ok(None)` immediately without calling `find_by_id` again — so a
  cycle never causes a second lookup of the same repository, let alone
  infinite recursion.
- An empty `Group` (no `group_members`) never enters the `for` loop and
  returns `Ok(None)` directly — it never even reaches `not_found`. So "empty
  group" and "the id you asked for was never found at all" are two genuinely
  different code paths, both surfacing as `Ok(None)` for a *group's member*,
  and `not_found()` is only invoked when `find_by_id` itself returns `None`
  (repository id does not exist as a row/aggregate at all).

### New tests (`use_cases::group_resolve::tests`)

1. `group_with_one_hosted_member_resolves_to_that_repository` — baseline:
   group → hosted member resolves via `try_hosted`.
2. `group_with_a_nested_group_resolves_two_levels_deep` — group → group →
   hosted, confirming multi-level recursion works.
3. `group_that_contains_itself_is_caught_by_the_cycle_guard` — a group whose
   own id is one of its members resolves to `Ok(None)`, not infinite
   recursion.
4. `two_groups_referencing_each_other_are_caught_by_the_cycle_guard` — the
   exact "two groups can still form one cycle" scenario from the doc
   comment: A contains B, B contains A. Resolves to `Ok(None)`.
5. `empty_group_resolves_to_none_rather_than_an_error` — a group with zero
   members resolves to `Ok(None)`, not an error, and not `not_found()`.
6. `missing_repository_surfaces_the_not_found_error` — contrast case: asking
   to resolve an id that doesn't exist at all in the store returns
   `Err(not_found())`, distinguishing it from the "found but empty group"
   case above.
7. `cycle_guard_never_looks_up_the_same_repository_more_than_once` — the
   mutation-testing regression guard (see below).

All 7 tests pass with `cargo test -p hangar-application group_resolve`.

### Mutation testing on the cycle guard

The brief asked for evidence the guard is load-bearing, without actually
running an unbounded infinite recursion in the test process (which could
hang the suite or overflow the stack).

**Approach taken:** I added `VisitCountingRepositories`, a thin wrapper
around the existing `FakeRepositories` test double that counts calls to
`find_by_id` per repository id and returns a `Storage` error the moment any
id is looked up more than `max_visits` times. With the real guard in place,
a two-group cycle looks up each repository *exactly once* (the second visit
is blocked by `visited.insert` before any lookup happens at all), so with
`max_visits = 1` the wrapper's cap is never tripped and the test asserts a
normal `Ok(None)` result. This makes the cap a safe, bounded proxy for "did
the guard actually stop the recursion" — if the guard were ever broken, the
mutual cycle would call `find_by_id` on the same id repeatedly and the
wrapper would return its `Storage` error within 2 calls, long before any
real stack growth.

**Before/after evidence:**

1. Baseline: `cargo test -p hangar-application group_resolve` → 7/7 pass,
   including `cycle_guard_never_looks_up_the_same_repository_more_than_once`.
2. Mutation: temporarily replaced the guard body

   ```rust
   if !visited.insert(repository_id) {
       return Ok(None);
   }
   ```

   with a no-op that still calls `insert` (to keep the borrow/move semantics
   compiling) but never returns early:

   ```rust
   if !visited.insert(repository_id) {
       // MUTATION-TEST: guard disabled temporarily to verify test coverage catches it.
   }
   ```

3. Ran only the safety-valve test in isolation (deliberately not the other,
   uncapped cyclic tests, since those would recurse genuinely unboundedly
   under this mutation):
   `cargo test -p hangar-application cycle_guard_never_looks_up_the_same_repository_more_than_once`
   → **FAILED**, with:
   ```
   thread '...' panicked at .../group_resolve.rs:263:27:
   called `Result::unwrap()` on an `Err` value: EventStore(Storage("repository <uuid> visited 2 times (max 1) - cycle guard not working"))
   ```
   This confirms that with the guard broken, the same repository id is
   looked up more than once during a two-group cycle — precisely the
   condition that would cause unbounded recursion in the unmutated code path
   for the uncapped tests.
4. Restored the guard to its original form. Re-ran
   `cargo test -p hangar-application group_resolve` → 7/7 pass again.
5. Confirmed via `git diff` that the working tree has no production-code
   deletions left over — the diff for both files is purely additive
   (new `#[cfg(test)]` modules), i.e. the mutation was fully reverted.

## 2. `npm_audit.rs`

### Risk being tested

`parse_advisories`/`parse_one_advisory` parse untrusted third-party JSON
(npm's public advisory database) and are documented to silently drop
malformed entries rather than fail the whole batch. There were zero tests of
this documented behavior before this change.

### What I verified by reading the code first (don't assume from the brief)

- `parse_one_advisory` uses `?` on `Option` for `id`, `url`, `title`,
  `severity`, and `vulnerable_versions` — any of these missing or of the
  wrong JSON type drops the whole advisory (returns `None`).
- `cwe` and `cvss.score` are read differently: `.and_then(...)` chains, never
  `?`. So:
  - `cwe` missing, `null`, or not a JSON array → `.as_array()` returns
    `None` → `.unwrap_or_default()` → **empty `Vec`**, and the advisory is
    still parsed and kept (does *not* get dropped).
  - `cvss` missing, or `cvss.score` missing/wrong type → `cvss_score`
    becomes `None`, and the advisory is still parsed and kept (does *not*
    get dropped).
  - This confirms the brief's hypothesis ("missing `cvss.score` being
    dropped") was **not what the code actually does** — I verified this by
    reading before writing the test, and wrote the test to match the real
    (more lenient) behavior rather than assume-and-fix.
- `parse_advisories` returns `HashMap::new()` if the top-level JSON isn't an
  object, and for any one package whose advisories value isn't a JSON array,
  that package's parsed list is `Vec::new()` via `.unwrap_or_default()`
  rather than propagating an error.

### New tests (`npm_audit::tests`)

1. `well_formed_batch_parses_every_advisory` — happy path across two
   packages; there was no existing happy-path test, so this was added.
2. `advisory_missing_cvss_score_still_parses_with_none` — advisory JSON has
   no `cvss` key at all; asserts the entry is kept with `cvss_score: None`
   (proves the brief's hypothesized "drop on missing cvss.score" is false).
3. `advisory_with_cvss_object_missing_score_field_still_parses_with_none` —
   `cvss` object present but without a `score` field; same conclusion.
4. `non_array_cwe_field_defaults_to_empty_rather_than_dropping_the_advisory`
   — `cwe` is a bare string instead of an array; entry kept, `cwe: vec![]`.
5. `advisory_missing_id_is_dropped` — confirms `id` is one of the required
   (`?`-gated) fields.
6. `advisory_with_wrong_type_id_is_dropped` — `id` present but a string, not
   a number.
7. `advisory_missing_a_required_string_field_is_dropped` — parametrized over
   `url`, `title`, `severity`, `vulnerable_versions`, each individually
   removed.
8. `non_object_advisory_entry_is_dropped` — an advisory array entry that is
   itself a string, `null`, or an array (not a JSON object at all).
9. `one_malformed_entry_does_not_take_down_the_rest_of_a_mixed_batch` — the
   key property from the brief: a batch of 5 entries (well-formed,
   missing-id, well-formed, garbage string, well-formed) still returns
   exactly the 3 well-formed advisories, in order, and none of the 4
   surrounding entries are lost or reordered.
10. `package_whose_advisories_field_is_not_an_array_yields_an_empty_list` —
    per-package non-array value degrades to an empty list, not an error.
11. `non_object_top_level_value_yields_no_advisories` — top-level JSON is an
    array or a string instead of an object.

All 11 tests pass with `cargo test -p hangar-domain npm_audit`.

### Mutation testing on malformed-entry isolation

**Approach:** temporarily changed `parse_advisories`'s inner mapping from
`filter_map(parse_one_advisory)` (skip malformed entries) to a version that
panics on the first malformed entry:

```rust
// MUTATION-TEST: panic on a malformed entry instead of skipping it.
let parsed = advisories
    .as_array()
    .map(|arr| arr.iter().map(|a| parse_one_advisory(a).expect("malformed advisory entry")).collect())
    .unwrap_or_default();
```

Ran the mixed-batch test in isolation:
`cargo test -p hangar-domain one_malformed_entry_does_not_take_down_the_rest_of_a_mixed_batch`
→ **FAILED**:
```
thread '...' panicked at .../npm_audit.rs:34:69:
malformed advisory entry
```
This confirms the test actually exercises the "one bad entry doesn't take
down the batch" property — it fails immediately when that property is
violated. Reverted the mutation, re-ran `cargo test -p hangar-domain
npm_audit` → 11/11 pass again. `git diff` on `npm_audit.rs` after the
revert shows only additions (the new `#[cfg(test)]` module), confirming the
mutation left no trace in the working tree.

## Bugs or gaps found

None. Both functions behave exactly as documented once read carefully; the
one place the brief's own hypothesis ("missing cvss.score is dropped") was
wrong turned out to be the code being *more* lenient than assumed, which is
consistent with, not contradictory to, the documented "malformed entries are
dropped" contract (cvss.score isn't treated as a required field by the
parser). No production code was changed.

## Full test suite result

Baseline (before any test files were added): `cargo build --workspace` —
clean, no errors.

After adding tests, full suite with a live local Postgres
(`hangar-postgres-1` container, `DATABASE_URL=postgres://hangar:change-me@localhost:5432/hangar`):

```
cargo test --workspace
```

- `hangar-api`: 229 passed; 0 failed; 1 ignored
- `hangar-application`: 269 passed; 0 failed; 0 ignored (includes the 7 new `group_resolve` tests)
- `hangar-docker`: 72 passed; 0 failed; 0 ignored
- `hangar-domain`: 61 passed; 0 failed; 0 ignored (includes the 11 new `npm_audit` tests)
- `hangar-infrastructure`: 223 passed; 0 failed; 5 ignored
- `hangar-npm`: 33 passed; 0 failed; 0 ignored
- Doc-tests: 0 in every crate

Total: 0 failures across the workspace.

## Files changed

- `crates/hangar-application/src/use_cases/group_resolve.rs` — added
  `#[cfg(test)] mod tests` (7 tests + a `VisitCountingRepositories` test
  double). No production code changed (mutation was applied and reverted
  during verification only).
- `crates/hangar-domain/src/npm_audit.rs` — added `#[cfg(test)] mod tests`
  (11 tests). No production code changed (mutation was applied and reverted
  during verification only).

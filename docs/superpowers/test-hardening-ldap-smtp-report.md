# Test hardening: LDAP search-result decision and SMTP message construction

Scope: `crates/hangar-infrastructure/src/ldap3_auth_adapter.rs` and
`crates/hangar-infrastructure/src/smtp_email_sender.rs`. Both files make real network
connections in production (LDAP, SMTP) that cannot be exercised without a live external
server. Following the pattern already used in `openidconnect_auth_adapter.rs`
(`external_identity_from_claims`), the pure decision logic in each file was extracted
into small, directly-testable functions; the network calls themselves remain untested
(disclosed gap, not attempted to close).

## File 1: `ldap3_auth_adapter.rs`

### Extraction

Verified first that `ldap3::SearchEntry` (crate 0.12.1) is trivially hand-constructible
in tests: it derives `Debug, Clone` and has three fully public fields —
`dn: String`, `attrs: HashMap<String, Vec<String>>`, `bin_attrs: HashMap<String, Vec<Vec<u8>>>`
— no private state, no special constructor required. This confirmed the intended seam.

**Before** (`authenticate`, inline):
```rust
if results.len() != 1 {
    return Err(DomainError::Infrastructure(format!("ldap search returned {} entries, expected exactly 1", results.len())));
}
let entry = SearchEntry::construct(results.into_iter().next().expect("length checked above"));
let email = entry
    .attrs
    .get(&config.email_attribute)
    .and_then(|values| values.first())
    .ok_or_else(|| DomainError::Infrastructure(format!("ldap entry missing {} attribute", config.email_attribute)))?
    .clone();
// ... entry.dn used below for re-bind
```

**After** — new pure function, called from `authenticate`:
```rust
fn extract_single_match(entries: Vec<SearchEntry>, email_attribute: &str) -> Result<(String, String), DomainError> {
    if entries.len() != 1 {
        return Err(DomainError::Infrastructure(format!("ldap search returned {} entries, expected exactly 1", entries.len())));
    }
    let entry = entries.into_iter().next().expect("length checked above");
    let email = entry
        .attrs
        .get(email_attribute)
        .and_then(|values| values.first())
        .ok_or_else(|| DomainError::Infrastructure(format!("ldap entry missing {email_attribute} attribute")))?
        .clone();
    Ok((entry.dn, email))
}
```

`authenticate()` now does: `results.into_iter().map(SearchEntry::construct).collect()`
(the same conversion, just moved before the length check instead of after) → calls
`extract_single_match(entries, &config.email_attribute)?` → uses the returned
`(dn, email)` for the re-bind and the final `ExternalIdentity`.

**Behavior-preserving**: error message wording, error ordering, and the re-bind DN/email
values are byte-for-byte identical to before — verified by re-reading the original code's
exact wording before extracting (not retyped from memory), and confirmed by all 4 previously
passing tests in this file still passing unchanged, plus the crate building clean.

### New tests (`ldap3_auth_adapter.rs`)

- `a_single_match_with_the_email_attribute_present_succeeds`
- `zero_matches_is_rejected`
- `more_than_one_match_is_rejected`
- `a_single_match_missing_the_email_attribute_is_rejected`
- `a_single_match_with_an_empty_value_list_for_the_email_attribute_is_treated_as_missing`
  — confirms an empty `Vec` for the attribute takes the same "missing" error path as a
  wholly absent key (`.first()` on an empty vec is `None`), which is today's actual
  behavior, preserved rather than changed.

All hand-construct `SearchEntry` via a small test helper (`fn entry(dn, attrs) -> SearchEntry`)
with no network involved.

### Mutation testing evidence

Temporarily changed the "exactly one match required" check from `entries.len() != 1` to
`entries.len() < 1`, then ran the multi-match test:

```
thread '...::more_than_one_match_is_rejected' panicked at ...:
called `Result::unwrap_err()` on an `Ok` value: ("uid=a,...", "a@corp.example")
test result: FAILED. 0 passed; 1 failed
```

Confirmed the mutant is caught (wrongly returns `Ok` on 2 matches), then reverted the
change back to `!= 1` and re-ran — all 9 tests in the file pass again.

## File 2: `smtp_email_sender.rs`

### Extraction

**Before**: `send()` did address parsing, the `if html_body.contains(&cid_reference) { ... }`
attach decision (including the async `self.branding.get(...)` call and `Message::builder()`)
all inline.

**After** — two new pure functions:

```rust
/// Whether the logo attachment is needed at all — gates both the branding fetch and
/// the attachment decision, from the same one check.
fn html_references_logo(html_body: &str) -> bool {
    html_body.contains(&format!("cid:{LOGO_CID}"))
}

/// Builds the outgoing MIME message from already-resolved, synchronous values — no
/// network or async I/O.
fn build_message(from_address: &str, from_name: &str, to: &str, subject: &str, text_body: &str, html_body: &str, logo: Option<(Vec<u8>, String)>) -> Result<Message, DomainError> {
    let from_address: Address = from_address.parse().map_err(|_| DomainError::Infrastructure("configured SMTP from-address is not a valid mailbox".to_string()))?;
    let from = Mailbox::new(Some(from_name.to_string()), from_address);
    let to: Mailbox = to.parse().map_err(|_| DomainError::Infrastructure("recipient address is not a valid mailbox".to_string()))?;

    let html_part = if html_references_logo(html_body) {
        let (logo_bytes, logo_content_type) = logo.unwrap_or_else(|| (DEFAULT_LOGO_BYTES.to_vec(), DEFAULT_LOGO_CONTENT_TYPE.to_string()));
        let logo = Attachment::new_inline(LOGO_CID.to_string()).body(Body::new(logo_bytes), logo_content_type.parse().map_err(|_| DomainError::Infrastructure("stored logo content type is invalid".to_string()))?);
        MultiPart::related().singlepart(SinglePart::html(html_body.to_string())).singlepart(logo)
    } else {
        MultiPart::related().singlepart(SinglePart::html(html_body.to_string()))
    };
    let body = MultiPart::alternative().singlepart(SinglePart::plain(text_body.to_string())).multipart(html_part);

    Message::builder().from(from).to(to).subject(subject).multipart(body).map_err(|e| DomainError::Infrastructure(format!("failed to build email message: {e}")))
}
```

`send()` now: resolves `settings`, computes `html_references_logo(html_body)` to decide
*whether* to await `self.branding.get(...)` (same single evaluation gates both the fetch
and, transitively, the attach decision inside `build_message` — no duplicate/diverging
checks), builds `logo: Option<(Vec<u8>, String)>` from the branding result exactly as
before (falling back to `DEFAULT_LOGO_BYTES`/`DEFAULT_LOGO_CONTENT_TYPE` when there's no
custom asset), then calls `build_message(...)`. Transport selection and `.send()` are
untouched.

**Behavior-preserving**: identical error message text for each failure mode, identical
MIME structure, identical lazy-fetch-only-when-needed behavior for the branding port
(the async fetch is still gated by the very same `contains` check as before — only its
extraction into a named, independently-testable function changed, not its evaluation
site or timing).

### New tests (`smtp_email_sender.rs`) — file had zero tests before

- `an_invalid_from_address_is_rejected`
- `an_invalid_recipient_address_is_rejected`
- `an_invalid_stored_logo_content_type_is_rejected`
- `the_logo_is_attached_when_the_html_references_its_cid` — asserts the formatted MIME
  bytes contain the logo's content type and CID
- `the_logo_is_not_attached_when_the_html_does_not_reference_its_cid` — asserts neither
  appears when `html_body` doesn't reference the logo, even though a resolved logo was
  passed in (proving the decision is driven by `html_body` content, not by whether a
  logo value happens to be available)
- `html_references_logo_detects_the_cid_reference` — direct test of the extracted
  boolean decision itself

### Mutation testing evidence

Temporarily changed `html_references_logo` to always return `false`:

```rust
fn html_references_logo(_html_body: &str) -> bool { false }
```

Re-ran the file's tests — 3 of 6 failed as expected:
```
failures:
    smtp_email_sender::tests::an_invalid_stored_logo_content_type_is_rejected
    smtp_email_sender::tests::html_references_logo_detects_the_cid_reference
    smtp_email_sender::tests::the_logo_is_attached_when_the_html_references_its_cid
test result: FAILED. 3 passed; 3 failed
```
(The content-type-rejection test failed too — a nice bonus: with the mutant, the logo
branch is skipped entirely, so the invalid content type is never even parsed, and the
call silently succeeds instead of erroring.) Reverted the mutation — all 6 tests pass
again.

### Transport-selection `match settings.security` block — investigated, not testable this way

The brief asked to check whether `relay()`/`starttls_relay()` (called for
`SmtpSecurity::Tls`/`StartTls`) synchronously reject a malformed host string, since
building a transport doesn't itself open a connection. Investigated by reading
`lettre` 0.11.23 source directly (this workspace uses the `tokio1-rustls-tls` feature,
i.e. the rustls backend) and by a throwaway probe test:

```rust
let r1 = AsyncSmtpTransport::<Tokio1Executor>::relay("not a valid host!!! \0");
let r2 = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay("not a valid host!!! \0");
// r1.is_ok() == true, r2.is_ok() == true
```

**Finding**: `relay()`/`starttls_relay()` never validate the host string. They build a
`TlsParameters` via `TlsParametersBuilder::new(domain).build()` → `build_rustls()`,
which only configures protocol versions and the root certificate store — it never
touches the `domain` string's syntactic validity. The actual `ServerName::try_from(domain)`
DNS-name validation (the only place a malformed host could error) lives in
`lettre::transport::smtp::client::{net.rs, async_net.rs}` and only runs when the
connection is actually opened, inside `.send()`. So the `"failed to build SMTP transport"`
error branch is not reachable synchronously with any string input under this crate's TLS
backend — per the brief's own instruction, no test was added for it rather than forcing
one that doesn't exercise anything real. (The scratch probe test used for this
investigation was removed after confirming the finding; it is not part of the committed
diff.)

## Disclosed, accepted gaps (not attempted to close)

- **LDAP**: the actual `connect` / service `simple_bind` / `search` / user re-bind
  network calls in `Ldap3AuthAdapter::authenticate` remain untested by this pass. Testing
  them would need a real or fake LDAP server (e.g. `testcontainers` + an OpenLDAP image),
  a larger infrastructure investment outside this pass's scope and explicitly out of
  bounds (no new dependencies).
- **SMTP TLS vs StartTLS handshake**: whether `SmtpSecurity::Tls` truly negotiates
  implicit TLS versus `SmtpSecurity::StartTls` truly upgrading via STARTTLS is not
  verifiable without a real or fake SMTP server that can report which handshake it
  received (e.g. `greenmail`/`mailhog` via Docker, or a hand-rolled TCP listener
  implementing just enough SMTP to observe the negotiation). Not force-closed with a
  weak test or a new dependency.
- **SMTP transport-build error branch**: confirmed above to be practically unreachable
  via a malformed host string with this crate's rustls backend; left untested rather
  than forcing a test that wouldn't exercise real logic.

## Full test suite result

`DATABASE_URL=postgres://hangar:change-me@localhost:5432/hangar cargo test --workspace`:

```
test result: ok. 229 passed; 0 failed; 1 ignored   (hangar-application)
test result: ok. 262 passed; 0 failed; 0 ignored   (hangar-docker)
test result: ok. 72  passed; 0 failed; 0 ignored   (hangar-domain)
test result: ok. 50  passed; 0 failed; 0 ignored   (hangar-domain, integration or bin target)
test result: ok. 204 passed; 0 failed; 5 ignored   (hangar-infrastructure)
test result: ok. 33  passed; 0 failed; 0 ignored   (hangar-npm)
+ 5x doc-tests: 0 passed; 0 failed
```

Zero failures anywhere in the workspace. `hangar-infrastructure` went from ~189 to 204
passing tests (+15: 9 new in `ldap3_auth_adapter.rs`, 6 new in `smtp_email_sender.rs`).
`cargo clippy -p hangar-infrastructure --lib --tests` reports no warnings for either file.

## Files changed

- `crates/hangar-infrastructure/src/ldap3_auth_adapter.rs`
- `crates/hangar-infrastructure/src/smtp_email_sender.rs`

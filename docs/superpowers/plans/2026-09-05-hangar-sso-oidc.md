# SSO — OIDC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an organization authenticate its members against an external OIDC provider (Okta, Azure AD, Google Workspace, Keycloak, etc.) using the standard Authorization Code flow with PKCE, reusing the exact JIT-provisioning and admin-configuration model LDAP already established — the second of three SSO protocols on the roadmap (LDAP done → **OIDC** → SAML deferred, per an explicit decision this session: SAML's recommended library needs a native `libxmlsec1` system dependency this codebase doesn't otherwise have, and that tradeoff needs its own dedicated conversation later).

**Architecture:** Unlike LDAP's same-request bind (no redirect), OIDC is a browser-redirect flow spanning two separate HTTP requests with no server-side session in between: `GET /api/auth/sso/oidc/login` sends the browser to the identity provider, and the provider later redirects back to `GET /api/auth/sso/oidc/callback`. Rather than adding a new stateful store for the CSRF token/nonce/PKCE verifier that must survive that gap, this plan follows the exact pattern this codebase already uses for its own short-lived, self-verifying tokens (`JwtMfaPendingTokenIssuer`): the OIDC adapter signs a JWT containing everything needed to complete the exchange (organization id, nonce, PKCE verifier) and uses that JWT itself as the OAuth `state` parameter — no new table, no in-memory map, works correctly even across multiple app instances. `hangar-domain::sso` gains `OidcConfig` and an `OidcAuthPort` trait; a new `hangar-infrastructure` adapter implements it with the `openidconnect` crate (pure Rust, already-used `reqwest` for HTTP, no native dependency — verified against the crate's real 4.0.1 API before writing this plan). The existing `organization_identity_providers` storage and admin routes (`GET`/`PUT`/`DELETE /api/organizations/:id/identity-provider`) are extended from LDAP-only to a `type`-tagged shape supporting both providers — this is a contained, in-plan breaking change to an endpoint that has no external consumers yet (only this repo's own frontend, updated in the same plan). On the frontend, `OrganizationDetail` gains a provider-type selector, and the login page shows a plain redirect button instead of a form when an organization is OIDC-configured, landing back on the login page with the session token in the URL fragment (never sent to any server, never logged) after a successful round trip.

**Tech Stack:** Rust (axum, sqlx, `openidconnect` + `reqwest` for the OIDC protocol, `jsonwebtoken` for the stateless flow token), Angular 18+ standalone components with signals.

**Spec:** [docs/superpowers/specs/2026-09-04-hangar-organizations-sso-design.md](../specs/2026-09-04-hangar-organizations-sso-design.md) — "SSO — modèle commun" (already implemented by the LDAP plan) and "SSO — OIDC" sections. This plan implements the OIDC trait with more parameters than the spec's own simplified sketch (`build_redirect`/`handle_callback` in the spec don't show the nonce/PKCE plumbing) — real completion of the Authorization Code flow requires threading these through, confirmed against the `openidconnect` crate's actual API before writing this plan (see Task 3's own note on this).

## Global Constraints

- **No server-side session state for the redirect gap.** Everything needed to complete the callback (organization id, CSRF binding, nonce, PKCE verifier) is embedded in a signed JWT that becomes the OAuth `state` parameter — verified by signature on the way back, never stored server-side, never trusted without verification.
- **JIT provisioning reuses `ProvisionSsoUserUseCase` unchanged** — the exact same organization-scoped, privilege-guarded use case LDAP already built and already had its Critical security fix (accounts are matched by email only within the resolving organization, and an existing admin/super-admin account is never silently reused). This plan does not touch that use case at all; it only produces a new `ExternalIdentity` source for it.
- **`client_secret` is encrypted at rest**, using the exact same `secret_box::encrypt_packed`/`decrypt_packed` mechanism already used for `bind_password` and SMTP settings.
- **The OIDC callback never issues a token to a request whose decoded `state` doesn't match the organization the callback request itself resolved to** — this is the redirect-flow's equivalent of LDAP's organization-scoping fix; a `state` token minted for organization A's flow must be rejected on organization B's callback endpoint, even if otherwise validly signed and unexpired.
- **The session token is delivered to the frontend via a URL fragment (`#token=...`), never a query parameter** — fragments are never sent to the server on the follow-up request and never appear in server access logs, unlike query parameters.
- **This is a contained, in-plan breaking change to `PUT`/`GET /api/organizations/:id/identity-provider`**: the request/response shape gains a `type` discriminator (`"ldap"` or `"oidc"`). The only consumer is this repo's own frontend, updated in the same plan. No migration path is needed for external API consumers because none exist yet.
- **`openidconnect` is pure Rust** (confirmed against the crate's real docs before writing this plan: no native/system library dependency, unlike SAML's `xmlsec`-based options) — this is precisely why OIDC was chosen to go before SAML.

---

### Task 1: `hangar-domain::sso` — add `OidcConfig` and `OidcAuthPort`

**Files:**
- Modify: `crates/hangar-domain/src/sso.rs`

**Interfaces:**
- Produces: `OidcConfig { issuer_url: String, client_id: String, client_secret: String }`; `IdentityProviderConfig::Oidc(OidcConfig)` (new enum variant, alongside the existing `Ldap(LdapConfig)`); `OidcAuthPort` trait with `build_redirect`/`handle_callback` — Task 3's adapter implements it, Task 5's routes call it.

- [ ] **Step 1: Write the failing tests**

Add to `crates/hangar-domain/src/sso.rs` (the existing file from the LDAP plan — add alongside `LdapConfig`/`LdapAuthPort`, don't restructure anything already there):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    /// e.g. `https://accounts.example.com` — discovery reads
    /// `{issuer_url}/.well-known/openid-configuration`.
    pub issuer_url: String,
    pub client_id: String,
    /// Plaintext in memory; encrypted at rest by whichever `IdentityProviderRepositoryPort`
    /// implementation persists it (same `secret_box` mechanism as `LdapConfig::bind_password`).
    pub client_secret: String,
}
```

Change the `IdentityProviderConfig` enum to add the new variant:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityProviderConfig {
    Ldap(LdapConfig),
    Oidc(OidcConfig),
}
```

Add the port trait, next to `LdapAuthPort`:

```rust
#[async_trait]
pub trait OidcAuthPort: Send + Sync {
    /// Returns the URL to redirect the browser to. All CSRF binding, nonce, and PKCE
    /// verifier needed to complete the flow are embedded in the URL's own `state` query
    /// parameter as a signed, self-contained token (no server-side session store) —
    /// this same adapter decodes and verifies that token in `handle_callback`.
    async fn build_redirect(&self, config: &OidcConfig, organization_id: Uuid, callback_url: &str) -> Result<String, DomainError>;

    /// `code` and `raw_state` are exactly the `code`/`state` query parameters the identity
    /// provider's redirect carried back. `expected_organization_id` is the organization the
    /// CALLBACK request itself resolved to (by subdomain, same as any other request) — this
    /// must match the organization id embedded in `raw_state` at redirect time, or the call
    /// fails closed. This is the redirect-flow's equivalent of the org-scoping check
    /// `ProvisionSsoUserUseCase` already enforces for LDAP: a `state` token minted for one
    /// organization's login attempt must never complete a session against a different one.
    async fn handle_callback(&self, config: &OidcConfig, code: &str, raw_state: &str, callback_url: &str, expected_organization_id: Uuid) -> Result<ExternalIdentity, DomainError>;
}
```

Add tests to the existing `#[cfg(test)] mod tests` block in this file:

```rust
    #[test]
    fn identity_provider_config_wraps_an_oidc_config_by_value() {
        let config = IdentityProviderConfig::Oidc(OidcConfig {
            issuer_url: "https://accounts.example.com".to_string(),
            client_id: "hangar".to_string(),
            client_secret: "s3cret!".to_string(),
        });
        let IdentityProviderConfig::Oidc(inner) = config else { panic!("expected Oidc variant") };
        assert_eq!(inner.issuer_url, "https://accounts.example.com");
    }
```

- [ ] **Step 2: Run to verify it passes**

Run: `cargo test -p hangar-domain sso:: -- --nocapture`
Expected: PASS (the pre-existing 2 LDAP-era tests plus this new one — 3 total). This test is light on purpose — it exists to catch a typo in the type definitions, not to test behavior (there is none yet; Task 3's adapter implementation arrives next).

- [ ] **Step 3: Commit**

```bash
git add crates/hangar-domain/src/sso.rs
git commit -m "feat: add OidcConfig and OidcAuthPort to hangar-domain"
```

---

### Task 2: `PostgresIdentityProviderRepository` — support the `Oidc` variant

**Files:**
- Modify: `crates/hangar-infrastructure/src/postgres/identity_provider_repository.rs`

**Interfaces:**
- Consumes: `IdentityProviderConfig::Oidc(OidcConfig)` (Task 1); `secret_box::{encrypt_packed, decrypt_packed}` (already imported in this file from the LDAP plan).
- Produces: no new public interface — `set`/`get` already accept/return `IdentityProviderConfig`, now correctly round-tripping the `Oidc` variant too. Task 6's organization routes and Task 4's `AppState` wiring are unaffected by this task (they already depend on the trait, not this file's internals).

This file already has a private `StoredConfig` enum (an internally-tagged serde enum, `#[serde(tag = "type", rename_all = "snake_case")]`) with one variant, `Ldap { ... }`. Add a second variant for OIDC, encrypting `client_secret` the exact same way `bind_password` is already encrypted.

- [ ] **Step 1: Write the failing tests**

Add to this file's existing `#[cfg(test)] mod tests` block:

```rust
    fn sample_oidc() -> IdentityProviderConfig {
        IdentityProviderConfig::Oidc(OidcConfig {
            issuer_url: "https://accounts.example.com".to_string(),
            client_id: "hangar".to_string(),
            client_secret: "s3cret!".to_string(),
        })
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn set_then_get_round_trips_an_oidc_config_including_the_client_secret(pool: PgPool) {
        let repo = PostgresIdentityProviderRepository::new(pool, "jwt-secret".to_string());
        let organization_id = Uuid::new_v4();

        repo.set(organization_id, &sample_oidc()).await.unwrap();

        assert_eq!(repo.get(organization_id).await.unwrap(), Some(sample_oidc()));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn the_oidc_client_secret_is_never_stored_in_plaintext(pool: PgPool) {
        let repo = PostgresIdentityProviderRepository::new(pool, "jwt-secret".to_string());
        let organization_id = Uuid::new_v4();
        repo.set(organization_id, &sample_oidc()).await.unwrap();

        let row: (serde_json::Value,) = sqlx::query_as("SELECT config FROM organization_identity_providers WHERE organization_id = $1")
            .bind(organization_id)
            .fetch_one(&repo.pool)
            .await
            .unwrap();
        assert!(!row.0.to_string().contains("s3cret!"), "the plaintext client secret must never appear in the stored JSON");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn switching_from_ldap_to_oidc_replaces_the_configuration_rather_than_merging_it(pool: PgPool) {
        let repo = PostgresIdentityProviderRepository::new(pool, "jwt-secret".to_string());
        let organization_id = Uuid::new_v4();
        repo.set(organization_id, &sample()).await.unwrap(); // sample() is the existing LDAP fixture already in this file

        repo.set(organization_id, &sample_oidc()).await.unwrap();

        assert_eq!(repo.get(organization_id).await.unwrap(), Some(sample_oidc()));
    }
```

(`sample()` is the pre-existing LDAP fixture function already in this file's test module from the LDAP plan — reuse it, don't redefine it.)

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hangar-infrastructure identity_provider_repository:: 2>&1 | tail -30`
Expected: FAIL to compile — `OidcConfig` isn't imported and `StoredConfig` has no `Oidc` arm yet.

- [ ] **Step 3: Implement**

Add `OidcConfig` to this file's existing `use hangar_domain::sso::{...}` import line.

Extend `StoredConfig`:

```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum StoredConfig {
    Ldap {
        server_url: String,
        bind_dn: String,
        bind_password_encrypted: String,
        user_search_base: String,
        user_search_filter: String,
        email_attribute: String,
    },
    Oidc {
        issuer_url: String,
        client_id: String,
        client_secret_encrypted: String,
    },
}
```

Extend `StoredConfig::from_domain` and `StoredConfig::into_domain` (both already `match` on `IdentityProviderConfig`/`StoredConfig` respectively — add the new arm to each, mirroring the existing `Ldap` arm's encrypt/decrypt calls exactly):

```rust
    fn from_domain(config: &IdentityProviderConfig, jwt_secret: &str) -> Self {
        match config {
            IdentityProviderConfig::Ldap(ldap) => StoredConfig::Ldap {
                server_url: ldap.server_url.clone(),
                bind_dn: ldap.bind_dn.clone(),
                bind_password_encrypted: secret_box::encrypt_packed(&ldap.bind_password, jwt_secret),
                user_search_base: ldap.user_search_base.clone(),
                user_search_filter: ldap.user_search_filter.clone(),
                email_attribute: ldap.email_attribute.clone(),
            },
            IdentityProviderConfig::Oidc(oidc) => StoredConfig::Oidc {
                issuer_url: oidc.issuer_url.clone(),
                client_id: oidc.client_id.clone(),
                client_secret_encrypted: secret_box::encrypt_packed(&oidc.client_secret, jwt_secret),
            },
        }
    }

    fn into_domain(self, jwt_secret: &str) -> IdentityProviderConfig {
        match self {
            StoredConfig::Ldap { server_url, bind_dn, bind_password_encrypted, user_search_base, user_search_filter, email_attribute } => {
                IdentityProviderConfig::Ldap(LdapConfig {
                    server_url,
                    bind_dn,
                    bind_password: secret_box::decrypt_packed(&bind_password_encrypted, jwt_secret),
                    user_search_base,
                    user_search_filter,
                    email_attribute,
                })
            }
            StoredConfig::Oidc { issuer_url, client_id, client_secret_encrypted } => {
                IdentityProviderConfig::Oidc(OidcConfig {
                    issuer_url,
                    client_id,
                    client_secret: secret_box::decrypt_packed(&client_secret_encrypted, jwt_secret),
                })
            }
        }
    }
```

- [ ] **Step 4: Run to verify the tests pass**

Run: `cargo test -p hangar-infrastructure identity_provider_repository:: -- --nocapture`
Expected: PASS (all pre-existing LDAP tests plus the 3 new OIDC ones).

- [ ] **Step 5: Regenerate the sqlx offline cache**

This task introduces no new SQL query text (it only changes what Rust value gets serialized into the same `config` JSONB column) — run `cargo sqlx prepare --workspace -- --all-targets` anyway and confirm `.sqlx/` shows no diff.

- [ ] **Step 6: Commit**

```bash
git add crates/hangar-infrastructure/src/postgres/identity_provider_repository.rs
git commit -m "feat: support OidcConfig in PostgresIdentityProviderRepository"
```

---

### Task 3: `OpenidConnectAuthAdapter`

**Files:**
- Modify: `crates/hangar-infrastructure/Cargo.toml` (add `openidconnect` dependency)
- Create: `crates/hangar-infrastructure/src/openidconnect_auth_adapter.rs`
- Modify: `crates/hangar-infrastructure/src/lib.rs` (add `pub mod openidconnect_auth_adapter;`)

**Interfaces:**
- Consumes: `hangar_domain::sso::{ExternalIdentity, OidcAuthPort, OidcConfig}`.
- Produces: `OpenidConnectAuthAdapter::new(jwt_secret: String) -> Self` implementing `OidcAuthPort` — Task 4 wires this into `AppState` as `state.oidc_auth`.

This is the one task in this plan whose exact third-party API calls this plan's author verified against the crate's current documentation (`openidconnect` 4.0.1, pure Rust, confirmed via a live web fetch while writing this plan) but could not execute end-to-end against a real identity provider while writing the plan. If a specific method name or generic bound below doesn't compile exactly as written, consult `cargo doc -p openidconnect --open` (or `https://docs.rs/openidconnect`) to adapt — the actual security contract to preserve is: (1) a fresh PKCE verifier and nonce are generated per redirect, (2) both are embedded in a JWT that becomes the OAuth `state` parameter (never sent anywhere except round-tripped through the identity provider), (3) `handle_callback` verifies that JWT's signature and expiry, checks its embedded organization id against the caller-supplied `expected_organization_id`, and only then uses the recovered nonce/PKCE verifier to complete the code exchange and validate the ID token.

- [ ] **Step 1: Add the dependency**

In `crates/hangar-infrastructure/Cargo.toml`, under `[dependencies]`, add:

```toml
openidconnect = "4"
```

(No extra features needed — `reqwest` async support is enabled by default in this crate, and `reqwest` is already a dependency of this crate via other adapters, e.g. `http_remote_docker_registry.rs`.)

Run: `cargo build -p hangar-infrastructure 2>&1 | tail -30` — confirm the new dependency resolves and compiles (with no adapter code yet, this just proves the dependency itself is sound).

- [ ] **Step 2: Write the failing unit tests**

This adapter's core protocol logic (discovery, code exchange, ID token validation) requires a real or mocked identity provider and is intentionally left to manual/integration verification later (Task 3's own final step below), not a unit test — mocking `openidconnect`'s HTTP client would test the mock, not the adapter. The one thing genuinely unit-testable without a network is the stateless `state`-JWT encode/decode round trip and its organization-mismatch rejection, since that logic is pure and self-contained.

Create `crates/hangar-infrastructure/src/openidconnect_auth_adapter.rs`:

```rust
use async_trait::async_trait;
use chrono::{Duration, Utc};
use hangar_domain::error::DomainError;
use hangar_domain::sso::{ExternalIdentity, OidcAuthPort, OidcConfig};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error_ext::InfraErr;

const OIDC_STATE_TOKEN_TYPE: &str = "oidc-state";
/// Generous enough for a slow identity-provider login screen, short enough that a captured
/// but unused redirect URL stops being useful quickly.
const STATE_TOKEN_TTL_MINUTES: i64 = 10;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateClaims {
    typ: String,
    exp: i64,
    organization_id: Uuid,
    nonce: String,
    pkce_verifier: String,
}

pub struct OpenidConnectAuthAdapter {
    jwt_secret: String,
}

impl OpenidConnectAuthAdapter {
    pub fn new(jwt_secret: String) -> Self {
        Self { jwt_secret }
    }

    fn encode_state(&self, organization_id: Uuid, nonce: &Nonce, pkce_verifier: &PkceCodeVerifier) -> Result<String, DomainError> {
        let claims = StateClaims {
            typ: OIDC_STATE_TOKEN_TYPE.to_string(),
            exp: (Utc::now() + Duration::minutes(STATE_TOKEN_TTL_MINUTES)).timestamp(),
            organization_id,
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
        };
        encode(&Header::default(), &claims, &EncodingKey::from_secret(self.jwt_secret.as_bytes())).infra_err()
    }

    fn decode_state(&self, raw_state: &str, expected_organization_id: Uuid) -> Result<StateClaims, DomainError> {
        let data = decode::<StateClaims>(raw_state, &DecodingKey::from_secret(self.jwt_secret.as_bytes()), &Validation::default()).infra_err()?;
        if data.claims.typ != OIDC_STATE_TOKEN_TYPE {
            return Err(DomainError::Infrastructure("not an oidc-state token".to_string()));
        }
        // The core of the org-scoping fix: a state token minted for one organization's login
        // attempt must never complete a session against a different one, even if the token
        // is otherwise validly signed and unexpired.
        if data.claims.organization_id != expected_organization_id {
            return Err(DomainError::Infrastructure("oidc state token organization mismatch".to_string()));
        }
        Ok(data.claims)
    }

    async fn build_client(&self, config: &OidcConfig, callback_url: &str) -> Result<CoreClient, DomainError> {
        let issuer_url = IssuerUrl::new(config.issuer_url.clone()).infra_err()?;
        let metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client).await.infra_err()?;
        let redirect_url = RedirectUrl::new(callback_url.to_string()).infra_err()?;
        Ok(CoreClient::from_provider_metadata(metadata, ClientId::new(config.client_id.clone()), Some(ClientSecret::new(config.client_secret.clone())))
            .set_redirect_uri(redirect_url))
    }
}

#[async_trait]
impl OidcAuthPort for OpenidConnectAuthAdapter {
    async fn build_redirect(&self, config: &OidcConfig, organization_id: Uuid, callback_url: &str) -> Result<String, DomainError> {
        let client = self.build_client(config, callback_url).await?;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let nonce = Nonce::new_random();
        let state_token = self.encode_state(organization_id, &nonce, &pkce_verifier)?;

        let (auth_url, _csrf, _nonce) = client
            .authorize_url(CoreAuthenticationFlow::AuthorizationCode, move || CsrfToken::new(state_token.clone()), move || nonce.clone())
            .add_scope(openidconnect::Scope::new("openid".to_string()))
            .add_scope(openidconnect::Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok(auth_url.to_string())
    }

    async fn handle_callback(&self, config: &OidcConfig, code: &str, raw_state: &str, callback_url: &str, expected_organization_id: Uuid) -> Result<ExternalIdentity, DomainError> {
        let claims = self.decode_state(raw_state, expected_organization_id)?;
        let client = self.build_client(config, callback_url).await?;

        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .infra_err()?
            .set_pkce_verifier(PkceCodeVerifier::new(claims.pkce_verifier))
            .request_async(async_http_client)
            .await
            .infra_err()?;

        // `client.id_token_verifier()` checks the token's signature against the keys the
        // discovery step already fetched and that it was issued for this `client_id`;
        // `claims(&verifier, &nonce)` additionally checks the `nonce` claim matches exactly
        // what this adapter generated for this specific redirect — together these are the
        // full validation `openidconnect` exists to provide instead of hand-parsing the JWT.
        let expected_nonce = Nonce::new(claims.nonce);
        let id_token = openidconnect::OAuth2TokenResponse::extra_fields(&token_response)
            .id_token()
            .ok_or_else(|| DomainError::Infrastructure("oidc token response had no id_token".to_string()))?;
        let id_token_claims = id_token.claims(&client.id_token_verifier(), &expected_nonce).infra_err()?;

        let email = id_token_claims
            .email()
            .ok_or_else(|| DomainError::Infrastructure("oidc id token missing the email claim".to_string()))?
            .to_string();

        Ok(ExternalIdentity { email, display_name: None })
    }
}
```

The `.id_token()` accessor above is called through the `OAuth2TokenResponse` trait rather than as an inherent method — `openidconnect`'s response types split standard OAuth2 fields (via `oauth2`'s `OAuth2TokenResponse` trait) from OIDC-specific ones; if this doesn't resolve exactly as written, `cargo doc -p openidconnect --open` will show whichever trait/inherent-method split this version actually uses — the three calls to get right are: extract the ID token from the token response, obtain an ID-token verifier from `client`, and call `.claims(&verifier, &nonce)` on the ID token to get validated claims with an `.email()` accessor. Do not skip this validation to make something compile — the whole reason to use `openidconnect` instead of hand-parsing the JWT is exactly this signature/audience/nonce checking.

The rest of the same file — the test module, appended directly below the `impl OidcAuthPort for OpenidConnectAuthAdapter` block above, still inside `openidconnect_auth_adapter.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_token_round_trips_its_claims() {
        let adapter = OpenidConnectAuthAdapter::new("jwt-secret".to_string());
        let organization_id = Uuid::new_v4();
        let nonce = Nonce::new("test-nonce".to_string());
        let pkce_verifier = PkceCodeVerifier::new("test-pkce-verifier".to_string());

        let token = adapter.encode_state(organization_id, &nonce, &pkce_verifier).unwrap();
        let claims = adapter.decode_state(&token, organization_id).unwrap();

        assert_eq!(claims.organization_id, organization_id);
        assert_eq!(claims.nonce, "test-nonce");
        assert_eq!(claims.pkce_verifier, "test-pkce-verifier");
    }

    #[test]
    fn a_state_token_minted_for_one_organization_is_rejected_for_another() {
        let adapter = OpenidConnectAuthAdapter::new("jwt-secret".to_string());
        let nonce = Nonce::new("test-nonce".to_string());
        let pkce_verifier = PkceCodeVerifier::new("test-pkce-verifier".to_string());
        let token = adapter.encode_state(Uuid::new_v4(), &nonce, &pkce_verifier).unwrap();

        let result = adapter.decode_state(&token, Uuid::new_v4());

        assert!(result.is_err(), "a state token must not verify against a different organization id than the one it was minted for");
    }

    #[test]
    fn a_state_token_signed_with_a_different_secret_is_rejected() {
        let adapter_a = OpenidConnectAuthAdapter::new("secret-a".to_string());
        let adapter_b = OpenidConnectAuthAdapter::new("secret-b".to_string());
        let organization_id = Uuid::new_v4();
        let nonce = Nonce::new("test-nonce".to_string());
        let pkce_verifier = PkceCodeVerifier::new("test-pkce-verifier".to_string());
        let token = adapter_a.encode_state(organization_id, &nonce, &pkce_verifier).unwrap();

        assert!(adapter_b.decode_state(&token, organization_id).is_err());
    }
}
```

If `handle_callback`'s `.id_token()`/`.id_token_verifier()`/`.claims()` calls above don't compile exactly as written against the actual installed `openidconnect` version, run `cargo doc -p openidconnect --open` (or browse `https://docs.rs/openidconnect`) to find the real method chain — the discovery, PKCE, and code-exchange calls earlier in this same function were verified with high confidence against the crate's real 4.0.1 API before this plan was written; the ID-token validation step was verified at slightly lower confidence (a documentation excerpt rather than the crate's own source), so it's the one part of this file most likely to need a small adjustment. Whatever the exact calls turn out to be, do not skip signature/audience/nonce validation to make something compile — the whole point of using `openidconnect` instead of hand-parsing the JWT is exactly this validation, and the end result must still produce an `ExternalIdentity { email, display_name: None }` where `email` comes from the validated ID token's standard `email` claim (fail closed with `DomainError::Infrastructure(...)` if the claim is absent, mirroring how `Ldap3AuthAdapter` fails when its configured `email_attribute` is missing).

- [ ] **Step 3: Run to verify the pure-logic tests pass**

Run: `cargo test -p hangar-infrastructure openidconnect_auth_adapter:: -- --nocapture`
Expected: PASS (3 tests) — these exercise only `encode_state`/`decode_state` and don't reach the network, but the whole file must compile first, so confirm `cargo build -p hangar-infrastructure` succeeds before running the tests if you had to adjust `handle_callback`'s ID-token validation calls per the note above.

- [ ] **Step 4: Manual integration note**

The discovery/exchange/validation flow itself needs verification against a real or containerized OIDC provider (e.g. a local Keycloak realm, or a free-tier Auth0/Okta developer tenant) before this feature is considered production-ready. This plan does not require standing up such a provider as part of this task — record in the task report that this manual verification was NOT performed automatically, so the controller can decide whether to do it before merge (mirroring how the LDAP plan's `Ldap3AuthAdapter` task deferred its own live-directory verification for the same reason).

Add to `crates/hangar-infrastructure/src/lib.rs`:

```rust
pub mod openidconnect_auth_adapter;
```

- [ ] **Step 5: Commit**

```bash
git add crates/hangar-infrastructure/Cargo.toml crates/hangar-infrastructure/src/openidconnect_auth_adapter.rs crates/hangar-infrastructure/src/lib.rs Cargo.lock
git commit -m "feat: add OpenidConnectAuthAdapter implementing OidcAuthPort"
```

---

### Task 4: Wire `OpenidConnectAuthAdapter` into `AppState`

**Files:**
- Modify: `crates/hangar-api/src/state.rs`

**Interfaces:**
- Consumes: `OpenidConnectAuthAdapter::new(jwt_secret: String)` (Task 3).
- Produces: `AppState.oidc_auth: Arc<dyn OidcAuthPort>` — Task 5's routes use this field.

- [ ] **Step 1: Add the import**

```rust
use hangar_domain::sso::OidcAuthPort;
use hangar_infrastructure::openidconnect_auth_adapter::OpenidConnectAuthAdapter;
```

(add `OidcAuthPort` to the existing `use hangar_domain::sso::{...}` import line from the LDAP plan rather than a new line, if that's how the file currently groups it — check the existing import first.)

- [ ] **Step 2: Add the field**

Next to `pub ldap_auth: Arc<dyn LdapAuthPort>,`, add:

```rust
pub oidc_auth: Arc<dyn OidcAuthPort>,
```

- [ ] **Step 3: Construct it in `AppState::build`**

Next to `let ldap_auth: Arc<dyn LdapAuthPort> = Arc::new(Ldap3AuthAdapter);`, add:

```rust
let oidc_auth: Arc<dyn OidcAuthPort> = Arc::new(OpenidConnectAuthAdapter::new(config.jwt_secret.clone()));
```

Next to `ldap_auth: ldap_auth.clone(),` in the struct literal, add:

```rust
oidc_auth: oidc_auth.clone(),
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build -p hangar-api 2>&1 | tail -40`
Expected: succeeds with no warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/hangar-api/src/state.rs
git commit -m "feat: wire OpenidConnectAuthAdapter into AppState"
```

---

### Task 5: `GET /api/auth/sso/oidc/login` and `GET /api/auth/sso/oidc/callback`

**Files:**
- Modify: `crates/hangar-api/src/dto.rs` (extend `SsoProviderType`)
- Modify: `crates/hangar-api/src/routes/auth.rs`

**Interfaces:**
- Consumes: `state.identity_providers.get(org_id)`, `state.oidc_auth.{build_redirect, handle_callback}` (Tasks 2-4), `state.provision_sso_user.execute(...)` (already exists from the LDAP plan, unchanged), `crate::organization_middleware::ResolvedOrganization`, `state.config.public_url` and `state.hangar_base_domain` (both already exist — check `state.rs`'s existing fields to confirm exact names before using them) for constructing the exact `callback_url` this organization's subdomain resolves to.
- Produces: routes `GET /api/auth/sso/oidc/login` and `GET /api/auth/sso/oidc/callback`, added to `pub fn router()` in this file. `GET /api/auth/sso/config` (already exists from the LDAP plan) is extended to report `"oidc"` as a possible type. Task 9 (frontend) consumes all three.

- [ ] **Step 1: Extend the DTO**

In `crates/hangar-api/src/dto.rs`, extend the existing `SsoProviderType` enum from the LDAP plan:

```rust
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SsoProviderType {
    Ldap,
    Oidc,
}
```

- [ ] **Step 2: Write the failing tests**

Add to `crates/hangar-api/src/routes/auth.rs`'s `#[cfg(test)] mod tests`, next to the existing `seed_ldap_config` helper from the LDAP plan:

```rust
    async fn seed_oidc_config(state: &AppState, organization_id: uuid::Uuid) {
        state
            .identity_providers
            .set(
                organization_id,
                &hangar_domain::sso::IdentityProviderConfig::Oidc(hangar_domain::sso::OidcConfig {
                    issuer_url: "https://accounts.example.com".to_string(),
                    client_id: "hangar".to_string(),
                    client_secret: "s3cret!".to_string(),
                }),
            )
            .await
            .unwrap();
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn sso_config_reports_oidc_for_a_configured_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        seed_oidc_config(&state, public_org.id).await;
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/auth/sso/config").body(Body::empty()).unwrap()).await.unwrap();

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["type"], "oidc");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn oidc_login_is_rejected_when_the_organization_has_no_identity_provider_configured(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/auth/sso/oidc/login").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn oidc_login_is_rejected_when_the_organization_has_an_ldap_provider_instead(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        seed_ldap_config(&state, public_org.id).await;
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/auth/sso/oidc/login").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_callback_with_no_state_parameter_is_rejected_as_unauthorized(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        seed_oidc_config(&state, public_org.id).await;
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/auth/sso/oidc/callback?code=abc").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_callback_with_an_invalid_state_token_is_rejected_as_unauthorized(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        seed_oidc_config(&state, public_org.id).await;
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/auth/sso/oidc/callback?code=abc&state=not-a-real-token").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p hangar-api routes::auth:: oidc 2>&1 | tail -40`
Expected: FAIL to compile (routes and DTO extension don't exist yet).

- [ ] **Step 4: Implement the routes**

In `crates/hangar-api/src/routes/auth.rs`, add to `router()`:

```rust
        .route("/api/auth/sso/oidc/login", get(sso_oidc_login))
        .route("/api/auth/sso/oidc/callback", get(sso_oidc_callback))
```

Extend the existing `sso_config` handler's `match` (from the LDAP plan) to add the OIDC arm:

```rust
    let provider_type = config.map(|c| match c {
        hangar_domain::sso::IdentityProviderConfig::Ldap(_) => SsoProviderType::Ldap,
        hangar_domain::sso::IdentityProviderConfig::Oidc(_) => SsoProviderType::Oidc,
    });
```

Add a small helper next to the existing route handlers — this constructs the exact callback URL this organization's subdomain resolves to, which must match what's registered with the identity provider byte-for-byte (OIDC redirect URIs are validated exactly by spec):

```rust
/// `https://<slug>.hangar.example/api/auth/sso/oidc/callback` (or `hangar.example` itself for
/// the public organization) — must match the `redirect_uri`/`callback_url` registered with the
/// identity provider exactly, so this is derived the same way the rest of this codebase derives
/// a subdomain, from `resolved_org`'s slug and `state.hangar_base_domain`, not from any header
/// the caller could influence for the login-initiation request.
fn oidc_callback_url(state: &AppState, resolved_org: &ResolvedOrganization) -> String {
    let host = if resolved_org.0.is_public { state.hangar_base_domain.clone() } else { format!("{}.{}", resolved_org.0.slug.as_str(), state.hangar_base_domain) };
    format!("{}://{}/api/auth/sso/oidc/callback", if state.hangar_base_domain.starts_with("localhost") { "http" } else { "https" }, host)
}
```

(Check `state.rs` for the exact field name holding the base domain string — the LDAP plan's routes reference `resolved_org.0.id`/`resolved_org.0.slug` and the organization middleware reads `state.hangar_base_domain`; confirm this exact name before using it, and adjust the localhost/https heuristic if this codebase already has an established way to decide the request scheme elsewhere — check `crates/hangar-api/src/organization_middleware.rs` and `crates/hangar-api/src/config.rs` for precedent rather than inventing a new convention.)

Add the two handlers:

```rust
/// Unauthenticated — starts the OIDC Authorization Code flow by redirecting the browser to
/// the identity provider. 400 if this organization has no OIDC provider configured (including
/// if it has LDAP configured instead — the two are mutually exclusive per organization).
async fn sso_oidc_login(State(state): State<AppState>, resolved_org: ResolvedOrganization) -> Result<axum::response::Redirect, (StatusCode, Json<ErrorResponse>)> {
    let config = state
        .identity_providers
        .get(resolved_org.0.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    let Some(hangar_domain::sso::IdentityProviderConfig::Oidc(oidc_config)) = config else {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "this organization has no OIDC identity provider configured".to_string() })));
    };

    let callback_url = oidc_callback_url(&state, &resolved_org);
    let redirect_url = state
        .oidc_auth
        .build_redirect(&oidc_config, resolved_org.0.id, &callback_url)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "failed to start oidc login".to_string() })))?;
    Ok(axum::response::Redirect::to(&redirect_url))
}

#[derive(Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

/// Unauthenticated — the identity provider redirects the browser here after the user
/// authenticates. On success, redirects the browser back to the SPA with the session token
/// in the URL FRAGMENT (`#token=...`), never a query parameter — fragments are never sent to
/// any server on the follow-up request and never appear in server access logs.
async fn sso_oidc_callback(
    State(state): State<AppState>,
    resolved_org: ResolvedOrganization,
    axum::extract::Query(query): axum::extract::Query<OidcCallbackQuery>,
) -> Result<axum::response::Redirect, (StatusCode, Json<ErrorResponse>)> {
    let (Some(code), Some(raw_state)) = (query.code, query.state) else {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "missing code or state".to_string() })));
    };

    let config = state
        .identity_providers
        .get(resolved_org.0.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    let Some(hangar_domain::sso::IdentityProviderConfig::Oidc(oidc_config)) = config else {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "this organization has no OIDC identity provider configured".to_string() })));
    };

    let callback_url = oidc_callback_url(&state, &resolved_org);
    let identity = state
        .oidc_auth
        .handle_callback(&oidc_config, &code, &raw_state, &callback_url, resolved_org.0.id)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid credentials".to_string() })))?;

    let token = state
        .provision_sso_user
        .execute(resolved_org.0.id, &identity)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid credentials".to_string() })))?;

    Ok(axum::response::Redirect::to(&format!("{}/login#token={}", state.config.public_url, token)))
}
```

Note: the LDAP plan's own `sso_ldap_login` route maps `provision_sso_user.execute`'s errors with a `match` that distinguishes `ApplicationError::InvalidCredentials` (→ 401) from everything else (→ `application_error_response`, e.g. 500 for a real infrastructure failure) — this was a Critical-severity fix from that plan's own final review, closing a gap where a blocked account reuse (wrong organization, or an existing admin account) needs to be indistinguishable from a wrong password. Mirror that exact `match` pattern here instead of the bare `.map_err(|_| 401)` sketched above — read `sso_ldap_login`'s current code in this same file first and copy its error-mapping approach precisely, since this callback route reuses the identical `provision_sso_user.execute` call and must preserve the identical security property.

Also double-check `state.config.public_url` is the right field path — confirm by reading how `InviteUserUseCase`/other code in this codebase already references the configured public URL (the LDAP plan's own summary of `Config` mentions a `public_url: String` field; confirm whether it's reached via `state.config.public_url` or a differently-named field on `AppState` itself before using it verbatim).

- [ ] **Step 5: Run to verify the tests pass**

Run: `cargo test -p hangar-api routes::auth:: -- --nocapture 2>&1 | tail -80`
Expected: PASS, including all pre-existing `auth.rs` tests (LDAP and earlier, no regressions) and the 5 new ones.

- [ ] **Step 6: Regenerate the sqlx offline cache**

This task introduces no new SQL query text of its own. Run `cargo sqlx prepare --workspace -- --all-targets` anyway and confirm `.sqlx/` shows no diff.

- [ ] **Step 7: Commit**

```bash
git add crates/hangar-api/src/dto.rs crates/hangar-api/src/routes/auth.rs
git commit -m "feat: add GET /api/auth/sso/oidc/login and /callback"
```

---

### Task 6: Extend organization identity-provider routes to a `type`-tagged shape

**Files:**
- Modify: `crates/hangar-api/src/routes/organizations.rs`

**Interfaces:**
- Produces: `GET`/`PUT /api/organizations/:id/identity-provider` now accept/return a `type`-discriminated shape covering both `"ldap"` and `"oidc"`. This is a breaking change to the LDAP-only shape the LDAP plan shipped — Task 8's frontend adapter is updated in the same plan to match.

- [ ] **Step 1: Write the failing tests**

This task REPLACES two existing tests in this file (`a_super_admin_can_configure_ldap_for_any_organization` and `getting_an_unconfigured_organizations_identity_provider_returns_no_type`, both from the LDAP plan) because the request body shape they assert against is changing, and ADDS new OIDC-equivalent tests. Read the file's current test module first (already read during this plan's own authoring — its full content is quoted in this plan's own reconnaissance) to see exactly where these tests sit, then:

Replace the LDAP `PUT` request body in `a_super_admin_can_configure_ldap_for_any_organization` from:
```json
{"server_url":"ldap://dc.corp.example:389","bind_dn":"cn=service,dc=corp,dc=example","bind_password":"s3cret!","user_search_base":"ou=people,dc=corp,dc=example","user_search_filter":"(uid={username})","email_attribute":"mail"}
```
to (adding the `"type":"ldap"` discriminator, otherwise identical):
```json
{"type":"ldap","server_url":"ldap://dc.corp.example:389","bind_dn":"cn=service,dc=corp,dc=example","bind_password":"s3cret!","user_search_base":"ou=people,dc=corp,dc=example","user_search_filter":"(uid={username})","email_attribute":"mail"}
```

Make the identical one-field addition to the request body in `a_non_admin_cannot_configure_ldap`'s test (it must still 403 regardless of body shape, but keep the body realistic).

Add new tests, next to the existing LDAP ones:

```rust
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_configure_oidc_for_any_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"type":"oidc","issuer_url":"https://accounts.example.com","client_id":"hangar","client_secret":"s3cret!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let get_response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(get_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["type"], "oidc");
        assert_eq!(json["issuer_url"], "https://accounts.example.com");
        assert_eq!(json["client_secret_set"], true);
        assert!(json.get("client_secret").is_none(), "the secret must never be echoed back");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn configuring_oidc_replaces_an_existing_ldap_configuration(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        state
            .identity_providers
            .set(
                public_org.id,
                &hangar_domain::sso::IdentityProviderConfig::Ldap(hangar_domain::sso::LdapConfig {
                    server_url: "ldap://dc.corp.example:389".to_string(),
                    bind_dn: "cn=service,dc=corp,dc=example".to_string(),
                    bind_password: "s3cret!".to_string(),
                    user_search_base: "ou=people,dc=corp,dc=example".to_string(),
                    user_search_filter: "(uid={username})".to_string(),
                    email_attribute: "mail".to_string(),
                }),
            )
            .await
            .unwrap();
        let app = crate::build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"type":"oidc","issuer_url":"https://accounts.example.com","client_id":"hangar","client_secret":"s3cret!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let stored = state.identity_providers.get(public_org.id).await.unwrap();
        assert!(matches!(stored, Some(hangar_domain::sso::IdentityProviderConfig::Oidc(_))), "the old LDAP config must be fully replaced, not merged");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn configuring_oidc_without_a_client_secret_on_first_setup_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"type":"oidc","issuer_url":"https://accounts.example.com","client_id":"hangar"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hangar-api routes::organizations:: 2>&1 | tail -40`
Expected: FAIL — the modified LDAP tests now send a `"type"` field the current handler doesn't expect (it should still pass today since `SetLdapConfigRequest` likely has no `#[serde(deny_unknown_fields)]`, so check whether Step 1's edit alone actually fails anything yet — the NEW oidc tests are what will fail to compile/behave, since `type: "oidc"` currently deserializes into the LDAP-only struct and fails required-field validation). Confirm the new tests fail with a clear body-shape error before proceeding.

- [ ] **Step 3: Implement**

Replace `IdentityProviderResponse` and `SetLdapConfigRequest` (and the `get_identity_provider`/`set_identity_provider` handlers) with type-discriminated versions. Note on the response shape: `#[serde(tag = "type")]` on an enum requires the tag field to always hold one of the variant's own string values, so it can't by itself also represent "no provider configured" as `{"type": null}` — rather than fight that with a flatten-over-`Option` wrapper (a real serde interaction with known edge cases for internally-tagged enums in some versions, not worth the risk here), this handler builds the response as a plain `serde_json::Value` directly, matching the exact `{"type": null}` / `{"type": "ldap", ...}` / `{"type": "oidc", ...}` shapes the frontend already expects:

```rust
async fn get_identity_provider(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let config = state.identity_providers.get(id).await.map_err(|e| application_error_response("failed to get identity provider", e.into()))?;
    let body = match config {
        None => serde_json::json!({ "type": null }),
        Some(hangar_domain::sso::IdentityProviderConfig::Ldap(ldap)) => serde_json::json!({
            "type": "ldap",
            "server_url": ldap.server_url,
            "bind_dn": ldap.bind_dn,
            "bind_password_set": true,
            "user_search_base": ldap.user_search_base,
            "user_search_filter": ldap.user_search_filter,
            "email_attribute": ldap.email_attribute,
        }),
        Some(hangar_domain::sso::IdentityProviderConfig::Oidc(oidc)) => serde_json::json!({
            "type": "oidc",
            "issuer_url": oidc.issuer_url,
            "client_id": oidc.client_id,
            "client_secret_set": true,
        }),
    };
    Ok(Json(body))
}
```

This also fully replaces the LDAP plan's own `IdentityProviderResponse` struct and its `::none()` associated function — delete both, they're superseded by the `serde_json::Value` approach above.

```rust
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SetIdentityProviderRequest {
    Ldap {
        server_url: String,
        bind_dn: String,
        #[serde(default)]
        bind_password: Option<String>,
        user_search_base: String,
        user_search_filter: String,
        email_attribute: String,
    },
    Oidc {
        issuer_url: String,
        client_id: String,
        #[serde(default)]
        client_secret: Option<String>,
    },
}

async fn set_identity_provider(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<SetIdentityProviderRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;

    let config = match body {
        SetIdentityProviderRequest::Ldap { server_url, bind_dn, bind_password, user_search_base, user_search_filter, email_attribute } => {
            let bind_password = match bind_password {
                Some(password) if !password.trim().is_empty() => password,
                _ => {
                    let existing = state.identity_providers.get(id).await.map_err(|e| application_error_response("failed to load existing identity provider", e.into()))?;
                    match existing {
                        Some(hangar_domain::sso::IdentityProviderConfig::Ldap(ldap)) => ldap.bind_password,
                        _ => return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "bind_password is required when configuring LDAP for the first time".to_string() }))),
                    }
                }
            };
            if server_url.trim().is_empty() || bind_dn.trim().is_empty() || user_search_base.trim().is_empty() || user_search_filter.trim().is_empty() || email_attribute.trim().is_empty() {
                return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "all LDAP fields except bind_password (when updating) are required".to_string() })));
            }
            hangar_domain::sso::IdentityProviderConfig::Ldap(hangar_domain::sso::LdapConfig { server_url, bind_dn, bind_password, user_search_base, user_search_filter, email_attribute })
        }
        SetIdentityProviderRequest::Oidc { issuer_url, client_id, client_secret } => {
            let client_secret = match client_secret {
                Some(secret) if !secret.trim().is_empty() => secret,
                _ => {
                    let existing = state.identity_providers.get(id).await.map_err(|e| application_error_response("failed to load existing identity provider", e.into()))?;
                    match existing {
                        Some(hangar_domain::sso::IdentityProviderConfig::Oidc(oidc)) => oidc.client_secret,
                        _ => return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "client_secret is required when configuring OIDC for the first time".to_string() }))),
                    }
                }
            };
            if issuer_url.trim().is_empty() || client_id.trim().is_empty() {
                return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "issuer_url and client_id are required".to_string() })));
            }
            hangar_domain::sso::IdentityProviderConfig::Oidc(hangar_domain::sso::OidcConfig { issuer_url, client_id, client_secret })
        }
    };
    state.identity_providers.set(id, &config).await.map_err(|e| application_error_response("failed to set identity provider", e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}
```

Note the "keep existing secret when switching a config's own fields but not its type" logic only looks at the EXISTING config if it's the SAME type being submitted (`Some(Ldap(_))` when submitting `Ldap`, `Some(Oidc(_))` when submitting `Oidc`) — switching FROM one type TO the other always requires the new type's secret (`_ => return Err(...)` correctly covers both "nothing configured yet" and "something of the other type is configured" in one arm).

- [ ] **Step 4: Run to verify the tests pass**

Run: `cargo test -p hangar-api routes::organizations:: -- --nocapture 2>&1 | tail -80`
Expected: PASS — the modified LDAP tests (now sending `"type":"ldap"`) and all new OIDC tests.

- [ ] **Step 5: Regenerate the sqlx offline cache**

No new SQL query text — confirm `.sqlx/` shows no diff after `cargo sqlx prepare --workspace -- --all-targets`.

- [ ] **Step 6: Commit**

```bash
git add crates/hangar-api/src/routes/organizations.rs
git commit -m "feat: support OIDC in organization identity-provider routes, type-tag the request/response shape"
```

---

### Task 7: Frontend — extend `organizations` port/service/adapter for OIDC

**Files:**
- Modify: `frontend/src/app/admin/domain/organization.entity.ts`
- Modify: `frontend/src/app/admin/application/organizations.port.ts`
- Modify: `frontend/src/app/admin/application/organizations.service.ts`
- Modify: `frontend/src/app/admin/infrastructure/http-organizations.adapter.ts`
- Modify: `frontend/src/app/admin/infrastructure/http-organizations.adapter.spec.ts`

**Interfaces:**
- Produces: `OidcIdentityProvider` type; `IdentityProviderSummary` widened to a 3-way union (`LdapIdentityProvider | OidcIdentityProvider | NoIdentityProvider`); `OrganizationsService.setOidcIdentityProvider(id, config)`; `HttpOrganizationsAdapter.setLdapIdentityProvider`'s request body updated to include `type: 'ldap'` (this task's one breaking-but-contained frontend change, matching Task 6's backend reshape) — Task 8's `OrganizationDetail` consumes all of this.

- [ ] **Step 1: Domain entity changes**

In `frontend/src/app/admin/domain/organization.entity.ts`, widen the union and add the OIDC shapes:

```typescript
export interface LdapIdentityProvider {
  type: 'ldap'
  server_url: string
  bind_dn: string
  bind_password_set: boolean
  user_search_base: string
  user_search_filter: string
  email_attribute: string
}

export interface OidcIdentityProvider {
  type: 'oidc'
  issuer_url: string
  client_id: string
  client_secret_set: boolean
}

export interface NoIdentityProvider {
  type: null
}

export type IdentityProviderSummary = LdapIdentityProvider | OidcIdentityProvider | NoIdentityProvider

export interface LdapIdentityProviderInput {
  server_url: string
  bind_dn: string
  /** Omit (or empty string) to keep the existing password when updating. */
  bind_password?: string
  user_search_base: string
  user_search_filter: string
  email_attribute: string
}

export interface OidcIdentityProviderInput {
  issuer_url: string
  client_id: string
  /** Omit (or empty string) to keep the existing secret when updating. */
  client_secret?: string
}
```

(`OrganizationSummary` is unchanged — leave it as-is.)

- [ ] **Step 2: Port**

In `frontend/src/app/admin/application/organizations.port.ts`, add to `OrganizationsPort`:

```typescript
  setOidcIdentityProvider(id: string, config: OidcIdentityProviderInput): Observable<void>
```

(add `OidcIdentityProviderInput` to the existing import from `'../domain/organization.entity'`).

- [ ] **Step 3: Write the failing test**

Add to `frontend/src/app/admin/infrastructure/http-organizations.adapter.spec.ts`:

```typescript
  it('puts an OIDC config with the type discriminator to /api/organizations/:id/identity-provider', () => {
    const { adapter, httpMock } = setup()
    const config = { issuer_url: 'https://accounts.example.com', client_id: 'hangar', client_secret: 's3cret!' }
    adapter.setOidcIdentityProvider('org-1', config).subscribe()
    const req = httpMock.expectOne('/api/organizations/org-1/identity-provider')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({ type: 'oidc', ...config })
    req.flush(null)
    httpMock.verify()
  })
```

Update the EXISTING test `'puts the LDAP config to /api/organizations/:id/identity-provider'` in this same file to expect the `type: 'ldap'` discriminator in the request body (matching Task 6's backend reshape):

```typescript
  it('puts the LDAP config to /api/organizations/:id/identity-provider', () => {
    const { adapter, httpMock } = setup()
    const config = {
      server_url: 'ldap://dc.corp.example:389',
      bind_dn: 'cn=service,dc=corp,dc=example',
      user_search_base: 'ou=people,dc=corp,dc=example',
      user_search_filter: '(uid={username})',
      email_attribute: 'mail',
    }
    adapter.setLdapIdentityProvider('org-1', config).subscribe()
    const req = httpMock.expectOne('/api/organizations/org-1/identity-provider')
    expect(req.request.method).toBe('PUT')
    expect(req.request.body).toEqual({ type: 'ldap', ...config })
    req.flush(null)
    httpMock.verify()
  })
```

- [ ] **Step 4: Run to verify they fail**

Run: `cd frontend && npx ng test --watch=false --include='**/http-organizations.adapter.spec.ts'`
Expected: FAIL — the existing LDAP test now expects a `type` field the adapter doesn't send yet, and `setOidcIdentityProvider` doesn't exist.

- [ ] **Step 5: Implement**

In `frontend/src/app/admin/infrastructure/http-organizations.adapter.ts`, update `setLdapIdentityProvider` to include the discriminator, and add `setOidcIdentityProvider`:

```typescript
  setLdapIdentityProvider(id: string, config: LdapIdentityProviderInput): Observable<void> {
    return this.http.put<void>(`/api/organizations/${id}/identity-provider`, { type: 'ldap', ...config })
  }

  setOidcIdentityProvider(id: string, config: OidcIdentityProviderInput): Observable<void> {
    return this.http.put<void>(`/api/organizations/${id}/identity-provider`, { type: 'oidc', ...config })
  }
```

(add `OidcIdentityProviderInput` to this file's existing import from `'../domain/organization.entity'`).

- [ ] **Step 6: Run to verify the tests pass**

Run: `cd frontend && npx ng test --watch=false --include='**/http-organizations.adapter.spec.ts'`
Expected: PASS.

- [ ] **Step 7: Service**

In `frontend/src/app/admin/application/organizations.service.ts`, add (mirroring `setLdapIdentityProvider`'s exact shape):

```typescript
  setOidcIdentityProvider(id: string, config: OidcIdentityProviderInput): Observable<void> {
    return this.port.setOidcIdentityProvider(id, config).pipe(tap(() => (this.cachedList$ = null)))
  }
```

(add `OidcIdentityProviderInput` to this file's existing import from `'../domain/organization.entity'`).

- [ ] **Step 8: Run the full frontend suite**

Run: `cd frontend && npx ng test --watch=false`
Expected: PASS, no regressions (this task's LDAP-request-shape change means `organization-detail.spec.ts` — from the LDAP plan — may now fail if it asserted on the exact old request body without the `type` field; if so, that's Task 8's job to fix, not this task's — note it in this task's report as a known follow-up for Task 8 rather than fixing it here, since `organization-detail.ts` itself doesn't change in this task).

- [ ] **Step 9: Commit**

```bash
git add frontend/src/app/admin/domain/organization.entity.ts frontend/src/app/admin/application/organizations.port.ts frontend/src/app/admin/application/organizations.service.ts frontend/src/app/admin/infrastructure/http-organizations.adapter.ts frontend/src/app/admin/infrastructure/http-organizations.adapter.spec.ts
git commit -m "feat(frontend): add OIDC support to organizations port/service/adapter"
```

---

### Task 8: `OrganizationDetail` — provider-type selector and OIDC form

**Files:**
- Modify: `frontend/src/app/admin/organization-detail/organization-detail.ts`
- Modify: `frontend/src/app/admin/organization-detail/organization-detail.html`
- Modify: `frontend/src/app/admin/organization-detail/organization-detail.spec.ts`

**Interfaces:**
- Consumes: `OrganizationsService.setOidcIdentityProvider` (Task 7); the widened `IdentityProviderSummary` union (Task 7).
- Produces: the same component, now supporting all three states (none / LDAP / OIDC) with a way to switch between LDAP and OIDC configuration forms.

This task's own scope is naturally larger than a typical "add one field" task because it introduces a real UI decision: how does an admin pick "LDAP" vs "OIDC" before filling in either form? Use a simple radio-button-style choice (`gbt-input` doesn't have a native radio group in this design system based on what's used elsewhere in this codebase — check `@masmarino/gabarit`'s actual exports; if a `Select`/`RadioGroup`-equivalent exists, use it, mirroring `smtp-settings.ts`'s use of `Select` for its security-mode choice; otherwise, two `gbt-button` toggle-style controls are an acceptable fallback, matching this codebase's existing tolerance for simple UI over building new design-system primitives).

- [ ] **Step 1: Write the failing tests**

This task both fixes the request-body assertion Task 7 flagged as a known follow-up AND adds new OIDC-specific test coverage. Read `organization-detail.spec.ts`'s current content first (it exists from the LDAP plan) and:

1. Update the existing `'saves the LDAP configuration'` test's expected `setLdapIdentityProvider` call — it currently doesn't need changing at the TEST level (the test only checks what `component.save()` passes to the SERVICE method, and the service method's own signature is unchanged — only the ADAPTER adds the `type` field, one layer below what this component talks to) — confirm this is genuinely unaffected before assuming a change is needed; if the existing test already only asserts against `OrganizationsService.setLdapIdentityProvider`'s call arguments (not raw HTTP), it needs no change here.

2. Add new tests (translate to this project's actual Vitest convention if the file's existing tests use `jasmine.createSpyObj`-descended-from-earlier-in-this-session syntax — check the file's current style first and match it, following the same translation discipline already established across this session for `mfa-enrollment.spec.ts`/`register-page.spec.ts`):

```typescript
  it('shows the OIDC form fields when OIDC is selected as the provider type', () => {
    setup()
    component.selectedProviderType.set('oidc')
    fixture.detectChanges()

    expect(component.selectedProviderType()).toBe('oidc')
  })

  it('reflects an existing OIDC configuration', () => {
    // mirror this file's existing 'reflects an existing LDAP configuration' test's setup
    // pattern exactly, but with organizationsServiceSpy.getIdentityProvider returning
    // { type: 'oidc', issuer_url: 'https://accounts.example.com', client_id: 'hangar', client_secret_set: true }
    // and asserting component.issuerUrl() === 'https://accounts.example.com',
    // component.clientId() === 'hangar', component.clientSecretSet() === true
  })

  it('saves the OIDC configuration', () => {
    setup()
    organizationsServiceSpy.setOidcIdentityProvider.and.returnValue(of(undefined)) // or vi.fn().mockReturnValue depending on this file's established convention
    component.selectedProviderType.set('oidc')
    component.issuerUrl.set('https://accounts.example.com')
    component.clientId.set('hangar')
    component.clientSecret.set('s3cret!')

    component.save()

    expect(organizationsServiceSpy.setOidcIdentityProvider).toHaveBeenCalledWith('org-1', {
      issuer_url: 'https://accounts.example.com',
      client_id: 'hangar',
      client_secret: 's3cret!',
    })
  })
```

(Write the actual, complete test bodies during implementation — the sketches above describe the scenarios precisely enough to write real code from, following this file's own already-established patterns for mocking `OrganizationsService` and constructing the fixture, rather than being placeholders to leave as prose.)

- [ ] **Step 2: Run to verify they fail**

Run: `cd frontend && npx ng test --watch=false --include='**/organization-detail.spec.ts'`
Expected: FAIL — `selectedProviderType`, `issuerUrl`, `clientId`, `clientSecret`, `clientSecretSet` don't exist yet.

- [ ] **Step 3: Implement**

In `frontend/src/app/admin/organization-detail/organization-detail.ts`, add state for the provider-type choice and the OIDC fields, and extend `reload()`/`save()` to handle all three states:

```typescript
  readonly selectedProviderType = signal<'ldap' | 'oidc'>('ldap')

  readonly issuerUrl = signal('')
  readonly clientId = signal('')
  readonly clientSecret = signal('')
  readonly clientSecretSet = signal(false)
```

In `reload()`'s `getIdentityProvider` subscription, extend the existing `if (config.type === 'ldap') { ... } else { ... }` branch into a 3-way branch:

```typescript
      if (config.type === 'ldap') {
        this.identityProviderConfigured.set(true)
        this.selectedProviderType.set('ldap')
        this.serverUrl.set(config.server_url)
        this.bindDn.set(config.bind_dn)
        this.bindPasswordSet.set(config.bind_password_set)
        this.userSearchBase.set(config.user_search_base)
        this.userSearchFilter.set(config.user_search_filter)
        this.emailAttribute.set(config.email_attribute)
      } else if (config.type === 'oidc') {
        this.identityProviderConfigured.set(true)
        this.selectedProviderType.set('oidc')
        this.issuerUrl.set(config.issuer_url)
        this.clientId.set(config.client_id)
        this.clientSecretSet.set(config.client_secret_set)
      } else {
        this.identityProviderConfigured.set(false)
      }
```

Update `hasErrors` to validate whichever form is currently selected:

```typescript
  readonly hasErrors = computed(() => {
    if (this.selectedProviderType() === 'oidc') {
      return this.issuerUrl().trim() === '' || this.clientId().trim() === '' || (!this.clientSecretSet() && this.clientSecret().trim() === '')
    }
    return (
      this.serverUrl().trim() === '' ||
      this.bindDn().trim() === '' ||
      this.userSearchBase().trim() === '' ||
      this.userSearchFilter().trim() === '' ||
      this.emailAttribute().trim() === '' ||
      (!this.bindPasswordSet() && this.bindPassword().trim() === '')
    )
  })
```

Update `save()` to call the right service method for the selected type:

```typescript
  save(): void {
    this.saved.set(false)
    this.errorMessage.set(null)
    if (this.hasErrors()) {
      return
    }
    this.saving.set(true)
    const request$ =
      this.selectedProviderType() === 'oidc'
        ? this.organizationsService.setOidcIdentityProvider(this.organizationId, {
            issuer_url: this.issuerUrl(),
            client_id: this.clientId(),
            client_secret: this.clientSecret().trim() === '' ? undefined : this.clientSecret(),
          })
        : this.organizationsService.setLdapIdentityProvider(this.organizationId, {
            server_url: this.serverUrl(),
            bind_dn: this.bindDn(),
            bind_password: this.bindPassword().trim() === '' ? undefined : this.bindPassword(),
            user_search_base: this.userSearchBase(),
            user_search_filter: this.userSearchFilter(),
            email_attribute: this.emailAttribute(),
          })
    request$.subscribe({
      next: () => {
        this.saving.set(false)
        this.saved.set(true)
        this.identityProviderConfigured.set(true)
        if (this.selectedProviderType() === 'oidc') {
          this.clientSecretSet.set(true)
          this.clientSecret.set('')
        } else {
          this.bindPasswordSet.set(true)
          this.bindPassword.set('')
        }
      },
      error: () => {
        this.saving.set(false)
        this.errorMessage.set('Échec de la mise à jour de la configuration.')
      },
    })
  }
```

Update `clear()`'s success handler to also reset the new OIDC fields:

```typescript
      next: () => {
        this.clearing.set(false)
        this.identityProviderConfigured.set(false)
        this.serverUrl.set('')
        this.bindDn.set('')
        this.bindPasswordSet.set(false)
        this.userSearchBase.set('')
        this.userSearchFilter.set('')
        this.emailAttribute.set('')
        this.issuerUrl.set('')
        this.clientId.set('')
        this.clientSecretSet.set(false)
      },
```

Update the template (`organization-detail.html`) to add a provider-type choice above the existing LDAP fields, and show the OIDC fields instead when selected. Use whatever this design system's actual radio/toggle primitive is (check `@masmarino/gabarit`'s exports first); if none fits cleanly, two buttons work:

```html
    <div class="auth-layout__actions">
      <gbt-button text="LDAP" [variant]="selectedProviderType() === 'ldap' ? 'primary' : 'secondary'" (clicked)="selectedProviderType.set('ldap')" />
      <gbt-button text="OIDC" [variant]="selectedProviderType() === 'oidc' ? 'primary' : 'secondary'" (clicked)="selectedProviderType.set('oidc')" />
    </div>

    @if (selectedProviderType() === 'ldap') {
      <gbt-input label="URL du serveur" [ngModel]="serverUrl()" (ngModelChange)="serverUrl.set($event)" placeholder="ldaps://dc.corp.example:636" />
      <gbt-input label="DN du compte de service" [ngModel]="bindDn()" (ngModelChange)="bindDn.set($event)" placeholder="cn=service,dc=corp,dc=example" />
      <gbt-input
        label="Mot de passe du compte de service"
        type="password"
        [ngModel]="bindPassword()"
        (ngModelChange)="bindPassword.set($event)"
        [placeholder]="bindPasswordSet() ? 'Laisser vide pour conserver le mot de passe actuel' : ''"
        showPasswordLabel="Afficher le mot de passe"
        hidePasswordLabel="Masquer le mot de passe"
      />
      <gbt-input label="Base de recherche" [ngModel]="userSearchBase()" (ngModelChange)="userSearchBase.set($event)" placeholder="ou=people,dc=corp,dc=example" />
      <gbt-input label="Filtre de recherche" [ngModel]="userSearchFilter()" (ngModelChange)="userSearchFilter.set($event)" placeholder="(uid={{ '{' }}username{{ '}' }})" />
      <gbt-input label="Attribut e-mail" [ngModel]="emailAttribute()" (ngModelChange)="emailAttribute.set($event)" placeholder="mail" />
    } @else {
      <gbt-input label="URL de l'émetteur (issuer)" [ngModel]="issuerUrl()" (ngModelChange)="issuerUrl.set($event)" placeholder="https://accounts.example.com" />
      <gbt-input label="Client ID" [ngModel]="clientId()" (ngModelChange)="clientId.set($event)" placeholder="hangar" />
      <gbt-input
        label="Client secret"
        type="password"
        [ngModel]="clientSecret()"
        (ngModelChange)="clientSecret.set($event)"
        [placeholder]="clientSecretSet() ? 'Laisser vide pour conserver le secret actuel' : ''"
        showPasswordLabel="Afficher le secret"
        hidePasswordLabel="Masquer le secret"
      />
    }
```

(Replace the existing bare LDAP `<gbt-input>` block in the current template with this `@if`/`@else` version — the LDAP fields' markup itself is unchanged, just now conditionally shown.)

- [ ] **Step 4: Run to verify the tests pass**

Run: `cd frontend && npx ng test --watch=false --include='**/organization-detail.spec.ts'`
Expected: PASS.

- [ ] **Step 5: Run the full frontend suite**

Run: `cd frontend && npx ng test --watch=false`
Expected: PASS, no regressions.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/app/admin/organization-detail/
git commit -m "feat(frontend): add OIDC provider-type selector and config form to OrganizationDetail"
```

---

### Task 9: Login page — OIDC redirect button and callback landing

**Files:**
- Modify: `frontend/src/app/auth/domain/auth.types.ts`
- Modify: `frontend/src/app/auth/application/auth.service.ts`
- Modify: `frontend/src/app/auth/application/auth.service.spec.ts`
- Modify: `frontend/src/app/auth/login-page/login-page.ts`
- Modify: `frontend/src/app/auth/login-page/login-page.html`
- Modify: `frontend/src/app/auth/login-page/login-page.spec.ts`

**Interfaces:**
- Produces: `SsoConfig.type` widened to `'ldap' | 'oidc' | null`; `AuthService.completeExternalLogin(token: string): void` (a new public wrapper around the existing private `setToken`, needed because the OIDC flow's token arrives via URL fragment, not an HTTP response body `AuthService` itself received); `LoginPage` shows a plain redirect link instead of the username/password form when `usesLdap()`-equivalent reports `'oidc'`, and checks `window.location.hash` on init for a completed OIDC round trip.

- [ ] **Step 1: Widen `SsoConfig`**

In `frontend/src/app/auth/domain/auth.types.ts`, change:

```typescript
export interface SsoConfig {
  type: 'ldap' | 'oidc' | null
}
```

- [ ] **Step 2: Add `AuthService.completeExternalLogin`**

In `frontend/src/app/auth/application/auth.service.ts`, add a public method next to the existing `logout()`:

```typescript
  /** For a login flow that completes outside this service's own HTTP calls (the OIDC
   * redirect round trip) — the token arrives via a URL fragment the login page reads
   * itself, not an HTTP response body this service received. */
  completeExternalLogin(token: string): void {
    this.setToken(token)
  }
```

- [ ] **Step 3: Write the failing test**

Add to `frontend/src/app/auth/application/auth.service.spec.ts`:

```typescript
  it('stores a token obtained externally (the OIDC redirect flow)', () => {
    const service = setup({})

    service.completeExternalLogin('a-jwt-token')

    expect(service.token()).toBe('a-jwt-token')
    expect(service.isAuthenticated()).toBe(true)
  })
```

- [ ] **Step 4: Run to verify it fails, then confirm it passes**

Run: `cd frontend && npx ng test --watch=false --include='**/auth.service.spec.ts'`

- [ ] **Step 5: Update `LoginPage`**

Change the `usesLdap` signal to a more general `ssoType` signal, and derive the two boolean cases from it (renaming preserves no external contract — this component's own signals aren't consumed elsewhere):

```typescript
  readonly ssoType = signal<'ldap' | 'oidc' | null>(null)
```

Update `ngOnInit` to also check for a completed OIDC round trip via the URL fragment, before (or alongside) the existing SSO-config check:

```typescript
  ngOnInit(): void {
    const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''))
    const token = hashParams.get('token')
    if (token) {
      this.auth.completeExternalLogin(token)
      // Clear the fragment so the token never lingers in browser history/bookmarks.
      history.replaceState(null, '', window.location.pathname + window.location.search)
      this.router.navigateByUrl('/')
      return
    }

    this.auth.getSsoConfig().subscribe({
      next: (config) => this.ssoType.set(config.type),
      // Local login is always a safe fallback — never block the form on this check failing.
      error: () => this.ssoType.set(null),
    })
  }
```

Update `submit()`'s branch condition from `this.usesLdap()` to `this.ssoType() === 'ldap'`:

```typescript
    const attempt = this.ssoType() === 'ldap' ? this.auth.loginWithLdap(username, password) : this.auth.login(username, password)
```

- [ ] **Step 6: Update the template**

In `login-page.html`, the existing `@if (!mfaToken())` branch currently always shows the username/password form. Wrap it so an OIDC-configured organization instead shows a plain redirect link:

```html
    @if (!mfaToken()) {
      @if (ssoType() === 'oidc') {
        <p>Cette organisation utilise l'authentification unique (OIDC).</p>
        <a href="/api/auth/sso/oidc/login" class="auth-layout__link">Se connecter avec le fournisseur d'identité</a>
      } @else {
        <form [formGroup]="form" (ngSubmit)="submit()">
          <!-- ... existing form markup, unchanged ... -->
        </form>
        <a routerLink="/register" class="auth-layout__link">Créer un compte</a>
      }
    } @else if (mfaSetupRequired()) {
```

(The `<a href="/api/auth/sso/oidc/login">` is a plain HTML anchor, not a `routerLink` — this must be a full browser navigation to a backend route, not client-side Angular routing, since the backend needs to issue an actual HTTP redirect to the identity provider.)

- [ ] **Step 7: Update `login-page.spec.ts`**

The existing tests reference `component.usesLdap` — rename every occurrence to `component.ssoType` and update assertions from a boolean (`true`/`false`) to the string/null values (`'ldap'`/`null`). Add one new test:

```typescript
  it('shows the OIDC redirect link when the organization uses OIDC', () => {
    // mirror this file's existing LDAP-detection test setup, but with getSsoConfig
    // resolving { type: 'oidc' }, and assert the rendered template contains the
    // OIDC redirect anchor rather than the username/password form — follow this
    // file's existing convention for querying rendered template content
    // (e.g. fixture.nativeElement.querySelector or DebugElement, whichever this
    // file already uses elsewhere)
  })
```

(Write the complete test during implementation, following the exact rendering-assertion pattern this spec file already uses elsewhere — the LDAP-detection test this mirrors is already in this file from the LDAP plan.)

- [ ] **Step 8: Run to verify it passes**

Run: `cd frontend && npx ng test --watch=false --include='**/login-page.spec.ts'`

- [ ] **Step 9: Run the full frontend suite**

Run: `cd frontend && npx ng test --watch=false`
Expected: PASS, no regressions — in particular, every pre-existing test that calls `submit()` without configuring `getSsoConfig()` must still exercise the local-login path (since `ssoType()` defaults to `null`, and `submit()`'s branch condition `=== 'ldap'` is false for both `null` and `'oidc'`, correctly falling through to local `login()` — the only NEW branch is the template's OIDC redirect link, gated on `ssoType() === 'oidc'` specifically, which no pre-existing test triggers).

- [ ] **Step 10: Commit**

```bash
git add frontend/src/app/auth/domain/auth.types.ts frontend/src/app/auth/application/auth.service.ts frontend/src/app/auth/application/auth.service.spec.ts frontend/src/app/auth/login-page/login-page.ts frontend/src/app/auth/login-page/login-page.html frontend/src/app/auth/login-page/login-page.spec.ts
git commit -m "feat(frontend): show an OIDC redirect link on the login page and complete the token-fragment round trip"
```

---

### Task 10: Full-workspace verification

**Files:** none (verification only).

**Interfaces:** none.

- [ ] **Step 1: Run the full Rust test suite**

Run: `cargo test --workspace 2>&1 | tail -60`
Expected: PASS. Baseline before this plan: 743 passing.

- [ ] **Step 2: Run the full frontend test suite and lint**

Run:
```bash
cd frontend && npx ng test --watch=false && npx ng lint
```
Expected: PASS. `ng lint` should show only the same 6 pre-existing, unrelated `no-empty-function` errors already tracked across this session's prior two plans — nothing new from this plan's files.

- [ ] **Step 3: Confirm the sqlx offline cache is committed and current**

Run: `SQLX_OFFLINE=true cargo build --workspace 2>&1 | tail -30`
Expected: builds successfully against the committed `.sqlx/` cache with no live database connection.

- [ ] **Step 4: Commit if Step 3 regenerated anything**

Run `git status --porcelain .sqlx/` first. If it prints nothing, skip this step. Otherwise:

```bash
git add .sqlx/
git commit -m "chore: regenerate sqlx offline cache"
```

- [ ] **Step 5: Flag the deferred manual OIDC integration check**

This plan's Task 3 explicitly deferred verifying the discovery/exchange/ID-token-validation flow against a real identity provider (no such provider is available in this environment), and its `handle_callback` implementation carries a lower-confidence sketch for the ID-token validation calls specifically (see that task's own note) that may have needed a small adjustment against the real crate API during implementation. Note the outcome clearly in the final report so the controller — or the human reviewing before merge — can decide whether to stand up a test identity provider (a local Keycloak realm is the most common free option) and manually exercise the full `GET /api/auth/sso/oidc/login` → provider login → `GET /api/auth/sso/oidc/callback` → landing-on-`/login`-with-a-working-session round trip before this feature reaches production use, the same way the LDAP plan flagged its own equivalent deferred check.

# SSO — LDAP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an organization authenticate its members against an LDAP directory instead of local Hangar accounts, with just-in-time (JIT) account provisioning on first successful bind, plus a minimal super-admin UI to configure it — the first of three SSO protocols on the roadmap (LDAP → SAML → OIDC), establishing the shared model (`IdentityProviderConfig` storage, JIT provisioning, org identity-provider admin routes) the other two will reuse.

**Architecture:** A new `organization_identity_providers` table (one row per org that has SSO configured, mirroring the existing `branding_settings` table's per-org-singleton shape) stores a JSON-encoded `IdentityProviderConfig` with its one secret field (`bind_password`) encrypted via the existing `secret_box` helper (same mechanism as SMTP settings). A new `hangar-domain::sso` module defines `ExternalIdentity`, `IdentityProviderConfig`/`LdapConfig`, and two ports: `LdapAuthPort` (bind-search-rebind against a directory) and `IdentityProviderRepositoryPort` (persistence). `ProvisionSsoUserUseCase` finds-or-creates a member-role-only local `User` row keyed by email, then issues a real session token directly — no MFA-pending flow, since the IdP is the trust anchor for this account (mirrors this session's earlier design decision that SSO accounts skip Hangar's own MFA). The `hangar-infrastructure` crate gets a new `ldap3`-based adapter. Two new backend routes (`POST /api/auth/sso/ldap`, unauthenticated `GET /api/auth/sso/config`) plus four organization-admin routes (list, detail, configure, clear) round out the API. On the frontend, a new super-admin-only "Organisations" admin page lets a super-admin configure an org's LDAP settings, and the login page detects (via the new unauthenticated config endpoint) whether the resolved organization uses LDAP and posts to the SSO route instead of `/api/auth/login` when it does.

**Tech Stack:** Rust (axum, sqlx, `ldap3` for the directory protocol), Angular 18+ standalone components with signals, `@masmarino/gabarit` design system.

**Spec:** [docs/superpowers/specs/2026-09-04-hangar-organizations-sso-design.md](../specs/2026-09-04-hangar-organizations-sso-design.md) — "SSO — modèle commun" and "SSO — LDAP" sections.

## Global Constraints

- Once an organization has an `IdentityProviderConfig` configured, **local authentication for regular members of that organization is disabled** — only that organization's admin (always local) keeps password+MFA login. This plan does not need to enforce the disabling itself (no existing route currently lets a *member* of a non-public org log in locally without SSO being a factor either way, since Foundation didn't build per-org login differentiation) — but the new JIT-provisioned accounts this plan creates must never be usable via `/api/auth/login` with a guessable password, which is naturally true since they get no password at all (see Task 5).
- **JIT provisioning never grants elevated roles**: a JIT-provisioned account is always `is_organization_admin: false` and `is_super_admin: false`, regardless of any group/role claim the directory returns. This mirrors the exact same invariant already enforced for public self-registration.
- **The LDAP bind password (`bind_password`) is encrypted at rest**, using the exact same `secret_box::encrypt_packed`/`decrypt_packed` helpers already used for SMTP settings (`crates/hangar-infrastructure/src/secret_box.rs`) — no new encryption mechanism.
- **SSO login never goes through the MFA-pending flow.** `POST /api/auth/sso/ldap`'s success response is `LoginResponse { token: Some(...), mfa_token: None, mfa_setup_required: false }` — a full session token issued directly, unconditionally.
- **The LDAP configuration route is reserved to that organization's own admin or a super-admin** (`PUT`/`DELETE /api/organizations/:id/identity-provider`), following the exact same authorization shape already established for branding settings (`crates/hangar-api/src/routes/branding.rs`'s private `require_super_admin_or_own_org_admin` helper — this plan promotes it into a shared `authz.rs` helper since two routes now need it).
- **Scope decision (confirmed with the user):** the admin UI this plan builds is reachable only through the existing super-admin-only `adminGuard` — there is no org-admin self-service console yet (none exists for anything in this codebase today). The backend authorization is still spec-complete (org-admin-or-super-admin), so a future org-admin console can call these same routes without any backend change.
- **`ldap://` connections are supported for local/dev use, `ldaps://` for production** — the crate config is TLS-capable but this plan does not mandate TLS at the application level (that's an operator configuration choice, same as this codebase's existing remote-registry-proxy credentials, which also don't mandate HTTPS).

---

### Task 1: `UserRepositoryPort::find_by_email`

**Files:**
- Modify: `crates/hangar-domain/src/user.rs` (trait method)
- Modify: `crates/hangar-infrastructure/src/postgres/user_repository.rs` (real impl + test)
- Modify: `crates/hangar-application/src/use_cases/user.rs` (fake impl, test module)
- Modify: `crates/hangar-application/src/use_cases/invitation.rs` (fake impl, test module)
- Modify: `crates/hangar-application/src/use_cases/registration.rs` (fake impl, test module)
- Modify: `crates/hangar-application/src/use_cases/permission.rs` (fake impl)
- Modify: `crates/hangar-application/src/use_cases/mfa.rs` (fake impl)
- Modify: `crates/hangar-application/src/use_cases/docker_access_token.rs` (fake impl)
- Modify: `crates/hangar-application/src/use_cases/webauthn.rs` (fake impl)
- Modify: `crates/hangar-application/src/use_cases/admin.rs` (fake impl)

**Interfaces:**
- Produces: `UserRepositoryPort::find_by_email(&self, email: &str) -> Result<Option<User>, DomainError>` — Task 5's `ProvisionSsoUserUseCase` calls this exact signature to find-or-create by email.

This task is purely mechanical: one new trait method, one real implementation, and a matching one-line addition to every existing fake `UserRepositoryPort` implementor in this codebase (there is no shared fake — each test module keeps its own copy, per this codebase's established convention, confirmed by reading each file below).

- [ ] **Step 1: Add the trait method**

In `crates/hangar-domain/src/user.rs`, add to `UserRepositoryPort` (next to `find_by_username`):

```rust
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, DomainError>;
```

- [ ] **Step 2: Write the failing Postgres test**

In `crates/hangar-infrastructure/src/postgres/user_repository.rs`'s `#[cfg(test)] mod tests`, add:

```rust
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn finds_a_user_by_email(pool: sqlx::PgPool) {
        let repo = PostgresUserRepository::new(pool);
        let user = User {
            id: Uuid::new_v4(),
            username: Username::parse("florian").unwrap(),
            password_hash: "hash".to_string(),
            is_super_admin: false,
            is_organization_admin: false,
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            created_at: chrono::Utc::now(),
            email: Some("florian@example.com".to_string()),
        };
        repo.insert(&user).await.unwrap();

        let found = repo.find_by_email("florian@example.com").await.unwrap().unwrap();
        assert_eq!(found.id, user.id);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn finding_by_an_unknown_email_returns_none(pool: sqlx::PgPool) {
        let repo = PostgresUserRepository::new(pool);
        assert!(repo.find_by_email("nobody@example.com").await.unwrap().is_none());
    }
```

- [ ] **Step 2b: Run to verify it fails**

Run: `cargo test -p hangar-infrastructure finds_a_user_by_email 2>&1 | tail -20`
Expected: FAIL to compile — `find_by_email` doesn't exist on `PostgresUserRepository` yet.

- [ ] **Step 3: Implement the real Postgres method**

In `crates/hangar-infrastructure/src/postgres/user_repository.rs`, add (mirroring `find_by_username`'s exact shape — read that method first for the row-mapping helper it uses):

```rust
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, DomainError> {
        let row = sqlx::query_as!(
            UserRow,
            "SELECT id, username, password_hash, is_super_admin, is_organization_admin, organization_id, created_at, email FROM users WHERE email = $1",
            email,
        )
        .fetch_optional(&self.pool)
        .await
        .infra_err()?;
        row.map(UserRow::into_domain).transpose()
    }
```

(If this file's row-mapping type or helper is named differently than `UserRow`/`into_domain`, use whatever the existing `find_by_username` method actually calls — read it first and match its exact pattern rather than the names above.)

- [ ] **Step 4: Add the fake implementations**

Add this exact method to **every** fake `UserRepositoryPort` implementor below — each one already has a `users: Mutex<HashMap<Uuid, User>>` (or equivalently-named) field; mirror the existing `find_by_username`'s body shape (a `.values().find(...)`) in each file, changing only the predicate:

```rust
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, DomainError> {
        Ok(self.users.lock().unwrap().values().find(|u| u.email.as_deref() == Some(email)).cloned())
    }
```

Add it to the `impl UserRepositoryPort for Fake...` block in each of:
- `crates/hangar-application/src/use_cases/user.rs` (`FakeUserRepository`)
- `crates/hangar-application/src/use_cases/invitation.rs` (`FakeUsers`)
- `crates/hangar-application/src/use_cases/registration.rs` (`FakeUsers`)
- `crates/hangar-application/src/use_cases/permission.rs`
- `crates/hangar-application/src/use_cases/mfa.rs`
- `crates/hangar-application/src/use_cases/docker_access_token.rs`
- `crates/hangar-application/src/use_cases/webauthn.rs`
- `crates/hangar-application/src/use_cases/admin.rs`

For each file, first read its existing `impl UserRepositoryPort for ...` block to find the exact field name holding the `HashMap<Uuid, User>` (it may not be named `users` in every file) and the exact existing `find_by_username` body to mirror precisely.

- [ ] **Step 5: Run to verify everything compiles and the new tests pass**

Run: `cargo build --workspace 2>&1 | tail -40` — must compile with no errors (a missed fake implementor shows up here as a "not all trait items implemented" error, naming the exact file).
Run: `cargo test -p hangar-infrastructure finds_a_user_by_email finding_by_an_unknown_email_returns_none -- --nocapture`
Expected: both PASS.
Run: `cargo test --workspace 2>&1 | grep -E "^test result|FAILED"` — confirm no regressions anywhere (baseline: 703 passing, 0 failed).

- [ ] **Step 6: Commit**

```bash
git add crates/hangar-domain/src/user.rs crates/hangar-infrastructure/src/postgres/user_repository.rs crates/hangar-application/src/use_cases/user.rs crates/hangar-application/src/use_cases/invitation.rs crates/hangar-application/src/use_cases/registration.rs crates/hangar-application/src/use_cases/permission.rs crates/hangar-application/src/use_cases/mfa.rs crates/hangar-application/src/use_cases/docker_access_token.rs crates/hangar-application/src/use_cases/webauthn.rs crates/hangar-application/src/use_cases/admin.rs
git commit -m "feat: add UserRepositoryPort::find_by_email"
```

---

### Task 2: `hangar-domain::sso` module

**Files:**
- Create: `crates/hangar-domain/src/sso.rs`
- Modify: `crates/hangar-domain/src/lib.rs` (add `pub mod sso;`)

**Interfaces:**
- Produces: `ExternalIdentity { email: String, display_name: Option<String> }`; `IdentityProviderConfig` enum (`Ldap(LdapConfig)` variant only, for now); `LdapConfig { server_url, bind_dn, bind_password, user_search_base, user_search_filter, email_attribute: all String }`; `LdapAuthPort::authenticate(&self, config: &LdapConfig, username: &str, password: &str) -> Result<ExternalIdentity, DomainError>`; `IdentityProviderRepositoryPort` with `get`/`set`/`clear`. Task 4's Postgres adapter implements `IdentityProviderRepositoryPort`; Task 6's `ldap3` adapter implements `LdapAuthPort`; Task 5's use case consumes `ExternalIdentity`.

- [ ] **Step 1: Write the failing tests**

Create `crates/hangar-domain/src/sso.rs`:

```rust
use async_trait::async_trait;
use uuid::Uuid;

use crate::error::DomainError;

/// What an identity provider vouches for after a successful authentication —
/// deliberately minimal: never a role, group, or admin claim, so a
/// misconfigured or compromised IdP can never escalate a JIT-provisioned
/// account beyond a plain member (see `ProvisionSsoUserUseCase`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIdentity {
    pub email: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityProviderConfig {
    Ldap(LdapConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapConfig {
    /// e.g. `ldap://dc.corp.example:389` or `ldaps://dc.corp.example:636`.
    pub server_url: String,
    pub bind_dn: String,
    /// Plaintext in memory; encrypted at rest by whichever `IdentityProviderRepositoryPort`
    /// implementation persists it (see `secret_box` in `hangar-infrastructure`).
    pub bind_password: String,
    pub user_search_base: String,
    /// e.g. `(uid={username})` — `{username}` is replaced with the submitted username,
    /// verbatim, by the `LdapAuthPort` implementation. Callers must ensure `{username}`
    /// cannot inject LDAP filter syntax (see the adapter's own escaping requirement).
    pub user_search_filter: String,
    pub email_attribute: String,
}

#[async_trait]
pub trait LdapAuthPort: Send + Sync {
    /// Binds as the service account, searches for exactly one entry matching
    /// `user_search_filter` (with `{username}` substituted) under `user_search_base`,
    /// then re-binds using the found entry's DN and the submitted `password`. Returns
    /// `Err` for every failure mode alike (unknown user, wrong password, ambiguous
    /// match, unreachable server) — the caller must never distinguish these to an
    /// unauthenticated client, exactly like `AuthenticateUserUseCase` already does
    /// for local login.
    async fn authenticate(&self, config: &LdapConfig, username: &str, password: &str) -> Result<ExternalIdentity, DomainError>;
}

#[async_trait]
pub trait IdentityProviderRepositoryPort: Send + Sync {
    /// `None` means the organization uses local accounts only.
    async fn get(&self, organization_id: Uuid) -> Result<Option<IdentityProviderConfig>, DomainError>;
    /// Replaces any existing configuration for this organization (one active provider at a time).
    async fn set(&self, organization_id: Uuid, config: &IdentityProviderConfig) -> Result<(), DomainError>;
    /// Idempotent: clearing an organization with no configuration is a no-op, not an error.
    async fn clear(&self, organization_id: Uuid) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> LdapConfig {
        LdapConfig {
            server_url: "ldap://dc.corp.example:389".to_string(),
            bind_dn: "cn=service,dc=corp,dc=example".to_string(),
            bind_password: "s3cret!".to_string(),
            user_search_base: "ou=people,dc=corp,dc=example".to_string(),
            user_search_filter: "(uid={username})".to_string(),
            email_attribute: "mail".to_string(),
        }
    }

    #[test]
    fn identity_provider_config_wraps_an_ldap_config_by_value() {
        let config = IdentityProviderConfig::Ldap(sample_config());
        let IdentityProviderConfig::Ldap(inner) = config;
        assert_eq!(inner.server_url, "ldap://dc.corp.example:389");
    }

    #[test]
    fn external_identity_carries_email_and_optional_display_name() {
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: Some("Florian".to_string()) };
        assert_eq!(identity.email, "florian@corp.example");
        assert_eq!(identity.display_name.as_deref(), Some("Florian"));
    }
}
```

Add to `crates/hangar-domain/src/lib.rs`:

```rust
pub mod sso;
```

(insert alphabetically-adjacent to the existing `pub mod` lines).

- [ ] **Step 2: Run to verify it passes**

Run: `cargo test -p hangar-domain sso:: -- --nocapture`
Expected: PASS (2 tests). These tests are deliberately light — they exist to catch a typo in the type definitions, not to test behavior (there is none yet; the trait implementations arrive in Tasks 4 and 6).

- [ ] **Step 3: Commit**

```bash
git add crates/hangar-domain/src/sso.rs crates/hangar-domain/src/lib.rs
git commit -m "feat: add ExternalIdentity, IdentityProviderConfig, and SSO ports to hangar-domain"
```

---

### Task 3: `organization_identity_providers` migration

**Files:**
- Modify: `crates/hangar-infrastructure/migrations/0001_init.sql`

**Interfaces:**
- Produces: table `organization_identity_providers (organization_id UUID PRIMARY KEY REFERENCES organizations(id), config JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())` — Task 4's Postgres repository reads/writes this exact table and column set.

This mirrors `branding_settings`'s existing shape exactly (per-org singleton, `organization_id` as the primary key, no seed rows — absence of a row means "not configured").

- [ ] **Step 1: Add the table**

In `crates/hangar-infrastructure/migrations/0001_init.sql`, immediately after the existing `branding_settings` table definition, add:

```sql
-- Per-org singleton, same pattern as branding_settings — absence of a row means
-- "local accounts only" (see IdentityProviderRepositoryPort::get returning None).
-- `config` holds a serialized IdentityProviderConfig; its one secret field
-- (LdapConfig::bind_password today) is encrypted before this column is written,
-- by whichever repository implementation persists it — never stored in plaintext.
CREATE TABLE organization_identity_providers (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id),
    config JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

- [ ] **Step 2: Verify the migration applies cleanly**

Run: `docker compose down -v && docker compose up -d` (resets the dev Postgres volume so the single consolidated migration file re-applies from scratch — confirm with the user before running this if a shared dev database is in use; in this worktree's disposable Postgres container this is safe) — or, if the dev database must be preserved, run `sqlx migrate run --source crates/hangar-infrastructure/migrations` against it and confirm no error.
Run: `cargo test -p hangar-infrastructure -- --nocapture 2>&1 | tail -20` — every existing `sqlx::test` in this crate re-runs the full migration file per test database, so a syntax error here would fail the entire crate's test suite immediately.
Expected: all existing tests still PASS (this step adds no new tests of its own — Task 4 tests the table's actual use).

- [ ] **Step 3: Commit**

```bash
git add crates/hangar-infrastructure/migrations/0001_init.sql
git commit -m "feat: add organization_identity_providers table"
```

---

### Task 4: `PostgresIdentityProviderRepository`

**Files:**
- Create: `crates/hangar-infrastructure/src/postgres/identity_provider_repository.rs`
- Modify: `crates/hangar-infrastructure/src/postgres/mod.rs` (add `pub mod identity_provider_repository;`)

**Interfaces:**
- Consumes: `secret_box::{encrypt_packed, decrypt_packed}` (Task 3's table, Task 2's `IdentityProviderConfig`/`LdapConfig`/`IdentityProviderRepositoryPort`).
- Produces: `PostgresIdentityProviderRepository::new(pool: PgPool, jwt_secret: String) -> Self` implementing `IdentityProviderRepositoryPort` — Task 8 wires this into `AppState` as `state.identity_providers`.

Storage strategy: serialize `IdentityProviderConfig` to a `serde_json::Value` for the JSONB column, but with `bind_password` replaced by its `encrypt_packed` string before serializing (and the reverse on read) — the plaintext password must never reach the JSONB column. Since `IdentityProviderConfig`/`LdapConfig` don't derive `Serialize`/`Deserialize` in `hangar-domain` (kept free of a serde dependency on principle — check whether `hangar-domain`'s `Cargo.toml` already depends on `serde` before assuming; if it does, deriving directly on the domain types is simpler and preferred over a local shadow struct), this task defines its own private, `Serialize`/`Deserialize`-deriving row-shape struct in this file that mirrors `LdapConfig`'s fields with `bind_password` renamed to `bind_password_encrypted`.

- [ ] **Step 1: Write the failing tests**

Create `crates/hangar-infrastructure/src/postgres/identity_provider_repository.rs`:

```rust
use async_trait::async_trait;
use hangar_domain::error::DomainError;
use hangar_domain::sso::{IdentityProviderConfig, IdentityProviderRepositoryPort, LdapConfig};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error_ext::InfraErr;
use crate::secret_box;

pub struct PostgresIdentityProviderRepository {
    pool: PgPool,
    /// Derives the AES-256 key for `secret_box` — never stored, never logged.
    jwt_secret: String,
}

impl PostgresIdentityProviderRepository {
    pub fn new(pool: PgPool, jwt_secret: String) -> Self {
        Self { pool, jwt_secret }
    }
}

/// The JSONB row shape — `bind_password_encrypted` is `secret_box::encrypt_packed`'s
/// output, never the plaintext password.
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
}

impl StoredConfig {
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
        }
    }
}

#[async_trait]
impl IdentityProviderRepositoryPort for PostgresIdentityProviderRepository {
    async fn get(&self, organization_id: Uuid) -> Result<Option<IdentityProviderConfig>, DomainError> {
        let row = sqlx::query!("SELECT config FROM organization_identity_providers WHERE organization_id = $1", organization_id)
            .fetch_optional(&self.pool)
            .await
            .infra_err()?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored: StoredConfig = serde_json::from_value(row.config).map_err(|e| DomainError::Infrastructure(e.to_string()))?;
        Ok(Some(stored.into_domain(&self.jwt_secret)))
    }

    async fn set(&self, organization_id: Uuid, config: &IdentityProviderConfig) -> Result<(), DomainError> {
        let stored = StoredConfig::from_domain(config, &self.jwt_secret);
        let json = serde_json::to_value(&stored).map_err(|e| DomainError::Infrastructure(e.to_string()))?;
        sqlx::query!(
            "INSERT INTO organization_identity_providers (organization_id, config, updated_at) VALUES ($1, $2, now()) \
             ON CONFLICT (organization_id) DO UPDATE SET config = EXCLUDED.config, updated_at = now()",
            organization_id,
            json,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn clear(&self, organization_id: Uuid) -> Result<(), DomainError> {
        sqlx::query!("DELETE FROM organization_identity_providers WHERE organization_id = $1", organization_id)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> IdentityProviderConfig {
        IdentityProviderConfig::Ldap(LdapConfig {
            server_url: "ldap://dc.corp.example:389".to_string(),
            bind_dn: "cn=service,dc=corp,dc=example".to_string(),
            bind_password: "s3cret!".to_string(),
            user_search_base: "ou=people,dc=corp,dc=example".to_string(),
            user_search_filter: "(uid={username})".to_string(),
            email_attribute: "mail".to_string(),
        })
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn get_returns_none_when_never_configured(pool: PgPool) {
        let repo = PostgresIdentityProviderRepository::new(pool, "jwt-secret".to_string());
        assert_eq!(repo.get(Uuid::new_v4()).await.unwrap(), None);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn set_then_get_round_trips_including_the_password(pool: PgPool) {
        let repo = PostgresIdentityProviderRepository::new(pool, "jwt-secret".to_string());
        let organization_id = Uuid::new_v4();

        repo.set(organization_id, &sample()).await.unwrap();

        assert_eq!(repo.get(organization_id).await.unwrap(), Some(sample()));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_second_set_overwrites_the_first_rather_than_inserting_a_row(pool: PgPool) {
        let repo = PostgresIdentityProviderRepository::new(pool, "jwt-secret".to_string());
        let organization_id = Uuid::new_v4();
        repo.set(organization_id, &sample()).await.unwrap();

        let IdentityProviderConfig::Ldap(mut updated) = sample();
        updated.server_url = "ldaps://dc2.corp.example:636".to_string();
        repo.set(organization_id, &IdentityProviderConfig::Ldap(updated)).await.unwrap();

        let count: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM organization_identity_providers WHERE organization_id = $1", organization_id)
            .fetch_one(&repo.pool)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(count, 1);
        let IdentityProviderConfig::Ldap(found) = repo.get(organization_id).await.unwrap().unwrap();
        assert_eq!(found.server_url, "ldaps://dc2.corp.example:636");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn clearing_an_unconfigured_organization_is_a_no_op(pool: PgPool) {
        let repo = PostgresIdentityProviderRepository::new(pool, "jwt-secret".to_string());
        repo.clear(Uuid::new_v4()).await.unwrap();
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn clearing_removes_the_configuration(pool: PgPool) {
        let repo = PostgresIdentityProviderRepository::new(pool, "jwt-secret".to_string());
        let organization_id = Uuid::new_v4();
        repo.set(organization_id, &sample()).await.unwrap();

        repo.clear(organization_id).await.unwrap();

        assert_eq!(repo.get(organization_id).await.unwrap(), None);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn the_bind_password_is_never_stored_in_plaintext(pool: PgPool) {
        let repo = PostgresIdentityProviderRepository::new(pool, "jwt-secret".to_string());
        let organization_id = Uuid::new_v4();
        repo.set(organization_id, &sample()).await.unwrap();

        let row: (serde_json::Value,) = sqlx::query_as("SELECT config FROM organization_identity_providers WHERE organization_id = $1")
            .bind(organization_id)
            .fetch_one(&repo.pool)
            .await
            .unwrap();
        assert!(!row.0.to_string().contains("s3cret!"), "the plaintext bind password must never appear in the stored JSON");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn decrypting_with_the_wrong_jwt_secret_does_not_return_the_original_password(pool: PgPool) {
        let write_repo = PostgresIdentityProviderRepository::new(pool.clone(), "jwt-secret-a".to_string());
        let organization_id = Uuid::new_v4();
        write_repo.set(organization_id, &sample()).await.unwrap();

        let read_repo = PostgresIdentityProviderRepository::new(pool, "jwt-secret-b".to_string());
        let IdentityProviderConfig::Ldap(found) = read_repo.get(organization_id).await.unwrap().unwrap();
        assert_ne!(found.bind_password, "s3cret!", "a mismatched key must not silently decrypt to the real password");
    }
}
```

Add to `crates/hangar-infrastructure/src/postgres/mod.rs`:

```rust
pub mod identity_provider_repository;
```

- [ ] **Step 2: Run to verify the tests pass**

Run: `cargo test -p hangar-infrastructure identity_provider_repository:: -- --nocapture`
Expected: PASS (7 tests). Note `decrypting_with_the_wrong_jwt_secret_does_not_return_the_original_password` relies on `secret_box::decrypt_packed`'s existing fallback behavior (returns the packed ciphertext string itself, not a panic, on a key mismatch — see `secret_box.rs`'s own tests) rather than an `Err` — the assertion only needs the *wrong* password to differ from the *real* one, which holds either way.

- [ ] **Step 3: Regenerate the sqlx offline cache**

Run: `cargo sqlx prepare --workspace -- --all-targets 2>&1 | tail -20` — this task introduces new SQL query text, so `.sqlx/` WILL change this time (unlike prior tasks in the public-registration plan). Verify with `git status .sqlx/` that new entries appeared, then verify the offline build still works: `SQLX_OFFLINE=true cargo build --workspace 2>&1 | tail -20`.

- [ ] **Step 4: Commit**

```bash
git add crates/hangar-infrastructure/src/postgres/identity_provider_repository.rs crates/hangar-infrastructure/src/postgres/mod.rs .sqlx/
git commit -m "feat: add PostgresIdentityProviderRepository with encrypted bind_password"
```

---

### Task 5: `ProvisionSsoUserUseCase`

**Files:**
- Create: `crates/hangar-application/src/use_cases/sso.rs`
- Modify: `crates/hangar-application/src/use_cases/mod.rs` (add `pub mod sso;`)

**Interfaces:**
- Consumes: `hangar_domain::sso::ExternalIdentity`; `hangar_domain::user::{User, UserRepositoryPort, TokenIssuerPort, Username}`; Task 1's `find_by_email`.
- Produces: `ProvisionSsoUserUseCase::new(users: Arc<dyn UserRepositoryPort>, tokens: Arc<dyn TokenIssuerPort>) -> Self` with `pub async fn execute(&self, organization_id: Uuid, identity: &ExternalIdentity) -> Result<String, ApplicationError>` (returns a real session token) — Task 9's route handler calls this exact signature after a successful `LdapAuthPort::authenticate`.

Username derivation for a newly-provisioned account: take the email's local-part (before `@`), lowercase it, keep only ASCII alphanumeric/`_`/`-` characters (dropping everything else, e.g. `.`/`+`), ensure it starts with a letter (prepend `u` if the first surviving character isn't an ASCII letter or the string became empty), then pad or truncate to satisfy `Username::parse`'s 3–32 character rule (pad short results by appending `-user`, truncate long ones to 32 characters). If the resulting username is already taken, append `-2`, `-3`, etc. (checking `find_by_username` each time) until one is free.

- [ ] **Step 1: Write the failing tests**

Create `crates/hangar-application/src/use_cases/sso.rs`. Note up front: this use case needs a password hasher dependency — `unusable_password_hash` (already `pub(crate)` in `invitation.rs`, reused here via a plain `use` import) takes `&dyn PasswordHasherPort`, so `ProvisionSsoUserUseCase::new` takes three parameters (`users`, `hasher`, `tokens`), exactly mirroring how `InviteUserUseCase` is already constructed.

```rust
use std::sync::Arc;

use hangar_domain::sso::ExternalIdentity;
use hangar_domain::user::{PasswordHasherPort, TokenIssuerPort, User, UserRepositoryPort, Username};
use uuid::Uuid;

use crate::error::ApplicationError;
use crate::use_cases::invitation::unusable_password_hash;

fn derive_username_candidate(email: &str) -> String {
    let local_part = email.split('@').next().unwrap_or(email).to_lowercase();
    let filtered: String = local_part.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
    let starts_with_letter = filtered.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
    let mut candidate = if starts_with_letter { filtered } else { format!("u{filtered}") };
    if candidate.len() < 3 {
        candidate.push_str("-user");
    }
    candidate.chars().take(32).collect()
}

pub struct ProvisionSsoUserUseCase {
    users: Arc<dyn UserRepositoryPort>,
    hasher: Arc<dyn PasswordHasherPort>,
    tokens: Arc<dyn TokenIssuerPort>,
}

impl ProvisionSsoUserUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>, hasher: Arc<dyn PasswordHasherPort>, tokens: Arc<dyn TokenIssuerPort>) -> Self {
        Self { users, hasher, tokens }
    }

    pub async fn execute(&self, organization_id: Uuid, identity: &ExternalIdentity) -> Result<String, ApplicationError> {
        if let Some(existing) = self.users.find_by_email(&identity.email).await? {
            return Ok(self.tokens.issue(existing.id)?);
        }

        let base = derive_username_candidate(&identity.email);
        let mut candidate = base.clone();
        let mut suffix = 1u32;
        let username = loop {
            let parsed = Username::parse(&candidate)?;
            if self.users.find_by_username(&parsed).await?.is_none() {
                break candidate;
            }
            suffix += 1;
            let suffix_str = format!("-{suffix}");
            let truncated_base: String = base.chars().take(32 - suffix_str.len()).collect();
            candidate = format!("{truncated_base}{suffix_str}");
        };

        let user = User {
            id: Uuid::new_v4(),
            username: Username::parse(&username)?,
            password_hash: unusable_password_hash(self.hasher.as_ref())?,
            is_super_admin: false,
            is_organization_admin: false,
            organization_id,
            created_at: chrono::Utc::now(),
            email: Some(identity.email.clone()),
        };
        self.users.insert(&user).await?;
        Ok(self.tokens.issue(user.id)?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use hangar_domain::error::DomainError;

    use super::*;

    struct FakeUsers {
        users: Mutex<HashMap<Uuid, User>>,
    }

    impl FakeUsers {
        fn new() -> Self {
            Self { users: Mutex::new(HashMap::new()) }
        }

        fn seeded(users: Vec<User>) -> Self {
            Self { users: Mutex::new(users.into_iter().map(|u| (u.id, u)).collect()) }
        }
    }

    #[async_trait]
    impl UserRepositoryPort for FakeUsers {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().get(&id).cloned())
        }
        async fn find_by_username(&self, username: &Username) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().values().find(|u| &u.username == username).cloned())
        }
        async fn find_by_email(&self, email: &str) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().values().find(|u| u.email.as_deref() == Some(email)).cloned())
        }
        async fn list_all(&self) -> Result<Vec<User>, DomainError> {
            Ok(self.users.lock().unwrap().values().cloned().collect())
        }
        async fn insert(&self, user: &User) -> Result<(), DomainError> {
            self.users.lock().unwrap().insert(user.id, user.clone());
            Ok(())
        }
        async fn delete(&self, id: Uuid) -> Result<(), DomainError> {
            self.users.lock().unwrap().remove(&id);
            Ok(())
        }
        async fn update_password(&self, id: Uuid, new_password_hash: String) -> Result<(), DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.password_hash = new_password_hash;
            }
            Ok(())
        }
        async fn set_super_admin(&self, id: Uuid, is_super_admin: bool) -> Result<(), DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.is_super_admin = is_super_admin;
            }
            Ok(())
        }
        async fn delete_unless_last_super_admin(&self, id: Uuid) -> Result<bool, DomainError> {
            self.users.lock().unwrap().remove(&id);
            Ok(true)
        }
        async fn set_super_admin_unless_last(&self, id: Uuid, is_super_admin: bool) -> Result<bool, DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.is_super_admin = is_super_admin;
            }
            Ok(true)
        }
    }

    struct FakeHasher;

    #[async_trait]
    impl PasswordHasherPort for FakeHasher {
        fn hash(&self, plain_password: &str) -> Result<String, DomainError> {
            Ok(format!("hashed:{plain_password}"))
        }
        fn verify(&self, plain_password: &str, hash: &str) -> bool {
            hash == format!("hashed:{plain_password}")
        }
    }

    struct FakeTokenIssuer;

    #[async_trait]
    impl TokenIssuerPort for FakeTokenIssuer {
        fn issue(&self, user_id: Uuid) -> Result<String, DomainError> {
            Ok(format!("token:{user_id}"))
        }
        fn verify(&self, token: &str) -> Result<Uuid, DomainError> {
            token.strip_prefix("token:").and_then(|s| Uuid::parse_str(s).ok()).ok_or_else(|| DomainError::InvalidUsername("bad token".to_string()))
        }
    }

    #[tokio::test]
    async fn provisions_a_fresh_member_account_on_first_login() {
        let use_case = ProvisionSsoUserUseCase::new(Arc::new(FakeUsers::new()), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer));
        let organization_id = Uuid::new_v4();
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: Some("Florian".to_string()) };

        let token = use_case.execute(organization_id, &identity).await.unwrap();

        assert!(token.starts_with("token:"));
    }

    #[tokio::test]
    async fn a_provisioned_account_is_never_an_admin_regardless_of_display_name_content() {
        let users = Arc::new(FakeUsers::new());
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer));
        let organization_id = Uuid::new_v4();
        // A directory attribute an attacker fully controls must never influence the role.
        let identity = ExternalIdentity { email: "attacker@corp.example".to_string(), display_name: Some("Admin Super-Admin Root".to_string()) };

        use_case.execute(organization_id, &identity).await.unwrap();

        let created = users.users.lock().unwrap().values().find(|u| u.email.as_deref() == Some("attacker@corp.example")).cloned().unwrap();
        assert!(!created.is_super_admin);
        assert!(!created.is_organization_admin);
    }

    #[tokio::test]
    async fn a_provisioned_account_has_no_usable_password() {
        let users = Arc::new(FakeUsers::new());
        let hasher = Arc::new(FakeHasher);
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), hasher.clone(), Arc::new(FakeTokenIssuer));
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: None };

        use_case.execute(Uuid::new_v4(), &identity).await.unwrap();

        let created = users.users.lock().unwrap().values().next().cloned().unwrap();
        assert!(!hasher.verify("anything", &created.password_hash), "no plaintext should ever verify against a JIT-provisioned account's placeholder hash");
    }

    #[tokio::test]
    async fn logging_in_again_with_the_same_email_reuses_the_existing_account() {
        let users = Arc::new(FakeUsers::new());
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer));
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: None };

        use_case.execute(Uuid::new_v4(), &identity).await.unwrap();
        let first_count = users.users.lock().unwrap().len();
        use_case.execute(Uuid::new_v4(), &identity).await.unwrap();
        let second_count = users.users.lock().unwrap().len();

        assert_eq!(first_count, second_count, "a second login with the same email must not create a second account");
    }

    #[tokio::test]
    async fn derives_a_username_from_the_email_local_part() {
        let users = Arc::new(FakeUsers::new());
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer));
        let identity = ExternalIdentity { email: "florian.dupont@corp.example".to_string(), display_name: None };

        use_case.execute(Uuid::new_v4(), &identity).await.unwrap();

        let created = users.users.lock().unwrap().values().next().cloned().unwrap();
        assert_eq!(created.username.as_str(), "floriandupont");
    }

    #[tokio::test]
    async fn a_colliding_username_gets_a_numeric_suffix() {
        let existing = User {
            id: Uuid::new_v4(),
            username: Username::parse("florian").unwrap(),
            password_hash: "placeholder".to_string(),
            is_super_admin: false,
            is_organization_admin: false,
            organization_id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            email: Some("someone-else@corp.example".to_string()),
        };
        let users = Arc::new(FakeUsers::seeded(vec![existing]));
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer));
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: None };

        use_case.execute(Uuid::new_v4(), &identity).await.unwrap();

        let created = users.users.lock().unwrap().values().find(|u| u.email.as_deref() == Some("florian@corp.example")).cloned().unwrap();
        assert_eq!(created.username.as_str(), "florian-2");
    }
}
```

Add to `crates/hangar-application/src/use_cases/mod.rs`:

```rust
pub mod sso;
```

- [ ] **Step 2: Run to verify the tests pass**

Run: `cargo test -p hangar-application sso:: -- --nocapture`
Expected: PASS (6 tests).

- [ ] **Step 3: Mutation-test the privilege-escalation guard**

This is the single most security-critical assertion in this task. Temporarily change `is_super_admin: false, is_organization_admin: false,` in the `User` construction to `is_super_admin: true, is_organization_admin: true,`, re-run `a_provisioned_account_is_never_an_admin_regardless_of_display_name_content`, confirm it now FAILS, then restore the original code and confirm the full `sso::` test module passes again.

- [ ] **Step 4: Commit**

```bash
git add crates/hangar-application/src/use_cases/sso.rs crates/hangar-application/src/use_cases/mod.rs
git commit -m "feat: add ProvisionSsoUserUseCase with member-only JIT provisioning"
```

---

### Task 6: `Ldap3AuthAdapter`

**Files:**
- Modify: `crates/hangar-infrastructure/Cargo.toml` (add `ldap3` dependency)
- Create: `crates/hangar-infrastructure/src/ldap3_auth_adapter.rs`
- Modify: `crates/hangar-infrastructure/src/lib.rs` (add `pub mod ldap3_auth_adapter;`)

**Interfaces:**
- Consumes: `hangar_domain::sso::{ExternalIdentity, LdapAuthPort, LdapConfig}`.
- Produces: `Ldap3AuthAdapter` (a unit struct, stateless — each call opens its own connection) implementing `LdapAuthPort` — Task 8 wires this into `AppState` as `state.ldap_auth`.

This is the one task in this plan that depends on a third-party network protocol library (`ldap3`) whose exact API this plan's author verified against the crate's current documentation (version 0.12, published 2025) but could not execute against a real directory server while writing this plan. If the API described below has changed by the time this task is implemented, treat the code below as the intended behavior and consult `cargo doc -p ldap3 --open` (or `https://docs.rs/ldap3`) to adapt the exact calls — the four steps (connect, admin-bind, search, user-rebind) are the actual contract to preserve.

- [ ] **Step 1: Add the dependency**

In `crates/hangar-infrastructure/Cargo.toml`, under `[dependencies]`, add:

```toml
ldap3 = { version = "0.12", default-features = false, features = ["tls-rustls-ring"] }
```

(`default-features = false` avoids pulling in `native-tls`/OpenSSL — this workspace already standardizes on rustls throughout, per `sqlx`'s `tls-rustls` feature and the `tokio-rustls`/`hyper-rustls`/`rustls-platform-verifier` dependencies already in the tree.)

Run: `cargo build -p hangar-infrastructure 2>&1 | tail -30` — confirm the new dependency resolves and compiles (with no adapter code yet, this just proves the dependency itself is sound).

- [ ] **Step 2: Write the failing unit test**

This adapter's core logic (filter substitution, exactly-one-result enforcement, DN-based re-bind) is testable without a real directory only at the substitution-helper level; the bind/search/rebind flow itself requires an actual LDAP server and is intentionally left to manual/integration verification (see Step 5) rather than a mocked unit test, since mocking `ldap3`'s connection type would test the mock, not the adapter. Write this one pure-logic test first:

Create `crates/hangar-infrastructure/src/ldap3_auth_adapter.rs`:

```rust
use async_trait::async_trait;
use hangar_domain::error::DomainError;
use hangar_domain::sso::{ExternalIdentity, LdapAuthPort, LdapConfig};
use ldap3::{LdapConnAsync, Scope, SearchEntry};

pub struct Ldap3AuthAdapter;

/// Substitutes the literal `{username}` placeholder with the submitted username.
/// LDAP filter metacharacters in `username` (`(`, `)`, `\`, `*`, NUL) are escaped
/// per RFC 4515 so a crafted username cannot alter the filter's structure —
/// this is the LDAP-filter-injection defense for this adapter.
fn build_filter(template: &str, username: &str) -> String {
    let escaped: String = username
        .chars()
        .map(|c| match c {
            '(' => "\\28".to_string(),
            ')' => "\\29".to_string(),
            '\\' => "\\5c".to_string(),
            '*' => "\\2a".to_string(),
            '\0' => "\\00".to_string(),
            other => other.to_string(),
        })
        .collect();
    template.replace("{username}", &escaped)
}

#[async_trait]
impl LdapAuthPort for Ldap3AuthAdapter {
    async fn authenticate(&self, config: &LdapConfig, username: &str, password: &str) -> Result<ExternalIdentity, DomainError> {
        let (conn, mut ldap) = LdapConnAsync::new(&config.server_url).await.map_err(|e| DomainError::Infrastructure(format!("ldap connect failed: {e}")))?;
        ldap3::drive!(conn);

        ldap.simple_bind(&config.bind_dn, &config.bind_password)
            .await
            .map_err(|e| DomainError::Infrastructure(format!("ldap service bind failed: {e}")))?
            .success()
            .map_err(|e| DomainError::Infrastructure(format!("ldap service bind rejected: {e}")))?;

        let filter = build_filter(&config.user_search_filter, username);
        let (results, _) = ldap
            .search(&config.user_search_base, Scope::Subtree, &filter, vec![config.email_attribute.as_str()])
            .await
            .map_err(|e| DomainError::Infrastructure(format!("ldap search failed: {e}")))?
            .success()
            .map_err(|e| DomainError::Infrastructure(format!("ldap search rejected: {e}")))?;

        // Exactly one match required — zero means unknown user, more than one means
        // an ambiguous filter/directory state; both must fail closed rather than
        // guess, since guessing here is an authentication bypass risk.
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

        // Re-bind on the SAME connection as the found entry's own DN — this is the
        // actual credential check. The prior service-account bind's success proves
        // nothing about the submitted password; only this second bind does.
        ldap.simple_bind(&entry.dn, password)
            .await
            .map_err(|e| DomainError::Infrastructure(format!("ldap user bind failed: {e}")))?
            .success()
            .map_err(|_| DomainError::Infrastructure("ldap user bind rejected: invalid credentials".to_string()))?;

        let _ = ldap.unbind().await;
        Ok(ExternalIdentity { email, display_name: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_the_username_placeholder() {
        assert_eq!(build_filter("(uid={username})", "florian"), "(uid=florian)");
    }

    #[test]
    fn escapes_ldap_filter_metacharacters_in_the_submitted_username() {
        assert_eq!(build_filter("(uid={username})", "a)(uid=*"), "(uid=a\\29\\28uid=\\2a)");
    }

    #[test]
    fn leaves_a_filter_with_no_placeholder_unchanged() {
        assert_eq!(build_filter("(objectClass=person)", "florian"), "(objectClass=person)");
    }
}
```

Add to `crates/hangar-infrastructure/src/lib.rs`:

```rust
pub mod ldap3_auth_adapter;
```

- [ ] **Step 3: Run to verify the tests pass**

Run: `cargo test -p hangar-infrastructure ldap3_auth_adapter:: -- --nocapture`
Expected: PASS (3 tests).

- [ ] **Step 4: Mutation-test the filter-injection escaping**

Temporarily change `build_filter` to skip escaping (`template.replace("{username}", username)`), re-run `escapes_ldap_filter_metacharacters_in_the_submitted_username`, confirm it now FAILS, then restore the escaping code and confirm the test passes again. This is the one security-relevant guarantee in this file that a unit test can actually verify without a live directory.

- [ ] **Step 5: Manual integration note**

The bind/search/rebind flow itself (Steps not covered by Step 2-4's pure-logic test) needs verification against a real or containerized LDAP server (e.g. `docker run --rm -p 389:389 osixia/openldap` with a seeded test user) before this feature is considered production-ready. This plan does not require standing up such a container as part of this task — record in the task report that this manual verification was NOT performed automatically, so the controller can decide whether to do it before merge (mirroring how the public-registration plan's frontend manual-browser-verification step was explicitly deferred with the same reasoning).

- [ ] **Step 6: Commit**

```bash
git add crates/hangar-infrastructure/Cargo.toml crates/hangar-infrastructure/src/ldap3_auth_adapter.rs crates/hangar-infrastructure/src/lib.rs Cargo.lock
git commit -m "feat: add Ldap3AuthAdapter implementing LdapAuthPort"
```

---

### Task 7: `authz.rs` — shared `require_organization_admin`

**Files:**
- Modify: `crates/hangar-api/src/authz.rs`
- Modify: `crates/hangar-api/src/routes/branding.rs`

**Interfaces:**
- Produces: `pub fn require_organization_admin(user: &AuthUser, organization_id: Uuid) -> Result<(), StatusCode>` — Task 11's organization SSO-config routes call this exact signature; `branding.rs`'s existing callers switch to it too.

This is a small, low-risk refactor: `branding.rs` already has a private helper (`require_super_admin_or_own_org_admin`) with exactly the logic this plan's LDAP config route needs. Rather than duplicate it a second time, promote it into the shared `authz.rs` module (which already holds `require_super_admin`/`require_same_organization`) and delete the private copy.

- [ ] **Step 1: Write the failing test**

In `crates/hangar-api/src/authz.rs`'s (new) `#[cfg(test)] mod tests` block — this file currently has no tests of its own; add the module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn user(is_super_admin: bool, is_organization_admin: bool, organization_id: Uuid) -> AuthUser {
        AuthUser { id: Uuid::new_v4(), username: "test".to_string(), is_super_admin, is_organization_admin, organization_id, created_at: Utc::now() }
    }

    #[test]
    fn a_super_admin_passes_regardless_of_organization() {
        let target_org = Uuid::new_v4();
        assert!(require_organization_admin(&user(true, false, Uuid::new_v4()), target_org).is_ok());
    }

    #[test]
    fn that_organizations_own_admin_passes() {
        let org = Uuid::new_v4();
        assert!(require_organization_admin(&user(false, true, org), org).is_ok());
    }

    #[test]
    fn a_regular_member_of_that_organization_is_rejected() {
        let org = Uuid::new_v4();
        assert!(require_organization_admin(&user(false, false, org), org).is_err());
    }

    #[test]
    fn an_admin_of_a_different_organization_is_rejected() {
        let org = Uuid::new_v4();
        assert!(require_organization_admin(&user(false, true, Uuid::new_v4()), org).is_err());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hangar-api authz:: 2>&1 | tail -20`
Expected: FAIL to compile — `require_organization_admin` doesn't exist in `authz.rs` yet.

- [ ] **Step 3: Add the function, moved from `branding.rs`**

In `crates/hangar-api/src/authz.rs`, add (matching `branding.rs`'s existing logic exactly — read `branding.rs`'s current `require_super_admin_or_own_org_admin` first to confirm you're preserving its exact behavior):

```rust
/// Super-admin, or that organization's own admin — the authorization shape shared by
/// every "an organization configures its own X" route (branding, and now identity
/// provider configuration).
pub fn require_organization_admin(user: &AuthUser, organization_id: Uuid) -> Result<(), StatusCode> {
    if user.is_super_admin {
        return Ok(());
    }
    if user.organization_id == organization_id && user.is_organization_admin {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}
```

- [ ] **Step 4: Run to verify the new tests pass**

Run: `cargo test -p hangar-api authz:: -- --nocapture`
Expected: PASS (4 tests).

- [ ] **Step 5: Update `branding.rs` to use the shared helper**

In `crates/hangar-api/src/routes/branding.rs`, delete the private `require_super_admin_or_own_org_admin` function entirely, add `require_organization_admin` to the existing `use crate::authz::{...}` import line, and replace every call site `require_super_admin_or_own_org_admin(&user, &resolved_org)` with `require_organization_admin(&user, resolved_org.0.id)` (note the signature difference: the shared helper takes a plain `Uuid`, not a `&ResolvedOrganization` reference — adjust each call site's argument accordingly).

- [ ] **Step 6: Run the full `hangar-api` suite to confirm no regression**

Run: `cargo test -p hangar-api -- --nocapture 2>&1 | tail -60`
Expected: PASS, including every pre-existing `branding.rs` test (this refactor must not change branding's authorization behavior at all — only where the logic lives).

- [ ] **Step 7: Commit**

```bash
git add crates/hangar-api/src/authz.rs crates/hangar-api/src/routes/branding.rs
git commit -m "refactor: promote require_organization_admin into shared authz.rs"
```

---

### Task 8: Wire Tasks 4-6 into `AppState`

**Files:**
- Modify: `crates/hangar-api/src/state.rs`

**Interfaces:**
- Consumes: `PostgresIdentityProviderRepository::new(pool, jwt_secret)` (Task 4), `Ldap3AuthAdapter` (Task 6, unit struct, no constructor args), `ProvisionSsoUserUseCase::new(users, hasher, tokens)` (Task 5).
- Produces: `AppState.identity_providers: Arc<dyn IdentityProviderRepositoryPort>`, `AppState.ldap_auth: Arc<dyn LdapAuthPort>`, `AppState.provision_sso_user: Arc<ProvisionSsoUserUseCase>` — Task 9's and Task 11's route handlers use these three fields.

- [ ] **Step 1: Add the imports**

In `crates/hangar-api/src/state.rs`, add:

```rust
use hangar_application::use_cases::sso::ProvisionSsoUserUseCase;
use hangar_domain::sso::{IdentityProviderRepositoryPort, LdapAuthPort};
use hangar_infrastructure::ldap3_auth_adapter::Ldap3AuthAdapter;
use hangar_infrastructure::postgres::identity_provider_repository::PostgresIdentityProviderRepository;
```

- [ ] **Step 2: Add the fields**

Next to `pub organizations: Arc<dyn OrganizationRepositoryPort>,`, add:

```rust
pub identity_providers: Arc<dyn IdentityProviderRepositoryPort>,
pub ldap_auth: Arc<dyn LdapAuthPort>,
pub provision_sso_user: Arc<ProvisionSsoUserUseCase>,
```

- [ ] **Step 3: Construct them in `AppState::build`**

Next to the existing `let organizations: Arc<dyn OrganizationRepositoryPort> = Arc::new(PostgresOrganizationRepository::new(pool.clone()));` line, add:

```rust
let identity_providers: Arc<dyn IdentityProviderRepositoryPort> = Arc::new(PostgresIdentityProviderRepository::new(pool.clone(), config.jwt_secret.clone()));
let ldap_auth: Arc<dyn LdapAuthPort> = Arc::new(Ldap3AuthAdapter);
```

Next to the struct-literal fields being assembled at the end of `build` (find where `organizations: organizations.clone(),` is assigned and add these three lines beside it — `provision_sso_user` needs `users_repo`, `hasher`, and `token_issuer`, which are already constructed earlier in this same function for other use cases; reuse those existing `Arc` clones rather than constructing new ones):

```rust
identity_providers: identity_providers.clone(),
ldap_auth: ldap_auth.clone(),
provision_sso_user: Arc::new(ProvisionSsoUserUseCase::new(users_repo.clone(), hasher.clone(), token_issuer.clone())),
```

(Check the exact variable name this file uses for its `Arc<dyn TokenIssuerPort>` — it's used to construct `AuthenticateUserUseCase` a few lines away; match that name exactly, it may not be `token_issuer`.)

- [ ] **Step 4: Verify it compiles**

Run: `cargo build -p hangar-api 2>&1 | tail -40`
Expected: succeeds with no warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/hangar-api/src/state.rs
git commit -m "feat: wire identity provider repository, LDAP auth, and SSO provisioning into AppState"
```

---

### Task 9: `POST /api/auth/sso/ldap` and `GET /api/auth/sso/config`

**Files:**
- Modify: `crates/hangar-api/src/dto.rs` (add `LdapLoginRequest`, `SsoConfigResponse`)
- Modify: `crates/hangar-api/src/routes/auth.rs`

**Interfaces:**
- Consumes: `state.identity_providers.get(org_id)` (Task 4/8), `state.ldap_auth.authenticate(...)` (Task 6/8), `state.provision_sso_user.execute(...)` (Task 5/8), `crate::organization_middleware::ResolvedOrganization` (already used by `register` in this same file).
- Produces: routes `POST /api/auth/sso/ldap` and `GET /api/auth/sso/config`, both added to `pub fn router()` in this file. Task 16 (frontend) consumes both over HTTP.

- [ ] **Step 1: Add the DTOs**

In `crates/hangar-api/src/dto.rs`, add:

```rust
#[derive(Debug, Deserialize)]
pub struct LdapLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SsoProviderType {
    Ldap,
}

#[derive(Debug, Serialize)]
pub struct SsoConfigResponse {
    /// `None` means this organization uses local accounts — the frontend's login
    /// page falls back to `/api/auth/login` in that case.
    #[serde(rename = "type")]
    pub provider_type: Option<SsoProviderType>,
}
```

- [ ] **Step 2: Write the failing tests**

Add to `crates/hangar-api/src/routes/auth.rs`'s `#[cfg(test)] mod tests`:

```rust
    async fn seed_ldap_config(state: &AppState, organization_id: Uuid) {
        state
            .identity_providers
            .set(
                organization_id,
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
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn sso_config_reports_no_provider_for_an_unconfigured_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/auth/sso/config").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["type"].is_null());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn sso_config_reports_ldap_for_a_configured_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        seed_ldap_config(&state, public_org.id).await;
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/auth/sso/config").body(Body::empty()).unwrap()).await.unwrap();

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["type"], "ldap");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn ldap_login_is_rejected_when_the_organization_has_no_identity_provider_configured(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/sso/ldap")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"florian","password":"s3cret!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_failed_ldap_bind_is_rejected_as_unauthorized(pool: sqlx::PgPool) {
        // No real directory is reachable in this test environment, so the
        // configured `Ldap3AuthAdapter` will fail to connect — this test proves
        // that failure surfaces as 401, not 500 or a stack trace, exactly like a
        // wrong local password does for `/api/auth/login`.
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        seed_ldap_config(&state, public_org.id).await;
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/sso/ldap")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"florian","password":"s3cret!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p hangar-api routes::auth:: sso 2>&1 | tail -40`
Expected: FAIL to compile (routes and DTOs don't exist yet).

- [ ] **Step 4: Implement the routes**

In `crates/hangar-api/src/routes/auth.rs`, update the `dto` import to add `LdapLoginRequest, SsoConfigResponse, SsoProviderType`, and add the routes to `router()`:

```rust
        .route("/api/auth/sso/ldap", post(sso_ldap_login))
        .route("/api/auth/sso/config", get(sso_config))
```

Add the handlers, next to `register`:

```rust
/// Unauthenticated — the login page calls this before the user submits anything,
/// to decide whether to post credentials to this route or to `/api/auth/login`.
/// Deliberately reveals only the provider type, never server details.
async fn sso_config(State(state): State<AppState>, resolved_org: ResolvedOrganization) -> Result<Json<SsoConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state
        .identity_providers
        .get(resolved_org.0.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    let provider_type = config.map(|c| match c {
        hangar_domain::sso::IdentityProviderConfig::Ldap(_) => SsoProviderType::Ldap,
    });
    Ok(Json(SsoConfigResponse { provider_type }))
}

/// Every failure mode — no LDAP configured, unreachable directory, wrong
/// credentials, ambiguous directory match — collapses to a single response per
/// case below; the LDAP-specific ones all collapse to 401, exactly like
/// `AuthenticateUserUseCase`'s own local-login failures never distinguish
/// "unknown user" from "wrong password" to an unauthenticated caller.
async fn sso_ldap_login(
    State(state): State<AppState>,
    resolved_org: ResolvedOrganization,
    Json(body): Json<LdapLoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state
        .identity_providers
        .get(resolved_org.0.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    let Some(hangar_domain::sso::IdentityProviderConfig::Ldap(ldap_config)) = config else {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "this organization has no LDAP identity provider configured".to_string() })));
    };

    let identity = state
        .ldap_auth
        .authenticate(&ldap_config, &body.username, &body.password)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid credentials".to_string() })))?;

    let token = state
        .provision_sso_user
        .execute(resolved_org.0.id, &identity)
        .await
        .map_err(|e| application_error_response("failed to provision sso user", e))?;
    Ok(Json(LoginResponse { token: Some(token), mfa_token: None, mfa_setup_required: false }))
}
```

- [ ] **Step 5: Run to verify the tests pass**

Run: `cargo test -p hangar-api routes::auth:: -- --nocapture 2>&1 | tail -60`
Expected: PASS, including all pre-existing `auth.rs` tests (no regressions) and the 4 new ones.

- [ ] **Step 6: Regenerate the sqlx offline cache**

This task introduces no new SQL query text of its own (it only calls existing repository methods) — run `cargo sqlx prepare --workspace -- --all-targets` anyway and confirm `.sqlx/` shows no diff.

- [ ] **Step 7: Commit**

```bash
git add crates/hangar-api/src/dto.rs crates/hangar-api/src/routes/auth.rs
git commit -m "feat: add POST /api/auth/sso/ldap and GET /api/auth/sso/config"
```

---

### Task 10: Organization admin routes — list, detail, identity-provider config

**Files:**
- Modify: `crates/hangar-api/src/routes/organizations.rs`

**Interfaces:**
- Produces: `GET /api/organizations` (list), `GET /api/organizations/:id` (detail), `GET /api/organizations/:id/identity-provider` (read config, secret masked), `PUT /api/organizations/:id/identity-provider` (configure), `DELETE /api/organizations/:id/identity-provider` (clear) — all added to `pub fn router()` in this file. Task 12's frontend `organizations` port/adapter consumes all five over HTTP.

- [ ] **Step 1: Write the failing tests**

Add to `crates/hangar-api/src/routes/organizations.rs`'s `#[cfg(test)] mod tests`. These tests only need the super-admin and regular-member cases at the route level — the "own org admin" branch of `require_organization_admin` is already covered directly by Task 7's unit tests, and there is no route yet to promote a user to org-admin (out of scope for this plan), so no new test helper is needed beyond the existing `bearer` function already in this file from the Foundation plan:

```rust
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_list_organizations(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/organizations").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().iter().any(|o| o["slug"] == "public"));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_super_admin_cannot_list_organizations(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "regular", "sup3r-s3cret!", false).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/organizations").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn getting_an_unconfigured_organizations_identity_provider_returns_no_type(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["type"].is_null());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_configure_ldap_for_any_organization(pool: sqlx::PgPool) {
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
                    .body(Body::from(
                        r#"{"server_url":"ldap://dc.corp.example:389","bind_dn":"cn=service,dc=corp,dc=example","bind_password":"s3cret!","user_search_base":"ou=people,dc=corp,dc=example","user_search_filter":"(uid={username})","email_attribute":"mail"}"#,
                    ))
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
        assert_eq!(json["type"], "ldap");
        assert_eq!(json["server_url"], "ldap://dc.corp.example:389");
        assert_eq!(json["bind_password_set"], true);
        assert!(json.get("bind_password").is_none(), "the secret must never be echoed back");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_configure_ldap(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "regular", "sup3r-s3cret!", false).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(
                        r#"{"server_url":"ldap://dc.corp.example:389","bind_dn":"cn=service,dc=corp,dc=example","bind_password":"s3cret!","user_search_base":"ou=people,dc=corp,dc=example","user_search_filter":"(uid={username})","email_attribute":"mail"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn clearing_removes_the_configuration(pool: sqlx::PgPool) {
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
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/organizations/{}/identity-provider", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        assert_eq!(state.identity_providers.get(public_org.id).await.unwrap(), None);
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p hangar-api routes::organizations:: 2>&1 | tail -40`
Expected: FAIL to compile (new routes/handlers don't exist).

- [ ] **Step 3: Implement the routes**

In `crates/hangar-api/src/routes/organizations.rs`, update the router and imports:

```rust
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth_middleware::AuthUser;
use crate::authz::{require_organization_admin, require_super_admin};
use crate::dto::{application_error_response, ErrorResponse};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/organizations", get(list_organizations).post(create_organization))
        .route("/api/organizations/:id", get(get_organization))
        .route(
            "/api/organizations/:id/identity-provider",
            get(get_identity_provider).put(set_identity_provider).delete(clear_identity_provider),
        )
}
```

Add, next to the existing `OrganizationResponse`:

```rust
async fn list_organizations(State(state): State<AppState>, user: AuthUser) -> Result<Json<Vec<OrganizationResponse>>, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let all = state.organizations.list_all().await.map_err(|e| application_error_response("failed to list organizations", e.into()))?;
    Ok(Json(all.into_iter().map(|o| OrganizationResponse { id: o.id, slug: o.slug.as_str().to_string(), display_name: o.display_name }).collect()))
}

async fn get_organization(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<Json<OrganizationResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let org = state
        .organizations
        .find_by_id(id)
        .await
        .map_err(|e| application_error_response("failed to get organization", e.into()))?
        .ok_or((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "organization not found".to_string() })))?;
    Ok(Json(OrganizationResponse { id: org.id, slug: org.slug.as_str().to_string(), display_name: org.display_name }))
}

#[derive(Serialize)]
struct IdentityProviderResponse {
    #[serde(rename = "type")]
    provider_type: Option<&'static str>,
    server_url: Option<String>,
    bind_dn: Option<String>,
    bind_password_set: bool,
    user_search_base: Option<String>,
    user_search_filter: Option<String>,
    email_attribute: Option<String>,
}

impl IdentityProviderResponse {
    fn none() -> Self {
        Self { provider_type: None, server_url: None, bind_dn: None, bind_password_set: false, user_search_base: None, user_search_filter: None, email_attribute: None }
    }
}

async fn get_identity_provider(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<Json<IdentityProviderResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let config = state.identity_providers.get(id).await.map_err(|e| application_error_response("failed to get identity provider", e.into()))?;
    let Some(hangar_domain::sso::IdentityProviderConfig::Ldap(ldap)) = config else {
        return Ok(Json(IdentityProviderResponse::none()));
    };
    Ok(Json(IdentityProviderResponse {
        provider_type: Some("ldap"),
        server_url: Some(ldap.server_url),
        bind_dn: Some(ldap.bind_dn),
        bind_password_set: true,
        user_search_base: Some(ldap.user_search_base),
        user_search_filter: Some(ldap.user_search_filter),
        email_attribute: Some(ldap.email_attribute),
    }))
}

#[derive(Deserialize)]
struct SetLdapConfigRequest {
    server_url: String,
    bind_dn: String,
    /// Omitted (or absent) means "keep the existing password" — only meaningful
    /// when a configuration already exists; required on first-time setup.
    #[serde(default)]
    bind_password: Option<String>,
    user_search_base: String,
    user_search_filter: String,
    email_attribute: String,
}

async fn set_identity_provider(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<SetLdapConfigRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;

    let bind_password = match body.bind_password {
        Some(password) if !password.trim().is_empty() => password,
        _ => {
            let existing = state.identity_providers.get(id).await.map_err(|e| application_error_response("failed to load existing identity provider", e.into()))?;
            match existing {
                Some(hangar_domain::sso::IdentityProviderConfig::Ldap(ldap)) => ldap.bind_password,
                None => return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "bind_password is required when configuring LDAP for the first time".to_string() }))),
            }
        }
    };

    if body.server_url.trim().is_empty() || body.bind_dn.trim().is_empty() || body.user_search_base.trim().is_empty() || body.user_search_filter.trim().is_empty() || body.email_attribute.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "all LDAP fields except bind_password (when updating) are required".to_string() })));
    }

    let config = hangar_domain::sso::IdentityProviderConfig::Ldap(hangar_domain::sso::LdapConfig {
        server_url: body.server_url,
        bind_dn: body.bind_dn,
        bind_password,
        user_search_base: body.user_search_base,
        user_search_filter: body.user_search_filter,
        email_attribute: body.email_attribute,
    });
    state.identity_providers.set(id, &config).await.map_err(|e| application_error_response("failed to set identity provider", e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn clear_identity_provider(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.identity_providers.clear(id).await.map_err(|e| application_error_response("failed to clear identity provider", e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}
```

Note: `application_error_response` takes an `ApplicationError`, but `state.organizations`/`state.identity_providers` return `DomainError` — check how the existing `create_organization` handler in this same file already bridges this (it calls `.map_err(|e| application_error_response("...", e))` directly on a `DomainError`-returning `Result`, per that handler's existing code you already read) and match that exact pattern rather than inserting `.into()` calls if the existing code doesn't need them — read `application_error_response`'s actual signature in `dto.rs` (Task 9 already touched this file) to confirm whether it takes `ApplicationError` or is generic enough to accept `DomainError` directly via a `From` impl, and adjust the `.map_err` calls above to compile cleanly either way.

- [ ] **Step 4: Run to verify the tests pass**

Run: `cargo test -p hangar-api routes::organizations:: -- --nocapture 2>&1 | tail -60`
Expected: PASS, including the 2 pre-existing tests from Foundation and the 7 new ones.

- [ ] **Step 5: Mutation-test the authorization gate**

Temporarily change `require_organization_admin(&user, id)` to `Ok(())` (unconditional) in `set_identity_provider`, re-run `a_non_admin_cannot_configure_ldap`, confirm it now FAILS (returns 204 instead of 403), then restore the check and confirm the test passes again.

- [ ] **Step 6: Commit**

```bash
git add crates/hangar-api/src/routes/organizations.rs
git commit -m "feat: add organization list/detail routes and LDAP identity-provider configuration"
```

---

### Task 11: `organizations` frontend port/service/adapter

**Files:**
- Create: `frontend/src/app/admin/domain/organization.entity.ts`
- Create: `frontend/src/app/admin/application/organizations.port.ts`
- Create: `frontend/src/app/admin/application/organizations.service.ts`
- Create: `frontend/src/app/admin/infrastructure/http-organizations.adapter.ts`
- Create: `frontend/src/app/admin/infrastructure/organizations.providers.ts`
- Modify: `frontend/src/app/app.config.ts` (register the new providers)

**Interfaces:**
- Produces: `OrganizationsService` with `list()`, `get(id)`, `getIdentityProvider(id)`, `setLdapIdentityProvider(id, config)`, `clearIdentityProvider(id)` — Task 12 and 13's components consume this service.

This mirrors `frontend/src/app/users/application/users.service.ts`'s exact hexagonal shape (port/service/adapter/providers), and `smtp-settings`'s "omit password to keep existing" convention for `setLdapIdentityProvider`.

- [ ] **Step 1: Domain entity**

Create `frontend/src/app/admin/domain/organization.entity.ts`:

```typescript
export interface OrganizationSummary {
  id: string
  slug: string
  display_name: string
}

export interface LdapIdentityProvider {
  type: 'ldap'
  server_url: string
  bind_dn: string
  bind_password_set: boolean
  user_search_base: string
  user_search_filter: string
  email_attribute: string
}

export interface NoIdentityProvider {
  type: null
}

export type IdentityProviderSummary = LdapIdentityProvider | NoIdentityProvider

export interface LdapIdentityProviderInput {
  server_url: string
  bind_dn: string
  /** Omit (or empty string) to keep the existing password when updating. */
  bind_password?: string
  user_search_base: string
  user_search_filter: string
  email_attribute: string
}
```

- [ ] **Step 2: Port**

Create `frontend/src/app/admin/application/organizations.port.ts`:

```typescript
import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import {
  IdentityProviderSummary,
  LdapIdentityProviderInput,
  OrganizationSummary,
} from '../domain/organization.entity'

/** Everything the application layer needs from wherever organizations actually live — implemented by an infrastructure adapter, never called directly by a component. */
export interface OrganizationsPort {
  list(): Observable<OrganizationSummary[]>
  get(id: string): Observable<OrganizationSummary>
  getIdentityProvider(id: string): Observable<IdentityProviderSummary>
  setLdapIdentityProvider(id: string, config: LdapIdentityProviderInput): Observable<void>
  clearIdentityProvider(id: string): Observable<void>
}

export const ORGANIZATIONS_PORT = new InjectionToken<OrganizationsPort>('OrganizationsPort')
```

- [ ] **Step 3: Write the failing test for the service**

Create `frontend/src/app/admin/application/organizations.service.spec.ts`:

```typescript
import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { OrganizationsService } from './organizations.service'
import { ORGANIZATIONS_PORT, OrganizationsPort } from './organizations.port'

describe('OrganizationsService', () => {
  function setup(port: Partial<OrganizationsPort>) {
    TestBed.configureTestingModule({
      providers: [OrganizationsService, { provide: ORGANIZATIONS_PORT, useValue: port }],
    })
    return TestBed.inject(OrganizationsService)
  }

  it('lists organizations from the port', () => {
    const orgs = [{ id: '1', slug: 'acme', display_name: 'Acme' }]
    const service = setup({ list: () => of(orgs) })

    let result
    service.list().subscribe((r) => (result = r))

    expect(result).toEqual(orgs)
  })

  it('caches the list and clears the cache after configuring an identity provider', () => {
    let listCalls = 0
    const service = setup({
      list: () => {
        listCalls++
        return of([])
      },
      setLdapIdentityProvider: () => of(undefined),
    })

    // Each subscribe below fires synchronously (of(...) emits immediately), so this
    // reads top-to-bottom rather than needing a done callback or nested subscribes.
    service.list().subscribe()
    service.list().subscribe()
    expect(listCalls).toBe(1)

    service
      .setLdapIdentityProvider('1', {
        server_url: 'ldap://x',
        bind_dn: 'cn=x',
        user_search_base: 'ou=x',
        user_search_filter: '(uid={username})',
        email_attribute: 'mail',
      })
      .subscribe()
    service.list().subscribe()
    expect(listCalls).toBe(2)
  })
})
```

- [ ] **Step 4: Run to verify it fails**

Run: `cd frontend && npx ng test --watch=false --include='**/organizations.service.spec.ts'`
Expected: FAIL — `./organizations.service` doesn't exist yet.

- [ ] **Step 5: Service**

Create `frontend/src/app/admin/application/organizations.service.ts`:

```typescript
import { Injectable, inject } from '@angular/core'
import { Observable, catchError, shareReplay, tap, throwError } from 'rxjs'
import {
  IdentityProviderSummary,
  LdapIdentityProviderInput,
  OrganizationSummary,
} from '../domain/organization.entity'
import { ORGANIZATIONS_PORT } from './organizations.port'

@Injectable({ providedIn: 'root' })
export class OrganizationsService {
  private readonly port = inject(ORGANIZATIONS_PORT)

  private cachedList$: Observable<OrganizationSummary[]> | null = null

  list(options?: { forceRefresh?: boolean }): Observable<OrganizationSummary[]> {
    if (!this.cachedList$ || options?.forceRefresh) {
      this.cachedList$ = this.port.list().pipe(
        catchError((err: unknown) => {
          this.cachedList$ = null
          return throwError(() => err)
        }),
        shareReplay(1),
      )
    }
    return this.cachedList$
  }

  get(id: string): Observable<OrganizationSummary> {
    return this.port.get(id)
  }

  getIdentityProvider(id: string): Observable<IdentityProviderSummary> {
    return this.port.getIdentityProvider(id)
  }

  setLdapIdentityProvider(id: string, config: LdapIdentityProviderInput): Observable<void> {
    return this.port.setLdapIdentityProvider(id, config).pipe(tap(() => (this.cachedList$ = null)))
  }

  clearIdentityProvider(id: string): Observable<void> {
    return this.port.clearIdentityProvider(id).pipe(tap(() => (this.cachedList$ = null)))
  }
}
```

- [ ] **Step 6: Run to verify the tests pass**

Run: `cd frontend && npx ng test --watch=false --include='**/organizations.service.spec.ts'`
Expected: PASS.

- [ ] **Step 7: HTTP adapter**

Create `frontend/src/app/admin/infrastructure/http-organizations.adapter.ts`:

```typescript
import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import {
  IdentityProviderSummary,
  LdapIdentityProviderInput,
  OrganizationSummary,
} from '../domain/organization.entity'
import { OrganizationsPort } from '../application/organizations.port'

@Injectable()
export class HttpOrganizationsAdapter implements OrganizationsPort {
  private readonly http = inject(HttpClient)

  list(): Observable<OrganizationSummary[]> {
    return this.http.get<OrganizationSummary[]>('/api/organizations')
  }

  get(id: string): Observable<OrganizationSummary> {
    return this.http.get<OrganizationSummary>(`/api/organizations/${id}`)
  }

  getIdentityProvider(id: string): Observable<IdentityProviderSummary> {
    return this.http.get<IdentityProviderSummary>(`/api/organizations/${id}/identity-provider`)
  }

  setLdapIdentityProvider(id: string, config: LdapIdentityProviderInput): Observable<void> {
    return this.http.put<void>(`/api/organizations/${id}/identity-provider`, config)
  }

  clearIdentityProvider(id: string): Observable<void> {
    return this.http.delete<void>(`/api/organizations/${id}/identity-provider`)
  }
}
```

- [ ] **Step 8: Write the failing test for the adapter**

Create `frontend/src/app/admin/infrastructure/http-organizations.adapter.spec.ts`:

```typescript
import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpOrganizationsAdapter } from './http-organizations.adapter'

describe('HttpOrganizationsAdapter', () => {
  function setup() {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpOrganizationsAdapter],
    })
    return {
      adapter: TestBed.inject(HttpOrganizationsAdapter),
      httpMock: TestBed.inject(HttpTestingController),
    }
  }

  it('lists organizations from GET /api/organizations', () => {
    const { adapter, httpMock } = setup()
    adapter.list().subscribe()
    const req = httpMock.expectOne('/api/organizations')
    expect(req.request.method).toBe('GET')
    req.flush([])
    httpMock.verify()
  })

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
    expect(req.request.body).toEqual(config)
    req.flush(null)
    httpMock.verify()
  })

  it('deletes the identity provider config', () => {
    const { adapter, httpMock } = setup()
    adapter.clearIdentityProvider('org-1').subscribe()
    const req = httpMock.expectOne('/api/organizations/org-1/identity-provider')
    expect(req.request.method).toBe('DELETE')
    req.flush(null)
    httpMock.verify()
  })
})
```

- [ ] **Step 9: Run to verify the tests pass**

Run: `cd frontend && npx ng test --watch=false --include='**/http-organizations.adapter.spec.ts'`
Expected: PASS.

- [ ] **Step 10: Providers, registered globally**

Create `frontend/src/app/admin/infrastructure/organizations.providers.ts`:

```typescript
import { Provider } from '@angular/core'
import { ORGANIZATIONS_PORT } from '../application/organizations.port'
import { HttpOrganizationsAdapter } from './http-organizations.adapter'

export const organizationsProviders: Provider[] = [
  { provide: ORGANIZATIONS_PORT, useClass: HttpOrganizationsAdapter },
]
```

In `frontend/src/app/app.config.ts`, add the import next to the existing `userProviders` import and spread it into the same providers array, next to `...userProviders,`:

```typescript
import { organizationsProviders } from './admin/infrastructure/organizations.providers'
```

```typescript
    ...organizationsProviders,
```

- [ ] **Step 11: Run the full frontend suite**

Run: `cd frontend && npx ng test --watch=false`
Expected: PASS (baseline 379 + this task's new tests, no regressions).

- [ ] **Step 12: Commit**

```bash
git add frontend/src/app/admin/domain/organization.entity.ts frontend/src/app/admin/application/organizations.port.ts frontend/src/app/admin/application/organizations.service.ts frontend/src/app/admin/application/organizations.service.spec.ts frontend/src/app/admin/infrastructure/http-organizations.adapter.ts frontend/src/app/admin/infrastructure/http-organizations.adapter.spec.ts frontend/src/app/admin/infrastructure/organizations.providers.ts frontend/src/app/app.config.ts
git commit -m "feat(frontend): add organizations port/service/adapter"
```

---

### Task 12: `OrganizationsList` admin page

**Files:**
- Create: `frontend/src/app/admin/organizations-list/organizations-list.ts`
- Create: `frontend/src/app/admin/organizations-list/organizations-list.html`
- Create: `frontend/src/app/admin/organizations-list/organizations-list.spec.ts`

**Interfaces:**
- Consumes: `OrganizationsService.list()` (Task 11).
- Produces: standalone `OrganizationsList` component, selector `app-organizations-list` — Task 14 wires it into `app.routes.ts` at `admin/organizations`.

This mirrors `frontend/src/app/users/users-list/users-list.ts`'s exact table-plus-navigate pattern (read that file's `.ts` and `.html` again if needed — you already have them from this plan's own reconnaissance).

- [ ] **Step 1: Write the failing test**

Create `frontend/src/app/admin/organizations-list/organizations-list.spec.ts`:

```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing'
import { Router } from '@angular/router'
import { provideRouter } from '@angular/router'
import { of } from 'rxjs'
import { OrganizationsList } from './organizations-list'
import { OrganizationsService } from '../application/organizations.service'

describe('OrganizationsList', () => {
  let fixture: ComponentFixture<OrganizationsList>
  let component: OrganizationsList
  let router: Router

  function setup(organizations: { id: string; slug: string; display_name: string }[]) {
    TestBed.configureTestingModule({
      imports: [OrganizationsList],
      providers: [
        provideRouter([]),
        { provide: OrganizationsService, useValue: { list: () => of(organizations) } },
      ],
    })
    fixture = TestBed.createComponent(OrganizationsList)
    component = fixture.componentInstance
    router = TestBed.inject(Router)
    fixture.detectChanges()
  }

  it('loads organizations on init', () => {
    setup([{ id: '1', slug: 'acme', display_name: 'Acme' }])
    expect(component.organizations()).toEqual([{ id: '1', slug: 'acme', display_name: 'Acme' }])
  })

  it('navigates to the organization detail page on row click', () => {
    setup([{ id: '1', slug: 'acme', display_name: 'Acme' }])
    const navigateSpy = spyOn(router, 'navigate')

    component.openDetail({ id: '1', slug: 'acme', display_name: 'Acme' })

    expect(navigateSpy).toHaveBeenCalledWith(['/admin/organizations', '1'])
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd frontend && npx ng test --watch=false --include='**/organizations-list.spec.ts'`
Expected: FAIL — `./organizations-list` doesn't exist yet.

- [ ] **Step 3: Implement**

Create `frontend/src/app/admin/organizations-list/organizations-list.ts`:

```typescript
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core'
import { Router } from '@angular/router'
import { Table, TableColumn } from '@masmarino/gabarit'
import { OrganizationsService } from '../application/organizations.service'
import { OrganizationSummary } from '../domain/organization.entity'

@Component({
  selector: 'app-organizations-list',
  standalone: true,
  imports: [Table],
  templateUrl: './organizations-list.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationsList implements OnInit {
  private readonly organizationsService = inject(OrganizationsService)
  private readonly router = inject(Router)

  readonly organizations = signal<OrganizationSummary[]>([])
  readonly loading = signal(true)
  readonly error = signal<string | null>(null)

  readonly columns: TableColumn<OrganizationSummary>[] = [
    { key: 'slug', label: 'Sous-domaine' },
    { key: 'display_name', label: 'Nom' },
  ]
  readonly rowId = (o: OrganizationSummary): string => o.id

  ngOnInit(): void {
    this.organizationsService.list().subscribe({
      next: (organizations) => {
        this.organizations.set(organizations)
        this.loading.set(false)
      },
      error: () => {
        this.loading.set(false)
        this.error.set('Échec du chargement des organisations.')
      },
    })
  }

  openDetail(organization: OrganizationSummary): void {
    this.router.navigate(['/admin/organizations', organization.id])
  }
}
```

Create `frontend/src/app/admin/organizations-list/organizations-list.html`:

```html
@if (loading()) {
  <p>Chargement…</p>
} @else if (error(); as message) {
  <p class="gbt-form-error" role="alert">{{ message }}</p>
} @else {
  <gbt-table
    caption="Organisations"
    emptyMessage="Aucune organisation"
    [clickableRows]="true"
    [data]="organizations()"
    [columns]="columns"
    [trackBy]="rowId"
    (rowClick)="openDetail($event)"
  />
}
```

- [ ] **Step 4: Run to verify the tests pass**

Run: `cd frontend && npx ng test --watch=false --include='**/organizations-list.spec.ts'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/app/admin/organizations-list/
git commit -m "feat(frontend): add OrganizationsList admin page"
```

---

### Task 13: `OrganizationDetail` admin page (LDAP configuration form)

**Files:**
- Create: `frontend/src/app/admin/organization-detail/organization-detail.ts`
- Create: `frontend/src/app/admin/organization-detail/organization-detail.html`
- Create: `frontend/src/app/admin/organization-detail/organization-detail.spec.ts`

**Interfaces:**
- Consumes: `OrganizationsService.get`, `getIdentityProvider`, `setLdapIdentityProvider`, `clearIdentityProvider` (Task 11).
- Produces: standalone `OrganizationDetail` component, selector `app-organization-detail` — Task 14 wires it into `app.routes.ts` at `admin/organizations/:id`.

This mirrors `frontend/src/app/admin/smtp-settings/smtp-settings.ts`'s exact form shape (per-field `computed` validators, a `bind_password_set`-style boolean standing in for `passwordSet`, save/saved/error signals) combined with `frontend/src/app/users/user-detail/user-detail.ts`'s route-param-driven loading pattern (`toSignal` on the route param, an `effect` that reloads on param change).

- [ ] **Step 1: Write the failing test**

Create `frontend/src/app/admin/organization-detail/organization-detail.spec.ts`:

```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing'
import { ActivatedRoute, convertToParamMap } from '@angular/router'
import { of } from 'rxjs'
import { OrganizationDetail } from './organization-detail'
import { OrganizationsService } from '../application/organizations.service'
import { PageTitleService } from '../../shell/page-title.service'

describe('OrganizationDetail', () => {
  let fixture: ComponentFixture<OrganizationDetail>
  let component: OrganizationDetail
  let organizationsServiceSpy: jasmine.SpyObj<OrganizationsService>

  function setup() {
    organizationsServiceSpy = jasmine.createSpyObj<OrganizationsService>('OrganizationsService', [
      'get',
      'getIdentityProvider',
      'setLdapIdentityProvider',
      'clearIdentityProvider',
    ])
    organizationsServiceSpy.get.and.returnValue(of({ id: 'org-1', slug: 'acme', display_name: 'Acme' }))
    organizationsServiceSpy.getIdentityProvider.and.returnValue(of({ type: null }))

    TestBed.configureTestingModule({
      imports: [OrganizationDetail],
      providers: [
        { provide: OrganizationsService, useValue: organizationsServiceSpy },
        { provide: PageTitleService, useValue: { title: { set: () => {} } } },
        {
          provide: ActivatedRoute,
          useValue: { paramMap: of(convertToParamMap({ id: 'org-1' })) },
        },
      ],
    })
    fixture = TestBed.createComponent(OrganizationDetail)
    component = fixture.componentInstance
    fixture.detectChanges()
  }

  it('loads the organization and its identity provider on init', () => {
    setup()
    expect(organizationsServiceSpy.get).toHaveBeenCalledWith('org-1')
    expect(organizationsServiceSpy.getIdentityProvider).toHaveBeenCalledWith('org-1')
    expect(component.organization()?.display_name).toBe('Acme')
    expect(component.identityProviderConfigured()).toBe(false)
  })

  it('reflects an existing LDAP configuration', () => {
    organizationsServiceSpy = jasmine.createSpyObj<OrganizationsService>('OrganizationsService', [
      'get',
      'getIdentityProvider',
      'setLdapIdentityProvider',
      'clearIdentityProvider',
    ])
    organizationsServiceSpy.get.and.returnValue(of({ id: 'org-1', slug: 'acme', display_name: 'Acme' }))
    organizationsServiceSpy.getIdentityProvider.and.returnValue(
      of({
        type: 'ldap',
        server_url: 'ldap://dc.corp.example:389',
        bind_dn: 'cn=service,dc=corp,dc=example',
        bind_password_set: true,
        user_search_base: 'ou=people,dc=corp,dc=example',
        user_search_filter: '(uid={username})',
        email_attribute: 'mail',
      }),
    )
    TestBed.configureTestingModule({
      imports: [OrganizationDetail],
      providers: [
        { provide: OrganizationsService, useValue: organizationsServiceSpy },
        { provide: PageTitleService, useValue: { title: { set: () => {} } } },
        { provide: ActivatedRoute, useValue: { paramMap: of(convertToParamMap({ id: 'org-1' })) } },
      ],
    })
    fixture = TestBed.createComponent(OrganizationDetail)
    component = fixture.componentInstance
    fixture.detectChanges()

    expect(component.identityProviderConfigured()).toBe(true)
    expect(component.serverUrl()).toBe('ldap://dc.corp.example:389')
    expect(component.bindPasswordSet()).toBe(true)
  })

  it('saves the LDAP configuration', () => {
    setup()
    organizationsServiceSpy.setLdapIdentityProvider.and.returnValue(of(undefined))
    component.serverUrl.set('ldap://dc.corp.example:389')
    component.bindDn.set('cn=service,dc=corp,dc=example')
    component.bindPassword.set('s3cret!')
    component.userSearchBase.set('ou=people,dc=corp,dc=example')
    component.userSearchFilter.set('(uid={username})')
    component.emailAttribute.set('mail')

    component.save()

    expect(organizationsServiceSpy.setLdapIdentityProvider).toHaveBeenCalledWith('org-1', {
      server_url: 'ldap://dc.corp.example:389',
      bind_dn: 'cn=service,dc=corp,dc=example',
      bind_password: 's3cret!',
      user_search_base: 'ou=people,dc=corp,dc=example',
      user_search_filter: '(uid={username})',
      email_attribute: 'mail',
    })
  })

  it('clears the LDAP configuration', () => {
    setup()
    organizationsServiceSpy.clearIdentityProvider.and.returnValue(of(undefined))

    component.clear()

    expect(organizationsServiceSpy.clearIdentityProvider).toHaveBeenCalledWith('org-1')
  })
})
```

If this project's frontend test runner is Vitest (confirmed in an earlier phase of this same session's work — see `angular.json`'s `@angular/build:unit-test` builder and `package.json`'s `vitest` devDependency, no jasmine/karma anywhere), translate every `jasmine.createSpyObj`/`.and.returnValue` in the test above to `vi.fn()`/`.mockReturnValue(...)` equivalents before writing the file, preserving every test name and assertion exactly — follow the established translation pattern already used in this codebase's `frontend/src/app/auth/mfa-enrollment/mfa-enrollment.spec.ts` and `frontend/src/app/auth/register-page/register-page.spec.ts`.

- [ ] **Step 2: Run to verify it fails**

Run: `cd frontend && npx ng test --watch=false --include='**/organization-detail.spec.ts'`
Expected: FAIL — `./organization-detail` doesn't exist yet.

- [ ] **Step 3: Implement**

Create `frontend/src/app/admin/organization-detail/organization-detail.ts`:

```typescript
import { ChangeDetectionStrategy, Component, computed, effect, inject, signal } from '@angular/core'
import { toSignal } from '@angular/core/rxjs-interop'
import { ActivatedRoute } from '@angular/router'
import { map } from 'rxjs'
import { FormsModule } from '@angular/forms'
import { Button, Card, GbtInput } from '@masmarino/gabarit'
import { PageTitleService } from '../../shell/page-title.service'
import { OrganizationsService } from '../application/organizations.service'
import { OrganizationSummary } from '../domain/organization.entity'

@Component({
  selector: 'app-organization-detail',
  standalone: true,
  imports: [Card, GbtInput, Button, FormsModule],
  templateUrl: './organization-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationDetail {
  private readonly route = inject(ActivatedRoute)
  private readonly organizationsService = inject(OrganizationsService)
  private readonly pageTitle = inject(PageTitleService)

  private readonly routeOrganizationId = toSignal(
    this.route.paramMap.pipe(map((params) => params.get('id')!)),
    { requireSync: true },
  )
  private organizationId!: string

  readonly organization = signal<OrganizationSummary | null>(null)
  readonly loading = signal(true)

  readonly identityProviderConfigured = signal(false)
  readonly serverUrl = signal('')
  readonly bindDn = signal('')
  readonly bindPassword = signal('')
  readonly bindPasswordSet = signal(false)
  readonly userSearchBase = signal('')
  readonly userSearchFilter = signal('')
  readonly emailAttribute = signal('')

  readonly saving = signal(false)
  readonly saved = signal(false)
  readonly errorMessage = signal<string | null>(null)
  readonly clearing = signal(false)

  readonly hasErrors = computed(
    () =>
      this.serverUrl().trim() === '' ||
      this.bindDn().trim() === '' ||
      this.userSearchBase().trim() === '' ||
      this.userSearchFilter().trim() === '' ||
      this.emailAttribute().trim() === '' ||
      (!this.bindPasswordSet() && this.bindPassword().trim() === ''),
  )

  constructor() {
    effect(() => {
      this.organizationId = this.routeOrganizationId()
      this.reload()
    })
  }

  private reload(): void {
    const requestedId = this.organizationId
    this.organizationsService.get(requestedId).subscribe((organization) => {
      if (requestedId === this.organizationId) {
        this.organization.set(organization)
        this.pageTitle.title.set(organization.display_name)
        this.loading.set(false)
      }
    })
    this.organizationsService.getIdentityProvider(requestedId).subscribe((config) => {
      if (requestedId !== this.organizationId) {
        return
      }
      if (config.type === 'ldap') {
        this.identityProviderConfigured.set(true)
        this.serverUrl.set(config.server_url)
        this.bindDn.set(config.bind_dn)
        this.bindPasswordSet.set(config.bind_password_set)
        this.userSearchBase.set(config.user_search_base)
        this.userSearchFilter.set(config.user_search_filter)
        this.emailAttribute.set(config.email_attribute)
      } else {
        this.identityProviderConfigured.set(false)
      }
    })
  }

  save(): void {
    this.saved.set(false)
    this.errorMessage.set(null)
    if (this.hasErrors()) {
      return
    }
    this.saving.set(true)
    this.organizationsService
      .setLdapIdentityProvider(this.organizationId, {
        server_url: this.serverUrl(),
        bind_dn: this.bindDn(),
        bind_password: this.bindPassword().trim() === '' ? undefined : this.bindPassword(),
        user_search_base: this.userSearchBase(),
        user_search_filter: this.userSearchFilter(),
        email_attribute: this.emailAttribute(),
      })
      .subscribe({
        next: () => {
          this.saving.set(false)
          this.saved.set(true)
          this.identityProviderConfigured.set(true)
          this.bindPasswordSet.set(true)
          this.bindPassword.set('')
        },
        error: () => {
          this.saving.set(false)
          this.errorMessage.set('Échec de la mise à jour de la configuration LDAP.')
        },
      })
  }

  clear(): void {
    if (!confirm('Revenir aux comptes locaux pour cette organisation ?')) {
      return
    }
    this.clearing.set(true)
    this.errorMessage.set(null)
    this.organizationsService.clearIdentityProvider(this.organizationId).subscribe({
      next: () => {
        this.clearing.set(false)
        this.identityProviderConfigured.set(false)
        this.serverUrl.set('')
        this.bindDn.set('')
        this.bindPasswordSet.set(false)
        this.userSearchBase.set('')
        this.userSearchFilter.set('')
        this.emailAttribute.set('')
      },
      error: () => {
        this.clearing.set(false)
        this.errorMessage.set('Échec de la suppression de la configuration LDAP.')
      },
    })
  }
}
```

Create `frontend/src/app/admin/organization-detail/organization-detail.html`:

```html
@if (loading()) {
  <p>Chargement…</p>
} @else if (organization(); as org) {
  <gbt-card>
    <h2>{{ org.display_name }}</h2>
    <p>Sous-domaine : {{ org.slug }}</p>
  </gbt-card>

  <gbt-card>
    <h3>Authentification LDAP</h3>
    @if (identityProviderConfigured()) {
      <p>LDAP est actuellement configuré pour cette organisation.</p>
    } @else {
      <p>Cette organisation utilise des comptes locaux.</p>
    }

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

    @if (errorMessage(); as message) {
      <p class="gbt-form-error" role="alert">{{ message }}</p>
    }
    @if (saved()) {
      <p>Configuration enregistrée.</p>
    }

    <gbt-button
      text="Enregistrer"
      [loading]="saving()"
      loadingLabel="Enregistrement…"
      [disabled]="hasErrors() || saving()"
      (clicked)="save()"
    />
    @if (identityProviderConfigured()) {
      <gbt-button
        text="Revenir aux comptes locaux"
        variant="secondary"
        [loading]="clearing()"
        loadingLabel="Suppression…"
        (clicked)="clear()"
      />
    }
  </gbt-card>
}
```

- [ ] **Step 4: Run to verify the tests pass**

Run: `cd frontend && npx ng test --watch=false --include='**/organization-detail.spec.ts'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/app/admin/organization-detail/
git commit -m "feat(frontend): add OrganizationDetail admin page with LDAP configuration"
```

---

### Task 14: Wire the admin organizations pages into routing and navigation

**Files:**
- Modify: `frontend/src/app/app.routes.ts`
- Modify: `frontend/src/app/shell/app-shell.ts`

**Interfaces:**
- Consumes: `OrganizationsList` (Task 12), `OrganizationDetail` (Task 13).
- Produces: routes `admin/organizations` and `admin/organizations/:id`, reachable from the admin nav.

- [ ] **Step 1: Add the routes**

In `frontend/src/app/app.routes.ts`, inside the authenticated shell's `children` array, next to the existing `'admin'` route, add:

```typescript
      {
        path: 'admin/organizations',
        loadComponent: () =>
          import('./admin/organizations-list/organizations-list').then((m) => m.OrganizationsList),
        canActivate: [adminGuard],
        data: { title: 'Organisations' },
      },
      {
        path: 'admin/organizations/:id',
        loadComponent: () =>
          import('./admin/organization-detail/organization-detail').then((m) => m.OrganizationDetail),
        canActivate: [adminGuard],
      },
```

- [ ] **Step 2: Add the nav entry**

In `frontend/src/app/shell/app-shell.ts`'s `navItems` computed property, add to the `children` array (next to `{ action: 'settings', ... }`):

```typescript
          { action: 'organizations', icon: 'building', text: 'Organisations', link: '/admin/organizations' },
```

Check whether `'organizations'` needs adding to this file's `ADMIN_ONLY_ACTIONS` set (read the file to confirm whether that set already includes every action under the `admin` parent by some other mechanism, or whether each child action must be listed individually — match whatever the existing entries like `'settings'`/`'smtp'` already do).

- [ ] **Step 3: Manual verification note**

This task wires navigation only — verifying the icon (`building`) actually renders (rather than a missing-icon fallback) requires a running frontend with the `@masmarino/gabarit` icon set loaded. Note in the task report whether this was checked; if the icon name doesn't exist in that library, pick any other icon already used elsewhere in this same `navItems` array as a safe fallback (e.g. `'shield'` or `'layout-dashboard'`) rather than guessing a new one.

- [ ] **Step 4: Run the full frontend suite**

Run: `cd frontend && npx ng test --watch=false`
Expected: PASS, no regressions.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/app/app.routes.ts frontend/src/app/shell/app-shell.ts
git commit -m "feat(frontend): wire organizations admin pages into routing and navigation"
```

---

### Task 15: Login page — SSO awareness

**Files:**
- Modify: `frontend/src/app/auth/domain/auth.types.ts` (add `SsoConfig` type)
- Modify: `frontend/src/app/auth/application/auth.port.ts` (add `getSsoConfig`, `loginWithLdap`)
- Modify: `frontend/src/app/auth/infrastructure/http-auth.adapter.ts` (implement both)
- Modify: `frontend/src/app/auth/application/auth.service.ts` (add `getSsoConfig`, `loginWithLdap`)
- Modify: `frontend/src/app/auth/login-page/login-page.ts`
- Modify: `frontend/src/app/auth/login-page/login-page.html`

**Interfaces:**
- Produces: `AuthService.getSsoConfig(): Observable<SsoConfig>`, `AuthService.loginWithLdap(username, password): Observable<LoginOutcome>` — `LoginPage` calls both; `loginWithLdap` reuses the exact same `toOutcome` mapping `login`/`register` already share (Task 5 of the public-registration plan established this factoring).

- [ ] **Step 1: Add the domain type**

In `frontend/src/app/auth/domain/auth.types.ts`, add:

```typescript
export interface SsoConfig {
  type: 'ldap' | null
}
```

- [ ] **Step 2: Port + adapter**

In `frontend/src/app/auth/application/auth.port.ts`, add to `AuthPort`:

```typescript
  getSsoConfig(): Observable<SsoConfig>
  loginWithLdap(username: string, password: string): Observable<LoginResponse>
```

(add `SsoConfig` to the existing `import { ... } from '../domain/auth.types'` line).

In `frontend/src/app/auth/infrastructure/http-auth.adapter.ts`, add:

```typescript
  getSsoConfig(): Observable<SsoConfig> {
    return this.http.get<SsoConfig>('/api/auth/sso/config')
  }

  loginWithLdap(username: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>('/api/auth/sso/ldap', { username, password })
  }
```

(add `SsoConfig` to that file's existing import from `'../domain/auth.types'` too).

- [ ] **Step 3: Write the failing test for the adapter**

Add to `frontend/src/app/auth/infrastructure/http-auth.adapter.spec.ts`:

```typescript
  it('gets the sso config from GET /api/auth/sso/config', () => {
    const { adapter, httpMock } = setup()
    adapter.getSsoConfig().subscribe()
    const req = httpMock.expectOne('/api/auth/sso/config')
    expect(req.request.method).toBe('GET')
    req.flush({ type: null })
    httpMock.verify()
  })

  it('posts username/password to /api/auth/sso/ldap', () => {
    const { adapter, httpMock } = setup()
    adapter.loginWithLdap('florian', 's3cret!').subscribe()
    const req = httpMock.expectOne('/api/auth/sso/ldap')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({ username: 'florian', password: 's3cret!' })
    req.flush({ token: 'a-jwt-token', mfa_token: null, mfa_setup_required: false })
    httpMock.verify()
  })
```

- [ ] **Step 4: Run to verify it fails, then implement, then verify it passes**

Run: `cd frontend && npx ng test --watch=false --include='**/http-auth.adapter.spec.ts'` — should FAIL until Step 2's code is in place, then PASS once it is (Steps 2 and 3 can be done together; this is listed separately only to keep the TDD record honest — write the test, watch it fail against the adapter as it existed before this task, then add the two methods).

- [ ] **Step 5: `AuthService`**

In `frontend/src/app/auth/application/auth.service.ts`, add:

```typescript
  getSsoConfig(): Observable<SsoConfig> {
    return this.port.getSsoConfig()
  }

  loginWithLdap(username: string, password: string): Observable<LoginOutcome> {
    return this.port.loginWithLdap(username, password).pipe(map((response) => this.toOutcome(response)))
  }
```

(add `SsoConfig` to the existing import from `'../domain/auth.types'`).

- [ ] **Step 6: Write the failing test for `AuthService.loginWithLdap`**

Add to `frontend/src/app/auth/application/auth.service.spec.ts`:

```typescript
  it('reports success when LDAP login returns a token directly', () => {
    const response: LoginResponse = { token: 'a-jwt-token', mfa_token: null, mfa_setup_required: false }
    const service = setup({ loginWithLdap: () => of(response) })

    let outcome
    service.loginWithLdap('florian', 's3cret!').subscribe((o) => (outcome = o))

    expect(outcome!.mfaRequired).toBe(false)
  })
```

Note: write this test with a synchronous subscribe-then-assert (as above), not a `(done) => { ...; done() }` callback — `of(...)` emits synchronously, and this file's Vitest-based test runner types `it`'s single callback parameter as `TestContext`, not a Jasmine-style completion callback, so a parameter named `done` fails to typecheck when called as a function. Mirror `auth.service.spec.ts`'s own existing tests (e.g. `'stores the token and flips isAuthenticated on a login without mfa'`), which already use exactly this synchronous pattern.

Run: `cd frontend && npx ng test --watch=false --include='**/auth.service.spec.ts'` — verify it fails first (against the pre-Step-5 service), then passes after Step 5's addition.

- [ ] **Step 7: `LoginPage` — detect SSO on init, branch `submit()`**

In `frontend/src/app/auth/login-page/login-page.ts`, add an `OnInit` that fetches the SSO config and stores whether this organization uses LDAP, and branch `submit()` accordingly:

```typescript
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core'
```

(add `OnInit` to the existing import)

```typescript
export class LoginPage implements OnInit {
```

Add a field:

```typescript
  readonly usesLdap = signal(false)
```

Add the lifecycle hook (place it near the top of the class body, after field declarations):

```typescript
  ngOnInit(): void {
    this.auth.getSsoConfig().subscribe({
      next: (config) => this.usesLdap.set(config.type === 'ldap'),
      // Local login is always a safe fallback — never block the form on this check failing.
      error: () => this.usesLdap.set(false),
    })
  }
```

Update `submit()` to branch on `this.usesLdap()`:

```typescript
  submit(): void {
    if (this.form.invalid || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    const { username, password } = this.form.getRawValue()
    const attempt = this.usesLdap() ? this.auth.loginWithLdap(username, password) : this.auth.login(username, password)
    attempt.subscribe({
      next: (outcome) => {
        if (outcome.mfaRequired && outcome.mfaToken) {
          this.submitting.set(false)
          this.mfaToken.set(outcome.mfaToken)
          this.mfaSetupRequired.set(!!outcome.mfaSetupRequired)
        } else {
          this.router.navigateByUrl('/')
        }
      },
      error: () => {
        this.submitting.set(false)
        this.errorMessage.set('Identifiants invalides')
      },
    })
  }
```

- [ ] **Step 8: Write the failing test**

Add to `frontend/src/app/auth/login-page/login-page.spec.ts` (translate to this project's actual test-double style — `vi.fn()`/Vitest, per the established convention referenced in Task 13 above — if the existing file already uses that style, match it exactly):

```typescript
  it('posts to the LDAP endpoint when the organization uses LDAP', () => {
    // set up the AuthService double so getSsoConfig() emits { type: 'ldap' } and
    // loginWithLdap is a spy the test can assert on, following this file's
    // existing AuthService-double pattern for its other tests
  })
```

Write this test to actually assert `authServiceSpy.loginWithLdap` was called (not `login`) once `usesLdap()` resolves to `true` and `submit()` runs — following whatever double-construction pattern this spec file already uses for `AuthService` (read the file's existing `beforeEach`/test setup first and match it exactly rather than inventing a new one).

- [ ] **Step 9: Run to verify it fails, then confirm it passes against Step 7's code**

Run: `cd frontend && npx ng test --watch=false --include='**/login-page.spec.ts'`

- [ ] **Step 10: Run the full frontend suite**

Run: `cd frontend && npx ng test --watch=false`
Expected: PASS, no regressions — in particular, every pre-existing `login-page.spec.ts` test that calls `submit()` without configuring `getSsoConfig()`'s response must still pass, meaning the `ngOnInit` SSO check must default `usesLdap()` to `false` (its initial `signal(false)` value) until the subscription resolves, so existing tests that never touch `getSsoConfig` at all still exercise the local-login path exactly as before. If any existing test's mock `AuthService` double doesn't implement `getSsoConfig` and the test now fails because `ngOnInit` calls an undefined method, add a default stub returning `of({ type: null })` to that test file's shared `AuthService` double setup.

- [ ] **Step 11: Commit**

```bash
git add frontend/src/app/auth/domain/auth.types.ts frontend/src/app/auth/application/auth.port.ts frontend/src/app/auth/infrastructure/http-auth.adapter.ts frontend/src/app/auth/infrastructure/http-auth.adapter.spec.ts frontend/src/app/auth/application/auth.service.ts frontend/src/app/auth/application/auth.service.spec.ts frontend/src/app/auth/login-page/login-page.ts frontend/src/app/auth/login-page/login-page.spec.ts
git commit -m "feat(frontend): detect LDAP-configured organizations on the login page"
```

---

### Task 16: Full-workspace verification

**Files:** none (verification only).

**Interfaces:** none.

- [ ] **Step 1: Run the full Rust test suite**

Run: `cargo test --workspace 2>&1 | tail -60`
Expected: PASS. Baseline before this plan: 703 passing. This plan adds tests across Tasks 1 (2), 2 (2), 4 (7), 5 (6), 6 (3), 7 (4), 9 (4), 10 (7) — expect roughly 703 + 35 ≈ 738, but treat the exact pre-task counts recorded in each task's own commit as the source of truth, not this estimate.

- [ ] **Step 2: Run the full frontend test suite and lint**

Run:
```bash
cd frontend && npx ng test --watch=false && npx ng lint
```
Expected: PASS. `ng lint` should show only the same 6 pre-existing, unrelated `no-empty-function` errors already tracked in this codebase's history (in `audit-log.spec.ts`, `export.spec.ts`, `security-log.spec.ts`, `repositories.service.spec.ts`, `me.service.spec.ts`, `users.service.spec.ts`) — nothing new from this plan's files.

- [ ] **Step 3: Confirm the sqlx offline cache is committed and current**

Run: `SQLX_OFFLINE=true cargo build --workspace 2>&1 | tail -30`
Expected: builds successfully against the committed `.sqlx/` cache with no live database connection.

- [ ] **Step 4: Commit if Step 3 regenerated anything**

Run `git status --porcelain .sqlx/` first. If it prints nothing, skip this step. Otherwise:

```bash
git add .sqlx/
git commit -m "chore: regenerate sqlx offline cache"
```

- [ ] **Step 5: Flag the deferred manual LDAP integration check**

This plan's Task 6 explicitly deferred verifying the bind/search/rebind flow against a real directory server (no such server is available in this environment). Note this clearly in the final report so the controller — or the human reviewing before merge — can decide whether to stand up a test LDAP container (e.g. `osixia/openldap`) and manually exercise `POST /api/auth/sso/ldap` end-to-end before this feature reaches production use, the same way the public-registration plan flagged its own deferred manual browser check.

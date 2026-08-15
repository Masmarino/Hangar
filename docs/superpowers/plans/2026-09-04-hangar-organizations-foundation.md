# Organizations Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce a multi-tenant `Organization` entity: a permanent `public` organization plus super-admin-created company organizations, each resolved from its own subdomain, each with its own repositories, branding, and members — with repository/branding access strictly scoped to the resolved organization (a leaked URL or a valid account from another organization must never reach it).

**Architecture:** `Organization` is a new plain-CRUD aggregate (no event sourcing — same family as `User`/`SystemSettings`, not `PackageRepository`/`Permission`). Every existing entity that needs scoping (`User`, `PackageRepository` and its projection, `branding_settings`) gains an `organization_id` foreign key. A new `ResolvedOrganization` Axum extractor (sibling to the existing `AuthUser` extractor) reads the `Host` header, strips the configured base domain, and resolves the leading label to an `Organization` (empty/`www` → the `public` organization). Every route that touches a repository or branding now takes `ResolvedOrganization` and scopes its query to it; the existing per-repository `Role` permission check stays exactly as it is, layered on top.

**Tech Stack:** Rust (hexagonal/DDD, same conventions as the rest of `hangar-api`/`hangar-domain`/`hangar-infrastructure`/`hangar-npm`/`hangar-docker`), sqlx + Postgres, Angular 22 (no frontend changes needed in this plan — see Task 12 note).

**Spec:** [`docs/superpowers/specs/2026-09-04-hangar-organizations-sso-design.md`](../specs/2026-09-04-hangar-organizations-sso-design.md)

## Global Constraints

- **Isolation is three independent checks, always in this order, on every repository/branding
  route**: (1) the resource is looked up *only* within the resolved organization — a row from
  another organization must never even be a candidate result, not filtered out after the fact;
  (2) `AuthUser.organization_id == resolved_org.id`, unless `AuthUser.is_super_admin`; (3) the
  existing per-repository `Role` check. Failure at (1) or (2) returns `404`, never `403` — do
  not confirm a resource exists in an organization the caller cannot reach. This mirrors the
  Docker blob IDOR fix already in this codebase's history (`28cd3ec`, before the develop
  squash) — read `crates/hangar-application/src/use_cases/docker_blob_get.rs` before writing
  any new isolation check, to match its testing style (a positive "reachable" test *and* a
  negative "not reachable from a different scope" regression test, every time).
- **This plan does NOT implement SSO, public self-registration, or any frontend UI for
  organizations.** Those are separate, later plans per the spec. This plan's `CreateOrganizationUseCase`
  is invoked by a route only a super-admin can call; there is no self-service org creation here.
- **`organizations.slug` parsing** mirrors `Username::parse` (`crates/hangar-domain/src/user.rs`):
  3-32 chars, starts with an ASCII letter, then alphanumeric/`_`/`-`. Not reusing `Username`
  itself — a `slug` is not a username — but the validation rule is identical, so copy it rather
  than inventing a different one.
- **Single consolidated migration**: this project has no historical migration chain — all schema
  changes in this plan go directly into `crates/hangar-infrastructure/migrations/0001_init.sql`,
  in place, not as a new file.
- **`branding_settings`'s current `id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1)` is a real
  database-level singleton constraint, not just an application convention.** It must be replaced
  by `organization_id UUID PRIMARY KEY REFERENCES organizations(id)` — adding an
  `organization_id` column *alongside* the existing `id` column is not sufficient and must not
  be done.
- **Docker access tokens are scoped by a bare repository-name string
  (`DockerGrantedScope.name`, e.g. `"backend/myimage"`), with no organization binding.** Because
  repository names are unique per-organization (not globally) after this plan, two organizations
  can have same-named repositories — a token minted for organization A's `backend` repo must not
  validate against organization B's differently-owned `backend` repo. Task 9 closes this by
  binding the granted scope to the resolved repository's UUID (already globally unique) instead
  of trusting the name string alone at verification time. This gap does not exist yet today
  (repository names are still globally unique before this plan lands) — it is introduced by this
  plan's own change and must be closed within it, not as a follow-up.
- **No frontend changes in this plan.** `login-page.html`/`app-shell.html`/`index.html` already
  reference `/api/branding/logo` and `/api/branding/favicon` as *relative* URLs — the browser's
  own `Host` header already carries the subdomain, so once the backend routes read
  `ResolvedOrganization`, branding resolves correctly with zero frontend changes. Verified by
  reading those three files during design reconnaissance — do not add subdomain-parsing logic to
  the frontend.
- Every existing `#[sqlx::test]` that constructs a `User { ... }` literal, seeds a user row
  directly, or builds a `test_state()`/route-test fixture will fail to compile once
  `organization_id` becomes a required field. This plan fixes them via `cargo build --workspace`'s
  own error list (Task 5, Step 4) rather than a pre-enumerated file list — the compiler is the
  source of truth for exactly which call sites exist.

---

### Task 1: Domain — `Organization` entity, slug parsing, `OrganizationRepositoryPort`

**Files:**
- Create: `crates/hangar-domain/src/organization.rs`
- Modify: `crates/hangar-domain/src/lib.rs` (add `pub mod organization;`)

**Interfaces:**
- Produces: `Organization`, `OrganizationSlug::parse(&str) -> Result<OrganizationSlug, DomainError>`, `OrganizationRepositoryPort` trait. Consumed by every later task in this plan.

- [ ] **Step 1: Write the failing tests**

```rust
// crates/hangar-domain/src/organization.rs
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OrganizationSlug(String);

impl OrganizationSlug {
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let len_ok = (3..=32).contains(&raw.len());
        let starts_with_letter = raw.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        let chars_ok = raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

        if len_ok && starts_with_letter && chars_ok {
            Ok(Self(raw.to_string()))
        } else {
            Err(DomainError::InvalidOrganizationSlug(raw.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Organization {
    pub id: Uuid,
    pub slug: OrganizationSlug,
    pub display_name: String,
    pub is_public: bool,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait OrganizationRepositoryPort: Send + Sync {
    async fn create(&self, org: &Organization) -> Result<(), DomainError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>, DomainError>;
    async fn find_by_slug(&self, slug: &OrganizationSlug) -> Result<Option<Organization>, DomainError>;
    /// Exactly one row always has `is_public = true` — this must never return `None` on a
    /// correctly migrated database. Returning `Result` (not the bare `Organization`) rather
    /// than panicking on a missing row keeps the failure mode a normal `DomainError` instead
    /// of an unwrap panic, in case of a broken/partial migration.
    async fn find_public(&self) -> Result<Organization, DomainError>;
    async fn list_all(&self) -> Result<Vec<Organization>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_slug_parses() {
        assert!(OrganizationSlug::parse("acme").is_ok());
        assert!(OrganizationSlug::parse("acme-corp").is_ok());
        assert!(OrganizationSlug::parse("acme_corp").is_ok());
    }

    #[test]
    fn a_slug_shorter_than_three_characters_is_rejected() {
        assert!(OrganizationSlug::parse("ab").is_err());
    }

    #[test]
    fn a_slug_not_starting_with_a_letter_is_rejected() {
        assert!(OrganizationSlug::parse("1acme").is_err());
        assert!(OrganizationSlug::parse("-acme").is_err());
    }

    #[test]
    fn a_slug_with_invalid_characters_is_rejected() {
        assert!(OrganizationSlug::parse("acme.corp").is_err());
        assert!(OrganizationSlug::parse("acme corp").is_err());
    }
}
```

- [ ] **Step 2: Add `InvalidOrganizationSlug` to `DomainError` and wire the module**

```rust
// crates/hangar-domain/src/error.rs — add a variant alongside the existing InvalidUsername etc.
    #[error("invalid organization slug: {0}")]
    InvalidOrganizationSlug(String),
```

```rust
// crates/hangar-domain/src/lib.rs — add near the other `pub mod` declarations
pub mod organization;
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p hangar-domain organization::`
Expected: PASS (4 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/hangar-domain/src/organization.rs crates/hangar-domain/src/error.rs crates/hangar-domain/src/lib.rs
git commit -m "feat(domain): add Organization entity and OrganizationRepositoryPort"
```

---

### Task 2: Infrastructure — `organizations` table, seed `public` org, `PostgresOrganizationRepository`

**Files:**
- Modify: `crates/hangar-infrastructure/migrations/0001_init.sql`
- Create: `crates/hangar-infrastructure/src/postgres/organization_repository.rs`
- Modify: `crates/hangar-infrastructure/src/postgres/mod.rs` (add `pub mod organization_repository;`)

**Interfaces:**
- Consumes: `Organization`, `OrganizationSlug`, `OrganizationRepositoryPort` (Task 1), `InfraErr` (`crates/hangar-infrastructure/src/error_ext.rs`, existing).
- Produces: `PostgresOrganizationRepository`, consumed by Task 4's `AppState` wiring.

- [ ] **Step 1: Add the `organizations` table to the migration, seeded with `public`**

Add near the top of `0001_init.sql`, before any table that will reference it (`users`,
`package_repository_projections`, `branding_settings` all need `organizations` to exist first):

```sql
CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Exactly one organization may be the public one.
CREATE UNIQUE INDEX organizations_single_public_idx ON organizations ((is_public)) WHERE is_public;

-- Fixed id so every environment (dev, test, prod) agrees on it without a lookup.
INSERT INTO organizations (id, slug, display_name, is_public)
VALUES ('00000000-0000-0000-0000-000000000001', 'public', 'Public', true);
```

- [ ] **Step 2: Write the failing integration test**

```rust
// crates/hangar-infrastructure/src/postgres/organization_repository.rs
use async_trait::async_trait;
use hangar_domain::error::DomainError;
use hangar_domain::organization::{Organization, OrganizationRepositoryPort, OrganizationSlug};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error_ext::InfraErr;

pub struct PostgresOrganizationRepository {
    pool: PgPool,
}

impl PostgresOrganizationRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

struct OrganizationRow {
    id: Uuid,
    slug: String,
    display_name: String,
    is_public: bool,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl OrganizationRow {
    fn into_domain(self) -> Result<Organization, DomainError> {
        Ok(Organization {
            id: self.id,
            slug: OrganizationSlug::parse(&self.slug)?,
            display_name: self.display_name,
            is_public: self.is_public,
            created_at: self.created_at,
        })
    }
}

#[async_trait]
impl OrganizationRepositoryPort for PostgresOrganizationRepository {
    async fn create(&self, org: &Organization) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO organizations (id, slug, display_name, is_public, created_at) VALUES ($1, $2, $3, $4, $5)",
            org.id,
            org.slug.as_str(),
            org.display_name,
            org.is_public,
            org.created_at,
        )
        .execute(&self.pool)
        .await
        .infra_err()?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>, DomainError> {
        let row = sqlx::query_as!(OrganizationRow, "SELECT id, slug, display_name, is_public, created_at FROM organizations WHERE id = $1", id)
            .fetch_optional(&self.pool)
            .await
            .infra_err()?;
        row.map(OrganizationRow::into_domain).transpose()
    }

    async fn find_by_slug(&self, slug: &OrganizationSlug) -> Result<Option<Organization>, DomainError> {
        let row = sqlx::query_as!(OrganizationRow, "SELECT id, slug, display_name, is_public, created_at FROM organizations WHERE slug = $1", slug.as_str())
            .fetch_optional(&self.pool)
            .await
            .infra_err()?;
        row.map(OrganizationRow::into_domain).transpose()
    }

    async fn find_public(&self) -> Result<Organization, DomainError> {
        let row = sqlx::query_as!(OrganizationRow, "SELECT id, slug, display_name, is_public, created_at FROM organizations WHERE is_public")
            .fetch_one(&self.pool)
            .await
            .infra_err()?;
        row.into_domain()
    }

    async fn list_all(&self) -> Result<Vec<Organization>, DomainError> {
        let rows = sqlx::query_as!(OrganizationRow, "SELECT id, slug, display_name, is_public, created_at FROM organizations ORDER BY created_at")
            .fetch_all(&self.pool)
            .await
            .infra_err()?;
        rows.into_iter().map(OrganizationRow::into_domain).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[sqlx::test]
    async fn the_seeded_public_organization_is_found(pool: PgPool) {
        let repo = PostgresOrganizationRepository::new(pool);
        let public = repo.find_public().await.unwrap();
        assert_eq!(public.slug.as_str(), "public");
        assert!(public.is_public);
    }

    #[sqlx::test]
    async fn creating_then_finding_by_slug_round_trips(pool: PgPool) {
        let repo = PostgresOrganizationRepository::new(pool);
        let org = Organization {
            id: Uuid::new_v4(),
            slug: OrganizationSlug::parse("acme").unwrap(),
            display_name: "Acme Corp".to_string(),
            is_public: false,
            created_at: Utc::now(),
        };
        repo.create(&org).await.unwrap();

        let found = repo.find_by_slug(&OrganizationSlug::parse("acme").unwrap()).await.unwrap().unwrap();
        assert_eq!(found.id, org.id);
        assert_eq!(found.display_name, "Acme Corp");
    }

    #[sqlx::test]
    async fn finding_by_an_unknown_slug_returns_none(pool: PgPool) {
        let repo = PostgresOrganizationRepository::new(pool);
        assert!(repo.find_by_slug(&OrganizationSlug::parse("nope").unwrap()).await.unwrap().is_none());
    }

    #[sqlx::test]
    async fn list_all_includes_the_seeded_public_organization_and_created_ones(pool: PgPool) {
        let repo = PostgresOrganizationRepository::new(pool);
        let org = Organization {
            id: Uuid::new_v4(),
            slug: OrganizationSlug::parse("acme").unwrap(),
            display_name: "Acme Corp".to_string(),
            is_public: false,
            created_at: Utc::now(),
        };
        repo.create(&org).await.unwrap();

        let all = repo.list_all().await.unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|o| o.is_public));
        assert!(all.iter().any(|o| o.id == org.id));
    }
}
```

```rust
// crates/hangar-infrastructure/src/postgres/mod.rs — add near the other `pub mod` declarations
pub mod organization_repository;
```

- [ ] **Step 3: Run the tests to verify they fail, then pass**

Run: `cargo test -p hangar-infrastructure organization_repository::`
Expected before the migration/impl exist: compile error or FAIL. After Steps 1-2: PASS (4 tests).

- [ ] **Step 4: Regenerate the sqlx offline query cache**

Run: `cargo sqlx prepare --workspace -- --all-targets` (with a running Postgres and `DATABASE_URL`
set, per this project's established process — see `crates/hangar-infrastructure/README` or the
project's `.sqlx/` directory precedent from prior sessions). This is required because these are
new `query!`/`query_as!` call sites — forgetting this step breaks `SQLX_OFFLINE=true` builds
(the Dockerfile), exactly as happened once already in this project's history.

- [ ] **Step 5: Commit**

```bash
git add crates/hangar-infrastructure/migrations/0001_init.sql crates/hangar-infrastructure/src/postgres/organization_repository.rs crates/hangar-infrastructure/src/postgres/mod.rs .sqlx/
git commit -m "feat(infra): add organizations table and PostgresOrganizationRepository"
```

---

### Task 3: API — `Config.hangar_base_domain` + `ResolvedOrganization` extractor

**Files:**
- Modify: `crates/hangar-api/src/config.rs`
- Create: `crates/hangar-api/src/organization_middleware.rs`
- Modify: `crates/hangar-api/src/main.rs` (add `mod organization_middleware;` — the
  `organizations: Arc<dyn OrganizationRepositoryPort>` field on `AppState` itself is added by
  Task 4, immediately next; this task's own tests need it to compile, so execute Task 4 right
  after this one before running either task's tests)

**Interfaces:**
- Consumes: `OrganizationRepositoryPort::find_by_slug`/`find_public` (Task 1/2).
- Produces: `ResolvedOrganization(pub Organization)`, a `FromRequestParts<AppState>` extractor. Consumed by every route in Tasks 7, 8, 9, 10.

- [ ] **Step 1: Add `hangar_base_domain` to `Config`**

```rust
// crates/hangar-api/src/config.rs — Config struct gains a field, Config::from_env() reads it
    pub hangar_base_domain: String,
```

```rust
// in the `from_env`-equivalent constructor, alongside the other std::env::var reads
            hangar_base_domain: std::env::var("HANGAR_BASE_DOMAIN")
                .unwrap_or_else(|_| "localhost".to_string()),
```

```rust
// crates/hangar-api/src/main.rs — test_config() helper, add the same field
            hangar_base_domain: "hangar.localhost".to_string(),
```

- [ ] **Step 2: Write the failing tests for `ResolvedOrganization`**

```rust
// crates/hangar-api/src/organization_middleware.rs
use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use hangar_domain::organization::{Organization, OrganizationSlug};

use crate::state::AppState;

#[derive(Clone)]
pub struct ResolvedOrganization(pub Organization);

#[async_trait]
impl FromRequestParts<AppState> for ResolvedOrganization {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let host = parts.headers.get(axum::http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
        // Strip a port if present (e.g. "acme.hangar.localhost:8080" in local dev).
        let host_without_port = host.split(':').next().unwrap_or(host);

        let label = host_without_port.strip_suffix(&format!(".{}", state.config.hangar_base_domain)).unwrap_or("");

        let org = if label.is_empty() || label == "www" {
            state.organizations.find_public().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        } else {
            let slug = OrganizationSlug::parse(label).map_err(|_| StatusCode::NOT_FOUND)?;
            state.organizations.find_by_slug(&slug).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.ok_or(StatusCode::NOT_FOUND)?
        };

        Ok(ResolvedOrganization(org))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    // This crate has no shared test Config helper — every route test module defines its own
    // local copy (see crates/hangar-api/src/routes/repositories.rs's own `test_config()` for
    // the established pattern this mirrors).
    fn test_config() -> Config {
        Config {
            database_url: String::new(),
            jwt_secret: "test-secret".to_string(),
            storage_root: std::env::temp_dir().to_string_lossy().to_string(),
            bind_addr: "0.0.0.0:0".to_string(),
            cors_allowed_origin: None,
            docker_token_realm: "http://localhost/v2/token".to_string(),
            public_url: "http://localhost:4200".to_string(),
            db_max_connections: hangar_infrastructure::postgres::DEFAULT_DB_MAX_CONNECTIONS,
            hangar_base_domain: "hangar.localhost".to_string(),
        }
    }

    fn router(state: AppState) -> Router {
        async fn handler(ResolvedOrganization(org): ResolvedOrganization) -> String {
            org.slug.as_str().to_string()
        }
        Router::new().route("/", get(handler)).with_state(state)
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_empty_host_label_resolves_to_the_public_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = router(state);
        let response = app.oneshot(Request::builder().uri("/").header("host", "hangar.localhost").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "public".as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_www_host_label_resolves_to_the_public_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = router(state);
        let response = app.oneshot(Request::builder().uri("/").header("host", "www.hangar.localhost").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_known_organization_slug_resolves_to_that_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state
            .organizations
            .create(&Organization {
                id: uuid::Uuid::new_v4(),
                slug: OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let app = router(state);
        let response = app.oneshot(Request::builder().uri("/").header("host", "acme.hangar.localhost").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "acme".as_bytes());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_unknown_organization_slug_is_not_found(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = router(state);
        let response = app.oneshot(Request::builder().uri("/").header("host", "nope.hangar.localhost").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_port_suffix_on_the_host_header_is_ignored(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = router(state);
        let response = app.oneshot(Request::builder().uri("/").header("host", "hangar.localhost:8080").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
```

- [ ] **Step 3: Wire the module**

```rust
// crates/hangar-api/src/main.rs — add near the other `mod` declarations
mod organization_middleware;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p hangar-api organization_middleware::`
Expected: this will not compile until Task 4 adds `state.organizations` to `AppState` — proceed
to Task 4 immediately, then return here and confirm PASS (5 tests) before committing either.

- [ ] **Step 5: Commit** (after Task 4 makes this compile)

```bash
git add crates/hangar-api/src/config.rs crates/hangar-api/src/organization_middleware.rs crates/hangar-api/src/main.rs
git commit -m "feat(api): add ResolvedOrganization subdomain-resolution extractor"
```

---

### Task 4: API — wire `AppState.organizations` and `CreateOrganizationUseCase`

**Files:**
- Create: `crates/hangar-application/src/use_cases/organization.rs`
- Modify: `crates/hangar-application/src/use_cases/mod.rs` (add `pub mod organization;`)
- Modify: `crates/hangar-api/src/state.rs`

**Interfaces:**
- Consumes: `OrganizationRepositoryPort` (Task 1), `PostgresOrganizationRepository` (Task 2).
- Produces: `AppState.organizations: Arc<dyn OrganizationRepositoryPort>`, `AppState.create_organization: Arc<CreateOrganizationUseCase>`. Makes Task 3's tests compile. Consumed by Task 6 (route).

- [ ] **Step 1: Write the failing test for `CreateOrganizationUseCase`**

```rust
// crates/hangar-application/src/use_cases/organization.rs
use std::sync::Arc;

use hangar_domain::organization::{Organization, OrganizationRepositoryPort, OrganizationSlug};
use uuid::Uuid;

use crate::error::ApplicationError;

pub struct CreateOrganizationUseCase {
    organizations: Arc<dyn OrganizationRepositoryPort>,
}

impl CreateOrganizationUseCase {
    pub fn new(organizations: Arc<dyn OrganizationRepositoryPort>) -> Self {
        Self { organizations }
    }

    pub async fn execute(&self, slug: &str, display_name: &str) -> Result<Uuid, ApplicationError> {
        let slug = OrganizationSlug::parse(slug)?;
        if self.organizations.find_by_slug(&slug).await?.is_some() {
            return Err(ApplicationError::OrganizationSlugTaken);
        }
        let id = Uuid::new_v4();
        let org = Organization { id, slug, display_name: display_name.to_string(), is_public: false, created_at: chrono::Utc::now() };
        self.organizations.create(&org).await?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository;

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn creating_an_organization_succeeds_and_is_findable(pool: sqlx::PgPool) {
        let organizations = Arc::new(PostgresOrganizationRepository::new(pool));
        let use_case = CreateOrganizationUseCase::new(organizations.clone());

        let id = use_case.execute("acme", "Acme Corp").await.unwrap();

        let found = organizations.find_by_id(id).await.unwrap().unwrap();
        assert_eq!(found.slug.as_str(), "acme");
        assert_eq!(found.display_name, "Acme Corp");
        assert!(!found.is_public);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn creating_an_organization_with_a_taken_slug_fails(pool: sqlx::PgPool) {
        let organizations = Arc::new(PostgresOrganizationRepository::new(pool));
        let use_case = CreateOrganizationUseCase::new(organizations.clone());
        use_case.execute("acme", "Acme Corp").await.unwrap();

        let result = use_case.execute("acme", "Acme Corp Again").await;

        assert!(matches!(result, Err(ApplicationError::OrganizationSlugTaken)));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_invalid_slug_is_rejected_before_touching_the_database(pool: sqlx::PgPool) {
        let organizations = Arc::new(PostgresOrganizationRepository::new(pool));
        let use_case = CreateOrganizationUseCase::new(organizations);

        let result = use_case.execute("1nvalid", "Whatever").await;

        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Add `OrganizationSlugTaken` to `ApplicationError`, wire the module**

```rust
// crates/hangar-application/src/error.rs — add alongside the other taken-name variants (e.g. RepositoryNameTaken)
    #[error("organization slug already taken")]
    OrganizationSlugTaken,
```

Also add a `From<DomainError>` mapping if `ApplicationError` doesn't already blanket-convert
`DomainError::InvalidOrganizationSlug` — check the existing `From<DomainError> for ApplicationError`
impl in `crates/hangar-application/src/error.rs` first; if it already forwards unknown
`DomainError` variants generically, no change is needed here beyond the new variant above.

```rust
// crates/hangar-application/src/use_cases/mod.rs
pub mod organization;
```

- [ ] **Step 3: Add `organizations` and `create_organization` to `AppState`**

```rust
// crates/hangar-api/src/state.rs — inside AppState::build, alongside users_repo's construction
        let organizations: Arc<dyn OrganizationRepositoryPort> = Arc::new(PostgresOrganizationRepository::new(pool.clone()));
        let create_organization = Arc::new(CreateOrganizationUseCase::new(organizations.clone()));
```

```rust
// crates/hangar-api/src/state.rs — AppState struct fields
    pub organizations: Arc<dyn OrganizationRepositoryPort>,
    pub create_organization: Arc<CreateOrganizationUseCase>,
```

```rust
// crates/hangar-api/src/state.rs — the final `Self { ... }` construction in `build`
            organizations: organizations.clone(),
            create_organization,
```

Add the two new `use` statements this needs (`hangar_domain::organization::OrganizationRepositoryPort`,
`hangar_application::use_cases::organization::CreateOrganizationUseCase`,
`hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository`) at
the top of `state.rs`, matching the existing import style for `users`/`repositories`.

- [ ] **Step 4: Run every test written so far**

Run: `cargo test -p hangar-domain -p hangar-infrastructure -p hangar-application -p hangar-api organization`
Expected: PASS (Task 1: 4, Task 2: 4, Task 3: 5, Task 4: 3 — 16 tests total).

- [ ] **Step 5: Regenerate the sqlx offline cache and commit**

Run: `cargo sqlx prepare --workspace -- --all-targets`

```bash
git add crates/hangar-application/src/use_cases/organization.rs crates/hangar-application/src/use_cases/mod.rs crates/hangar-application/src/error.rs crates/hangar-api/src/state.rs crates/hangar-api/src/organization_middleware.rs .sqlx/
git commit -m "feat: wire Organization into AppState, add CreateOrganizationUseCase"
```

---

### Task 5: `User` gains `organization_id` + `is_organization_admin`

**Files:**
- Modify: `crates/hangar-infrastructure/migrations/0001_init.sql`
- Modify: `crates/hangar-domain/src/user.rs`
- Modify: `crates/hangar-infrastructure/src/postgres/user_repository.rs`
- Modify: `crates/hangar-api/src/auth_middleware.rs`
- Modify (mechanically, compiler-driven — see Step 5): every existing call site across the
  workspace that constructs a `User { ... }` literal or seeds a `users` row directly in a test.

**Interfaces:**
- Consumes: `Organization` (Task 1).
- Produces: `User.organization_id: Uuid`, `User.is_organization_admin: bool`,
  `AuthUser.organization_id: Uuid`, `AuthUser.is_organization_admin: bool`. Consumed by every
  later task's isolation checks.

- [ ] **Step 1: Migration — add the columns**

```sql
-- crates/hangar-infrastructure/migrations/0001_init.sql — in the existing `CREATE TABLE users` statement
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_super_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_organization_admin BOOLEAN NOT NULL DEFAULT FALSE,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_unique ON users (email) WHERE email IS NOT NULL;
```

(`organizations` is defined earlier in the same file per Task 2, so the foreign key resolves —
double check table ordering when editing.)

- [ ] **Step 2: Update the domain model**

```rust
// crates/hangar-domain/src/user.rs — User struct
pub struct User {
    pub id: Uuid,
    pub username: Username,
    pub password_hash: String,
    pub is_super_admin: bool,
    pub is_organization_admin: bool,
    pub organization_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub email: Option<String>,
}
```

`UserRepositoryPort`'s method signatures are unchanged (still keyed by `id`/`Username`) — the
struct gaining fields is enough; no new port methods needed for this task.

- [ ] **Step 3: Update the Postgres adapter**

```rust
// crates/hangar-infrastructure/src/postgres/user_repository.rs — UserRow gains the two fields,
// every SELECT lists them, insert() writes them
struct UserRow {
    id: Uuid,
    username: String,
    password_hash: String,
    is_super_admin: bool,
    is_organization_admin: bool,
    organization_id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    email: Option<String>,
}
```

Update `find_by_id`, `find_by_username`, and `list_all`'s `sqlx::query_as!` column lists to
include `is_organization_admin, organization_id` (in the same position as the struct field
order, matching this file's existing convention of listing columns explicitly rather than
`SELECT *`). Update `insert`'s `INSERT INTO users (...)` column list and bound parameters the
same way. `UserRow::into_domain` gains the two field copies.

- [ ] **Step 4: Update `AuthUser`**

```rust
// crates/hangar-api/src/auth_middleware.rs
#[derive(Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub is_super_admin: bool,
    pub is_organization_admin: bool,
    pub organization_id: Uuid,
    pub created_at: DateTime<Utc>,
}
```

```rust
// same file, inside from_request_parts, the final Ok(AuthUser { ... })
        Ok(AuthUser {
            id: user.id,
            username: user.username.as_str().to_string(),
            is_super_admin: user.is_super_admin,
            is_organization_admin: user.is_organization_admin,
            organization_id: user.organization_id,
            created_at: user.created_at,
        })
```

- [ ] **Step 5: `CreateUserUseCase` gains an explicit `organization_id` parameter**

This one call site is production code (used by the startup bootstrap-admin path), not a test
fixture — it needs a deliberate parameter, not an arbitrary UUID.

```rust
// crates/hangar-application/src/use_cases/user.rs — CreateUserUseCase::execute
    pub async fn execute(&self, organization_id: Uuid, username: &str, password: &str, is_super_admin: bool) -> Result<Uuid, ApplicationError> {
        // ...unchanged body, except the constructed User { ... } literal gains
        // organization_id, and_is_organization_admin: false (nothing in this use case ever
        // creates an org-admin — that's Task 12's InviteUserUseCase extension)...
    }
```

```rust
// crates/hangar-api/src/main.rs — bootstrap_super_admin
    match state.users.list_all().await {
        Ok(users) if users.is_empty() => {
            let public_org = match state.organizations.find_public().await {
                Ok(org) => org,
                Err(e) => {
                    tracing::warn!("failed to resolve the public organization for super-admin bootstrap: {e}");
                    return;
                }
            };
            match state.create_user.execute(public_org.id, &username, &password, true).await {
                Ok(id) => tracing::info!("bootstrapped initial super-admin {username} ({id})"),
                Err(e) => tracing::warn!("failed to bootstrap initial super-admin {username}: {e}"),
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("failed to read users table for super-admin bootstrap: {e}"),
    }
```

The bootstrapped super-admin lands in the `public` organization — it has no meaningful company
affiliation, and `public` is this plan's established default for anything not deliberately
assigned elsewhere (same reasoning as the spec's data-migration section).

- [ ] **Step 6: Fix every remaining compile error**

Run: `cargo build --workspace 2>&1 | grep -B2 "missing field\|E0063\|E0308" | less`

Every reported call site constructing a bare `User { ... }` literal, or calling
`state.create_user.execute(...)` with the old 3-argument signature (test fixtures across
`hangar-infrastructure`, `hangar-application`, `hangar-api`, `hangar-npm`, `hangar-docker`,
including `repositories.rs`'s own `bearer()` helper — add `organization_id` as its own new
first parameter, defaulting test call sites to a fresh `Uuid::new_v4()` per test unless the
test is specifically about organization scoping, in which case use a deliberately shared or
distinct id as the test requires) needs fixing. Route-test helpers that seed a user row
directly via raw SQL (search for `INSERT INTO users` in test modules) need `organization_id`
added to their insert — use the fixed public-organization UUID
(`00000000-0000-0000-0000-000000000001`) for these unless the specific test needs a different
organization.

Repeat `cargo build --workspace` until it succeeds with zero errors.

- [ ] **Step 7: Run the full test suite**

Run: `cargo test --workspace`
Expected: PASS, same total test count as before this task plus this plan's own new tests so far
(no regressions — every fixed-up test should still assert what it asserted before, just with the
two new fields present).

- [ ] **Step 8: Regenerate the sqlx offline cache and commit**

Run: `cargo sqlx prepare --workspace -- --all-targets`

```bash
git add -A
git commit -m "feat: scope User to an organization, add is_organization_admin"
```

---

### Task 6: `POST /api/organizations` — super-admin creates an organization

**Files:**
- Create: `crates/hangar-api/src/routes/organizations.rs`
- Modify: `crates/hangar-api/src/routes/mod.rs` (add `pub mod organizations;`)
- Modify: `crates/hangar-api/src/main.rs` (`.merge(routes::organizations::router())`)

**Interfaces:**
- Consumes: `AppState.create_organization` (Task 4), `require_super_admin` (existing,
  `crates/hangar-api/src/authz.rs`).
- Produces: `POST /api/organizations`.

- [ ] **Step 1: Write the failing route tests**

```rust
// crates/hangar-api/src/routes/organizations.rs
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::authz::require_super_admin;
use crate::auth_middleware::AuthUser;
use crate::dto::{application_error_response, ErrorResponse};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/organizations", post(create_organization))
}

#[derive(Deserialize)]
struct CreateOrganizationRequest {
    slug: String,
    display_name: String,
}

#[derive(Serialize)]
struct OrganizationResponse {
    id: Uuid,
    slug: String,
    display_name: String,
}

async fn create_organization(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CreateOrganizationRequest>,
) -> Result<(StatusCode, Json<OrganizationResponse>), (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let id = state
        .create_organization
        .execute(&body.slug, &body.display_name)
        .await
        .map_err(|e| application_error_response("failed to create organization", e))?;
    Ok((StatusCode::CREATED, Json(OrganizationResponse { id, slug: body.slug, display_name: body.display_name })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    // Local copy of the established per-file pattern (see
    // crates/hangar-api/src/routes/repositories.rs's own `test_config()`/`bearer()`).
    fn test_config() -> Config {
        Config {
            database_url: String::new(),
            jwt_secret: "test-secret".to_string(),
            storage_root: std::env::temp_dir().to_string_lossy().to_string(),
            bind_addr: "0.0.0.0:0".to_string(),
            cors_allowed_origin: None,
            docker_token_realm: "http://localhost/v2/token".to_string(),
            public_url: "http://localhost:4200".to_string(),
            db_max_connections: hangar_infrastructure::postgres::DEFAULT_DB_MAX_CONNECTIONS,
            hangar_base_domain: "hangar.localhost".to_string(),
        }
    }

    // organization_id is the new first parameter Task 5 added to CreateUserUseCase::execute —
    // these tests aren't about organization scoping, so the public organization is a fine
    // default for both the admin and the non-admin account.
    async fn bearer(state: &AppState, organization_id: uuid::Uuid, username: &str, password: &str, is_super_admin: bool) -> String {
        state.create_user.execute(organization_id, username, password, is_super_admin).await.unwrap();
        state.authenticate_user.execute(username, password).await.unwrap()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_create_an_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/organizations")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"slug":"acme","display_name":"Acme Corp"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_super_admin_cannot_create_an_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "regular", "sup3r-s3cret!", false).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/organizations")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"slug":"acme","display_name":"Acme Corp"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
```

Note: `state.create_user`/`state.authenticate_user` are `CreateUserUseCase`/
`AuthenticateUserUseCase` — they create a usable local account and issue a real session token
directly, bypassing the route-level mandatory-MFA-enrollment wrapping (that wrapping lives in
`routes/auth.rs`'s `login` handler, not in the use cases themselves), exactly as
`repositories.rs`'s own existing tests already rely on.

- [ ] **Step 2: Wire the router**

```rust
// crates/hangar-api/src/routes/mod.rs
pub mod organizations;
```

```rust
// crates/hangar-api/src/main.rs — build_router_with_cors, alongside the other .merge(...) calls
        .merge(routes::organizations::router())
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p hangar-api routes::organizations::`
Expected: PASS (2 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/hangar-api/src/routes/organizations.rs crates/hangar-api/src/routes/mod.rs crates/hangar-api/src/main.rs
git commit -m "feat(api): add POST /api/organizations, super-admin only"
```

---

### Task 7: `PackageRepository` gains `organization_id`, query port becomes org-scoped

**Files:**
- Modify: `crates/hangar-domain/src/package_repository.rs`
- Modify: `crates/hangar-infrastructure/migrations/0001_init.sql`
- Modify: `crates/hangar-infrastructure/src/postgres/package_repository_store.rs`
- Modify (mechanically, compiler-driven): every call site of `PackageRepository::create(...)` and
  `PackageRepositoryQueryPort::find_by_name(...)`.

**Interfaces:**
- Produces: `PackageRepositoryEvent::Created` gains `organization_id: Uuid`;
  `PackageRepositorySummary` gains `organization_id: Uuid`;
  `PackageRepositoryQueryPort::find_by_org_and_name(organization_id, name)` replaces
  `find_by_name(name)`. Consumed by Tasks 8, 9, 10.

- [ ] **Step 1: Migration — column + corrected partial unique index**

```sql
-- crates/hangar-infrastructure/migrations/0001_init.sql
CREATE TABLE package_repository_projections (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name TEXT NOT NULL,
    format TEXT NOT NULL,
    repo_type TEXT NOT NULL,
    remote_url TEXT,
    remote_username TEXT,
    remote_password TEXT,
    quota_bytes BIGINT,
    retention_keep_last_n INT,
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);
-- Replaces the old global-uniqueness index (package_repository_projections_name_active_idx):
-- uniqueness is now per organization, still only among non-deleted rows.
CREATE UNIQUE INDEX package_repository_org_name_active_idx
    ON package_repository_projections (organization_id, name)
    WHERE deleted_at IS NULL;
```

Remove the old `CREATE UNIQUE INDEX package_repository_projections_name_active_idx ON
package_repository_projections (name) WHERE deleted_at IS NULL;` statement entirely (this is a
single consolidated migration recreating the schema from scratch — there is no live data to
preserve, so no `DROP INDEX` is needed, just delete the old `CREATE UNIQUE INDEX` line and
replace it with the one above).

- [ ] **Step 2: Domain — event, aggregate, summary, query port**

```rust
// crates/hangar-domain/src/package_repository.rs — PackageRepositoryEvent::Created
    Created {
        repository_id: Uuid,
        organization_id: Uuid,
        name: String,
        format: RepositoryFormat,
        repo_type: RepositoryType,
        remote_url: Option<String>,
        remote_username: Option<String>,
        remote_password: Option<String>,
    },
```

```rust
// PackageRepository::create — add organization_id as the 2nd positional parameter
#[allow(clippy::too_many_arguments)]
pub fn create(
    repository_id: Uuid,
    organization_id: Uuid,
    name: String,
    format: RepositoryFormat,
    repo_type: RepositoryType,
    remote_url: Option<String>,
    remote_username: Option<String>,
    remote_password: Option<String>,
) -> PackageRepositoryEvent {
    PackageRepositoryEvent::Created { repository_id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password }
}
```

```rust
// PackageRepositorySummary — add the field
pub struct PackageRepositorySummary {
    pub id: Uuid,
    pub organization_id: Uuid,
    // ...existing fields unchanged...
}
```

```rust
// PackageRepositoryQueryPort — replace find_by_name
#[async_trait]
pub trait PackageRepositoryQueryPort: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<PackageRepositorySummary>, EventStoreError>;
    async fn find_by_org_and_name(&self, organization_id: Uuid, name: &str) -> Result<Option<PackageRepositorySummary>, EventStoreError>;
    async fn list_all(&self) -> Result<Vec<PackageRepositorySummary>, EventStoreError>;
}
```

(`list_all` stays global here deliberately — it backs the super-admin's cross-organization
repository listing; Task 11 adds an org-scoped listing route on top of it by filtering in the
route handler, not by changing this port method. `find_by_id` also stays global-by-UUID — every
caller of `find_by_id` in Tasks 8-10 must independently verify the returned summary's
`organization_id` matches the resolved organization before using it, exactly as
`AddGroupMemberUseCase` in `crates/hangar-application/src/use_cases/package_repository.rs`
already does today when validating a group member's format — apply the identical
"fetch-then-check" pattern there for organization, alongside the existing format check.)

- [ ] **Step 3: Postgres adapter**

```rust
// crates/hangar-infrastructure/src/postgres/package_repository_store.rs — apply_to_projection's Created arm
            PackageRepositoryEvent::Created { organization_id, name, format, repo_type, remote_url, remote_username, remote_password, .. } => {
                sqlx::query!(
                    "INSERT INTO package_repository_projections (id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password, version, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), now())",
                    repository_id, organization_id, name, format_to_str(*format), repo_type_to_str(*repo_type),
                    remote_url.as_deref(), remote_username.as_deref(), remote_password.as_deref(), version
                )
                .execute(&mut **tx).await.storage_err()?;
            }
```

```rust
// PackageRepositoryQueryPort impl — find_by_org_and_name replaces find_by_name
    async fn find_by_org_and_name(&self, organization_id: Uuid, name: &str) -> Result<Option<PackageRepositorySummary>, EventStoreError> {
        let row = sqlx::query!(
            "SELECT id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password, quota_bytes, retention_keep_last_n, version \
             FROM package_repository_projections WHERE organization_id = $1 AND name = $2 AND deleted_at IS NULL",
            organization_id, name
        )
        .fetch_optional(&self.pool)
        .await
        .storage_err()?;
        // ...map row into PackageRepositorySummary exactly as find_by_name did, plus organization_id
    }
```

`find_by_id` and `list_all` gain `organization_id` in their `SELECT` column list and their
`PackageRepositorySummary` construction, unchanged otherwise.

- [ ] **Step 4: Fix every resulting compile error**

Run: `cargo build --workspace 2>&1 | grep -B2 "E0061\|E0599\|missing field"`

Fix every call site of `PackageRepository::create(...)` (add the organization id argument — for
`CreatePackageRepositoryUseCase`, thread it through from a new `organization_id: Uuid` parameter
on `execute`, see Task 8) and every call site of `.find_by_name(...)` across
`hangar-application`, `hangar-npm`, `hangar-docker` (rename to `.find_by_org_and_name(org_id,
name)`, threading the caller's own organization context through — Task 8 and Task 9 cover the
route-level threading in detail; other call sites like `docker_scan.rs`/`docker_access_token.rs`
need the same organization id passed down from their own callers).

Repeat until `cargo build --workspace` succeeds.

- [ ] **Step 5: Run the full test suite, regenerate sqlx cache, commit**

Run: `cargo test --workspace` (expect failures in tests that assert repository-name uniqueness
globally — fix those assertions to create the two repositories in *different* organizations if
the test is specifically about name reuse being fine across organizations, or leave them in the
same organization if the test is about the duplicate-name-rejection behavior, which still holds
within one organization).

Run: `cargo sqlx prepare --workspace -- --all-targets`

```bash
git add -A
git commit -m "feat: scope PackageRepository to an organization"
```

---

### Task 8: Repository routes use `ResolvedOrganization` + isolation checks

**Files:**
- Modify: `crates/hangar-api/src/authz.rs`
- Modify: `crates/hangar-api/src/routes/repositories.rs`
- Modify: `crates/hangar-application/src/use_cases/package_repository.rs` (`CreatePackageRepositoryUseCase::execute` gains `organization_id: Uuid` as its first parameter)

**Interfaces:**
- Consumes: `ResolvedOrganization` (Task 3), `find_by_org_and_name` (Task 7).
- Produces: `require_same_organization` in `authz.rs`; every `/api/repositories*` route scoped to
  the resolved organization.

- [ ] **Step 1: Write the failing isolation test — the core regression this whole plan exists for**

```rust
// crates/hangar-api/src/routes/repositories.rs — add to the existing test module
// (test_config() here also needs `hangar_base_domain: "hangar.localhost".to_string()` added,
// same as every other test_config() copy — this file's existing one is one of the compile
// errors Task 5 Step 6 already fixes, so it has the field by the time this task runs)
#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn a_repository_in_one_organization_is_not_reachable_from_another_organizations_subdomain(pool: sqlx::PgPool) {
    let state = AppState::build(pool, &test_config());
    let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
    let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
    let admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
    let repo_id = state
        .create_repository
        .execute(acme_id, "backend", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id)
        .await
        .unwrap();
    let other_token = bearer(&state, other_id, "other-user", "sup3r-s3cret!", false).await;
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/repositories/{repo_id}"))
                .header("host", "other.hangar.localhost")
                .header("authorization", format!("Bearer {other_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn a_super_admin_can_still_reach_any_organizations_repository(pool: sqlx::PgPool) {
    let state = AppState::build(pool, &test_config());
    let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
    let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
    let admin_id = state.create_user.execute(acme_id, "acme-admin", "sup3r-s3cret!", false).await.unwrap();
    let repo_id = state
        .create_repository
        .execute(acme_id, "backend", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id)
        .await
        .unwrap();
    let super_admin_token = bearer(&state, other_id, "the-super-admin", "sup3r-s3cret!", true).await;
    let app = build_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/repositories/{repo_id}"))
                .header("host", "other.hangar.localhost")
                .header("authorization", format!("Bearer {super_admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
}
```

- [ ] **Step 2: `require_same_organization` in `authz.rs`**

```rust
// crates/hangar-api/src/authz.rs — alongside require_super_admin
pub fn require_same_organization(user: &AuthUser, organization_id: Uuid) -> Result<(), StatusCode> {
    if user.is_super_admin || user.organization_id == organization_id {
        Ok(())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
```

- [ ] **Step 3: Thread `ResolvedOrganization` through the repository routes**

Every handler in `crates/hangar-api/src/routes/repositories.rs` that looks up a repository by
name or lists repositories gains `resolved_org: ResolvedOrganization` as a new extractor
parameter (Axum extracts it automatically from the request, same as `AuthUser` today — order
matters only relative to the body extractor, which must stay last). For each:

- `list_repositories`: filter `state.repositories.list_all()`'s result to
  `r.organization_id == resolved_org.0.id`, unless the caller `is_super_admin` (in which case
  list_all's full result stands, matching today's cross-organization admin visibility from the
  spec).
- `get_repository`/`rename_repository`/`delete_repository`/permission and quota/retention routes
  that take `:id`: after `state.repositories.find_by_id(id)`, call
  `require_same_organization(&user, summary.organization_id)?` before doing anything else with
  the result — this is Step 1's isolation check (2) from the Global Constraints, layered on top
  of the existing `require_repository_role` check (3). Do this check *before* the role check,
  and return its `404` directly rather than letting a later role check produce a `403` first —
  order matters for not leaking existence information.
- `create_repository`: replace the current `require_super_admin`-only gate with
  `if !user.is_super_admin { require_same_organization(&user, resolved_org.0.id)?; if !user.is_organization_admin { return Err(...FORBIDDEN...) } }`
  — i.e. super-admin (any org) or an org-admin creating within their own resolved organization.
  Pass `resolved_org.0.id` as the new first argument to `state.create_repository.execute(...)`.

```rust
// crates/hangar-application/src/use_cases/package_repository.rs — CreatePackageRepositoryUseCase::execute
    #[allow(clippy::too_many_arguments)]
    pub async fn execute(
        &self,
        organization_id: Uuid,
        name: &str,
        format: RepositoryFormat,
        repo_type: RepositoryType,
        remote_url: Option<String>,
        remote_username: Option<String>,
        remote_password: Option<String>,
        actor_id: Uuid,
    ) -> Result<Uuid, ApplicationError> {
        let name = parse_repository_name(name)?;
        if self.query.find_by_org_and_name(organization_id, &name).await?.is_some() {
            return Err(ApplicationError::RepositoryNameTaken);
        }
        let repository_id = Uuid::new_v4();
        let event = PackageRepository::create(repository_id, organization_id, name, format, repo_type, remote_url, remote_username, remote_password);
        self.events.append(repository_id, 0, vec![event], actor_id).await?;
        Ok(repository_id)
    }
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p hangar-api routes::repositories::`
Expected: PASS, including the two new isolation tests from Step 1.

- [ ] **Step 5: Run the full suite, regenerate sqlx cache, commit**

Run: `cargo test --workspace`, then `cargo sqlx prepare --workspace -- --all-targets`.

```bash
git add -A
git commit -m "feat(api): scope repository routes to the resolved organization, enforce isolation"
```

---

### Task 9: npm/Docker repository lookup becomes org-scoped

**Files:**
- Modify: `crates/hangar-npm/src/authz.rs`
- Modify: `crates/hangar-npm/src/routes/*.rs` (every handler calling `require_repository_by_name`)
- Modify: `crates/hangar-docker/src/authz.rs`
- Modify: `crates/hangar-docker/src/routes/*.rs` (every handler calling `require_repository_by_name`)

**Interfaces:**
- Consumes: `ResolvedOrganization` (Task 3, re-exported or duplicated as needed — `hangar-npm`/
  `hangar-docker` are separate crates from `hangar-api` with their own `NpmState`/`DockerState`,
  not `AppState`; add a lightweight equivalent org-resolution extractor scoped to each crate's
  own state type, following the exact same `Host`-header logic as
  `crates/hangar-api/src/organization_middleware.rs` — do not import across crate boundaries
  where the state types differ).

- [ ] **Step 1: Add an org-resolution extractor to each protocol crate, and organization_id to their test seeding helpers**

`NpmState`/`DockerState` need their own `organizations: Arc<dyn OrganizationRepositoryPort>` and
`hangar_base_domain: String` fields (mirroring what `build_npm_state`/`build_docker_state` in
`crates/hangar-api/src/main.rs` already do for other shared ports — add these two the same way,
cloned off `AppState`). Then in each crate, add a `ResolvedOrganization` extractor identical in
logic to Task 3's, adapted to that crate's own `State` type. Given the logic is byte-for-byte
identical apart from the state type, write it once and copy it verbatim into each of
`crates/hangar-npm/src/organization_resolution.rs` and
`crates/hangar-docker/src/organization_resolution.rs` — a shared crate for this one extractor
would be over-engineering for two call sites.

`crates/hangar-docker/src/route_test_support.rs` (a shared test-fixture module used by every
Docker route test file) needs three changes for its existing helpers to keep compiling and to
support the isolation tests below:

```rust
// test_state — add organizations + hangar_base_domain to the returned DockerState
pub async fn test_state(pool: PgPool, root: &Path) -> DockerState {
    let organizations: Arc<dyn hangar_domain::organization::OrganizationRepositoryPort> =
        Arc::new(hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository::new(pool.clone()));
    // ...unchanged construction of repositories/permissions/etc. above...
    DockerState {
        organizations: organizations.clone(),
        hangar_base_domain: "hangar.localhost".to_string(),
        // ...every existing field unchanged...
    }
}

// seed_repository — organization_id becomes a required parameter, threaded into the INSERT
pub async fn seed_repository(pool: &PgPool, organization_id: Uuid, id: Uuid, format: &str, repo_type: &str) {
    sqlx::query!(
        "INSERT INTO package_repository_projections (id, organization_id, name, format, repo_type, remote_url, version, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, NULL, 1, now(), now())",
        id,
        organization_id,
        format!("repo-{id}"),
        format,
        repo_type,
    )
    .execute(pool)
    .await
    .unwrap();
}

// seed_user_with_active_token — organization_id becomes a required parameter
pub async fn seed_user_with_active_token(pool: &PgPool, organization_id: Uuid, plaintext_token: &str) -> Uuid {
    let user_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO users (id, organization_id, username, password_hash, is_super_admin, is_organization_admin, created_at) \
         VALUES ($1, $2, $3, 'irrelevant', false, false, now())",
        user_id,
        organization_id,
        format!("user-{}", &user_id.simple().to_string()[..8]),
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO api_tokens (id, user_id, token_hash, label, created_at) VALUES ($1, $2, $3, 'test', now())",
        Uuid::new_v4(),
        user_id,
        hash_api_token(plaintext_token),
    )
    .execute(pool)
    .await
    .unwrap();
    user_id
}
```

Fix every existing call site of `seed_repository`/`seed_user_with_active_token` across
`crates/hangar-docker/src/routes/*.rs`'s test modules to pass an `organization_id` (the
compiler will list every one — same "fix what `cargo build` reports" approach as Task 5 Step 6).
`seed_permission` and `issue_test_token` are unaffected (permissions and token scope are keyed
by repository UUID, not organization, already).

- [ ] **Step 2: Write the failing isolation tests (mirroring the Docker blob IDOR fix's test style)**

```rust
// crates/hangar-docker/src/routes/manifests.rs — add to the existing test module
#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn a_manifest_in_one_organizations_repository_is_not_reachable_from_another_organization(pool: sqlx::PgPool) {
    let dir = tempfile::tempdir().unwrap();
    let state = crate::route_test_support::test_state(pool.clone(), dir.path()).await;

    // OrganizationRepositoryPort::create takes a caller-assigned id (Task 1) rather than
    // generating and returning one, so declare each id before building its Organization literal.
    let acme_id = Uuid::new_v4();
    state
        .organizations
        .create(&hangar_domain::organization::Organization {
            id: acme_id,
            slug: hangar_domain::organization::OrganizationSlug::parse("acme").unwrap(),
            display_name: "Acme".to_string(),
            is_public: false,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let other_id = Uuid::new_v4();
    state
        .organizations
        .create(&hangar_domain::organization::Organization {
            id: other_id,
            slug: hangar_domain::organization::OrganizationSlug::parse("other").unwrap(),
            display_name: "Other".to_string(),
            is_public: false,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();

    let repo_id = Uuid::new_v4();
    crate::route_test_support::seed_repository(&pool, acme_id, repo_id, "docker", "hosted").await;
    let other_user_id = crate::route_test_support::seed_user_with_active_token(&pool, other_id, "plaintext-token").await;
    let token = crate::route_test_support::issue_test_token(&state, other_user_id, &format!("repo-{repo_id}"), "myimage", &["pull"]);
    let app = crate::router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/repo-{repo_id}/myimage/manifests/latest"))
                .header("host", "other.hangar.localhost")
                .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
```

**Implementer note for the npm-side equivalent**: unlike `hangar-docker`, `hangar-npm` has no
shared `route_test_support.rs` — each route test file seeds its own fixtures inline (verify this
by reading `crates/hangar-npm/src/routes/metadata.rs`'s existing test module in full before
writing this test). Write
`a_package_in_one_organizations_repository_is_not_reachable_from_another_organization` in
`crates/hangar-npm/src/routes/metadata.rs` following that file's own existing inline seeding
pattern, adapted to create two organizations and assert `GET /npm/<repo>/<package>` 404s when
requested with the wrong organization's `Host` header — same shape as the Docker test above,
translated to npm's URL scheme and existing test fixtures.

- [ ] **Step 3: Update `require_repository_by_name` in both crates**

```rust
// crates/hangar-npm/src/authz.rs
pub async fn require_repository_by_name(state: &NpmState, organization_id: Uuid, name: &str) -> Result<PackageRepositorySummary, StatusCode> {
    state
        .repositories
        .find_by_org_and_name(organization_id, name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)
}
```

Identical change in `crates/hangar-docker/src/authz.rs`.

- [ ] **Step 4: Thread `ResolvedOrganization` through every calling route handler**

Every route handler in both crates that currently calls
`authz::require_repository_by_name(&state, &name)` gains a `resolved_org: ResolvedOrganization`
parameter and passes `resolved_org.0.id` as the new second argument. This touches every handler
in `hangar-npm/src/routes/{publish,unpublish,metadata,dist_tags,search,advisories}.rs` and every
handler reached through `hangar-docker/src/routes/dispatch.rs`'s `handle_get`/`handle_head`/
`handle_post`/`handle_put`/`handle_patch`/`handle_delete` (each of which calls into
`blobs.rs`/`manifests.rs`/`tags.rs` — those inner functions need the org id threaded through as
well, from `dispatch.rs`'s handlers down).

- [ ] **Step 5: Run the tests**

Run: `cargo test -p hangar-npm -p hangar-docker`
Expected: PASS, including the two new isolation tests.

- [ ] **Step 6: Run the full suite, regenerate sqlx cache, commit**

```bash
git add -A
git commit -m "feat: scope npm/Docker repository lookup to the resolved organization"
```

---

### Task 10: Docker access tokens bind to the repository UUID, not just its name

**Files:**
- Modify: `crates/hangar-domain/src/docker_registry.rs`
- Modify: `crates/hangar-application/src/use_cases/docker_access_token.rs`
- Modify: `crates/hangar-docker/src/authz.rs`
- Modify: `crates/hangar-docker/src/routes/handshake.rs`

**Interfaces:**
- Produces: `DockerGrantedScope.granted_repository_id: Option<Uuid>`; `require_granted_action`
  additionally verifies the currently-resolved repository's id matches it.
- Closes the gap noted in Global Constraints: same-named repositories in different organizations
  must not accept each other's tokens.

- [ ] **Step 1: Write the failing test**

```rust
// crates/hangar-application/src/use_cases/docker_access_token.rs — add to the existing test module
#[tokio::test]
async fn a_token_scoped_to_one_organizations_repository_carries_that_repositorys_id() {
    // Using this file's existing FakeDockerBlobStore/fixture pattern (read the existing test
    // module in full first — do not invent a different fixture shape): seed two repositories
    // both named "backend", one in organization A, one in organization B. Issue a token scoped
    // to `repository:backend/image:pull` while resolved against organization A. Assert the
    // returned DockerGrantedScope.granted_repository_id equals organization A's repository id,
    // not organization B's, even though both share the name "backend".
}
```

```rust
// crates/hangar-docker/src/authz.rs — add to the existing test module (or a new one if none exists)
#[test]
fn a_granted_scope_for_a_different_repository_id_is_rejected_even_with_a_matching_name() {
    // build a DockerAuthUser with granted_scope.name = "backend/image" and
    // granted_repository_id = Some(repo_a_id), then call require_granted_action against a
    // resolved repository summary whose id is repo_b_id but whose name is also "backend" —
    // assert it's rejected (FORBIDDEN), where today's name-only check would have wrongly
    // accepted it.
}
```

- [ ] **Step 2: Add the field to the domain**

```rust
// crates/hangar-domain/src/docker_registry.rs — DockerGrantedScope
pub struct DockerGrantedScope {
    pub resource_type: String,
    pub name: String,
    pub actions: Vec<String>,
    /// The specific repository this scope was granted against, resolved at issuance time.
    /// `None` only for scopes granted before this field existed (never re-issued, so this is
    /// purely a defensive Option, not an expected runtime case for freshly issued tokens).
    pub granted_repository_id: Option<Uuid>,
}
```

- [ ] **Step 3: Set it at issuance time**

```rust
// crates/hangar-application/src/use_cases/docker_access_token.rs
// execute(...) gains organization_id: Uuid as a new parameter, threaded from the route handler
// (handshake.rs, Step 5 below) via ResolvedOrganization
    pub async fn execute(&self, organization_id: Uuid, password: &str, scope: Option<&str>) -> Result<String, ApplicationError> {
        // ...unchanged up to the authorize(...) call...
        let granted_scope = match scope.and_then(DockerScopeRequest::parse) {
            None => None,
            Some(requested) => Some(self.authorize(organization_id, &user, &requested).await?),
        };
        Ok(self.token_issuer.issue(user.id, granted_scope)?)
    }

    async fn authorize(&self, organization_id: Uuid, user: &User, requested: &DockerScopeRequest) -> Result<DockerGrantedScope, ApplicationError> {
        let repository = self.repositories.find_by_org_and_name(organization_id, requested.hangar_repository_name()).await?;

        let (actions, granted_repository_id) = match &repository {
            None => (vec![], None),
            Some(repository) => {
                let role = if user.is_super_admin { Some(Role::Admin) } else { self.permissions.find_role(user.id, repository.id).await? };
                let actions = requested.actions.iter().filter(|action| role.is_some_and(|role| role.satisfies(required_role_for_action(action)))).cloned().collect();
                (actions, Some(repository.id))
            }
        };

        Ok(DockerGrantedScope { resource_type: requested.resource_type.clone(), name: requested.name.clone(), actions, granted_repository_id })
    }
```

- [ ] **Step 4: Verify it at request time**

```rust
// crates/hangar-docker/src/authz.rs
pub fn require_granted_action(user: &DockerAuthUser, resolved_repository_id: Uuid, repository_name: &str, action: &str) -> Result<(), StatusCode> {
    let scope = user.granted_scope.as_ref().ok_or(StatusCode::FORBIDDEN)?;
    let scope_repository = scope.name.split('/').next().unwrap_or(&scope.name);
    if scope_repository != repository_name || !scope.actions.iter().any(|a| a == action) {
        return Err(StatusCode::FORBIDDEN);
    }
    if scope.granted_repository_id != Some(resolved_repository_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}
```

Every existing call site of `require_granted_action(user, repository_name, action)` (in
`blobs.rs`/`manifests.rs`/`tags.rs`, already threading `ResolvedOrganization` through per Task
9) gains `resolved_repository_id` as a new second argument — the id comes from the same
`require_repository_by_name` call each handler already makes just before this check, so no new
lookup is introduced, just passing an id that's already in scope.

- [ ] **Step 5: Thread `organization_id` into the `/v2/token` handshake route**

```rust
// crates/hangar-docker/src/routes/handshake.rs — issue_token
async fn issue_token(
    State(state): State<DockerState>,
    resolved_org: ResolvedOrganization,
    RawQuery(raw_query): RawQuery,
    basic_auth: Option<TypedHeader<Authorization<Basic>>>,
) -> Response {
    // ...unchanged scope parsing...
    match state.issue_access_token.execute(resolved_org.0.id, basic.password(), merged_scope.as_deref()).await {
        // ...unchanged...
    }
}
```

- [ ] **Step 6: Run the tests**

Run: `cargo test -p hangar-domain -p hangar-application -p hangar-docker`
Expected: PASS, including the two new tests from Step 1.

- [ ] **Step 7: Run the full suite, regenerate sqlx cache, commit**

```bash
git add -A
git commit -m "fix(security): bind Docker access tokens to a repository UUID, not just its name"
```

---

### Task 11: `branding_settings` scoped to an organization

**Files:**
- Modify: `crates/hangar-infrastructure/migrations/0001_init.sql`
- Modify: `crates/hangar-domain/src/branding.rs`
- Modify: `crates/hangar-infrastructure/src/postgres/branding_repository.rs`
- Modify: `crates/hangar-application/src/use_cases/branding.rs`
- Modify: `crates/hangar-api/src/routes/branding.rs`

**Interfaces:**
- Produces: `BrandingPort` methods all take `organization_id: Uuid`.

- [ ] **Step 1: Migration — replace the singleton primary key**

```sql
-- crates/hangar-infrastructure/migrations/0001_init.sql — replaces the existing
-- `id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1)` table definition entirely
CREATE TABLE branding_settings (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id),
    logo_bytes BYTEA,
    logo_content_type TEXT,
    favicon_bytes BYTEA,
    favicon_content_type TEXT,
    CONSTRAINT logo_bytes_and_content_type_together CHECK ((logo_bytes IS NULL) = (logo_content_type IS NULL)),
    CONSTRAINT favicon_bytes_and_content_type_together CHECK ((favicon_bytes IS NULL) = (favicon_content_type IS NULL))
);
```

- [ ] **Step 2: Domain port**

```rust
// crates/hangar-domain/src/branding.rs
#[async_trait]
pub trait BrandingPort: Send + Sync {
    async fn get(&self, organization_id: Uuid) -> Result<BrandingSettings, DomainError>;
    async fn set_logo(&self, organization_id: Uuid, asset: &BrandingAsset) -> Result<(), DomainError>;
    async fn clear_logo(&self, organization_id: Uuid) -> Result<(), DomainError>;
    async fn set_favicon(&self, organization_id: Uuid, asset: &BrandingAsset) -> Result<(), DomainError>;
    async fn clear_favicon(&self, organization_id: Uuid) -> Result<(), DomainError>;
}
```

- [ ] **Step 3: Postgres adapter — every method keys on `organization_id` instead of `id = 1`**

```rust
// crates/hangar-infrastructure/src/postgres/branding_repository.rs
    async fn get(&self, organization_id: Uuid) -> Result<BrandingSettings, DomainError> {
        let row = sqlx::query!(
            "SELECT logo_bytes, logo_content_type, favicon_bytes, favicon_content_type FROM branding_settings WHERE organization_id = $1",
            organization_id
        )
        .fetch_optional(&self.pool).await.infra_err()?;
        // ...unchanged mapping...
    }

    async fn set_logo(&self, organization_id: Uuid, asset: &BrandingAsset) -> Result<(), DomainError> {
        sqlx::query!(
            "INSERT INTO branding_settings (organization_id, logo_bytes, logo_content_type) VALUES ($1, $2, $3) \
             ON CONFLICT (organization_id) DO UPDATE SET logo_bytes = EXCLUDED.logo_bytes, logo_content_type = EXCLUDED.logo_content_type",
            organization_id, asset.bytes, asset.content_type,
        ).execute(&self.pool).await.infra_err()?;
        Ok(())
    }
```

Apply the identical `organization_id`-keyed pattern to `clear_logo`, `set_favicon`,
`clear_favicon` (each already has an `ON CONFLICT`/`WHERE id = 1` today — swap the key column,
keep the rest of each statement's shape unchanged).

- [ ] **Step 4: Use cases and routes take `organization_id`**

```rust
// crates/hangar-application/src/use_cases/branding.rs
impl GetBrandingUseCase {
    pub async fn execute(&self, organization_id: Uuid) -> Result<ResolvedBranding, ApplicationError> {
        let settings = self.branding.get(organization_id).await?;
        Ok(ResolvedBranding { logo: settings.logo.unwrap_or_else(|| self.defaults.logo.clone()), favicon: settings.favicon.unwrap_or_else(|| self.defaults.favicon.clone()) })
    }
}
```

Same pattern for `SetBrandingLogoUseCase::execute(organization_id, bytes)`,
`ClearBrandingLogoUseCase::execute(organization_id)`, and the favicon equivalents.

```rust
// crates/hangar-api/src/routes/branding.rs
async fn get_logo(State(state): State<AppState>, resolved_org: ResolvedOrganization) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let branding = state.get_branding.execute(resolved_org.0.id).await.map_err(|e| application_error_response("failed to get branding", e))?;
    Ok(([(header::CONTENT_TYPE, branding.logo.content_type), (header::CACHE_CONTROL, "no-cache".to_string())], branding.logo.bytes))
}
```

`get_favicon` mirrors `get_logo`. `set_logo`/`clear_logo`/`set_favicon`/`clear_favicon` gain
`resolved_org: ResolvedOrganization` too, pass `resolved_org.0.id` into their use case call, and
their authz check changes from `require_super_admin`-only to
`require_super_admin(&user).or_else(|_| { require_same_organization(&user, resolved_org.0.id)?; if user.is_organization_admin { Ok(()) } else { Err(StatusCode::FORBIDDEN) } })`
— i.e. super-admin or that organization's own admin.

- [ ] **Step 5: Fix compile errors, run the full suite, regenerate sqlx cache, commit**

Run: `cargo build --workspace`, fix every remaining call site (should be limited to this task's
own files plus their existing tests, which need `organization_id` added to their `.execute(...)`
calls — search each test module for `.execute()` calls on branding use cases).

Run: `cargo test --workspace`, then `cargo sqlx prepare --workspace -- --all-targets`.

```bash
git add -A
git commit -m "feat: scope branding to an organization"
```

---

### Task 12: Super-admin invites an organization's first local admin

**Files:**
- Modify: `crates/hangar-application/src/use_cases/invitation.rs` (`InviteUserUseCase`)
- Modify: `crates/hangar-api/src/routes/users.rs` (`CreateUserRequest`, `create_user`)

**Interfaces:**
- Closes the spec's requirement: "quand le super-admin crée une organisation, il désigne un
  premier admin local pour la nouvelle organisation, par le mécanisme d'invitation déjà
  existant." Restricted to super-admin for this plan — organization admins inviting their own
  members is out of scope here (a natural follow-up, not required for this plan's own
  "working, testable software" bar, since Task 6 already lets a super-admin create an
  organization and this task lets them populate it with its first admin).

- [ ] **Step 1: Write the failing test**

```rust
// crates/hangar-application/src/use_cases/invitation.rs — add to the existing test module
#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn inviting_a_user_assigns_them_to_the_given_organization_and_admin_flag(pool: sqlx::PgPool) {
    let organizations = std::sync::Arc::new(hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository::new(pool.clone()));
    let organization_id = uuid::Uuid::new_v4();
    organizations
        .create(&hangar_domain::organization::Organization {
            id: organization_id,
            slug: hangar_domain::organization::OrganizationSlug::parse("acme").unwrap(),
            display_name: "Acme".to_string(),
            is_public: false,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
    let users = std::sync::Arc::new(hangar_infrastructure::postgres::user_repository::PostgresUserRepository::new(pool.clone()));
    // mirror this file's existing test fixtures for invitations/hasher/email — read the
    // existing test module above this addition in full first, this use case's constructor
    // signature (users, invitations, hasher, email, public_url) is unchanged by this task, only
    // execute()'s parameters grow
    let use_case = InviteUserUseCase::new(users.clone(), invitations, hasher, email, "http://localhost:4200".to_string());

    let user_id = use_case.execute(organization_id, true, "acme-admin", "admin@acme.example", false).await.unwrap();

    let created = users.find_by_id(user_id).await.unwrap().unwrap();
    assert_eq!(created.organization_id, organization_id);
    assert!(created.is_organization_admin);
    assert!(!created.is_super_admin);
}
```

- [ ] **Step 2: Extend `InviteUserUseCase::execute`**

```rust
// crates/hangar-application/src/use_cases/invitation.rs
    pub async fn execute(&self, organization_id: Uuid, is_organization_admin: bool, username: &str, email: &str, is_super_admin: bool) -> Result<Uuid, ApplicationError> {
        let username = Username::parse(username)?;
        validate_email(email)?;
        if self.users.find_by_username(&username).await?.is_some() {
            return Err(ApplicationError::UsernameTaken);
        }
        let user = User {
            id: Uuid::new_v4(),
            username,
            password_hash: unusable_password_hash(self.hasher.as_ref())?,
            is_super_admin,
            is_organization_admin,
            organization_id,
            created_at: Utc::now(),
            email: Some(email.to_string()),
        };
        // ...unchanged from here: insert, generate/hash the invitation token, send the email...
    }
```

- [ ] **Step 3: Route — `CreateUserRequest` gains the two fields, resolved against the request's own organization**

```rust
// crates/hangar-api/src/routes/users.rs
#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    email: String,
    is_super_admin: bool,
    #[serde(default)]
    is_organization_admin: bool,
}

async fn create_user(
    State(state): State<AppState>,
    user: AuthUser,
    resolved_org: ResolvedOrganization,
    Json(body): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let id = state
        .invite_user
        .execute(resolved_org.0.id, body.is_organization_admin, &body.username, &body.email, body.is_super_admin)
        .await
        .map_err(|e| application_error_response("failed to invite user", e))?;
    Ok((
        StatusCode::CREATED,
        Json(UserResponse { id, username: body.username, is_super_admin: body.is_super_admin, email: Some(body.email), invitation_pending: true }),
    ))
}
```

The new admin is invited into whichever organization's subdomain the super-admin made the
request against (`companya.hangar.example/api/users` invites into `companya`) — consistent with
every other resolved-organization route in this plan, and requires no new "which organization"
field in the request body.

- [ ] **Step 4: Fix compile errors, run the full suite, regenerate sqlx cache, commit**

Run: `cargo build --workspace`, fix every remaining call site of `InviteUserUseCase::execute`
and `invite_user.execute` (existing tests in `crates/hangar-api/src/routes/users.rs` and
`crates/hangar-application/src/use_cases/invitation.rs` itself — pass a fresh organization id
and `false` for `is_organization_admin` unless the specific test is about this task's new
behavior).

Run: `cargo test --workspace`, then `cargo sqlx prepare --workspace -- --all-targets`.

```bash
git add -A
git commit -m "feat: super-admin invites an organization's first local admin"
```

---

### Task 13: Final verification

**Files:** none — verification only.

- [ ] **Step 1: Full workspace build and test**

Run: `cargo build --workspace` — zero warnings, zero errors.
Run: `cargo test --workspace` — zero failures.

- [ ] **Step 2: Confirm the sqlx offline cache is committed and correct**

Run: `git status --porcelain .sqlx/` — must be clean (nothing staged/untracked) after the
previous tasks' `cargo sqlx prepare` runs were committed. If anything shows up here, one of the
earlier tasks' Step "regenerate the sqlx offline cache" was skipped or its output wasn't
committed — go back and fix it now, this exact class of mistake broke the Dockerfile's offline
build once already in this project's history.

- [ ] **Step 3: Confirm `SQLX_OFFLINE=true` build succeeds**

Run: `SQLX_OFFLINE=true cargo build --workspace` from a state where the relevant crates have been
`cargo clean -p hangar-infrastructure -p hangar-api -p hangar-npm -p hangar-docker`'d first (a
plain re-run without cleaning can falsely pass by reusing incremental artifacts from the earlier
online build — this exact false-positive already happened once in this project's history,
confirm a genuine clean rebuild here).

- [ ] **Step 4: No further commit needed** — this task is verification-only. If any step above
      surfaces a problem, fix it as a new commit and re-run this task's steps from the top.

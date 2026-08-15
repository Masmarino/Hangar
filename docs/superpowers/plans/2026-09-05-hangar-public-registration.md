# Public Self-Registration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let anyone create an account in the `public` organization through a new `POST /api/auth/register` route and a real Angular registration page, landing them in the same mandatory-MFA-enrollment flow that invited users already go through.

**Architecture:** A new `RegisterPublicUserUseCase` in `hangar-application` creates a `User` directly (real password hash, no invitation/activation token) scoped to whatever organization the request resolves to. The route handler in `hangar-api` uses the existing `ResolvedOrganization` extractor to gate the route to `is_public` organizations only (400 elsewhere) and returns the exact same `LoginResponse` shape `POST /api/auth/login` returns, so the frontend can reuse its login-response handling. On the frontend, the mandatory MFA-enrollment UI currently lives inline inside `LoginPage`; it is extracted into a shared `MfaEnrollmentPage` component so both `LoginPage` and the new `RegisterPage` drive the same enrollment code instead of duplicating ~150 lines of security-sensitive logic.

**Tech Stack:** Rust (axum, sqlx, thiserror), Angular 18+ standalone components with signals, `@masmarino/gabarit` design system components (`gbt-input`, `gbt-button`).

**Spec:** [docs/superpowers/specs/2026-09-04-hangar-organizations-sso-design.md](../specs/2026-09-04-hangar-organizations-sso-design.md) — "Inscription publique" section: *"Nouvelle route POST /api/auth/register, disponible uniquement quand ResolvedOrganization est public (400 ailleurs). Flux : username/email/mot de passe → création du compte dans public, rôle membre simple → même parcours d'enrôlement MFA obligatoire que l'inscription actuelle par invitation."*

## Global Constraints

- The route is gated to `ResolvedOrganization.is_public == true` — any other organization's subdomain gets `400 Bad Request`, never `404` (this is a routing/config question, not a resource-existence question).
- A registered account always gets `is_organization_admin: false` and `is_super_admin: false` — public self-registration can never grant elevated roles.
- The account is created with a real, immediately-usable password hash (unlike `InviteUserUseCase`, which hashes random bytes as a placeholder until activation). No invitation row, no activation token, no activation email.
- The response from `POST /api/auth/register` has the exact same JSON shape as `POST /api/auth/login`'s `LoginResponse` (`token`, `mfa_token`, `mfa_setup_required`) — a fresh account has zero MFA factors, so `mfa_setup_required` is always `true` and `token` is always `null`.
- Username/email/password validation reuses the existing domain/application primitives: `Username::parse`, `Password::parse` (min 8 chars), and the email check already used by `InviteUserUseCase` (non-empty, contains `@`).
- No new `ApplicationError` variants are needed — `UsernameTaken`, `InvalidEmail`, and `Domain(DomainError::PasswordTooShort)` already exist and already map to `400 Bad Request` via `application_error_response`.

---

### Task 1: `RegisterPublicUserUseCase`

**Files:**
- Modify: `crates/hangar-application/src/use_cases/invitation.rs:34` (widen `validate_email` visibility)
- Create: `crates/hangar-application/src/use_cases/registration.rs`
- Modify: `crates/hangar-application/src/use_cases/mod.rs` (add `pub mod registration;`)

**Interfaces:**
- Consumes: `hangar_domain::user::{Password, PasswordHasherPort, User, UserRepositoryPort, Username}`; `crate::use_cases::invitation::validate_email` (widened to `pub(crate)`); `crate::error::ApplicationError`.
- Produces: `pub struct RegisterPublicUserUseCase` with `pub fn new(users: Arc<dyn UserRepositoryPort>, hasher: Arc<dyn PasswordHasherPort>) -> Self` and `pub async fn execute(&self, organization_id: Uuid, username: &str, email: &str, password: &str) -> Result<Uuid, ApplicationError>` — later tasks (Task 2: state wiring, Task 3: route) call this exact signature.

- [ ] **Step 1: Widen `validate_email` so the new use case can reuse it**

In `crates/hangar-application/src/use_cases/invitation.rs:34`, change:

```rust
fn validate_email(email: &str) -> Result<(), ApplicationError> {
```

to:

```rust
pub(crate) fn validate_email(email: &str) -> Result<(), ApplicationError> {
```

- [ ] **Step 2: Write the failing tests**

Create `crates/hangar-application/src/use_cases/registration.rs`:

```rust
use std::sync::Arc;

use hangar_domain::user::{Password, PasswordHasherPort, User, UserRepositoryPort, Username};
use uuid::Uuid;

use crate::error::ApplicationError;
use crate::use_cases::invitation::validate_email;

pub struct RegisterPublicUserUseCase {
    users: Arc<dyn UserRepositoryPort>,
    hasher: Arc<dyn PasswordHasherPort>,
}

impl RegisterPublicUserUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>, hasher: Arc<dyn PasswordHasherPort>) -> Self {
        Self { users, hasher }
    }

    /// `organization_id` is always the organization the request resolved to — the route
    /// handler is responsible for rejecting anything but the public organization before
    /// calling this. Unlike `InviteUserUseCase`, this hashes the caller's real password
    /// immediately: there is no invitation/activation step for a self-registered account.
    pub async fn execute(&self, organization_id: Uuid, username: &str, email: &str, password: &str) -> Result<Uuid, ApplicationError> {
        let username = Username::parse(username)?;
        validate_email(email)?;
        let password = Password::parse(password)?;
        if self.users.find_by_username(&username).await?.is_some() {
            return Err(ApplicationError::UsernameTaken);
        }

        let user = User {
            id: Uuid::new_v4(),
            username,
            password_hash: self.hasher.hash(password.as_str())?,
            is_super_admin: false,
            is_organization_admin: false,
            organization_id,
            created_at: chrono::Utc::now(),
            email: Some(email.to_string()),
        };
        self.users.insert(&user).await?;
        Ok(user.id)
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
    }

    #[async_trait]
    impl UserRepositoryPort for FakeUsers {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().get(&id).cloned())
        }
        async fn find_by_username(&self, username: &Username) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().values().find(|u| &u.username == username).cloned())
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

    fn setup() -> (Arc<FakeUsers>, Arc<FakeHasher>) {
        (Arc::new(FakeUsers::new()), Arc::new(FakeHasher))
    }

    #[tokio::test]
    async fn registers_a_user_with_an_immediately_usable_password() {
        let (users, hasher) = setup();
        let use_case = RegisterPublicUserUseCase::new(users.clone(), hasher.clone());
        let organization_id = Uuid::new_v4();

        let id = use_case.execute(organization_id, "florian", "florian@example.com", "sup3r-s3cret!").await.unwrap();

        let user = users.find_by_id(id).await.unwrap().unwrap();
        assert_eq!(user.organization_id, organization_id);
        assert_eq!(user.email.as_deref(), Some("florian@example.com"));
        assert!(!user.is_super_admin);
        assert!(!user.is_organization_admin);
        assert!(hasher.verify("sup3r-s3cret!", &user.password_hash), "the real password must work immediately, unlike an invited account's placeholder hash");
    }

    #[tokio::test]
    async fn rejects_a_duplicate_username() {
        let (users, hasher) = setup();
        let use_case = RegisterPublicUserUseCase::new(users, hasher);
        use_case.execute(Uuid::new_v4(), "florian", "a@example.com", "sup3r-s3cret!").await.unwrap();

        let err = use_case.execute(Uuid::new_v4(), "florian", "b@example.com", "sup3r-s3cret!").await.unwrap_err();
        assert!(matches!(err, ApplicationError::UsernameTaken));
    }

    #[tokio::test]
    async fn rejects_an_invalid_email() {
        let (users, hasher) = setup();
        let use_case = RegisterPublicUserUseCase::new(users, hasher);

        let err = use_case.execute(Uuid::new_v4(), "florian", "not-an-email", "sup3r-s3cret!").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidEmail(_)));
    }

    #[tokio::test]
    async fn rejects_a_password_shorter_than_the_minimum() {
        let (users, hasher) = setup();
        let use_case = RegisterPublicUserUseCase::new(users, hasher);

        let err = use_case.execute(Uuid::new_v4(), "florian", "florian@example.com", "short").await.unwrap_err();
        assert!(matches!(err, ApplicationError::Domain(DomainError::PasswordTooShort)), "got {err:?}");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn registering_persists_the_user_scoped_to_the_given_organization(pool: sqlx::PgPool) {
        let organizations = Arc::new(hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository::new(pool.clone()));
        let organization_id = Uuid::new_v4();
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
        let users = Arc::new(hangar_infrastructure::postgres::user_repository::PostgresUserRepository::new(pool.clone()));
        let (_, hasher) = setup();
        let use_case = RegisterPublicUserUseCase::new(users.clone(), hasher);

        let user_id = use_case.execute(organization_id, "acme-member", "member@acme.example", "sup3r-s3cret!").await.unwrap();

        let created = users.find_by_id(user_id).await.unwrap().unwrap();
        assert_eq!(created.organization_id, organization_id);
        assert!(!created.is_organization_admin);
        assert!(!created.is_super_admin);
    }
}
```

Add the module to `crates/hangar-application/src/use_cases/mod.rs`:

```rust
pub mod registration;
```

(insert alphabetically-adjacent to the existing `pub mod` lines — exact position doesn't matter, the file has no ordering convention beyond insertion order).

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test -p hangar-application registration:: -- --nocapture`
Expected: PASS (5 tests: 4 unit + 1 `sqlx::test`, the latter requires the dev Postgres container to be running). Step 2 wrote the use case and its tests together since the implementation is a direct, well-specified transcription of `CreateUserUseCase`/`InviteUserUseCase`'s already-established pattern — there is no meaningful "red" state to observe first. Before trusting a PASS here, sanity-check each test actually exercises its claim: temporarily comment out the `if self.users.find_by_username(&username).await?.is_some() { ... }` block and confirm `rejects_a_duplicate_username` now fails, then restore it — same for the email/password checks against their respective tests. This is the mutation-testing discipline this codebase already applies to its security-relevant tests (see the isolation tests in `crates/hangar-api/src/routes/repositories.rs`); apply it here too since account creation is security-relevant.

- [ ] **Step 4: Commit**

```bash
git add crates/hangar-application/src/use_cases/invitation.rs crates/hangar-application/src/use_cases/registration.rs crates/hangar-application/src/use_cases/mod.rs
git commit -m "feat: add RegisterPublicUserUseCase for public self-registration"
```

---

### Task 2: Wire `RegisterPublicUserUseCase` into `AppState`

**Files:**
- Modify: `crates/hangar-api/src/state.rs`

**Interfaces:**
- Consumes: `RegisterPublicUserUseCase::new(users: Arc<dyn UserRepositoryPort>, hasher: Arc<dyn PasswordHasherPort>)` from Task 1; the existing `users_repo` and `hasher` `Arc`s already constructed earlier in `AppState::build` (the same ones passed to `CreateUserUseCase::new(users_repo.clone(), hasher.clone())` at `state.rs:276`).
- Produces: `pub register_public_user: Arc<RegisterPublicUserUseCase>` field on `AppState`, consumed by Task 3's route handler as `state.register_public_user`.

- [ ] **Step 1: Add the import**

In `crates/hangar-api/src/state.rs`, next to the existing:

```rust
use hangar_application::use_cases::user::{AuthenticateUserUseCase, ChangePasswordUseCase, CreateUserUseCase, DeleteUserUseCase, SetSuperAdminUseCase};
```

add:

```rust
use hangar_application::use_cases::registration::RegisterPublicUserUseCase;
```

- [ ] **Step 2: Add the field**

Next to the existing `pub create_user: Arc<CreateUserUseCase>,` (around `state.rs:88`), add:

```rust
pub register_public_user: Arc<RegisterPublicUserUseCase>,
```

- [ ] **Step 3: Construct it in `AppState::build`**

Next to the existing `create_user: Arc::new(CreateUserUseCase::new(users_repo.clone(), hasher.clone())),` (around `state.rs:276`), add:

```rust
register_public_user: Arc::new(RegisterPublicUserUseCase::new(users_repo.clone(), hasher.clone())),
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo build -p hangar-api 2>&1 | tail -40`
Expected: succeeds (this task adds no new tests of its own — Task 3's route tests exercise this wiring).

- [ ] **Step 5: Commit**

```bash
git add crates/hangar-api/src/state.rs
git commit -m "feat: wire RegisterPublicUserUseCase into AppState"
```

---

### Task 3: `POST /api/auth/register` route

**Files:**
- Modify: `crates/hangar-api/src/dto.rs` (add `RegisterRequest`)
- Modify: `crates/hangar-api/src/routes/auth.rs`

**Interfaces:**
- Consumes: `crate::organization_middleware::ResolvedOrganization` (the `Organization` it wraps has a `pub is_public: bool` field and `pub id: Uuid`, per `hangar_domain::organization::Organization`); `state.register_public_user.execute(organization_id, username, email, password)` from Task 2; `crate::dto::{application_error_response, ErrorResponse, LoginResponse}` (all already imported in `auth.rs`); `state.mfa_pending_token_issuer` (already used by the `login` handler at `auth.rs:67`).
- Produces: the route `POST /api/auth/register`, added to the `Router` returned by `pub fn router()` in `auth.rs`. No later task in this plan consumes this directly — it is the frontend's `HttpAuthAdapter.register()` (Task 5) that calls it over HTTP.

- [ ] **Step 1: Add the request DTO**

In `crates/hangar-api/src/dto.rs`, next to the existing `LoginRequest`/`MfaVerifyRequest` structs, add:

```rust
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}
```

(Match the existing `derive` list and field visibility used by `LoginRequest` in this same file — copy its exact `#[derive(...)]` line so `serde` behavior stays consistent.)

- [ ] **Step 2: Write the failing tests**

Add to the `#[cfg(test)] mod tests` block in `crates/hangar-api/src/routes/auth.rs`, after `login_request` (around line 997):

```rust
    fn register_request(username: &str, email: &str, password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/auth/register")
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"username":"{username}","email":"{email}","password":"{password}"}}"#)))
            .unwrap()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn registering_on_the_public_organization_returns_a_mfa_setup_response(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(register_request("florian", "florian@example.com", "sup3r-s3cret!")).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["token"].is_null());
        assert!(json["mfa_token"].is_string());
        assert_eq!(json["mfa_setup_required"], true);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_registered_account_can_complete_enrollment_and_log_in_again(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.clone().oneshot(register_request("florian", "florian@example.com", "sup3r-s3cret!")).await.unwrap();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mfa_token = json["mfa_token"].as_str().unwrap();

        let enroll_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/setup/totp/enroll")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"mfa_token":"{mfa_token}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(enroll_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let secret = json["secret"].as_str().unwrap();
        let code = hangar_application::use_cases::mfa::generate_current_totp_code(secret);

        let confirm_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/setup/totp/confirm")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"mfa_token":"{mfa_token}","code":"{code}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(confirm_response.status(), axum::http::StatusCode::OK);

        // The real password set at registration must work immediately — no activation step.
        let login = app.oneshot(login_request("florian", "sup3r-s3cret!")).await.unwrap();
        assert_eq!(login.status(), axum::http::StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn registering_on_a_non_public_organization_subdomain_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state
            .organizations
            .create(&hangar_domain::organization::Organization {
                id: Uuid::new_v4(),
                slug: hangar_domain::organization::OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let app = build_router(state);

        let mut request = register_request("florian", "florian@example.com", "sup3r-s3cret!");
        request.headers_mut().insert("host", "acme.hangar.localhost".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn registering_a_duplicate_username_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);
        app.clone().oneshot(register_request("florian", "a@example.com", "sup3r-s3cret!")).await.unwrap();

        let response = app.oneshot(register_request("florian", "b@example.com", "sup3r-s3cret!")).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn registering_with_a_weak_password_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(register_request("florian", "florian@example.com", "short")).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }
```

Note: `test_config()` in this file sets `hangar_base_domain: "hangar.localhost".to_string()` — the default `Request::builder()` used by `register_request`/`login_request` sends no explicit `host` header, and axum test requests without one resolve to an empty `Host`, which `ResolvedOrganization` treats as the public organization (see `organization_middleware.rs`'s `an_empty_host_label_resolves_to_the_public_organization` test) — so the plain-host tests above exercise the public path without needing to set a header.

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p hangar-api routes::auth:: register 2>&1 | tail -40`
Expected: FAIL to compile (`register_request` and the route `/api/auth/register` don't exist yet) or 404s once compiling against the router without the new route.

- [ ] **Step 4: Implement the route handler**

In `crates/hangar-api/src/routes/auth.rs`, update the import line:

```rust
use crate::dto::{application_error_response, ActivateAccountRequest, ChangePasswordRequest, ErrorResponse, LoginRequest, LoginResponse, MeResponse, MfaVerifyRequest};
```

to:

```rust
use crate::dto::{application_error_response, ActivateAccountRequest, ChangePasswordRequest, ErrorResponse, LoginRequest, LoginResponse, MeResponse, MfaVerifyRequest, RegisterRequest};
use crate::organization_middleware::ResolvedOrganization;
```

Add the route to `pub fn router()`:

```rust
        .route("/api/auth/register", post(register))
```

(placed next to `.route("/api/auth/login", post(login))`).

Add the handler, next to `login`:

```rust
/// Unauthenticated by design — this is how an account is first created. Gated to the
/// `public` organization: any other organization's accounts are provisioned by an
/// org-admin invitation instead (`InviteUserUseCase`), never by open self-registration.
async fn register(
    State(state): State<AppState>,
    resolved_org: ResolvedOrganization,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    if !resolved_org.0.is_public {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "public self-registration is not available on this organization".to_string() })));
    }

    let user_id = state
        .register_public_user
        .execute(resolved_org.0.id, &body.username, &body.email, &body.password)
        .await
        .map_err(|e| application_error_response("failed to register user", e))?;

    // A fresh account has zero MFA factors — always route straight to mandatory setup,
    // exactly like `login`'s `!already_enrolled` branch.
    let mfa_token = state
        .mfa_pending_token_issuer
        .issue(user_id)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    Ok(Json(LoginResponse { token: None, mfa_token: Some(mfa_token), mfa_setup_required: true }))
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p hangar-api routes::auth:: -- --nocapture 2>&1 | tail -60`
Expected: PASS, including all pre-existing `auth.rs` tests (no regressions) and the 5 new ones from Step 2.

- [ ] **Step 6: Regenerate the sqlx offline cache**

The new route introduces no new SQL queries (it only calls existing repository methods), so this step should be a no-op — run it anyway to confirm:

Run: `cargo sqlx prepare --workspace -- --all-targets 2>&1 | tail -20`
Expected: no changes to `.sqlx/` (or a clean regeneration if the tool reformats the cache).

- [ ] **Step 7: Commit**

```bash
git add crates/hangar-api/src/dto.rs crates/hangar-api/src/routes/auth.rs .sqlx/
git commit -m "feat: add POST /api/auth/register, gated to the public organization"
```

---

### Task 4: Update README config/route documentation

**Files:**
- Modify: `README.md`
- Modify: `README.en.md`

**Interfaces:**
- Consumes: nothing (documentation only).
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Add the route to each README's API/route listing**

Grep both files for where `/api/auth/login` or `/api/auth/activate` are documented (each README lists its API routes in a table or bullet list near the authentication section):

```bash
grep -n "api/auth/login\|api/auth/activate" README.md README.en.md
```

Add a row/bullet for `POST /api/auth/register` immediately after the `/api/auth/login` entry in each file, phrased consistently with the surrounding entries in that file (French in `README.md`, English in `README.en.md`). Example English phrasing: *"`POST /api/auth/register` — self-registers a new account in the public organization (disabled on any other organization's subdomain); returns the same MFA-enrollment response as login."*

- [ ] **Step 2: Commit**

```bash
git add README.md README.en.md
git commit -m "docs: document the public self-registration route"
```

---

### Task 5: `AuthPort`/`AuthService` — `register()`

**Files:**
- Modify: `frontend/src/app/auth/application/auth.port.ts`
- Modify: `frontend/src/app/auth/infrastructure/http-auth.adapter.ts`
- Modify: `frontend/src/app/auth/application/auth.service.ts`
- Test: `frontend/src/app/auth/application/auth.service.spec.ts` (new)

**Interfaces:**
- Consumes: `LoginResponse` from `../domain/auth.types` (unchanged shape — the backend returns exactly this shape from Task 3).
- Produces: `AuthPort.register(username: string, email: string, password: string): Observable<LoginResponse>`; `AuthService.register(username: string, email: string, password: string): Observable<LoginOutcome>` — Task 7's `RegisterPage` calls this exact method.

- [ ] **Step 1: Add `register` to the port interface**

In `frontend/src/app/auth/application/auth.port.ts`, add to `AuthPort`:

```typescript
  register(username: string, email: string, password: string): Observable<LoginResponse>
```

(placed next to the existing `login` method).

- [ ] **Step 2: Implement it in the HTTP adapter**

In `frontend/src/app/auth/infrastructure/http-auth.adapter.ts`, add:

```typescript
  register(username: string, email: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>('/api/auth/register', { username, email, password })
  }
```

(placed next to the existing `login` method).

- [ ] **Step 3: Write the failing test for `AuthService.register`**

Create `frontend/src/app/auth/application/auth.service.spec.ts`:

```typescript
import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { AuthService } from './auth.service'
import { AUTH_PORT, AuthPort } from './auth.port'
import { LoginResponse } from '../domain/auth.types'

describe('AuthService', () => {
  function setup(port: Partial<AuthPort>) {
    TestBed.configureTestingModule({
      providers: [AuthService, { provide: AUTH_PORT, useValue: port }],
    })
    return TestBed.inject(AuthService)
  }

  it('reports mfa setup required when registration returns no token', (done) => {
    const response: LoginResponse = { token: null, mfa_token: 'mfa-token-123', mfa_setup_required: true }
    const service = setup({ register: () => of(response) })

    service.register('florian', 'florian@example.com', 'sup3r-s3cret!').subscribe((outcome) => {
      expect(outcome.mfaRequired).toBe(true)
      expect(outcome.mfaToken).toBe('mfa-token-123')
      expect(outcome.mfaSetupRequired).toBe(true)
      done()
    })
  })
})
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cd frontend && npx ng test --watch=false --include='**/auth.service.spec.ts'`
Expected: FAIL — `AuthService.register` doesn't exist yet.

- [ ] **Step 5: Implement `AuthService.register`, factoring out the shared response mapping**

In `frontend/src/app/auth/application/auth.service.ts`, `login` and the new `register` produce an identical `LoginOutcome` from a `LoginResponse` — factor that mapping into one private method rather than duplicating it:

```typescript
  login(username: string, password: string): Observable<LoginOutcome> {
    return this.port.login(username, password).pipe(map((response) => this.toOutcome(response)))
  }

  register(username: string, email: string, password: string): Observable<LoginOutcome> {
    return this.port.register(username, email, password).pipe(map((response) => this.toOutcome(response)))
  }

  private toOutcome(response: LoginResponse): LoginOutcome {
    if (response.token) {
      this.setToken(response.token)
      return { mfaRequired: false }
    }
    return {
      mfaRequired: true,
      mfaToken: response.mfa_token ?? undefined,
      mfaSetupRequired: response.mfa_setup_required,
    }
  }
```

This replaces the existing `login` method body (which currently inlines the same `map` callback — see `auth.service.ts:15-29`) and adds `register` next to it.

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd frontend && npx ng test --watch=false --include='**/auth.service.spec.ts'`
Expected: PASS.

- [ ] **Step 7: Run the full frontend test suite to confirm no regression on `login`**

Run: `cd frontend && npx ng test --watch=false`
Expected: PASS (the `toOutcome` refactor must not change `login`'s existing observable behavior).

- [ ] **Step 8: Commit**

```bash
git add frontend/src/app/auth/application/auth.port.ts frontend/src/app/auth/infrastructure/http-auth.adapter.ts frontend/src/app/auth/application/auth.service.ts frontend/src/app/auth/application/auth.service.spec.ts
git commit -m "feat(frontend): add AuthService.register and factor out LoginResponse mapping"
```

---

### Task 6: Extract `MfaEnrollmentPage` out of `LoginPage`

**Files:**
- Create: `frontend/src/app/auth/mfa-enrollment/mfa-enrollment.ts`
- Create: `frontend/src/app/auth/mfa-enrollment/mfa-enrollment.html`
- Create: `frontend/src/app/auth/mfa-enrollment/mfa-enrollment.scss`
- Create: `frontend/src/app/auth/mfa-enrollment/mfa-enrollment.spec.ts`
- Modify: `frontend/src/app/auth/login-page/login-page.ts`
- Modify: `frontend/src/app/auth/login-page/login-page.html`

**Interfaces:**
- Consumes: `AuthService.startTotpSetup`, `confirmTotpSetup`, `startPasskeySetup`, `finishPasskeySetup` (all pre-existing, unchanged); `passkeysSupported`, `createPasskeyCredential`, `getPasskeyAssertion` from `'../../shared/webauthn-browser'` (unchanged).
- Produces: standalone `MfaEnrollmentPage` component, selector `app-mfa-enrollment`, with a required `mfaToken` input (`input.required<string>()`) and a `completed` output (`output<void>()`) fired once a factor has been fully enrolled and a real session token has been stored. Task 7's `RegisterPage` template uses this component directly: `<app-mfa-enrollment [mfaToken]="mfaToken()!" (completed)="onEnrollmentCompleted()" />`.

This task is a pure refactor: the mandatory-enrollment behavior (`setupStep`, `totpSecret`, `qrCodeDataUrl`, `setupCode`, `passkeyName`, `backupCodes`, `chooseTotpSetup`, `choosePasskeySetup`, `backToChoice`, `confirmTotpSetup`, `finishSetup`, `registerSetupPasskey`, and their template block) moves out of `LoginPage` verbatim into the new component. `LoginPage` keeps everything about its own username/password form and the "verify an already-enrolled factor" branch (`mfaForm`, `useBackupCode`, `submitMfa`, `submitPasskey`) — those stay, since they only apply when an account already has a factor, which is a login-only concern the register flow never hits (a freshly registered account is always in the `mfa_setup_required: true` branch).

- [ ] **Step 1: Write the failing test for the extracted component**

Create `frontend/src/app/auth/mfa-enrollment/mfa-enrollment.spec.ts`:

```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { MfaEnrollmentPage } from './mfa-enrollment'
import { AuthService } from '../application/auth.service'

describe('MfaEnrollmentPage', () => {
  let fixture: ComponentFixture<MfaEnrollmentPage>
  let component: MfaEnrollmentPage
  let authServiceSpy: jasmine.SpyObj<AuthService>

  beforeEach(() => {
    authServiceSpy = jasmine.createSpyObj<AuthService>('AuthService', [
      'startTotpSetup',
      'confirmTotpSetup',
      'startPasskeySetup',
      'finishPasskeySetup',
    ])

    TestBed.configureTestingModule({
      imports: [MfaEnrollmentPage],
      providers: [{ provide: AuthService, useValue: authServiceSpy }],
    })
    fixture = TestBed.createComponent(MfaEnrollmentPage)
    component = fixture.componentInstance
    fixture.componentRef.setInput('mfaToken', 'mfa-token-123')
    fixture.detectChanges()
  })

  it('starts in the choice step', () => {
    expect(component.setupStep()).toBe('choice')
  })

  it('moves to the totp-enroll step and stores the secret on chooseTotpSetup', () => {
    authServiceSpy.startTotpSetup.and.returnValue(of({ secret: 'ABCD1234', otpauth_url: 'otpauth://totp/x' }))

    component.chooseTotpSetup()

    expect(authServiceSpy.startTotpSetup).toHaveBeenCalledWith('mfa-token-123')
    expect(component.setupStep()).toBe('totp-enroll')
    expect(component.totpSecret()).toBe('ABCD1234')
  })

  it('emits completed once backup codes are acknowledged', () => {
    const completedSpy = jasmine.createSpy('completed')
    component.completed.subscribe(completedSpy)

    component.finishSetup()

    expect(completedSpy).toHaveBeenCalled()
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd frontend && npx ng test --watch=false --include='**/mfa-enrollment.spec.ts'`
Expected: FAIL — `./mfa-enrollment` doesn't exist yet.

- [ ] **Step 3: Create the component, moving the enrollment logic out of `LoginPage`**

Create `frontend/src/app/auth/mfa-enrollment/mfa-enrollment.ts`:

```typescript
import {
  ChangeDetectionStrategy,
  Component,
  EventEmitter,
  Output,
  inject,
  input,
  signal,
} from '@angular/core'
import { FormsModule } from '@angular/forms'
import { firstValueFrom } from 'rxjs'
import { Button, GbtInput } from '@masmarino/gabarit'
import { AuthService } from '../application/auth.service'
import {
  createPasskeyCredential,
  passkeysSupported,
} from '../../shared/webauthn-browser'

type SetupStep = 'choice' | 'totp-enroll' | 'backup-codes' | 'passkey'

/**
 * The mandatory first-time MFA enrollment flow — every account must enroll a factor before
 * it can be used, whether the account came from an invitation, a login on an account with
 * no factor yet, or public self-registration. `AuthService.confirmTotpSetup` /
 * `finishPasskeySetup` already store the resulting session token; this component only
 * drives the enrollment steps and tells its parent when a factor is in place.
 */
@Component({
  selector: 'app-mfa-enrollment',
  standalone: true,
  imports: [FormsModule, GbtInput, Button],
  templateUrl: './mfa-enrollment.html',
  styleUrl: './mfa-enrollment.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class MfaEnrollmentPage {
  private readonly auth = inject(AuthService)

  readonly mfaToken = input.required<string>()

  @Output() readonly completed = new EventEmitter<void>()

  readonly errorMessage = signal<string | null>(null)
  readonly submitting = signal(false)
  readonly passkeysSupported = passkeysSupported()

  readonly setupStep = signal<SetupStep>('choice')
  readonly totpSecret = signal('')
  readonly qrCodeDataUrl = signal<string | null>(null)
  readonly setupCode = signal('')
  readonly passkeyName = signal('')
  readonly backupCodes = signal<string[]>([])

  chooseTotpSetup(): void {
    if (this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    this.auth.startTotpSetup(this.mfaToken()).subscribe({
      next: (enrollment) => {
        this.submitting.set(false)
        this.totpSecret.set(enrollment.secret)
        // Only needed for this one-time enrollment screen — not worth shipping to every login-page visit.
        import('qrcode')
          .then((QRCode) => QRCode.toDataURL(enrollment.otpauth_url))
          .then((dataUrl) => this.qrCodeDataUrl.set(dataUrl))
          .catch(() => this.qrCodeDataUrl.set(null))
        this.setupStep.set('totp-enroll')
      },
      error: () => {
        this.submitting.set(false)
        this.errorMessage.set("Échec de la préparation de l'application d'authentification.")
      },
    })
  }

  choosePasskeySetup(): void {
    this.errorMessage.set(null)
    this.setupStep.set('passkey')
  }

  backToChoice(): void {
    this.errorMessage.set(null)
    this.setupCode.set('')
    this.passkeyName.set('')
    this.setupStep.set('choice')
  }

  confirmTotpSetup(): void {
    if (this.setupCode().trim() === '' || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    this.auth.confirmTotpSetup(this.mfaToken(), this.setupCode()).subscribe({
      next: (result) => {
        this.submitting.set(false)
        this.backupCodes.set(result.backup_codes)
        this.setupStep.set('backup-codes')
      },
      error: () => {
        this.submitting.set(false)
        this.errorMessage.set('Code invalide.')
      },
    })
  }

  finishSetup(): void {
    this.completed.emit()
  }

  async registerSetupPasskey(): Promise<void> {
    if (this.passkeyName().trim() === '' || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    try {
      const start = await firstValueFrom(this.auth.startPasskeySetup(this.mfaToken()))
      const credential = await createPasskeyCredential(start.public_key)
      await firstValueFrom(
        this.auth.finishPasskeySetup(this.mfaToken(), start.challenge_id, credential, this.passkeyName()),
      )
      this.completed.emit()
    } catch (err) {
      console.error('Passkey registration failed:', err)
      this.submitting.set(false)
      this.errorMessage.set("Échec de l'enregistrement de la clé d'accès. Réessayez.")
    }
  }
}
```

Create `frontend/src/app/auth/mfa-enrollment/mfa-enrollment.html` (moved verbatim from the `@else if (mfaSetupRequired())` block of `login-page.html:21-109`, with `mfaToken()` calls removed since this component reaches it directly via its own `mfaToken` input rather than a parent-passed signal):

```html
<p>La double authentification est obligatoire sur ce compte.</p>
@switch (setupStep()) {
  @case ('choice') {
    <p>Choisissez une méthode pour continuer :</p>
    @if (errorMessage(); as message) {
      <p class="gbt-form-error" role="alert">{{ message }}</p>
    }
    <div class="auth-layout__actions">
      <gbt-button
        text="Application d'authentification (TOTP)"
        [loading]="submitting()"
        loadingLabel="Chargement en cours"
        [disabled]="submitting()"
        (clicked)="chooseTotpSetup()"
      />
      @if (passkeysSupported) {
        <gbt-button
          text="Clé d'accès (passkey)"
          variant="secondary"
          [disabled]="submitting()"
          (clicked)="choosePasskeySetup()"
        />
      }
    </div>
  }
  @case ('totp-enroll') {
    <p>
      Scannez ce QR code avec votre application d'authentification, ou saisissez le code
      manuellement :
    </p>
    @if (qrCodeDataUrl(); as dataUrl) {
      <img [src]="dataUrl" alt="QR code d'activation" class="auth-layout__qr" />
    }
    <p class="auth-layout__secret">{{ totpSecret() }}</p>
    <gbt-input
      label="Code de vérification"
      [ngModel]="setupCode()"
      [ngModelOptions]="{ standalone: true }"
      (ngModelChange)="setupCode.set($event)"
    />
    @if (errorMessage(); as message) {
      <p class="gbt-form-error" role="alert">{{ message }}</p>
    }
    <div class="auth-layout__actions">
      <gbt-button
        text="Confirmer"
        [loading]="submitting()"
        loadingLabel="Chargement en cours"
        [disabled]="setupCode().trim() === ''"
        (clicked)="confirmTotpSetup()"
      />
      <gbt-button text="Retour" variant="secondary" (clicked)="backToChoice()" />
    </div>
  }
  @case ('backup-codes') {
    <p>
      Double authentification activée. Conservez ces codes de secours dans un endroit sûr —
      chacun ne peut être utilisé qu'une seule fois.
    </p>
    <ul class="auth-layout__codes">
      @for (code of backupCodes(); track code) {
        <li>{{ code }}</li>
      }
    </ul>
    <gbt-button text="J'ai sauvegardé ces codes" (clicked)="finishSetup()" />
  }
  @case ('passkey') {
    <gbt-input
      label="Nom de la clé (ex. « MacBook Touch ID »)"
      [ngModel]="passkeyName()"
      [ngModelOptions]="{ standalone: true }"
      (ngModelChange)="passkeyName.set($event)"
    />
    @if (errorMessage(); as message) {
      <p class="gbt-form-error" role="alert">{{ message }}</p>
    }
    <div class="auth-layout__actions">
      <gbt-button
        text="Enregistrer la clé d'accès"
        [loading]="submitting()"
        loadingLabel="Chargement en cours"
        [disabled]="passkeyName().trim() === ''"
        (clicked)="registerSetupPasskey()"
      />
      <gbt-button text="Retour" variant="secondary" (clicked)="backToChoice()" />
    </div>
  }
}
```

Create `frontend/src/app/auth/mfa-enrollment/mfa-enrollment.scss`:

```scss
@use '../login-page/login-page.scss';
```

(the `.auth-layout__*` classes referenced in the template above are already defined in `login-page.scss`; this component is always rendered inside a page that already wraps it in `<main class="auth-layout"><div class="auth-layout__card">`, both `LoginPage`'s and Task 7's `RegisterPage`'s, so no new layout classes are needed. If `@use` on a sibling stylesheet doesn't resolve cleanly given this project's Sass/Angular build config, fall back to `styleUrl: '../login-page/login-page.scss'` on the `@Component` decorator instead, mirroring the exact pattern `ActivatePage` already uses at `activate-page.ts:12`.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd frontend && npx ng test --watch=false --include='**/mfa-enrollment.spec.ts'`
Expected: PASS.

- [ ] **Step 5: Update `LoginPage` to use the extracted component**

In `frontend/src/app/auth/login-page/login-page.ts`, remove the now-duplicated state and methods (`setupStep`, `totpSecret`, `qrCodeDataUrl`, `setupCode`, `passkeyName`, `backupCodes`, `chooseTotpSetup`, `choosePasskeySetup`, `backToChoice`, `confirmTotpSetup`, `finishSetup`, `registerSetupPasskey`), remove the now-unused `createPasskeyCredential` import (keep `getPasskeyAssertion`, still used by `submitPasskey`), and add `MfaEnrollmentPage` to `imports`:

```typescript
import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core'
import {
  FormControl,
  FormGroup,
  FormsModule,
  ReactiveFormsModule,
  Validators,
} from '@angular/forms'
import { Router } from '@angular/router'
import { firstValueFrom } from 'rxjs'
import { Button, GbtInput } from '@masmarino/gabarit'
import { AuthService } from '../application/auth.service'
import { getPasskeyAssertion, passkeysSupported } from '../../shared/webauthn-browser'
import { MfaEnrollmentPage } from '../mfa-enrollment/mfa-enrollment'

@Component({
  selector: 'app-login-page',
  standalone: true,
  imports: [ReactiveFormsModule, FormsModule, GbtInput, Button, MfaEnrollmentPage],
  templateUrl: './login-page.html',
  styleUrl: './login-page.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LoginPage {
  private readonly auth = inject(AuthService)
  private readonly router = inject(Router)

  readonly form = new FormGroup({
    username: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    password: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  })

  readonly errorMessage = signal<string | null>(null)
  readonly submitting = signal(false)

  // `null` until a login response says a second factor is required — the
  // template swaps to the MFA form the moment this is set. `mfaSetupRequired`
  // then decides whether that shows `app-mfa-enrollment` or the "verify an
  // existing factor" form below.
  readonly mfaToken = signal<string | null>(null)
  readonly mfaSetupRequired = signal(false)
  readonly useBackupCode = signal(false)
  readonly mfaForm = new FormGroup({
    code: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  })
  readonly passkeysSupported = passkeysSupported()

  submit(): void {
    if (this.form.invalid || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    const { username, password } = this.form.getRawValue()
    this.auth.login(username, password).subscribe({
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

  toggleBackupCode(): void {
    this.useBackupCode.update((value) => !value)
    this.mfaForm.reset()
    this.errorMessage.set(null)
  }

  submitMfa(): void {
    const mfaToken = this.mfaToken()
    if (!mfaToken || this.mfaForm.invalid || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    const { code } = this.mfaForm.getRawValue()
    const verify = this.useBackupCode()
      ? this.auth.verifyMfa(mfaToken, undefined, code)
      : this.auth.verifyMfa(mfaToken, code, undefined)
    verify.subscribe({
      next: () => this.router.navigateByUrl('/'),
      error: () => {
        this.submitting.set(false)
        this.errorMessage.set(this.useBackupCode() ? 'Code de secours invalide.' : 'Code invalide.')
      },
    })
  }

  async submitPasskey(): Promise<void> {
    const mfaToken = this.mfaToken()
    if (!mfaToken || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    try {
      const start = await firstValueFrom(this.auth.startMfaPasskey(mfaToken))
      const credential = await getPasskeyAssertion(start.public_key)
      await firstValueFrom(this.auth.finishMfaPasskey(mfaToken, start.challenge_id, credential))
      this.router.navigateByUrl('/')
    } catch {
      this.submitting.set(false)
      this.errorMessage.set("Échec de l'authentification par clé d'accès.")
    }
  }

  onEnrollmentCompleted(): void {
    this.router.navigateByUrl('/')
  }
}
```

In `frontend/src/app/auth/login-page/login-page.html`, replace the entire `@else if (mfaSetupRequired()) { ... }` block (lines 21-109) with:

```html
    } @else if (mfaSetupRequired()) {
      <app-mfa-enrollment [mfaToken]="mfaToken()!" (completed)="onEnrollmentCompleted()" />
    } @else {
```

- [ ] **Step 6: Run the full frontend test suite**

Run: `cd frontend && npx ng test --watch=false`
Expected: PASS — no regression on any existing `login-page.spec.ts` test that exercises mandatory enrollment (if such a test exists, it now needs to assert against `app-mfa-enrollment`'s presence/inputs rather than the old inline template; adjust it to match if the suite reports a failure here, following the same before/after pattern used throughout this plan).

- [ ] **Step 7: Commit**

```bash
git add frontend/src/app/auth/mfa-enrollment/ frontend/src/app/auth/login-page/login-page.ts frontend/src/app/auth/login-page/login-page.html frontend/src/app/auth/login-page/login-page.spec.ts
git commit -m "refactor(frontend): extract MfaEnrollmentPage out of LoginPage"
```

---

### Task 7: `RegisterPage`

**Files:**
- Create: `frontend/src/app/auth/register-page/register-page.ts`
- Create: `frontend/src/app/auth/register-page/register-page.html`
- Create: `frontend/src/app/auth/register-page/register-page.spec.ts`
- Modify: `frontend/src/app/app.routes.ts`
- Modify: `frontend/src/app/auth/login-page/login-page.html`

**Interfaces:**
- Consumes: `AuthService.register` from Task 5; `MfaEnrollmentPage` from Task 6.
- Produces: route `path: 'register'`, reachable from a link on the login page.

- [ ] **Step 1: Write the failing test**

Create `frontend/src/app/auth/register-page/register-page.spec.ts`:

```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing'
import { provideRouter } from '@angular/router'
import { of, throwError } from 'rxjs'
import { RegisterPage } from './register-page'
import { AuthService } from '../application/auth.service'

describe('RegisterPage', () => {
  let fixture: ComponentFixture<RegisterPage>
  let component: RegisterPage
  let authServiceSpy: jasmine.SpyObj<AuthService>

  beforeEach(() => {
    authServiceSpy = jasmine.createSpyObj<AuthService>('AuthService', ['register'])
    TestBed.configureTestingModule({
      imports: [RegisterPage],
      providers: [provideRouter([]), { provide: AuthService, useValue: authServiceSpy }],
    })
    fixture = TestBed.createComponent(RegisterPage)
    component = fixture.componentInstance
    fixture.detectChanges()
  })

  it('does not submit an invalid form', () => {
    component.submit()
    expect(authServiceSpy.register).not.toHaveBeenCalled()
  })

  it('routes to mandatory enrollment on a successful registration', () => {
    authServiceSpy.register.and.returnValue(of({ mfaRequired: true, mfaToken: 'mfa-token-123', mfaSetupRequired: true }))
    component.form.setValue({ username: 'florian', email: 'florian@example.com', password: 'sup3r-s3cret!' })

    component.submit()

    expect(authServiceSpy.register).toHaveBeenCalledWith('florian', 'florian@example.com', 'sup3r-s3cret!')
    expect(component.mfaToken()).toBe('mfa-token-123')
  })

  it('surfaces a duplicate-username error', () => {
    authServiceSpy.register.and.returnValue(throwError(() => new Error('username already taken')))
    component.form.setValue({ username: 'florian', email: 'florian@example.com', password: 'sup3r-s3cret!' })

    component.submit()

    expect(component.errorMessage()).toContain('nom d’utilisateur')
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd frontend && npx ng test --watch=false --include='**/register-page.spec.ts'`
Expected: FAIL — `./register-page` doesn't exist yet.

- [ ] **Step 3: Implement `RegisterPage`**

Create `frontend/src/app/auth/register-page/register-page.ts`. Note: unlike `LoginPage`'s `error: () => ...` handlers (which show one fixed string, e.g. `login-page.ts:78-81`), this page needs the actual backend validation message to tell "username taken" apart from "weak password" — `HttpClient` surfaces the backend's `ErrorResponse { error: String }` body at `HttpErrorResponse.error.error`, so the error handler reads it from there rather than from `Error.message`:

```typescript
import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core'
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms'
import { Router, RouterLink } from '@angular/router'
import { Button, GbtInput } from '@masmarino/gabarit'
import { AuthService } from '../application/auth.service'
import { MfaEnrollmentPage } from '../mfa-enrollment/mfa-enrollment'

@Component({
  selector: 'app-register-page',
  standalone: true,
  imports: [ReactiveFormsModule, GbtInput, Button, MfaEnrollmentPage, RouterLink],
  templateUrl: './register-page.html',
  styleUrl: '../login-page/login-page.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class RegisterPage {
  private readonly auth = inject(AuthService)
  private readonly router = inject(Router)

  readonly form = new FormGroup({
    username: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    email: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.email] }),
    password: new FormControl('', { nonNullable: true, validators: [Validators.required, Validators.minLength(8)] }),
  })

  readonly errorMessage = signal<string | null>(null)
  readonly submitting = signal(false)

  // `null` until a successful registration returns an mfa_token — the template then
  // swaps to the mandatory enrollment flow (a fresh account always needs one; see
  // `RegisterPublicUserUseCase` on the backend, which never returns an already-enrolled account).
  readonly mfaToken = signal<string | null>(null)

  submit(): void {
    if (this.form.invalid || this.submitting()) {
      return
    }
    this.submitting.set(true)
    this.errorMessage.set(null)
    const { username, email, password } = this.form.getRawValue()
    this.auth.register(username, email, password).subscribe({
      next: (outcome) => {
        this.submitting.set(false)
        if (outcome.mfaToken) {
          this.mfaToken.set(outcome.mfaToken)
        }
      },
      error: (err: unknown) => {
        this.submitting.set(false)
        const backendMessage = (err as { error?: { error?: string } })?.error?.error ?? ''
        this.errorMessage.set(this.messageFor(backendMessage))
      },
    })
  }

  onEnrollmentCompleted(): void {
    this.router.navigateByUrl('/')
  }

  private messageFor(backendMessage: string): string {
    if (backendMessage.includes('username already taken')) {
      return 'Ce nom d’utilisateur est déjà pris.'
    }
    if (backendMessage.includes('invalid email')) {
      return 'Adresse e-mail invalide.'
    }
    if (backendMessage.includes('password must be at least')) {
      return 'Le mot de passe doit comporter au moins 8 caractères.'
    }
    return 'Impossible de créer le compte. Réessayez.'
  }
}
```

Update `register-page.spec.ts`'s `throwError` call to match this actual error shape:

```typescript
    authServiceSpy.register.and.returnValue(throwError(() => ({ error: { error: 'username already taken' } })))
```

Create `frontend/src/app/auth/register-page/register-page.html`:

```html
<main class="auth-layout">
  <div class="auth-layout__card">
    <h1 class="sr-only">Créer un compte Hangar</h1>
    <img src="/api/branding/logo" alt="Hangar logo" class="auth-layout__logo" />
    @if (!mfaToken()) {
      <form [formGroup]="form" (ngSubmit)="submit()">
        <p class="gbt-form-required-note">Les champs marqués d'un astérisque (*) sont obligatoires.</p>
        <gbt-input label="Nom d'utilisateur" formControlName="username" [required]="true" autocomplete="username" />
        <gbt-input label="Adresse e-mail" type="email" formControlName="email" [required]="true" autocomplete="email" />
        <gbt-input label="Mot de passe" type="password" formControlName="password" [required]="true" autocomplete="new-password" showPasswordLabel="Afficher le mot de passe" hidePasswordLabel="Masquer le mot de passe" />
        @if (errorMessage(); as message) {
          <p class="gbt-form-error" role="alert">{{ message }}</p>
        }
        <gbt-button
          text="Créer mon compte"
          type="submit"
          [loading]="submitting()"
          loadingLabel="Chargement en cours"
          [disabled]="form.invalid || submitting()"
        />
      </form>
      <a routerLink="/login" class="auth-layout__link">J'ai déjà un compte</a>
    } @else {
      <app-mfa-enrollment [mfaToken]="mfaToken()!" (completed)="onEnrollmentCompleted()" />
    }
  </div>
</main>
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd frontend && npx ng test --watch=false --include='**/register-page.spec.ts'`
Expected: PASS.

- [ ] **Step 5: Add the route**

In `frontend/src/app/app.routes.ts`, add next to the existing `'activate'` route:

```typescript
  {
    path: 'register',
    loadComponent: () => import('./auth/register-page/register-page').then((m) => m.RegisterPage),
  },
```

- [ ] **Step 6: Link to it from the login page**

In `frontend/src/app/auth/login-page/login-page.html`, inside the `@if (!mfaToken())` form block (after the closing `</form>`, before the `} @else if`), add:

```html
      <a routerLink="/register" class="auth-layout__link">Créer un compte</a>
```

This needs `RouterLink` added to `LoginPage`'s imports too — add `import { Router, RouterLink } from '@angular/router'` (merging with the existing `Router` import) and `RouterLink` to the component's `imports` array.

- [ ] **Step 7: Run the full frontend test suite**

Run: `cd frontend && npx ng test --watch=false`
Expected: PASS.

- [ ] **Step 8: Manually verify the golden path in a browser**

Start the dev server and the backend (`docker compose up -d` for Postgres if needed, then `cargo run -p hangar-api` and `cd frontend && npx ng serve`). Navigate to `http://hangar.localhost:4200/register` (or whatever the local `HANGAR_BASE_DOMAIN`-based public host resolves to), submit the form with a fresh username, confirm it lands on the TOTP/passkey choice screen, complete TOTP enrollment, confirm it redirects to `/` and the app shell loads authenticated. Then reload `/login` and confirm the new "Créer un compte" link navigates to `/register` and back.

- [ ] **Step 9: Commit**

```bash
git add frontend/src/app/auth/register-page/ frontend/src/app/app.routes.ts frontend/src/app/auth/login-page/login-page.html frontend/src/app/auth/login-page/login-page.ts
git commit -m "feat(frontend): add public self-registration page"
```

---

### Task 8: Full-workspace verification

**Files:** none (verification only).

**Interfaces:** none.

- [ ] **Step 1: Run the full Rust test suite**

Run: `cargo test --workspace 2>&1 | tail -60`
Expected: PASS, 0 failures.

- [ ] **Step 2: Run the full frontend test suite and lints**

Run:
```bash
cd frontend && npx ng test --watch=false && npx ng lint
```
Expected: PASS.

- [ ] **Step 3: Confirm the sqlx offline cache is committed and current**

Run: `SQLX_OFFLINE=true cargo build --workspace 2>&1 | tail -30`
Expected: builds successfully against the committed `.sqlx/` cache with no live database connection.

- [ ] **Step 4: Commit if Step 3 regenerated anything**

Run `git status --porcelain .sqlx/` first. If it prints nothing, skip this step — there is nothing to commit. Otherwise:

```bash
git add .sqlx/
git commit -m "chore: regenerate sqlx offline cache"
```

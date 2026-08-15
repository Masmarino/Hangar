# Hangar — Organization Creation & Member Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a super-admin create organizations from the UI, and let a super-admin (any org) or an organization's own org-admin (their org only) list its members, invite a new one directly into it, and promote/demote org-admin status — none of which is reachable today even though most of the backend plumbing already exists.

**Architecture:** Reuse existing backend primitives wherever they exist (`POST /api/organizations`, `InviteUserUseCase`, `require_organization_admin`) and add only what's missing: one new port method (`set_organization_admin`), one new use case, three new nested routes under `/api/organizations/:id/users`, and two new `/api/me` fields so the frontend can tell whether the current user administers an organization. On the frontend, follow the existing domain/application/infrastructure layering exactly (mirrors `users`/`organizations` slices already in the codebase) and reuse the `.stack` layout utility and `confirm()`-gated destructive-action pattern already established elsewhere in this app.

**Tech Stack:** Rust (Axum, sqlx/Postgres, hexagonal-ish ports-and-adapters in `hangar-domain`/`hangar-application`/`hangar-infrastructure`/`hangar-api`), Angular (standalone components, signals, `@masmarino/gabarit` component library), Vitest (frontend), `#[sqlx::test]` (backend, ephemeral Postgres per test).

**Spec:** `docs/superpowers/specs/2026-09-07-hangar-organization-management-design.md`

## Global Constraints

- The org-scoped invite endpoint (`POST /api/organizations/:id/users`) must never be able to set `is_super_admin: true` — this is enforced server-side by never reading that field from the request body at all, not just hidden client-side.
- All three new `/api/organizations/:id/users*` routes are authorized with the existing `require_organization_admin(&user, id)` (super-admin, or that organization's own org-admin) — never `require_super_admin`.
- A user in a DIFFERENT organization than the one being managed gets `404 Not Found`, never `403 Forbidden` (existing convention in `require_same_organization`, to avoid confirming another organization's existence to a non-member).
- `admin/organizations` (the full list) stays behind `adminGuard` (super-admin only). Only `admin/organizations/:id` moves to the new `organizationAdminGuard`.
- No database migration needed — `users.is_organization_admin` already exists (migration `0001_init.sql`).
- Follow the existing per-slice frontend layering (`domain/`, `application/`, `infrastructure/`) exactly as done for `users` and `organizations`.

---

## Task 1: `set_organization_admin` on `UserRepositoryPort`

**Files:**
- Modify: `crates/hangar-domain/src/user.rs`
- Modify: `crates/hangar-infrastructure/src/postgres/user_repository.rs`
- Test: `crates/hangar-infrastructure/src/postgres/user_repository.rs` (same file, `#[cfg(test)] mod tests`)

**Interfaces:**
- Produces: `UserRepositoryPort::set_organization_admin(&self, id: Uuid, is_organization_admin: bool) -> Result<(), DomainError>` — a **default** trait method (not a required one), so the many existing `FakeUserRepository`/fake-port implementations across `hangar-application/src/use_cases/*.rs` keep compiling unchanged. Only implementations that actually need real behavior (the Postgres repo here, and a fresh fake added in Task 2) override it.

- [ ] **Step 1: Add the default method to the trait**

In `crates/hangar-domain/src/user.rs`, add this method to `pub trait UserRepositoryPort` (right after `set_super_admin_unless_last`):

```rust
    /// Default panics — only the Postgres implementation and any fake that actually
    /// exercises this path need to override it, keeping the many other fakes across
    /// `hangar-application`'s use-case tests unchanged.
    async fn set_organization_admin(&self, _id: Uuid, _is_organization_admin: bool) -> Result<(), DomainError> {
        unimplemented!("set_organization_admin")
    }
```

- [ ] **Step 2: Write the failing Postgres test**

In `crates/hangar-infrastructure/src/postgres/user_repository.rs`, inside `#[cfg(test)] mod tests`, add:

```rust
    #[sqlx::test]
    async fn sets_organization_admin_status(pool: sqlx::PgPool) {
        let repo = PostgresUserRepository::new(pool);
        let user = User {
            id: Uuid::new_v4(),
            username: Username::parse("florian").unwrap(),
            password_hash: "hash".to_string(),
            is_super_admin: false,
            is_organization_admin: false,
            organization_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            created_at: chrono::Utc::now(),
            email: None,
        };
        repo.insert(&user).await.unwrap();

        repo.set_organization_admin(user.id, true).await.unwrap();

        let found = repo.find_by_id(user.id).await.unwrap().unwrap();
        assert!(found.is_organization_admin);
    }
```

- [ ] **Step 3: Run it to confirm it fails**

Run: `cargo test -p hangar-infrastructure sets_organization_admin_status`
Expected: FAIL — `set_organization_admin` is `unimplemented!()` (panics) since `PostgresUserRepository` hasn't overridden it yet.

- [ ] **Step 4: Implement the Postgres override**

In `crates/hangar-infrastructure/src/postgres/user_repository.rs`, inside `impl UserRepositoryPort for PostgresUserRepository`, add (right after `set_super_admin`):

```rust
    async fn set_organization_admin(&self, id: Uuid, is_organization_admin: bool) -> Result<(), DomainError> {
        sqlx::query!("UPDATE users SET is_organization_admin = $1 WHERE id = $2", is_organization_admin, id)
            .execute(&self.pool)
            .await
            .infra_err()?;
        Ok(())
    }
```

- [ ] **Step 5: Run the test again to confirm it passes**

Run: `cargo test -p hangar-infrastructure sets_organization_admin_status`
Expected: PASS

- [ ] **Step 6: Regenerate the sqlx offline query cache**

The workspace compiles queries against a live Postgres or the committed `.sqlx/` cache (`SQLX_OFFLINE=true` in CI). Regenerate it against your local dev Postgres:

```bash
cargo sqlx prepare --workspace -- --tests
```

Run: `cargo build --workspace --locked` (with `SQLX_OFFLINE=true` set) to confirm the new query is covered by the regenerated cache.

- [ ] **Step 7: Commit**

```bash
git add crates/hangar-domain/src/user.rs crates/hangar-infrastructure/src/postgres/user_repository.rs .sqlx
git commit -m "feat(backend): add set_organization_admin to UserRepositoryPort"
```

---

## Task 2: `SetOrganizationAdminUseCase`

**Files:**
- Modify: `crates/hangar-application/src/use_cases/user.rs`

**Interfaces:**
- Consumes: `UserRepositoryPort::set_organization_admin` (Task 1); `UserRepositoryPort::find_by_id`, `insert` (already exist, used by the test's own `FakeUserRepository`).
- Produces: `pub struct SetOrganizationAdminUseCase { .. }` with `pub fn new(users: Arc<dyn UserRepositoryPort>) -> Self` and `pub async fn execute(&self, id: Uuid, is_organization_admin: bool) -> Result<(), ApplicationError>` — used by Task 6's route handler.

- [ ] **Step 1: Write the failing tests**

In `crates/hangar-application/src/use_cases/user.rs`, inside `#[cfg(test)] mod tests`, add:

```rust
    #[tokio::test]
    async fn promotes_a_regular_member_to_organization_admin() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let id = create.execute(Uuid::new_v4(), "florian", "sup3r-s3cret!", false).await.unwrap();

        let use_case = SetOrganizationAdminUseCase::new(users.clone());
        use_case.execute(id, true).await.unwrap();

        assert!(users.find_by_id(id).await.unwrap().unwrap().is_organization_admin);
    }

    #[tokio::test]
    async fn demotes_an_organization_admin() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let id = create.execute(Uuid::new_v4(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let use_case = SetOrganizationAdminUseCase::new(users.clone());
        use_case.execute(id, true).await.unwrap();

        use_case.execute(id, false).await.unwrap();

        assert!(!users.find_by_id(id).await.unwrap().unwrap().is_organization_admin);
    }
```

- [ ] **Step 2: Run to confirm they fail**

Run: `cargo test -p hangar-application promotes_a_regular_member_to_organization_admin demotes_an_organization_admin`
Expected: FAIL with "cannot find type `SetOrganizationAdminUseCase`" (doesn't exist yet) and the fake's default `unimplemented!()` if it got that far.

- [ ] **Step 3: Add the use case**

In `crates/hangar-application/src/use_cases/user.rs`, right after `SetSuperAdminUseCase`'s `impl` block, add:

```rust
pub struct SetOrganizationAdminUseCase {
    users: Arc<dyn UserRepositoryPort>,
}

impl SetOrganizationAdminUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>) -> Self {
        Self { users }
    }

    // Unlike SetSuperAdminUseCase, no "unless last" guard: an organization can validly
    // end up with zero org-admins — the super-admin can always still manage it.
    pub async fn execute(&self, id: Uuid, is_organization_admin: bool) -> Result<(), ApplicationError> {
        self.users.set_organization_admin(id, is_organization_admin).await?;
        Ok(())
    }
}
```

- [ ] **Step 4: Override `set_organization_admin` on this file's own `FakeUserRepository`**

In the same file's `impl UserRepositoryPort for FakeUserRepository` block, add (after `set_super_admin_unless_last`):

```rust
        async fn set_organization_admin(&self, id: Uuid, is_organization_admin: bool) -> Result<(), DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.is_organization_admin = is_organization_admin;
            }
            Ok(())
        }
```

- [ ] **Step 5: Run the tests again to confirm they pass**

Run: `cargo test -p hangar-application promotes_a_regular_member_to_organization_admin demotes_an_organization_admin`
Expected: PASS

- [ ] **Step 6: Run the full crate's test suite to confirm no other fake broke**

Run: `cargo test -p hangar-application`
Expected: PASS (the default trait method means every other fake still compiles unchanged)

- [ ] **Step 7: Commit**

```bash
git add crates/hangar-application/src/use_cases/user.rs
git commit -m "feat(backend): add SetOrganizationAdminUseCase"
```

---

## Task 3: Extend `/api/me` with organization fields

**Files:**
- Modify: `crates/hangar-api/src/dto.rs`
- Modify: `crates/hangar-api/src/routes/auth.rs`

**Interfaces:**
- Consumes: `AuthUser.organization_id: Uuid`, `AuthUser.is_organization_admin: bool` (already exist on `AuthUser`, `crates/hangar-api/src/auth_middleware.rs`).
- Produces: `MeResponse` now serializes `organization_id` and `is_organization_admin` — Task 7 (frontend) depends on these exact field names.

- [ ] **Step 1: Write the failing test**

In `crates/hangar-api/src/routes/auth.rs`, inside `#[cfg(test)] mod tests`, right after `me_returns_the_authenticated_user`, add:

```rust
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn me_returns_the_users_organization_fields(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let user_id = state.create_user.execute(public_org_id, "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/me").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["organization_id"], public_org_id.to_string());
        assert_eq!(json["is_organization_admin"], false);
        let _ = user_id;
    }
```

- [ ] **Step 2: Run it to confirm it fails**

Run: `cargo test -p hangar-api me_returns_the_users_organization_fields`
Expected: FAIL — `json["organization_id"]` is `Value::Null` (field doesn't exist on `MeResponse` yet), so the assertion fails.

- [ ] **Step 3: Extend `MeResponse`**

In `crates/hangar-api/src/dto.rs`, change:

```rust
pub struct MeResponse {
    pub id: Uuid,
    pub username: String,
    pub is_super_admin: bool,
    pub created_at: DateTime<Utc>,
}
```

to:

```rust
pub struct MeResponse {
    pub id: Uuid,
    pub username: String,
    pub is_super_admin: bool,
    pub is_organization_admin: bool,
    pub organization_id: Uuid,
    pub created_at: DateTime<Utc>,
}
```

- [ ] **Step 4: Populate the new fields in the handler**

In `crates/hangar-api/src/routes/auth.rs`, change:

```rust
async fn me(user: AuthUser) -> Json<MeResponse> {
    Json(MeResponse { id: user.id, username: user.username, is_super_admin: user.is_super_admin, created_at: user.created_at })
}
```

to:

```rust
async fn me(user: AuthUser) -> Json<MeResponse> {
    Json(MeResponse {
        id: user.id,
        username: user.username,
        is_super_admin: user.is_super_admin,
        is_organization_admin: user.is_organization_admin,
        organization_id: user.organization_id,
        created_at: user.created_at,
    })
}
```

- [ ] **Step 5: Run the test again to confirm it passes**

Run: `cargo test -p hangar-api me_returns_the_users_organization_fields`
Expected: PASS

- [ ] **Step 6: Run the full `hangar-api` test suite**

Run: `cargo test -p hangar-api`
Expected: PASS — no other test asserts an exact/exhaustive `MeResponse` shape (the existing `me_returns_the_authenticated_user`/`me_returns_the_users_created_at` tests only check individual fields, so they're unaffected by the two additions).

- [ ] **Step 7: Commit**

```bash
git add crates/hangar-api/src/dto.rs crates/hangar-api/src/routes/auth.rs
git commit -m "feat(backend): expose organization_id and is_organization_admin on /api/me"
```

---

## Task 4: `GET`/`POST /api/organizations/:id/users` (list members, invite)

**Files:**
- Modify: `crates/hangar-api/src/routes/organizations.rs`
- Modify: `crates/hangar-api/src/state.rs` (no new field needed — reuses `state.users` and `state.invite_user`, already present)

**Interfaces:**
- Consumes: `require_organization_admin(&user, id)` (existing, `crates/hangar-api/src/authz.rs`); `state.users.list_all()` (existing); `state.invite_user.execute(organization_id, is_organization_admin, username, email, is_super_admin)` (existing, `InviteUserUseCase`).
- Produces: `GET /api/organizations/:id/users` → `Vec<OrganizationMemberResponse>`; `POST /api/organizations/:id/users` → `(StatusCode::CREATED, Json<OrganizationMemberResponse>)`. `OrganizationMemberResponse { id: Uuid, username: String, email: Option<String>, is_organization_admin: bool, invitation_pending: bool }` — Task 11 (frontend adapter) depends on these exact JSON field names.

- [ ] **Step 1: Write the failing tests**

In `crates/hangar-api/src/routes/organizations.rs`, inside `#[cfg(test)] mod tests`, add:

```rust
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_super_admin_can_list_any_organizations_members(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        state.create_user.execute(acme_id, "acme-member", "sup3r-s3cret!", false).await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{acme_id}/users"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let members = json.as_array().unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0]["username"], "acme-member");
        assert_eq!(members[0]["is_organization_admin"], false);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_regular_member_cannot_list_their_organizations_members(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let token = bearer(&state, public_org.id, "regular", "sup3r-s3cret!", false).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{}/users", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_list_their_own_organizations_members(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{}/users", public_org.id))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_of_a_different_organization_gets_not_found(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/organizations/{acme_id}/users"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_invite_a_member_into_their_own_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/organizations/{}/users", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"username":"newmember","email":"newmember@example.com","is_organization_admin":false}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let created = state.users.find_by_username(&hangar_domain::user::Username::parse("newmember").unwrap()).await.unwrap().unwrap();
        assert_eq!(created.organization_id, public_org.id);
        assert!(!created.is_super_admin, "an org-scoped invite must never grant super-admin");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn inviting_a_member_ignores_a_forged_is_super_admin_field(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state.clone());

        // is_super_admin isn't part of the request DTO at all — sending it anyway must
        // be silently ignored rather than deserialization-erroring, and must never apply.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/organizations/{}/users", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"username":"sneaky","email":"sneaky@example.com","is_organization_admin":false,"is_super_admin":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let created = state.users.find_by_username(&hangar_domain::user::Username::parse("sneaky").unwrap()).await.unwrap().unwrap();
        assert!(!created.is_super_admin);
    }
```

- [ ] **Step 2: Run to confirm they fail**

Run: `cargo test -p hangar-api organizations::tests::a_super_admin_can_list_any_organizations_members organizations::tests::a_regular_member_cannot_list_their_organizations_members organizations::tests::an_organization_admin_can_list_their_own_organizations_members organizations::tests::an_organization_admin_of_a_different_organization_gets_not_found organizations::tests::an_organization_admin_can_invite_a_member_into_their_own_organization organizations::tests::inviting_a_member_ignores_a_forged_is_super_admin_field`
Expected: FAIL — `404 Not Found` from the router (no matching route yet).

- [ ] **Step 3: Add the route, DTOs, and handlers**

In `crates/hangar-api/src/routes/organizations.rs`, change the `router()` function:

```rust
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/organizations", post(create_organization).get(list_organizations))
        .route("/api/organizations/:id", get(get_organization))
        .route("/api/organizations/:id/users", get(list_organization_members).post(invite_organization_member))
        .route(
            "/api/organizations/:id/identity-provider",
            get(get_identity_provider).put(set_identity_provider).delete(clear_identity_provider),
        )
}
```

Then, right after `get_organization`, add:

```rust
#[derive(Serialize)]
struct OrganizationMemberResponse {
    id: Uuid,
    username: String,
    email: Option<String>,
    is_organization_admin: bool,
    invitation_pending: bool,
}

async fn list_organization_members(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<Json<Vec<OrganizationMemberResponse>>, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let members: Vec<_> = state
        .users
        .list_all()
        .await
        .map_err(|e| application_error_response("failed to list organization members", e.into()))?
        .into_iter()
        .filter(|u| u.organization_id == id)
        .collect();
    let member_ids: Vec<Uuid> = members.iter().map(|u| u.id).collect();
    let pending = state
        .user_invitations
        .list_pending_user_ids(&member_ids)
        .await
        .map_err(|e| application_error_response("failed to list pending invitations", e.into()))?;
    Ok(Json(
        members
            .into_iter()
            .map(|u| OrganizationMemberResponse { invitation_pending: pending.contains(&u.id), id: u.id, username: u.username.as_str().to_string(), email: u.email, is_organization_admin: u.is_organization_admin })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct InviteOrganizationMemberRequest {
    username: String,
    email: String,
    #[serde(default)]
    is_organization_admin: bool,
}

async fn invite_organization_member(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(body): Json<InviteOrganizationMemberRequest>,
) -> Result<(StatusCode, Json<OrganizationMemberResponse>), (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    // is_super_admin is never read from this request — an org-scoped invite can never grant it.
    let member_id = state
        .invite_user
        .execute(id, body.is_organization_admin, &body.username, &body.email, false)
        .await
        .map_err(|e| application_error_response("failed to invite organization member", e))?;
    Ok((
        StatusCode::CREATED,
        Json(OrganizationMemberResponse { id: member_id, username: body.username, email: Some(body.email), is_organization_admin: body.is_organization_admin, invitation_pending: true }),
    ))
}
```

Note the `state.user_invitations.list_pending_user_ids(&member_ids)` call mirrors `list_users` in `crates/hangar-api/src/routes/users.rs` exactly — same field already on `AppState`, no new wiring needed.

- [ ] **Step 4: Run the tests again to confirm they pass**

Run: `cargo test -p hangar-api organizations::tests::a_super_admin_can_list_any_organizations_members organizations::tests::a_regular_member_cannot_list_their_organizations_members organizations::tests::an_organization_admin_can_list_their_own_organizations_members organizations::tests::an_organization_admin_of_a_different_organization_gets_not_found organizations::tests::an_organization_admin_can_invite_a_member_into_their_own_organization organizations::tests::inviting_a_member_ignores_a_forged_is_super_admin_field`
Expected: PASS

- [ ] **Step 5: Run the full `hangar-api` test suite**

Run: `cargo test -p hangar-api`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/hangar-api/src/routes/organizations.rs
git commit -m "feat(backend): list and invite organization members"
```

---

## Task 5: `PUT /api/organizations/:id/users/:user_id/organization-admin`

**Files:**
- Modify: `crates/hangar-api/src/routes/organizations.rs`
- Modify: `crates/hangar-api/src/state.rs`

**Interfaces:**
- Consumes: `SetOrganizationAdminUseCase` (Task 2); `require_organization_admin` (existing); `state.users.find_by_id` (existing).
- Produces: `PUT /api/organizations/:id/users/:user_id/organization-admin` → `204 No Content`, or `404` if `:user_id` doesn't belong to organization `:id`.

- [ ] **Step 1: Wire `SetOrganizationAdminUseCase` into `AppState`**

In `crates/hangar-api/src/state.rs`, change the import:

```rust
use hangar_application::use_cases::user::{AuthenticateUserUseCase, ChangePasswordUseCase, CreateUserUseCase, DeleteUserUseCase, SetSuperAdminUseCase};
```

to:

```rust
use hangar_application::use_cases::user::{AuthenticateUserUseCase, ChangePasswordUseCase, CreateUserUseCase, DeleteUserUseCase, SetOrganizationAdminUseCase, SetSuperAdminUseCase};
```

Add the field, right after `pub set_super_admin: Arc<SetSuperAdminUseCase>,`:

```rust
    pub set_organization_admin: Arc<SetOrganizationAdminUseCase>,
```

Add the construction, right after `set_super_admin: Arc::new(SetSuperAdminUseCase::new(users_repo.clone())),`:

```rust
            set_organization_admin: Arc::new(SetOrganizationAdminUseCase::new(users_repo.clone())),
```

- [ ] **Step 2: Write the failing tests**

In `crates/hangar-api/src/routes/organizations.rs`, inside `#[cfg(test)] mod tests`, add:

```rust
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_promote_a_member_of_their_own_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let admin_id = state.create_user.execute(public_org.id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(admin_id, true).await.unwrap();
        let member_id = state.create_user.execute(public_org.id, "member", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = crate::build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/users/{member_id}/organization-admin", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"is_organization_admin":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(state.users.find_by_id(member_id).await.unwrap().unwrap().is_organization_admin);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn promoting_a_member_of_a_different_organization_is_not_found(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let outsider_id = state.create_user.execute(acme_id, "outsider", "sup3r-s3cret!", false).await.unwrap();
        let token = bearer(&state, public_org.id, "admin", "sup3r-s3cret!", true).await;
        let app = crate::build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/users/{outsider_id}/organization-admin", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"is_organization_admin":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!state.users.find_by_id(outsider_id).await.unwrap().unwrap().is_organization_admin);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_regular_member_cannot_promote_anyone(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let public_org = state.organizations.find_public().await.unwrap();
        let member_id = state.create_user.execute(public_org.id, "member", "sup3r-s3cret!", false).await.unwrap();
        let token = bearer(&state, public_org.id, "regular", "sup3r-s3cret!", false).await;
        let app = crate::build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/organizations/{}/users/{member_id}/organization-admin", public_org.id))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"is_organization_admin":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
```

- [ ] **Step 3: Run to confirm they fail**

Run: `cargo test -p hangar-api organizations::tests::an_organization_admin_can_promote_a_member_of_their_own_organization organizations::tests::promoting_a_member_of_a_different_organization_is_not_found organizations::tests::a_regular_member_cannot_promote_anyone`
Expected: FAIL — `404 Not Found` from the router (no matching route yet).

- [ ] **Step 4: Add the route and handler**

In `crates/hangar-api/src/routes/organizations.rs`, add a fourth route to `router()`:

```rust
        .route("/api/organizations/:id/users/:user_id/organization-admin", axum::routing::put(set_organization_member_admin))
```

Then, right after `invite_organization_member`, add:

```rust
#[derive(Deserialize)]
struct SetOrganizationMemberAdminRequest {
    is_organization_admin: bool,
}

async fn set_organization_member_admin(
    State(state): State<AppState>,
    user: AuthUser,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<SetOrganizationMemberAdminRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let not_found = || (StatusCode::NOT_FOUND, Json(ErrorResponse { error: "user not found".to_string() }));
    let target = state
        .users
        .find_by_id(user_id)
        .await
        .map_err(|e| application_error_response("failed to look up organization member", e.into()))?
        .ok_or_else(not_found)?;
    if target.organization_id != id {
        // Same privacy stance as require_same_organization: don't confirm this user
        // exists in a different organization.
        return Err(not_found());
    }
    state
        .set_organization_admin
        .execute(user_id, body.is_organization_admin)
        .await
        .map_err(|e| application_error_response("failed to update organization admin status", e))?;
    Ok(StatusCode::NO_CONTENT)
}
```

- [ ] **Step 5: Run the tests again to confirm they pass**

Run: `cargo test -p hangar-api organizations::tests::an_organization_admin_can_promote_a_member_of_their_own_organization organizations::tests::promoting_a_member_of_a_different_organization_is_not_found organizations::tests::a_regular_member_cannot_promote_anyone`
Expected: PASS

- [ ] **Step 6: Run the full backend workspace test suite**

Run: `cargo build --workspace --locked && cargo test --workspace --locked`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add crates/hangar-api/src/routes/organizations.rs crates/hangar-api/src/state.rs
git commit -m "feat(backend): promote/demote an organization member's org-admin status"
```

---

## Task 6: `MeService` — expose organization fields

**Files:**
- Modify: `frontend/src/app/shell/domain/me.entity.ts`
- Modify: `frontend/src/app/shell/application/me.service.ts`
- Test: `frontend/src/app/shell/application/me.service.spec.ts`

**Interfaces:**
- Consumes: `/api/me` now returns `organization_id`/`is_organization_admin` (Task 3).
- Produces: `MeService.organizationId: Signal<string | null>`, `MeService.isOrganizationAdmin: Signal<boolean>` — Task 8 (guard) and Task 9 (sidebar) depend on these exact names.

- [ ] **Step 1: Write the failing test**

Read `frontend/src/app/shell/application/me.service.spec.ts` first to match its existing setup pattern, then add a test asserting the two new signals are populated after `load()`, e.g.:

```typescript
it('exposes the organization fields from the response', () => {
  const service = setup({
    load: () =>
      of({
        id: 'user-1',
        username: 'florian',
        is_super_admin: false,
        is_organization_admin: true,
        organization_id: 'org-1',
        created_at: '2026-01-01T00:00:00Z',
      }),
  })

  service.load().subscribe()

  expect(service.organizationId()).toBe('org-1')
  expect(service.isOrganizationAdmin()).toBe(true)
})
```

(Match the exact `setup(...)` helper and provider wiring already used by the other tests in that file — do not invent a different pattern.)

- [ ] **Step 2: Run it to confirm it fails**

Run: `npx ng test --watch=false --include='src/app/shell/application/me.service.spec.ts'`
Expected: FAIL — `TS2339: Property 'organizationId' does not exist on type 'MeService'`.

- [ ] **Step 3: Extend `MeResponse`**

In `frontend/src/app/shell/domain/me.entity.ts`:

```typescript
export interface MeResponse {
  id: string
  username: string
  is_super_admin: boolean
  is_organization_admin: boolean
  organization_id: string
  created_at: string
}
```

- [ ] **Step 4: Extend `MeService`**

In `frontend/src/app/shell/application/me.service.ts`, add two signals alongside the existing ones:

```typescript
  readonly organizationId = signal<string | null>(null)
  readonly isOrganizationAdmin = signal(false)
```

In the token-change `effect()` inside the constructor, reset them alongside the other three:

```typescript
      this.username.set(null)
      this.isSuperAdmin.set(false)
      this.createdAt.set(null)
      this.organizationId.set(null)
      this.isOrganizationAdmin.set(false)
```

In `load()`'s `tap((me) => { ... })`, populate them alongside the existing three:

```typescript
        tap((me) => {
          this.username.set(me.username)
          this.isSuperAdmin.set(me.is_super_admin)
          this.createdAt.set(me.created_at)
          this.organizationId.set(me.organization_id)
          this.isOrganizationAdmin.set(me.is_organization_admin)
        }),
```

- [ ] **Step 5: Run the test again to confirm it passes**

Run: `npx ng test --watch=false --include='src/app/shell/application/me.service.spec.ts'`
Expected: PASS

- [ ] **Step 6: Fix every other test fixture in the repo that constructs a `MeResponse`-shaped object**

`is_organization_admin`/`organization_id` are now required (non-optional) fields, so every existing object literal typed against `MeResponse` fails to compile until updated. Search for them:

```bash
grep -rln "is_super_admin" frontend/src/app --include="*.spec.ts" | xargs grep -l "created_at"
```

For each match (this will include at least `admin.guard.spec.ts`, `http-me.adapter.spec.ts`, and `app-shell.spec.ts` if it exists), add `is_organization_admin: false, organization_id: 'org-1',` (or values appropriate to what that specific test is asserting) to every `MeResponse`-shaped literal.

- [ ] **Step 7: Run the full frontend test suite**

Run: `npx ng test --watch=false`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add frontend/src/app/shell/domain/me.entity.ts frontend/src/app/shell/application/me.service.ts frontend/src/app/shell/application/me.service.spec.ts
git commit -m "feat(frontend): expose organization_id and is_organization_admin from MeService"
```

(If Step 6 touched other files, `git add` those too before committing — same commit, this is one logical change.)

---

## Task 7: `organizationAdminGuard`

**Files:**
- Create: `frontend/src/app/auth/organization-admin.guard.ts`
- Create: `frontend/src/app/auth/organization-admin.guard.spec.ts`
- Modify: `frontend/src/app/app.routes.ts`

**Interfaces:**
- Consumes: `MeService.load()`, `.isSuperAdmin()`, `.isOrganizationAdmin()`, `.organizationId()` (Task 6); `ActivatedRouteSnapshot.paramMap.get('id')`.
- Produces: `organizationAdminGuard: CanActivateFn` — replaces `adminGuard` on the `admin/organizations/:id` route only.

- [ ] **Step 1: Write the failing tests**

Create `frontend/src/app/auth/organization-admin.guard.spec.ts`, mirroring `admin.guard.spec.ts`'s structure exactly but exercising the route's `:id` param:

```typescript
import { TestBed } from '@angular/core/testing'
import { provideHttpClient } from '@angular/common/http'
import { provideHttpClientTesting } from '@angular/common/http/testing'
import { ActivatedRouteSnapshot, convertToParamMap, provideRouter, Router, UrlTree } from '@angular/router'
import { Observable, firstValueFrom, of, throwError } from 'rxjs'
import { organizationAdminGuard } from './organization-admin.guard'
import { ME_PORT, MePort } from '../shell/application/me.port'
import { authProviders } from './infrastructure/auth.providers'

describe('organizationAdminGuard', () => {
  function setup(port: Partial<MePort>) {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        ...authProviders,
        { provide: ME_PORT, useValue: port },
      ],
    })
  }

  function runGuard(routeOrgId: string): Promise<boolean | UrlTree> {
    const route = { paramMap: convertToParamMap({ id: routeOrgId }) } as ActivatedRouteSnapshot
    const result$ = TestBed.runInInjectionContext(() =>
      organizationAdminGuard(route, {} as never),
    ) as Observable<boolean | UrlTree>
    return firstValueFrom(result$)
  }

  it('allows a super-admin to access any organization', async () => {
    setup({
      load: () =>
        of({
          id: 'user-1',
          username: 'admin',
          is_super_admin: true,
          is_organization_admin: false,
          organization_id: 'org-other',
          created_at: '2026-01-01T00:00:00Z',
        }),
    })

    expect(await runGuard('org-1')).toBe(true)
  })

  it("allows an org-admin to access their own organization's page", async () => {
    setup({
      load: () =>
        of({
          id: 'user-1',
          username: 'org-admin',
          is_super_admin: false,
          is_organization_admin: true,
          organization_id: 'org-1',
          created_at: '2026-01-01T00:00:00Z',
        }),
    })

    expect(await runGuard('org-1')).toBe(true)
  })

  it("redirects an org-admin trying to access a DIFFERENT organization's page", async () => {
    setup({
      load: () =>
        of({
          id: 'user-1',
          username: 'org-admin',
          is_super_admin: false,
          is_organization_admin: true,
          organization_id: 'org-1',
          created_at: '2026-01-01T00:00:00Z',
        }),
    })
    const router = TestBed.inject(Router)

    expect(await runGuard('org-2')).toEqual(router.createUrlTree(['/repositories']))
  })

  it('redirects a regular member, even of the target organization', async () => {
    setup({
      load: () =>
        of({
          id: 'user-1',
          username: 'regular',
          is_super_admin: false,
          is_organization_admin: false,
          organization_id: 'org-1',
          created_at: '2026-01-01T00:00:00Z',
        }),
    })
    const router = TestBed.inject(Router)

    expect(await runGuard('org-1')).toEqual(router.createUrlTree(['/repositories']))
  })

  it('fails toward redirect, rather than hanging navigation, when the identity request errors', async () => {
    setup({ load: () => throwError(() => new Error('network blip')) })
    const router = TestBed.inject(Router)

    expect(await runGuard('org-1')).toEqual(router.createUrlTree(['/repositories']))
  })
})
```

- [ ] **Step 2: Run to confirm it fails**

Run: `npx ng test --watch=false --include='src/app/auth/organization-admin.guard.spec.ts'`
Expected: FAIL — cannot find module `./organization-admin.guard`.

- [ ] **Step 3: Implement the guard**

Create `frontend/src/app/auth/organization-admin.guard.ts`:

```typescript
import { inject } from '@angular/core'
import { CanActivateFn, Router } from '@angular/router'
import { catchError, map, of } from 'rxjs'
import { MeService } from '../shell/application/me.service'

// Same defense-in-depth stance as admin.guard.ts (the backend already enforces this via
// require_organization_admin) — forceRefresh so a mid-session demotion doesn't sail
// through on a cached flag.
export const organizationAdminGuard: CanActivateFn = (route) => {
  const me = inject(MeService)
  const router = inject(Router)
  const targetOrganizationId = route.paramMap.get('id')

  return me.load({ forceRefresh: true }).pipe(
    map(
      (response) =>
        response.is_super_admin ||
        (response.is_organization_admin && response.organization_id === targetOrganizationId) ||
        router.createUrlTree(['/repositories']),
    ),
    catchError(() => of(router.createUrlTree(['/repositories']))),
  )
}
```

- [ ] **Step 4: Run the tests again to confirm they pass**

Run: `npx ng test --watch=false --include='src/app/auth/organization-admin.guard.spec.ts'`
Expected: PASS

- [ ] **Step 5: Wire the guard into the route**

In `frontend/src/app/app.routes.ts`, change:

```typescript
      {
        path: 'admin/organizations/:id',
        loadComponent: () =>
          import('./admin/organization-detail/organization-detail').then(
            (m) => m.OrganizationDetail,
          ),
        canActivate: [adminGuard],
      },
```

to:

```typescript
      {
        path: 'admin/organizations/:id',
        loadComponent: () =>
          import('./admin/organization-detail/organization-detail').then(
            (m) => m.OrganizationDetail,
          ),
        canActivate: [organizationAdminGuard],
      },
```

Add the import at the top of the file:

```typescript
import { organizationAdminGuard } from './auth/organization-admin.guard'
```

(`admin/organizations` — the list route — keeps `canActivate: [adminGuard]` unchanged.)

- [ ] **Step 6: Run the full frontend test suite**

Run: `npx ng test --watch=false`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add frontend/src/app/auth/organization-admin.guard.ts frontend/src/app/auth/organization-admin.guard.spec.ts frontend/src/app/app.routes.ts
git commit -m "feat(frontend): let an org-admin reach their own organization's page"
```

---

## Task 8: Sidebar "Mon organisation" link

**Files:**
- Modify: `frontend/src/app/shell/app-shell.ts`
- Test: `frontend/src/app/shell/app-shell.spec.ts` (extend if it exists; check first with `find frontend/src/app/shell -iname "app-shell.spec.ts"`)

**Interfaces:**
- Consumes: `MeService.isOrganizationAdmin()`, `.isSuperAdmin()`, `.organizationId()` (Task 6).
- Produces: `AppShell.navItems()` includes a "Mon organisation" entry, link `/admin/organizations/${organizationId}`, only when `isOrganizationAdmin() && !isSuperAdmin()`.

- [ ] **Step 1: Write the failing tests**

`frontend/src/app/shell/app-shell.spec.ts` already exists. It has a local `flushMe(me: { id: string; username: string; is_super_admin: boolean })` helper (used by nearly every test in the file) that flushes `/api/me` then `/api/repositories` (and `/api/users` when `is_super_admin`). Extend its parameter type with two optional fields and spread sensible defaults, so every existing call site (which only ever passes `id`/`username`/`is_super_admin`) keeps behaving exactly as today:

```typescript
  function flushMe(me: {
    id: string
    username: string
    is_super_admin: boolean
    is_organization_admin?: boolean
    organization_id?: string
  }) {
    httpMock.expectOne('/api/me').flush({ is_organization_admin: false, organization_id: 'org-1', ...me })
    httpMock.expectOne('/api/repositories').flush([])
    if (me.is_super_admin) {
      httpMock.expectOne('/api/users').flush([])
    }
  }
```

Then add two new tests, anywhere alongside the existing `navItems()`-related tests:

```typescript
  it('shows "Mon organisation" for an org-admin who is not a super-admin, linking to their own organization', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({
      id: 'user-1',
      username: 'org-admin',
      is_super_admin: false,
      is_organization_admin: true,
      organization_id: 'org-1',
    })
    fixture.detectChanges()

    const actions = fixture.componentInstance.navItems().map((item) => item.action)
    expect(actions).toEqual(['repositories', 'organization'])
    const orgItem = fixture.componentInstance.navItems().find((item) => item.action === 'organization')!
    expect(orgItem.link).toBe('/admin/organizations/org-1')
  })

  it('does not show "Mon organisation" for a super-admin, who already reaches every organization', () => {
    const fixture = TestBed.createComponent(AppShell)
    fixture.detectChanges()
    flushMe({
      id: 'user-1',
      username: 'admin',
      is_super_admin: true,
      is_organization_admin: true,
      organization_id: 'org-1',
    })
    fixture.detectChanges()

    const actions = fixture.componentInstance.navItems().map((item) => item.action)
    expect(actions).not.toContain('organization')
  })
```

- [ ] **Step 2: Run to confirm the two new tests fail**

Run: `npx ng test --watch=false --include='src/app/shell/app-shell.spec.ts'`
Expected: the two new tests FAIL (`actions` doesn't include `'organization'` yet); every pre-existing test in the file still PASSES (the `flushMe` change is backward-compatible).

- [ ] **Step 3: Add the nav item**

In `frontend/src/app/shell/app-shell.ts`, change the `navItems` computed:

```typescript
  readonly navItems = computed<NavItem[]>(() => {
    const items: NavItem[] = [
      { action: 'repositories', icon: 'package', text: 'Dépôts', link: '/repositories' },
      { action: 'users', icon: 'users', text: 'Utilisateurs', link: '/users' },
      {
        action: 'admin',
        icon: 'layout-dashboard',
        text: 'Administration',
        link: '/admin',
        children: [
          { action: 'settings', icon: 'settings', text: 'Paramètres', link: '/admin/settings' },
          { action: 'smtp', icon: 'mail', text: 'Serveur mail', link: '/admin/smtp' },
          { action: 'branding', icon: 'image', text: 'Marque', link: '/admin/branding' },
          { action: 'tokens', icon: 'key', text: 'Jetons API', link: '/admin/tokens' },
          { action: 'export', icon: 'download', text: 'Export', link: '/admin/export' },
          { action: 'audit', icon: 'history', text: 'Historique', link: '/admin/audit' },
          { action: 'metrics', icon: 'bar-chart', text: 'Métriques', link: '/admin/metrics' },
          { action: 'security', icon: 'shield', text: 'Sécurité', link: '/admin/security' },
          { action: 'health', icon: 'activity', text: 'Santé', link: '/admin/health' },
          {
            action: 'organizations',
            icon: 'server',
            text: 'Organisations',
            link: '/admin/organizations',
          },
        ],
      },
    ]
    if (this.me.isSuperAdmin()) {
      return items
    }
    const filtered = items.filter((item) => !ADMIN_ONLY_ACTIONS.has(item.action))
    const organizationId = this.me.organizationId()
    if (this.me.isOrganizationAdmin() && organizationId) {
      filtered.push({
        action: 'organization',
        icon: 'server',
        text: 'Mon organisation',
        link: `/admin/organizations/${organizationId}`,
      })
    }
    return filtered
  })
```

- [ ] **Step 4: Run the test again (if one was written) to confirm it passes**

Run: `npx ng test --watch=false --include='src/app/shell/app-shell.spec.ts'`
Expected: PASS

- [ ] **Step 5: Run the full frontend test suite**

Run: `npx ng test --watch=false`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add frontend/src/app/shell/app-shell.ts
git commit -m "feat(frontend): show a sidebar link to their own organization for org-admins"
```

---

## Task 9: Create-organization modal

**Files:**
- Modify: `frontend/src/app/admin/application/organizations.port.ts`
- Modify: `frontend/src/app/admin/application/organizations.service.ts`
- Modify: `frontend/src/app/admin/infrastructure/http-organizations.adapter.ts`
- Create: `frontend/src/app/admin/create-organization-modal/create-organization-modal.ts`
- Create: `frontend/src/app/admin/create-organization-modal/create-organization-modal.html`
- Create: `frontend/src/app/admin/create-organization-modal/create-organization-modal.spec.ts`
- Modify: `frontend/src/app/admin/organizations-list/organizations-list.ts`
- Modify: `frontend/src/app/admin/organizations-list/organizations-list.html`
- Test: `frontend/src/app/admin/organizations-list/organizations-list.spec.ts`
- Test: `frontend/src/app/admin/application/organizations.service.spec.ts`
- Test: `frontend/src/app/admin/infrastructure/http-organizations.adapter.spec.ts`

**Interfaces:**
- Consumes: `POST /api/organizations` (already exists, Task 4's earlier work in the codebase — no backend change).
- Produces: `OrganizationsPort.create(slug, displayName): Observable<OrganizationSummary>`; `OrganizationsService.create(slug, displayName): Observable<OrganizationSummary>` (clears the list cache); `CreateOrganizationModal` component with `created = output<void>()`, `cancelled = output<void>()`, mirroring `CreateUserModal` exactly.

- [ ] **Step 1: Write the failing port/service/adapter tests**

In `frontend/src/app/admin/application/organizations.service.spec.ts`, add (mirrors the existing `'caches the list and clears the cache after configuring an identity provider'` test in the same file):

```typescript
  it('creates an organization and clears the cache', () => {
    let listCalls = 0
    const service = setup({
      list: () => {
        listCalls++
        return of([])
      },
      create: () => of({ id: '2', slug: 'acme', display_name: 'Acme Corp' }),
    })

    service.list().subscribe()
    service.list().subscribe()
    expect(listCalls).toBe(1)

    service.create('acme', 'Acme Corp').subscribe()

    service.list().subscribe()
    expect(listCalls).toBe(2)
  })
```

In `frontend/src/app/admin/infrastructure/http-organizations.adapter.spec.ts`, add:

```typescript
  it('creates an organization via POST /api/organizations', () => {
    const { adapter, httpMock } = setup()
    adapter.create('acme', 'Acme Corp').subscribe()
    const req = httpMock.expectOne('/api/organizations')
    expect(req.request.method).toBe('POST')
    expect(req.request.body).toEqual({ slug: 'acme', display_name: 'Acme Corp' })
    req.flush({ id: 'org-1', slug: 'acme', display_name: 'Acme Corp' })
    httpMock.verify()
  })
```

- [ ] **Step 2: Run to confirm they fail**

Run: `npx ng test --watch=false --include='src/app/admin/application/organizations.service.spec.ts' --include='src/app/admin/infrastructure/http-organizations.adapter.spec.ts'`
Expected: FAIL — `create` doesn't exist on the port/service/adapter yet.

- [ ] **Step 3: Extend the port**

In `frontend/src/app/admin/application/organizations.port.ts`:

```typescript
export interface OrganizationsPort {
  list(): Observable<OrganizationSummary[]>
  get(id: string): Observable<OrganizationSummary>
  create(slug: string, displayName: string): Observable<OrganizationSummary>
  getIdentityProvider(id: string): Observable<IdentityProviderSummary>
  setLdapIdentityProvider(id: string, config: LdapIdentityProviderInput): Observable<void>
  setOidcIdentityProvider(id: string, config: OidcIdentityProviderInput): Observable<void>
  clearIdentityProvider(id: string): Observable<void>
}
```

- [ ] **Step 4: Extend the adapter**

In `frontend/src/app/admin/infrastructure/http-organizations.adapter.ts`, add:

```typescript
  create(slug: string, displayName: string): Observable<OrganizationSummary> {
    return this.http.post<OrganizationSummary>('/api/organizations', {
      slug,
      display_name: displayName,
    })
  }
```

- [ ] **Step 5: Extend the service**

In `frontend/src/app/admin/application/organizations.service.ts`, add:

```typescript
  create(slug: string, displayName: string): Observable<OrganizationSummary> {
    return this.port.create(slug, displayName).pipe(tap(() => (this.cachedList$ = null)))
  }
```

- [ ] **Step 6: Run the tests again to confirm they pass**

Run: `npx ng test --watch=false --include='src/app/admin/application/organizations.service.spec.ts' --include='src/app/admin/infrastructure/http-organizations.adapter.spec.ts'`
Expected: PASS

- [ ] **Step 7: Write the failing modal component test**

Create `frontend/src/app/admin/create-organization-modal/create-organization-modal.spec.ts`, mirroring `frontend/src/app/users/create-user-modal/create-user-modal.spec.ts`'s structure but WITHOUT the `provideTransloco` provider (that file's own inclusion of it is vestigial — nothing in this app actually uses Transloco elsewhere; don't propagate it):

```typescript
import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { CreateOrganizationModal } from './create-organization-modal'
import { organizationsProviders } from '../infrastructure/organizations.providers'

describe('CreateOrganizationModal', () => {
  let httpMock: HttpTestingController

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [CreateOrganizationModal],
      providers: [provideHttpClient(), provideHttpClientTesting(), ...organizationsProviders],
    })
    httpMock = TestBed.inject(HttpTestingController)
  })

  afterEach(() => {
    httpMock.verify()
  })

  it('posts the slug and display name on submit', () => {
    const fixture = TestBed.createComponent(CreateOrganizationModal)
    fixture.detectChanges()

    fixture.componentInstance.form.setValue({ slug: 'acme', displayName: 'Acme Corp' })
    fixture.componentInstance.submit()

    const request = httpMock.expectOne('/api/organizations')
    expect(request.request.body).toEqual({ slug: 'acme', display_name: 'Acme Corp' })
    request.flush({ id: 'org-1', slug: 'acme', display_name: 'Acme Corp' })
  })

  it('emits created after a successful submit', () => {
    const fixture = TestBed.createComponent(CreateOrganizationModal)
    fixture.detectChanges()
    let created = false
    fixture.componentInstance.created.subscribe(() => (created = true))

    fixture.componentInstance.form.setValue({ slug: 'acme', displayName: 'Acme Corp' })
    fixture.componentInstance.submit()
    httpMock.expectOne('/api/organizations').flush({ id: 'org-1', slug: 'acme', display_name: 'Acme Corp' })

    expect(created).toBe(true)
  })

  it('does not submit an invalid form', () => {
    const fixture = TestBed.createComponent(CreateOrganizationModal)
    fixture.detectChanges()

    fixture.componentInstance.submit()

    httpMock.expectNone('/api/organizations')
  })
})
```

- [ ] **Step 8: Run to confirm it fails**

Run: `npx ng test --watch=false --include='src/app/admin/create-organization-modal/create-organization-modal.spec.ts'`
Expected: FAIL — cannot find module `./create-organization-modal`.

- [ ] **Step 9: Implement the component**

Create `frontend/src/app/admin/create-organization-modal/create-organization-modal.ts`:

```typescript
import { ChangeDetectionStrategy, Component, inject, output, signal } from '@angular/core'
import { FormControl, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms'
import { Button, GbtInput, Modal } from '@masmarino/gabarit'
import { OrganizationsService } from '../application/organizations.service'

@Component({
  selector: 'app-create-organization-modal',
  standalone: true,
  imports: [ReactiveFormsModule, Modal, GbtInput, Button],
  templateUrl: './create-organization-modal.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class CreateOrganizationModal {
  private readonly organizationsService = inject(OrganizationsService)

  readonly created = output<void>()
  readonly cancelled = output<void>()

  readonly form = new FormGroup({
    slug: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
    displayName: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
  })

  readonly creating = signal(false)

  submit(): void {
    if (this.form.invalid || this.creating()) {
      return
    }
    this.creating.set(true)
    const { slug, displayName } = this.form.getRawValue()
    this.organizationsService.create(slug, displayName).subscribe({
      next: () => {
        this.creating.set(false)
        this.created.emit()
      },
      error: () => this.creating.set(false),
    })
  }
}
```

Create `frontend/src/app/admin/create-organization-modal/create-organization-modal.html`:

```html
<gbt-modal [isOpen]="true" heading="Nouvelle organisation" closeLabel="Fermer" (closed)="cancelled.emit()">
  <form class="stack" [formGroup]="form" (ngSubmit)="submit()">
    <p class="gbt-form-required-note">Les champs marqués d'un astérisque (*) sont obligatoires.</p>
    <gbt-input label="Sous-domaine" formControlName="slug" [required]="true" placeholder="acme" />
    <gbt-input label="Nom" formControlName="displayName" [required]="true" placeholder="Acme Corp" />
    <gbt-button text="Créer" type="submit" [disabled]="form.invalid" [loading]="creating()" loadingLabel="Chargement en cours" />
  </form>
</gbt-modal>
```

- [ ] **Step 10: Run the tests again to confirm they pass**

Run: `npx ng test --watch=false --include='src/app/admin/create-organization-modal/create-organization-modal.spec.ts'`
Expected: PASS

- [ ] **Step 11: Wire the modal into `organizations-list`**

In `frontend/src/app/admin/organizations-list/organizations-list.ts`, mirror `UsersList` exactly:

```typescript
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core'
import { Router } from '@angular/router'
import { Button, Table, TableColumn } from '@masmarino/gabarit'
import { CreateOrganizationModal } from '../create-organization-modal/create-organization-modal'
import { OrganizationsService } from '../application/organizations.service'
import { OrganizationSummary } from '../domain/organization.entity'

@Component({
  selector: 'app-organizations-list',
  standalone: true,
  imports: [Table, Button, CreateOrganizationModal],
  templateUrl: './organizations-list.html',
  styleUrl: './organizations-list.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationsList implements OnInit {
  private readonly organizationsService = inject(OrganizationsService)
  private readonly router = inject(Router)

  readonly organizations = signal<OrganizationSummary[]>([])
  readonly showCreateModal = signal(false)
  readonly loading = signal(true)
  readonly error = signal<string | null>(null)

  readonly columns: TableColumn<OrganizationSummary>[] = [
    { key: 'slug', label: 'Sous-domaine' },
    { key: 'display_name', label: 'Nom' },
  ]
  readonly rowId = (o: OrganizationSummary): string => o.id

  ngOnInit(): void {
    this.reload()
  }

  reload(): void {
    this.error.set(null)
    this.organizationsService.list({ forceRefresh: true }).subscribe({
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

  onOrganizationCreated(): void {
    this.showCreateModal.set(false)
    this.reload()
  }

  openDetail(organization: OrganizationSummary): void {
    this.router.navigate(['/admin/organizations', organization.id])
  }
}
```

In `frontend/src/app/admin/organizations-list/organizations-list.html`:

```html
<gbt-button text="Nouvelle organisation" (clicked)="showCreateModal.set(true)" />
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
@if (showCreateModal()) {
  <app-create-organization-modal (created)="onOrganizationCreated()" (cancelled)="showCreateModal.set(false)" />
}
```

- [ ] **Step 12: Update the existing `organizations-list.spec.ts`**

The existing test `'loads organizations on init'` calls `component.organizations()` right after `fixture.detectChanges()` without calling `reload()` explicitly — since `reload()` is still called from `ngOnInit`, this test still passes unchanged. But it mocks `{ list: () => of(organizations) }` — `reload()` now calls `this.organizationsService.list({ forceRefresh: true })` instead of `this.organizationsService.list()`; update the mock's `list` signature to accept (and ignore) an options argument:

```typescript
{ provide: OrganizationsService, useValue: { list: (_options?: unknown) => of(organizations) } },
```

- [ ] **Step 13: Run the full frontend test suite**

Run: `npx ng test --watch=false`
Expected: PASS

- [ ] **Step 14: Commit**

```bash
git add frontend/src/app/admin
git commit -m "feat(frontend): create organizations from the admin UI"
```

---

## Task 10: Organization members domain/application/infrastructure layer

**Files:**
- Create: `frontend/src/app/admin/domain/organization-member.entity.ts`
- Create: `frontend/src/app/admin/application/organization-members.port.ts`
- Create: `frontend/src/app/admin/application/organization-members.service.ts`
- Create: `frontend/src/app/admin/application/organization-members.service.spec.ts`
- Create: `frontend/src/app/admin/infrastructure/http-organization-members.adapter.ts`
- Create: `frontend/src/app/admin/infrastructure/http-organization-members.adapter.spec.ts`
- Create: `frontend/src/app/admin/infrastructure/organization-members.providers.ts`

**Interfaces:**
- Consumes: `GET`/`POST /api/organizations/:id/users`, `PUT /api/organizations/:id/users/:user_id/organization-admin` (Tasks 4–5).
- Produces: `OrganizationMember` type; `OrganizationMembersService.list(organizationId)`, `.invite(organizationId, username, email, isOrganizationAdmin)`, `.setOrganizationAdmin(organizationId, userId, isOrganizationAdmin)` — Task 11 (component) depends on these exact names. No caching in this service (unlike `UsersService`/`OrganizationsService`) — deliberately: exactly one component ever calls it, once per organization-detail page visit, so a cache would add complexity with no reuse to justify it (YAGNI).

- [ ] **Step 1: Write the failing adapter test**

Create `frontend/src/app/admin/infrastructure/http-organization-members.adapter.spec.ts`:

```typescript
import { TestBed } from '@angular/core/testing'
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing'
import { provideHttpClient } from '@angular/common/http'
import { HttpOrganizationMembersAdapter } from './http-organization-members.adapter'

describe('HttpOrganizationMembersAdapter', () => {
  let adapter: HttpOrganizationMembersAdapter
  let httpMock: HttpTestingController

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), HttpOrganizationMembersAdapter],
    })
    adapter = TestBed.inject(HttpOrganizationMembersAdapter)
    httpMock = TestBed.inject(HttpTestingController)
  })

  afterEach(() => {
    httpMock.verify()
  })

  it('lists members of an organization', () => {
    let result: unknown
    adapter.list('org-1').subscribe((r) => (result = r))

    const request = httpMock.expectOne('/api/organizations/org-1/users')
    expect(request.request.method).toBe('GET')
    request.flush([{ id: 'user-1', username: 'florian', email: 'florian@example.com', is_organization_admin: false, invitation_pending: true }])

    expect(result).toEqual([{ id: 'user-1', username: 'florian', email: 'florian@example.com', is_organization_admin: false, invitation_pending: true }])
  })

  it('invites a new member into an organization', () => {
    adapter.invite('org-1', 'florian', 'florian@example.com', true).subscribe()

    const request = httpMock.expectOne('/api/organizations/org-1/users')
    expect(request.request.method).toBe('POST')
    expect(request.request.body).toEqual({ username: 'florian', email: 'florian@example.com', is_organization_admin: true })
    request.flush({ id: 'user-1', username: 'florian', email: 'florian@example.com', is_organization_admin: true, invitation_pending: true })
  })

  it("sets a member's organization-admin status", () => {
    adapter.setOrganizationAdmin('org-1', 'user-1', true).subscribe()

    const request = httpMock.expectOne('/api/organizations/org-1/users/user-1/organization-admin')
    expect(request.request.method).toBe('PUT')
    expect(request.request.body).toEqual({ is_organization_admin: true })
    request.flush(null)
  })
})
```

- [ ] **Step 2: Run to confirm it fails**

Run: `npx ng test --watch=false --include='src/app/admin/infrastructure/http-organization-members.adapter.spec.ts'`
Expected: FAIL — cannot find module `./http-organization-members.adapter`.

- [ ] **Step 3: Create the domain entity**

Create `frontend/src/app/admin/domain/organization-member.entity.ts`:

```typescript
export interface OrganizationMember {
  id: string
  username: string
  email: string | null
  is_organization_admin: boolean
  invitation_pending: boolean
}
```

- [ ] **Step 4: Create the port**

Create `frontend/src/app/admin/application/organization-members.port.ts`:

```typescript
import { InjectionToken } from '@angular/core'
import { Observable } from 'rxjs'
import { OrganizationMember } from '../domain/organization-member.entity'

/** Everything the application layer needs to manage one organization's members — implemented by an infrastructure adapter, never called directly by a component. */
export interface OrganizationMembersPort {
  list(organizationId: string): Observable<OrganizationMember[]>
  invite(organizationId: string, username: string, email: string, isOrganizationAdmin: boolean): Observable<OrganizationMember>
  setOrganizationAdmin(organizationId: string, userId: string, isOrganizationAdmin: boolean): Observable<void>
}

export const ORGANIZATION_MEMBERS_PORT = new InjectionToken<OrganizationMembersPort>('OrganizationMembersPort')
```

- [ ] **Step 5: Implement the adapter**

Create `frontend/src/app/admin/infrastructure/http-organization-members.adapter.ts`:

```typescript
import { Injectable, inject } from '@angular/core'
import { HttpClient } from '@angular/common/http'
import { Observable } from 'rxjs'
import { OrganizationMember } from '../domain/organization-member.entity'
import { OrganizationMembersPort } from '../application/organization-members.port'

@Injectable()
export class HttpOrganizationMembersAdapter implements OrganizationMembersPort {
  private readonly http = inject(HttpClient)

  list(organizationId: string): Observable<OrganizationMember[]> {
    return this.http.get<OrganizationMember[]>(`/api/organizations/${organizationId}/users`)
  }

  invite(organizationId: string, username: string, email: string, isOrganizationAdmin: boolean): Observable<OrganizationMember> {
    return this.http.post<OrganizationMember>(`/api/organizations/${organizationId}/users`, {
      username,
      email,
      is_organization_admin: isOrganizationAdmin,
    })
  }

  setOrganizationAdmin(organizationId: string, userId: string, isOrganizationAdmin: boolean): Observable<void> {
    return this.http.put<void>(`/api/organizations/${organizationId}/users/${userId}/organization-admin`, {
      is_organization_admin: isOrganizationAdmin,
    })
  }
}
```

- [ ] **Step 6: Run the adapter test again to confirm it passes**

Run: `npx ng test --watch=false --include='src/app/admin/infrastructure/http-organization-members.adapter.spec.ts'`
Expected: PASS

- [ ] **Step 7: Write the failing service test**

Create `frontend/src/app/admin/application/organization-members.service.spec.ts`:

```typescript
import { TestBed } from '@angular/core/testing'
import { of } from 'rxjs'
import { OrganizationMembersService } from './organization-members.service'
import { ORGANIZATION_MEMBERS_PORT, OrganizationMembersPort } from './organization-members.port'

describe('OrganizationMembersService', () => {
  function setup(port: Partial<OrganizationMembersPort>) {
    TestBed.configureTestingModule({
      providers: [OrganizationMembersService, { provide: ORGANIZATION_MEMBERS_PORT, useValue: port }],
    })
    return TestBed.inject(OrganizationMembersService)
  }

  it('delegates list to the port', () => {
    const members = [{ id: 'user-1', username: 'florian', email: null, is_organization_admin: false, invitation_pending: false }]
    const service = setup({ list: () => of(members) })

    let result
    service.list('org-1').subscribe((r) => (result = r))

    expect(result).toEqual(members)
  })

  it('delegates invite to the port', () => {
    const list = vi.fn(() => of([]))
    const invite = vi.fn(() => of({ id: 'user-1', username: 'florian', email: 'florian@example.com', is_organization_admin: false, invitation_pending: true }))
    const service = setup({ list, invite })

    service.invite('org-1', 'florian', 'florian@example.com', false).subscribe()

    expect(invite).toHaveBeenCalledWith('org-1', 'florian', 'florian@example.com', false)
  })

  it('delegates setOrganizationAdmin to the port', () => {
    const setOrganizationAdmin = vi.fn(() => of(undefined))
    const service = setup({ setOrganizationAdmin })

    service.setOrganizationAdmin('org-1', 'user-1', true).subscribe()

    expect(setOrganizationAdmin).toHaveBeenCalledWith('org-1', 'user-1', true)
  })
})
```

- [ ] **Step 8: Run to confirm it fails**

Run: `npx ng test --watch=false --include='src/app/admin/application/organization-members.service.spec.ts'`
Expected: FAIL — cannot find module `./organization-members.service`.

- [ ] **Step 9: Implement the service**

Create `frontend/src/app/admin/application/organization-members.service.ts`:

```typescript
import { Injectable, inject } from '@angular/core'
import { Observable } from 'rxjs'
import { OrganizationMember } from '../domain/organization-member.entity'
import { ORGANIZATION_MEMBERS_PORT } from './organization-members.port'

@Injectable({ providedIn: 'root' })
export class OrganizationMembersService {
  private readonly port = inject(ORGANIZATION_MEMBERS_PORT)

  list(organizationId: string): Observable<OrganizationMember[]> {
    return this.port.list(organizationId)
  }

  invite(organizationId: string, username: string, email: string, isOrganizationAdmin: boolean): Observable<OrganizationMember> {
    return this.port.invite(organizationId, username, email, isOrganizationAdmin)
  }

  setOrganizationAdmin(organizationId: string, userId: string, isOrganizationAdmin: boolean): Observable<void> {
    return this.port.setOrganizationAdmin(organizationId, userId, isOrganizationAdmin)
  }
}
```

- [ ] **Step 10: Run the test again to confirm it passes**

Run: `npx ng test --watch=false --include='src/app/admin/application/organization-members.service.spec.ts'`
Expected: PASS

- [ ] **Step 11: Create the providers file**

Create `frontend/src/app/admin/infrastructure/organization-members.providers.ts`:

```typescript
import { Provider } from '@angular/core'
import { ORGANIZATION_MEMBERS_PORT } from '../application/organization-members.port'
import { HttpOrganizationMembersAdapter } from './http-organization-members.adapter'

export const organizationMembersProviders: Provider[] = [
  { provide: ORGANIZATION_MEMBERS_PORT, useClass: HttpOrganizationMembersAdapter },
]
```

- [ ] **Step 12: Run the full frontend test suite**

Run: `npx ng test --watch=false`
Expected: PASS

- [ ] **Step 13: Commit**

```bash
git add frontend/src/app/admin/domain/organization-member.entity.ts frontend/src/app/admin/application/organization-members.port.ts frontend/src/app/admin/application/organization-members.service.ts frontend/src/app/admin/application/organization-members.service.spec.ts frontend/src/app/admin/infrastructure/http-organization-members.adapter.ts frontend/src/app/admin/infrastructure/http-organization-members.adapter.spec.ts frontend/src/app/admin/infrastructure/organization-members.providers.ts
git commit -m "feat(frontend): add the organization-members port/service/adapter layer"
```

---

## Task 11: `app-organization-members` component

**Files:**
- Create: `frontend/src/app/admin/organization-members/organization-members.ts`
- Create: `frontend/src/app/admin/organization-members/organization-members.html`
- Create: `frontend/src/app/admin/organization-members/organization-members.spec.ts`

**Interfaces:**
- Consumes: `OrganizationMembersService` (Task 10).
- Produces: `OrganizationMembers` standalone component, selector `app-organization-members`, `organizationId = input.required<string>()` — Task 12 embeds it into `organization-detail.html`.

- [ ] **Step 1: Write the failing component tests**

Create `frontend/src/app/admin/organization-members/organization-members.spec.ts`:

```typescript
import { ComponentFixture, TestBed } from '@angular/core/testing'
import { of, throwError } from 'rxjs'
import { OrganizationMembers } from './organization-members'
import { OrganizationMembersService } from '../application/organization-members.service'

describe('OrganizationMembers', () => {
  let fixture: ComponentFixture<OrganizationMembers>
  let component: OrganizationMembers
  let serviceSpy: {
    list: ReturnType<typeof vi.fn>
    invite: ReturnType<typeof vi.fn>
    setOrganizationAdmin: ReturnType<typeof vi.fn>
  }

  function setup() {
    serviceSpy = { list: vi.fn(), invite: vi.fn(), setOrganizationAdmin: vi.fn() }
    serviceSpy.list.mockReturnValue(
      of([{ id: 'user-1', username: 'florian', email: 'florian@example.com', is_organization_admin: false, invitation_pending: false }]),
    )
    TestBed.configureTestingModule({
      imports: [OrganizationMembers],
      providers: [{ provide: OrganizationMembersService, useValue: serviceSpy }],
    })
    fixture = TestBed.createComponent(OrganizationMembers)
    component = fixture.componentInstance
    fixture.componentRef.setInput('organizationId', 'org-1')
    fixture.detectChanges()
  }

  it('loads members for the given organization on init', () => {
    setup()

    expect(serviceSpy.list).toHaveBeenCalledWith('org-1')
    expect(component.members()).toEqual([
      { id: 'user-1', username: 'florian', email: 'florian@example.com', is_organization_admin: false, invitation_pending: false },
    ])
  })

  it('invites a new member and reloads the list', () => {
    setup()
    serviceSpy.invite.mockReturnValue(
      of({ id: 'user-2', username: 'newmember', email: 'newmember@example.com', is_organization_admin: false, invitation_pending: true }),
    )
    component.startAdding()
    component.newUsername.set('newmember')
    component.newEmail.set('newmember@example.com')

    component.invite()

    expect(serviceSpy.invite).toHaveBeenCalledWith('org-1', 'newmember', 'newmember@example.com', false)
    expect(serviceSpy.list).toHaveBeenCalledTimes(2)
    expect(component.addingMember()).toBe(false)
  })

  it('shows an error when the invite fails', () => {
    setup()
    serviceSpy.invite.mockReturnValue(throwError(() => new Error('conflict')))
    component.startAdding()
    component.newUsername.set('newmember')
    component.newEmail.set('newmember@example.com')

    component.invite()

    expect(component.errorMessage()).toBe("Échec de l'invitation.")
  })

  it('toggles organization-admin status after confirmation and reloads', () => {
    setup()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    serviceSpy.setOrganizationAdmin.mockReturnValue(of(undefined))

    component.toggleOrganizationAdmin({ id: 'user-1', username: 'florian', email: 'florian@example.com', is_organization_admin: false, invitation_pending: false })

    expect(serviceSpy.setOrganizationAdmin).toHaveBeenCalledWith('org-1', 'user-1', true)
    expect(serviceSpy.list).toHaveBeenCalledTimes(2)
  })

  it('does nothing when the toggle confirmation is dismissed', () => {
    setup()
    vi.spyOn(window, 'confirm').mockReturnValue(false)

    component.toggleOrganizationAdmin({ id: 'user-1', username: 'florian', email: 'florian@example.com', is_organization_admin: false, invitation_pending: false })

    expect(serviceSpy.setOrganizationAdmin).not.toHaveBeenCalled()
  })
})
```

- [ ] **Step 2: Run to confirm they fail**

Run: `npx ng test --watch=false --include='src/app/admin/organization-members/organization-members.spec.ts'`
Expected: FAIL — cannot find module `./organization-members`.

- [ ] **Step 3: Implement the component**

Create `frontend/src/app/admin/organization-members/organization-members.ts`:

```typescript
import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core'
import { FormsModule } from '@angular/forms'
import { Button, Checkbox, GbtInput, Table, TableColumn } from '@masmarino/gabarit'
import { OrganizationMembersService } from '../application/organization-members.service'
import { OrganizationMember } from '../domain/organization-member.entity'

@Component({
  selector: 'app-organization-members',
  standalone: true,
  imports: [Table, Button, GbtInput, Checkbox, FormsModule],
  templateUrl: './organization-members.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationMembers implements OnInit {
  private readonly organizationMembersService = inject(OrganizationMembersService)

  readonly organizationId = input.required<string>()

  readonly members = signal<OrganizationMember[]>([])
  readonly loading = signal(true)
  readonly errorMessage = signal<string | null>(null)

  readonly addingMember = signal(false)
  readonly newUsername = signal('')
  readonly newEmail = signal('')
  readonly newIsOrganizationAdmin = signal(false)
  readonly inviting = signal(false)

  readonly columns: TableColumn<OrganizationMember>[] = [
    { key: 'username', label: "Nom d'utilisateur" },
    { key: 'email', label: 'E-mail' },
    { key: 'is_organization_admin', label: 'Administrateur' },
    { key: 'invitation_pending', label: 'Invitation en attente' },
  ]
  readonly rowId = (m: OrganizationMember): string => m.id

  ngOnInit(): void {
    this.reload()
  }

  private reload(): void {
    this.organizationMembersService.list(this.organizationId()).subscribe({
      next: (members) => {
        this.members.set(members)
        this.loading.set(false)
      },
      error: () => {
        this.loading.set(false)
        this.errorMessage.set('Échec du chargement des membres.')
      },
    })
  }

  startAdding(): void {
    this.addingMember.set(true)
    this.newUsername.set('')
    this.newEmail.set('')
    this.newIsOrganizationAdmin.set(false)
    this.errorMessage.set(null)
  }

  cancelAdding(): void {
    this.addingMember.set(false)
  }

  invite(): void {
    if (this.newUsername().trim() === '' || this.newEmail().trim() === '' || this.inviting()) {
      return
    }
    this.inviting.set(true)
    this.errorMessage.set(null)
    this.organizationMembersService
      .invite(this.organizationId(), this.newUsername(), this.newEmail(), this.newIsOrganizationAdmin())
      .subscribe({
        next: () => {
          this.inviting.set(false)
          this.addingMember.set(false)
          this.reload()
        },
        error: () => {
          this.inviting.set(false)
          this.errorMessage.set("Échec de l'invitation.")
        },
      })
  }

  toggleOrganizationAdmin(member: OrganizationMember): void {
    const promoting = !member.is_organization_admin
    const verb = promoting ? 'promouvoir' : 'rétrograder'
    if (!confirm(`Voulez-vous ${verb} ${member.username} ${promoting ? 'en administrateur' : "de son rôle d'administrateur"} de l'organisation ?`)) {
      return
    }
    this.errorMessage.set(null)
    this.organizationMembersService.setOrganizationAdmin(this.organizationId(), member.id, promoting).subscribe({
      next: () => this.reload(),
      error: () => this.errorMessage.set("Échec de la mise à jour du statut d'administrateur."),
    })
  }
}
```

Create `frontend/src/app/admin/organization-members/organization-members.html`:

```html
<div class="stack">
  @if (loading()) {
    <p>Chargement…</p>
  } @else {
    <gbt-table
      caption="Membres de l'organisation"
      emptyMessage="Aucun membre"
      [clickableRows]="true"
      [data]="members()"
      [columns]="columns"
      [trackBy]="rowId"
      (rowClick)="toggleOrganizationAdmin($event)"
    />
  }

  @if (errorMessage(); as message) {
    <p class="gbt-form-error" role="alert">{{ message }}</p>
  }

  @if (addingMember()) {
    <div class="stack">
      <gbt-input
        label="Nom d'utilisateur"
        [ngModel]="newUsername()"
        (ngModelChange)="newUsername.set($event)"
      />
      <gbt-input
        label="Adresse e-mail"
        [ngModel]="newEmail()"
        (ngModelChange)="newEmail.set($event)"
      />
      <gbt-checkbox
        label="Administrateur de cette organisation"
        [ngModel]="newIsOrganizationAdmin()"
        (ngModelChange)="newIsOrganizationAdmin.set($event)"
      />
      <div class="d-flex gap-2">
        <gbt-button
          text="Inviter"
          [loading]="inviting()"
          loadingLabel="Chargement en cours"
          [disabled]="newUsername().trim() === '' || newEmail().trim() === ''"
          (clicked)="invite()"
        />
        <gbt-button text="Annuler" variant="secondary" (clicked)="cancelAdding()" />
      </div>
    </div>
  } @else {
    <gbt-button text="Inviter un membre" (clicked)="startAdding()" />
  }
</div>
```

- [ ] **Step 4: Run the tests again to confirm they pass**

Run: `npx ng test --watch=false --include='src/app/admin/organization-members/organization-members.spec.ts'`
Expected: PASS

- [ ] **Step 5: Run the full frontend test suite**

Run: `npx ng test --watch=false`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add frontend/src/app/admin/organization-members
git commit -m "feat(frontend): add the organization members list/invite/promote component"
```

---

## Task 12: Wire members into `organization-detail`

**Files:**
- Modify: `frontend/src/app/admin/organization-detail/organization-detail.ts`
- Modify: `frontend/src/app/admin/organization-detail/organization-detail.html`
- Test: `frontend/src/app/admin/organization-detail/organization-detail.spec.ts`

**Interfaces:**
- Consumes: `OrganizationMembers` component, selector `app-organization-members`, input `organizationId` (Task 11).
- Produces: `organization-detail.html` renders a third `<gbt-card>` "Membres".

- [ ] **Step 1: Write the failing test**

`OrganizationMembers` (Task 11) is a real component, not a mock, and its `ngOnInit` injects `OrganizationMembersService` — which itself injects the `ORGANIZATION_MEMBERS_PORT` token. `organization-detail.spec.ts` has no `provideHttpClient`/`HttpTestingController` at all today (it mocks `OrganizationsService` directly via `useValue`), so without a mock, creating `OrganizationDetail` in this spec file will throw ("no provider for ORGANIZATION_MEMBERS_PORT") the moment `OrganizationMembers` is instantiated. Add a mock `OrganizationMembersService` provider to **every** `TestBed.configureTestingModule({...})` call in this file — there are four: the one inside the top-level `setup()` function, and three more duplicated inline inside the `'reflects an existing LDAP configuration'`, `'reflects an existing OIDC configuration'`, and `'shows an error and does not reset the form when clearing the configuration fails'` tests. Each currently ends its `providers` array with:

```typescript
        { provide: ActivatedRoute, useValue: { paramMap: of(convertToParamMap({ id: 'org-1' })) } },
      ],
    })
```

In all four places, add one more entry to that array:

```typescript
        { provide: ActivatedRoute, useValue: { paramMap: of(convertToParamMap({ id: 'org-1' })) } },
        { provide: OrganizationMembersService, useValue: { list: () => of([]) } },
      ],
    })
```

Add the import at the top of the file:

```typescript
import { By } from '@angular/platform-browser'
import { OrganizationMembers } from '../organization-members/organization-members'
import { OrganizationMembersService } from '../application/organization-members.service'
```

Then add the new test itself:

```typescript
it('renders the members component with the resolved organization id', () => {
  setup()

  const membersDebugElement = fixture.debugElement.query(By.directive(OrganizationMembers))
  expect(membersDebugElement).not.toBeNull()
  expect(membersDebugElement.componentInstance.organizationId()).toBe('org-1')
})
```

- [ ] **Step 2: Run to confirm it fails**

Run: `npx ng test --watch=false --include='src/app/admin/organization-detail/organization-detail.spec.ts'`
Expected: FAIL — `app-organization-members` isn't in the template yet, so `By.directive(OrganizationMembers)` finds nothing.

- [ ] **Step 3: Expose the organization id and embed the component**

In `frontend/src/app/admin/organization-detail/organization-detail.ts`, make the route-derived id public (drop `private` — the template needs to bind it) and register the new component:

```typescript
import { OrganizationMembers } from '../organization-members/organization-members'
```

```typescript
@Component({
  selector: 'app-organization-detail',
  standalone: true,
  imports: [Card, GbtInput, Button, Select, FormsModule, OrganizationMembers],
  templateUrl: './organization-detail.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class OrganizationDetail {
  private readonly route = inject(ActivatedRoute)
  private readonly organizationsService = inject(OrganizationsService)
  private readonly pageTitle = inject(PageTitleService)

  readonly routeOrganizationId = toSignal(
    this.route.paramMap.pipe(map((params) => params.get('id')!)),
    { requireSync: true },
  )
  private organizationId!: string
```

(Only the `private readonly routeOrganizationId` → `readonly routeOrganizationId` visibility change and the new import/`imports` entry — everything else in the class body stays exactly as it is today.)

In `frontend/src/app/admin/organization-detail/organization-detail.html`, add a third card right after the "Authentification" card's closing `</gbt-card>`:

```html
    <gbt-card>
      <div class="stack">
        <h3>Membres</h3>
        <app-organization-members [organizationId]="routeOrganizationId()" />
      </div>
    </gbt-card>
```

- [ ] **Step 4: Run the test again to confirm it passes**

Run: `npx ng test --watch=false --include='src/app/admin/organization-detail/organization-detail.spec.ts'`
Expected: PASS

- [ ] **Step 5: Run the full frontend test suite**

Run: `npx ng test --watch=false`
Expected: PASS

- [ ] **Step 6: Run a full production build to catch any template/type error the unit tests don't**

Run: `npm run build -- --configuration production` (from `frontend/`)
Expected: builds cleanly

- [ ] **Step 7: Commit**

```bash
git add frontend/src/app/admin/organization-detail
git commit -m "feat(frontend): show the members card on the organization detail page"
```

---

## Task 13: End-to-end manual verification

**Files:** none (verification only)

- [ ] **Step 1: Run the full backend and frontend suites one more time**

```bash
cargo build --workspace --locked && cargo test --workspace --locked
```
```bash
cd frontend && npm run build -- --configuration production && npm test -- --watch=false
```
Expected: both PASS.

- [ ] **Step 2: Manually verify in the browser**

Using the project's own dev workflow (`scripts/dev.sh`, or `preview_start`/browser tools if working inside an agent session):
1. Log in as a super-admin. Go to `/admin/organizations`. Click "Nouvelle organisation", create one (e.g. slug `acme`, name `Acme Corp`). Confirm it appears in the list.
2. Click into the new organization. Confirm the "Membres" card renders, empty.
3. Click "Inviter un membre", fill in a username/email, submit. Confirm the member appears in the table with "Invitation en attente" = true.
4. Click that member's row, confirm the promotion dialog, confirm. Reload the page, confirm "Administrateur" is now true for that row.
5. Log out, register a throwaway account (or use an existing non-super-admin account), have a super-admin promote it to org-admin of its own organization via the members card.
6. Log in as that newly-promoted org-admin. Confirm the sidebar shows "Mon organisation" (not the full "Administration" menu). Click it, confirm it lands on that organization's own detail page and the members card works there too.
7. As that same org-admin, try navigating directly to a DIFFERENT organization's URL (e.g. `/admin/organizations/<acme's id>`). Confirm it redirects to `/repositories`.

- [ ] **Step 3: Report results**

No commit for this task — it's verification only. If any manual check fails, go back to the relevant task, fix, and re-run that task's tests before re-verifying here.

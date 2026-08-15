# Per-Organization System Settings and SMTP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each organization its own login-throttle/session-TTL/registration policy and its own SMTP relay, instead of one singleton shared by the whole Hangar instance, and expose both to organization admins through the existing admin UI.

**Architecture:** `system_settings` and `smtp_settings` move from a singleton row (`id = 1`) to one row per organization (`organization_id` as primary key). `SystemSettingsPort`, `SmtpSettingsPort`, `EmailPort::send`, and `TokenIssuerPort::issue` all gain an `organization_id`/`ttl` parameter that callers resolve from whichever user is in scope. `LoginThrottle` and `JwtTokenIssuer` stop holding global mutable settings state — the caller resolves the right limits/TTL per request instead. No fallback: an organization with no SMTP configured simply does not send email for its members, exactly like today's instance-wide "unconfigured" behavior.

**Tech Stack:** Rust (axum, sqlx/Postgres, async-trait), Angular (standalone components, signals).

**Spec:** `docs/superpowers/specs/2026-09-07-hangar-per-organization-system-settings-design.md`

## Global Constraints

- No fallback SMTP: an org without its own configured SMTP does not send email — never falls back to another organization's settings.
- An organization with no `system_settings` row uses `SystemSettings::defaults()` (max_login_attempts: 10, login_attempt_window_seconds: 300, session_ttl_hours: 12, registration_enabled: true) — never treated as "missing."
- `POST /api/auth/register`'s IP-keyed throttle stays on the existing global constants (`MAX_LOGIN_ATTEMPTS`, `LOGIN_ATTEMPT_WINDOW`) — no organization is resolvable at that point. Out of scope.
- Never commit without an explicit request from the user (this session's established convention) — every task below ends with a `git commit`, but do not `git push` or open a PR unless asked.
- Every task must leave `cargo test --workspace` and the frontend `ng test` suite fully green before moving to the next task.
- Set `DATABASE_URL` (e.g. `postgres://hangar:<password from .env>@localhost:5432/hangar`, matching this repo's `.env`) before any `cargo build`/`cargo test` that touches `hangar-infrastructure` or `hangar-api` — the `sqlx::query!` macros validate against a live database at compile time. Run `cargo sqlx prepare --workspace -- --all-targets` (from the repo root, with `DATABASE_URL` set) after any change to a `sqlx::query!`/`query_as!` call, and commit the resulting `.sqlx/` changes alongside the code.

---

### Task 1: Migrate `system_settings` and `smtp_settings` to per-organization rows

**Files:**
- Create: `crates/hangar-infrastructure/migrations/0004_per_organization_settings.sql`
- Modify: `crates/hangar-infrastructure/src/postgres/system_settings_repository.rs`
- Modify: `crates/hangar-infrastructure/src/postgres/smtp_settings_repository.rs`

**Interfaces:**
- Consumes: `hangar_domain::organization::PUBLIC_ORGANIZATION_ID` (already exists, `Uuid::from_u128(1)`).
- Produces: no public interface change in this task — `SystemSettingsPort`/`SmtpSettingsPort` keep their current `get(&self)`/`update(&self, settings)` signatures. Internally, both Postgres implementations now query by `organization_id = PUBLIC_ORGANIZATION_ID` instead of `id = 1`. This is a deliberately inert intermediate step: behavior is unchanged (still one global "singleton" from every caller's point of view), so every existing test in both files should pass unmodified except for one new test added below.

- [ ] **Step 1: Write the migration**

Create `crates/hangar-infrastructure/migrations/0004_per_organization_settings.sql`:

```sql
-- Both tables move from a single global row (id = 1) to one row per
-- organization (organization_id as primary key). The existing singleton
-- row, if any, is reattached to the public organization so nothing already
-- configured breaks.
ALTER TABLE system_settings ADD COLUMN organization_id UUID REFERENCES organizations(id);
UPDATE system_settings SET organization_id = '00000000-0000-0000-0000-000000000001';
ALTER TABLE system_settings ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE system_settings DROP COLUMN id;
ALTER TABLE system_settings ADD PRIMARY KEY (organization_id);

ALTER TABLE smtp_settings ADD COLUMN organization_id UUID REFERENCES organizations(id);
UPDATE smtp_settings SET organization_id = '00000000-0000-0000-0000-000000000001';
ALTER TABLE smtp_settings ALTER COLUMN organization_id SET NOT NULL;
ALTER TABLE smtp_settings DROP COLUMN id;
ALTER TABLE smtp_settings ADD PRIMARY KEY (organization_id);
```

- [ ] **Step 2: Update `system_settings_repository.rs` to query by the public organization**

In `crates/hangar-infrastructure/src/postgres/system_settings_repository.rs`, replace the body of `get` and `update`:

```rust
async fn get(&self) -> Result<SystemSettings, DomainError> {
    let row = sqlx::query!(
        "SELECT max_login_attempts, login_attempt_window_seconds, session_ttl_hours, registration_enabled FROM system_settings WHERE organization_id = $1",
        hangar_domain::organization::PUBLIC_ORGANIZATION_ID
    )
    .fetch_optional(&self.pool)
    .await
    .infra_err()?;
    Ok(match row {
        Some(row) => SystemSettings {
            max_login_attempts: row.max_login_attempts,
            login_attempt_window_seconds: row.login_attempt_window_seconds,
            session_ttl_hours: row.session_ttl_hours,
            registration_enabled: row.registration_enabled,
        },
        None => SystemSettings::defaults(),
    })
}

async fn update(&self, settings: &SystemSettings) -> Result<(), DomainError> {
    sqlx::query!(
        "INSERT INTO system_settings (organization_id, max_login_attempts, login_attempt_window_seconds, session_ttl_hours, registration_enabled) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (organization_id) DO UPDATE SET \
         max_login_attempts = EXCLUDED.max_login_attempts, \
         login_attempt_window_seconds = EXCLUDED.login_attempt_window_seconds, \
         session_ttl_hours = EXCLUDED.session_ttl_hours, \
         registration_enabled = EXCLUDED.registration_enabled",
        hangar_domain::organization::PUBLIC_ORGANIZATION_ID,
        settings.max_login_attempts,
        settings.login_attempt_window_seconds,
        settings.session_ttl_hours,
        settings.registration_enabled,
    )
    .execute(&self.pool)
    .await
    .infra_err()?;
    Ok(())
}
```

Add this test to the `mod tests` block in the same file:

```rust
#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn a_pre_migration_singleton_row_is_reattached_to_the_public_organization(pool: sqlx::PgPool) {
    // Migration 0004 runs as part of `migrations = "../hangar-infrastructure/migrations"`
    // above, on a fresh database with no prior data — so this proves the *shape* the
    // migration produces (a row addressable by organization_id) rather than replaying an
    // upgrade from a populated instance. `update` below exercises exactly the path a
    // pre-migration singleton row is expected to end up in after the `UPDATE ... SET
    // organization_id = ...` statement: reachable by the public organization's id.
    let repo = PostgresSystemSettingsRepository::new(pool.clone());
    repo.update(&SystemSettings { max_login_attempts: 7, login_attempt_window_seconds: 90, session_ttl_hours: 6, registration_enabled: false }).await.unwrap();

    let row: (uuid::Uuid,) = sqlx::query_as("SELECT organization_id FROM system_settings").fetch_one(&pool).await.unwrap();
    assert_eq!(row.0, hangar_domain::organization::PUBLIC_ORGANIZATION_ID);
}
```

- [ ] **Step 3: Update `smtp_settings_repository.rs` to query by the public organization**

In `crates/hangar-infrastructure/src/postgres/smtp_settings_repository.rs`, replace the body of `get` and `update`:

```rust
async fn get(&self) -> Result<Option<SmtpSettings>, DomainError> {
    let row = sqlx::query!(
        "SELECT host, port, username, encrypted_password, password_nonce, from_name, from_address, security FROM smtp_settings WHERE organization_id = $1",
        hangar_domain::organization::PUBLIC_ORGANIZATION_ID
    )
    .fetch_optional(&self.pool)
    .await
    .infra_err()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let password = secret_box::decrypt(&row.encrypted_password, &row.password_nonce, &self.jwt_secret)?;
    let security = security_from_str(&row.security).ok_or_else(|| DomainError::Infrastructure(format!("unknown smtp security {}", row.security)))?;
    Ok(Some(SmtpSettings { host: row.host, port: row.port, username: row.username, password, from_name: row.from_name, from_address: row.from_address, security }))
}

async fn update(&self, settings: &SmtpSettings) -> Result<(), DomainError> {
    let (encrypted_password, password_nonce) = secret_box::encrypt(&settings.password, &self.jwt_secret);
    sqlx::query!(
        "INSERT INTO smtp_settings (organization_id, host, port, username, encrypted_password, password_nonce, from_name, from_address, security) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (organization_id) DO UPDATE SET \
         host = EXCLUDED.host, port = EXCLUDED.port, username = EXCLUDED.username, \
         encrypted_password = EXCLUDED.encrypted_password, password_nonce = EXCLUDED.password_nonce, \
         from_name = EXCLUDED.from_name, from_address = EXCLUDED.from_address, security = EXCLUDED.security",
        hangar_domain::organization::PUBLIC_ORGANIZATION_ID,
        settings.host,
        settings.port,
        settings.username,
        encrypted_password,
        password_nonce,
        settings.from_name,
        settings.from_address,
        security_to_str(settings.security),
    )
    .execute(&self.pool)
    .await
    .infra_err()?;
    Ok(())
}
```

No new test needed here — `system_settings_repository.rs`'s new test already proves the migration's row-reattachment shape, and `smtp_settings`'s existing tests already cover get/update round-tripping through the new column.

- [ ] **Step 4: Regenerate the sqlx offline query cache**

```bash
set -a && source .env && set +a
export DATABASE_URL="postgres://hangar:${POSTGRES_PASSWORD}@localhost:5432/hangar"
cargo sqlx prepare --workspace -- --all-targets
```

- [ ] **Step 5: Run the full workspace test suite**

```bash
cargo test --workspace
```

Expected: all tests pass, including the new one from Step 2.

- [ ] **Step 6: Commit**

```bash
git add crates/hangar-infrastructure/migrations/0004_per_organization_settings.sql \
        crates/hangar-infrastructure/src/postgres/system_settings_repository.rs \
        crates/hangar-infrastructure/src/postgres/smtp_settings_repository.rs \
        .sqlx
git commit -m "$(cat <<'EOF'
migrate system_settings and smtp_settings to per-organization rows

Schema-only step: both Postgres repositories still query the public
organization's row internally, so behavior is unchanged. Later tasks
thread organization_id through the port interfaces themselves.
EOF
)"
```

---

### Task 2: Thread `organization_id` through `SystemSettingsPort`

**Files:**
- Modify: `crates/hangar-domain/src/system_settings.rs`
- Modify: `crates/hangar-infrastructure/src/postgres/system_settings_repository.rs`
- Modify: `crates/hangar-application/src/use_cases/admin.rs` (`GetSystemSettingsUseCase`, `UpdateSystemSettingsUseCase`, `FakeSystemSettings`, and their tests; also `ImportConfigurationUseCase`'s call to `self.update_settings.execute(...)`)
- Modify: `crates/hangar-api/src/routes/admin.rs` (`get_system_settings`, `update_system_settings` route handlers)
- Modify: `crates/hangar-api/src/routes/auth.rs` (`register`, `sso_config` route handlers, plus the tests at the bottom of the file that call `get_system_settings.execute()`/`update_system_settings.execute()`)
- Modify: `crates/hangar-api/src/state.rs` (`sync_settings_from_storage` — resolve for the public organization; this becomes fully obsolete in Task 7, left working for now)

**Interfaces:**
- Consumes: `hangar_domain::organization::PUBLIC_ORGANIZATION_ID`.
- Produces: `SystemSettingsPort::get(&self, organization_id: Uuid) -> Result<SystemSettings, DomainError>`, `SystemSettingsPort::update(&self, organization_id: Uuid, settings: &SystemSettings) -> Result<(), DomainError>`. `GetSystemSettingsUseCase::execute(&self, organization_id: Uuid)`, `UpdateSystemSettingsUseCase::execute(&self, organization_id: Uuid, settings: SystemSettings)`. Later tasks (5 and 7) rely on these exact signatures.

- [ ] **Step 1: Update the failing/changed tests first — `SystemSettingsPort`'s own trait, `system_settings_repository.rs`**

In `crates/hangar-domain/src/system_settings.rs`, change the trait:

```rust
#[async_trait]
pub trait SystemSettingsPort: Send + Sync {
    async fn get(&self, organization_id: Uuid) -> Result<SystemSettings, DomainError>;
    async fn update(&self, organization_id: Uuid, settings: &SystemSettings) -> Result<(), DomainError>;
}
```

Add `use uuid::Uuid;` to that file's imports.

In `crates/hangar-infrastructure/src/postgres/system_settings_repository.rs`, change the signatures and drop the now-redundant `PUBLIC_ORGANIZATION_ID` binding in favor of the passed-in parameter:

```rust
async fn get(&self, organization_id: Uuid) -> Result<SystemSettings, DomainError> {
    let row = sqlx::query!(
        "SELECT max_login_attempts, login_attempt_window_seconds, session_ttl_hours, registration_enabled FROM system_settings WHERE organization_id = $1",
        organization_id
    )
    .fetch_optional(&self.pool)
    .await
    .infra_err()?;
    Ok(match row {
        Some(row) => SystemSettings {
            max_login_attempts: row.max_login_attempts,
            login_attempt_window_seconds: row.login_attempt_window_seconds,
            session_ttl_hours: row.session_ttl_hours,
            registration_enabled: row.registration_enabled,
        },
        None => SystemSettings::defaults(),
    })
}

async fn update(&self, organization_id: Uuid, settings: &SystemSettings) -> Result<(), DomainError> {
    sqlx::query!(
        "INSERT INTO system_settings (organization_id, max_login_attempts, login_attempt_window_seconds, session_ttl_hours, registration_enabled) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (organization_id) DO UPDATE SET \
         max_login_attempts = EXCLUDED.max_login_attempts, \
         login_attempt_window_seconds = EXCLUDED.login_attempt_window_seconds, \
         session_ttl_hours = EXCLUDED.session_ttl_hours, \
         registration_enabled = EXCLUDED.registration_enabled",
        organization_id,
        settings.max_login_attempts,
        settings.login_attempt_window_seconds,
        settings.session_ttl_hours,
        settings.registration_enabled,
    )
    .execute(&self.pool)
    .await
    .infra_err()?;
    Ok(())
}
```

Add `use uuid::Uuid;` to that file's imports. Update its existing tests (`get_returns_the_seeded_defaults_on_a_fresh_instance`, `update_then_get_round_trips_the_new_values`, `a_second_update_overwrites_the_first_rather_than_inserting_a_row`, `registration_enabled_round_trips_through_an_update`) to pass `hangar_domain::organization::PUBLIC_ORGANIZATION_ID` as the first argument to every `repo.get(...)`/`repo.update(...)` call. Add one new test proving isolation:

```rust
#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn settings_for_one_organization_do_not_affect_another(pool: sqlx::PgPool) {
    let repo = PostgresSystemSettingsRepository::new(pool.clone());
    let other_org_id = sqlx::query_scalar!(
        "INSERT INTO organizations (id, slug, display_name, is_public) VALUES (gen_random_uuid(), 'acme', 'Acme', false) RETURNING id"
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    repo.update(other_org_id, &SystemSettings { max_login_attempts: 3, login_attempt_window_seconds: 30, session_ttl_hours: 2, registration_enabled: false }).await.unwrap();

    assert_eq!(repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap(), SystemSettings::defaults(), "the public organization's settings must be untouched");
    assert_eq!(repo.get(other_org_id).await.unwrap().max_login_attempts, 3);
}
```

- [ ] **Step 2: Run this crate's tests to confirm the new isolation test passes and nothing regressed here**

```bash
set -a && source .env && set +a
export DATABASE_URL="postgres://hangar:${POSTGRES_PASSWORD}@localhost:5432/hangar"
cargo test -p hangar-infrastructure system_settings_repository
```

Expected: all pass. (The workspace as a whole will not compile yet — `hangar-application`/`hangar-api` still call the old no-argument signature. That's fixed in the next steps.)

- [ ] **Step 3: Update `GetSystemSettingsUseCase`/`UpdateSystemSettingsUseCase` and their fake**

In `crates/hangar-application/src/use_cases/admin.rs`:

```rust
impl GetSystemSettingsUseCase {
    pub fn new(settings: Arc<dyn SystemSettingsPort>) -> Self {
        Self { settings }
    }

    pub async fn execute(&self, organization_id: Uuid) -> Result<SystemSettings, ApplicationError> {
        Ok(self.settings.get(organization_id).await?)
    }
}
```

```rust
impl UpdateSystemSettingsUseCase {
    pub fn new(settings: Arc<dyn SystemSettingsPort>) -> Self {
        Self { settings }
    }

    pub async fn execute(&self, organization_id: Uuid, settings: SystemSettings) -> Result<(), ApplicationError> {
        if !(1..=1000).contains(&settings.max_login_attempts) {
            return Err(ApplicationError::InvalidSystemSettings("max_login_attempts must be between 1 and 1000".to_string()));
        }
        if !(1..=86_400).contains(&settings.login_attempt_window_seconds) {
            return Err(ApplicationError::InvalidSystemSettings("login_attempt_window_seconds must be between 1 and 86400 (24h)".to_string()));
        }
        if !(1..=720).contains(&settings.session_ttl_hours) {
            return Err(ApplicationError::InvalidSystemSettings("session_ttl_hours must be between 1 and 720 (30 days)".to_string()));
        }
        self.settings.update(organization_id, &settings).await?;
        Ok(())
    }
}
```

Update `FakeSystemSettings` in the same file's `mod tests`:

```rust
struct FakeSystemSettings {
    settings: Mutex<std::collections::HashMap<Uuid, SystemSettings>>,
}

#[async_trait]
impl SystemSettingsPort for FakeSystemSettings {
    async fn get(&self, organization_id: Uuid) -> Result<SystemSettings, DomainError> {
        Ok(self.settings.lock().unwrap().get(&organization_id).copied().unwrap_or(SystemSettings::defaults()))
    }
    async fn update(&self, organization_id: Uuid, settings: &SystemSettings) -> Result<(), DomainError> {
        self.settings.lock().unwrap().insert(organization_id, *settings);
        Ok(())
    }
}
```

Update every `FakeSystemSettings { settings: Mutex::new(SystemSettings::defaults()) }` construction in that test module to `FakeSystemSettings { settings: Mutex::new(std::collections::HashMap::new()) }`, and every `use_case.execute(...)`/`settings.get(...)`/`settings.update(...)` call to pass a `Uuid` first — reuse one constant across a test, e.g. `let org_id = Uuid::new_v4();`, and pass `org_id` everywhere that test previously called `execute()`/`get()`/`update()` with no organization argument.

Also fix `ImportConfigurationUseCase`'s call site (around line 584 in the same file, inside `execute`): change `self.update_settings.execute(import.system_settings)` to `self.update_settings.execute(restore_organization_id, import.system_settings)` — `restore_organization_id` is already computed a few lines earlier in that same function.

- [ ] **Step 4: Update `crates/hangar-api/src/routes/admin.rs`'s two route handlers**

```rust
async fn get_system_settings(State(state): State<AppState>, user: AuthUser) -> Result<Json<SystemSettings>, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let settings = state.get_system_settings.execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.map_err(|e| application_error_response("failed to get system settings", e))?;
    Ok(Json(settings))
}

async fn update_system_settings(
    State(state): State<AppState>,
    user: AuthUser,
    Json(settings): Json<SystemSettings>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.update_system_settings.execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, settings).await.map_err(|e| application_error_response("failed to update system settings", e))?;
    apply_system_settings(&state.login_throttle, &state.token_issuer, &settings);
    Ok(StatusCode::NO_CONTENT)
}
```

(This route stays super-admin-only and hardcoded to the public organization for now — Task 5 makes it org-aware. This step's only job is to keep the workspace compiling with the new signature.) Update the test at line ~1446 (`state.get_system_settings.execute().await.unwrap()`) to pass `hangar_domain::organization::PUBLIC_ORGANIZATION_ID`.

- [ ] **Step 5: Update `crates/hangar-api/src/routes/auth.rs`'s `register` and `sso_config`, and their tests**

In `register`, change:

```rust
let settings = state
    .get_system_settings
    .execute(resolved_org.0.id)
    .await
    .map_err(|e| application_error_response("failed to check system settings", e))?;
```

In `sso_config`, change:

```rust
let settings = state
    .get_system_settings
    .execute(resolved_org.0.id)
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
```

(Both already had `resolved_org` in scope — passing `resolved_org.0.id` here is strictly more correct than the hardcoded constant used in Step 4's admin routes, since `register` only ever reaches this line when `resolved_org.0.is_public` is already true.) Update the two tests around line 1347–1372 in the same file (`state.get_system_settings.execute().await.unwrap()` / `state.update_system_settings.execute(settings).await.unwrap()`) to pass `hangar_domain::organization::PUBLIC_ORGANIZATION_ID` as the first argument in each call.

- [ ] **Step 6: Update `crates/hangar-api/src/state.rs`'s `sync_settings_from_storage`**

```rust
pub async fn sync_settings_from_storage(&self) {
    match self.get_system_settings.execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await {
        Ok(settings) => apply_system_settings(&self.login_throttle, &self.token_issuer, &settings),
        Err(e) => tracing::warn!("failed to load persisted system settings, keeping defaults: {e}"),
    }
}
```

- [ ] **Step 7: Run the full workspace test suite**

```bash
cargo test --workspace
```

Expected: all pass. Fix any remaining compile error the same way — pass `hangar_domain::organization::PUBLIC_ORGANIZATION_ID` (production code paths outside `register`/`sso_config`) or the test's own `org_id` variable (test code) as the new first argument.

- [ ] **Step 8: Commit**

```bash
git add crates/hangar-domain/src/system_settings.rs \
        crates/hangar-infrastructure/src/postgres/system_settings_repository.rs \
        crates/hangar-application/src/use_cases/admin.rs \
        crates/hangar-api/src/routes/admin.rs \
        crates/hangar-api/src/routes/auth.rs \
        crates/hangar-api/src/state.rs \
        .sqlx
git commit -m "$(cat <<'EOF'
thread organization_id through SystemSettingsPort

Every current caller still resolves either the public organization or
a hardcoded constant, so behavior is unchanged — this proves the
plumbing compiles and every test still passes before Task 5 makes the
admin routes actually organization-aware.
EOF
)"
```

---

### Task 3: Thread `organization_id` through `SmtpSettingsPort`

**Files:**
- Modify: `crates/hangar-domain/src/email.rs`
- Modify: `crates/hangar-infrastructure/src/postgres/smtp_settings_repository.rs`
- Modify: `crates/hangar-application/src/use_cases/smtp.rs` (`GetSmtpSettingsUseCase`, `UpdateSmtpSettingsUseCase`, `FakeSmtpSettings`, and their tests)
- Modify: `crates/hangar-api/src/routes/admin.rs` (`get_smtp_settings`, `update_smtp_settings` route handlers)

**Interfaces:**
- Consumes: `hangar_domain::organization::PUBLIC_ORGANIZATION_ID`.
- Produces: `SmtpSettingsPort::get(&self, organization_id: Uuid) -> Result<Option<SmtpSettings>, DomainError>`, `SmtpSettingsPort::update(&self, organization_id: Uuid, settings: &SmtpSettings) -> Result<(), DomainError>`. `GetSmtpSettingsUseCase::execute(&self, organization_id: Uuid)`, `UpdateSmtpSettingsUseCase::execute(&self, organization_id: Uuid, input: UpdateSmtpSettingsInput)`.

- [ ] **Step 1: Update the trait and the Postgres repository, with a new isolation test**

In `crates/hangar-domain/src/email.rs`:

```rust
#[async_trait]
pub trait SmtpSettingsPort: Send + Sync {
    /// `None` means never configured — treat as disabled, not an error.
    async fn get(&self, organization_id: Uuid) -> Result<Option<SmtpSettings>, DomainError>;
    async fn update(&self, organization_id: Uuid, settings: &SmtpSettings) -> Result<(), DomainError>;
}
```

Add `use uuid::Uuid;` to that file's imports.

In `crates/hangar-infrastructure/src/postgres/smtp_settings_repository.rs`:

```rust
async fn get(&self, organization_id: Uuid) -> Result<Option<SmtpSettings>, DomainError> {
    let row = sqlx::query!(
        "SELECT host, port, username, encrypted_password, password_nonce, from_name, from_address, security FROM smtp_settings WHERE organization_id = $1",
        organization_id
    )
    .fetch_optional(&self.pool)
    .await
    .infra_err()?;
    let Some(row) = row else {
        return Ok(None);
    };
    let password = secret_box::decrypt(&row.encrypted_password, &row.password_nonce, &self.jwt_secret)?;
    let security = security_from_str(&row.security).ok_or_else(|| DomainError::Infrastructure(format!("unknown smtp security {}", row.security)))?;
    Ok(Some(SmtpSettings { host: row.host, port: row.port, username: row.username, password, from_name: row.from_name, from_address: row.from_address, security }))
}

async fn update(&self, organization_id: Uuid, settings: &SmtpSettings) -> Result<(), DomainError> {
    let (encrypted_password, password_nonce) = secret_box::encrypt(&settings.password, &self.jwt_secret);
    sqlx::query!(
        "INSERT INTO smtp_settings (organization_id, host, port, username, encrypted_password, password_nonce, from_name, from_address, security) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (organization_id) DO UPDATE SET \
         host = EXCLUDED.host, port = EXCLUDED.port, username = EXCLUDED.username, \
         encrypted_password = EXCLUDED.encrypted_password, password_nonce = EXCLUDED.password_nonce, \
         from_name = EXCLUDED.from_name, from_address = EXCLUDED.from_address, security = EXCLUDED.security",
        organization_id,
        settings.host,
        settings.port,
        settings.username,
        encrypted_password,
        password_nonce,
        settings.from_name,
        settings.from_address,
        security_to_str(settings.security),
    )
    .execute(&self.pool)
    .await
    .infra_err()?;
    Ok(())
}
```

Add `use uuid::Uuid;`. Update the existing tests in that file's `mod tests` to pass `hangar_domain::organization::PUBLIC_ORGANIZATION_ID` as the first argument to every `repo.get(...)`/`repo.update(...)` call. Add:

```rust
#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn settings_for_one_organization_do_not_affect_another(pool: sqlx::PgPool) {
    let repo = PostgresSmtpSettingsRepository::new(pool.clone(), "test-secret".to_string());
    let other_org_id = sqlx::query_scalar!(
        "INSERT INTO organizations (id, slug, display_name, is_public) VALUES (gen_random_uuid(), 'acme', 'Acme', false) RETURNING id"
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    repo.update(other_org_id, &sample()).await.unwrap();

    assert_eq!(repo.get(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap(), None, "the public organization must still be unconfigured");
    assert!(repo.get(other_org_id).await.unwrap().is_some());
}
```

(`sample()` is the existing test helper already defined in that file's `mod tests`.)

- [ ] **Step 2: Run this crate's tests**

```bash
set -a && source .env && set +a
export DATABASE_URL="postgres://hangar:${POSTGRES_PASSWORD}@localhost:5432/hangar"
cargo test -p hangar-infrastructure smtp_settings_repository
```

Expected: all pass.

- [ ] **Step 3: Update `GetSmtpSettingsUseCase`/`UpdateSmtpSettingsUseCase` and `FakeSmtpSettings`**

In `crates/hangar-application/src/use_cases/smtp.rs`:

```rust
impl GetSmtpSettingsUseCase {
    pub fn new(settings: Arc<dyn SmtpSettingsPort>) -> Self {
        Self { settings }
    }

    pub async fn execute(&self, organization_id: uuid::Uuid) -> Result<Option<SmtpSettingsView>, ApplicationError> {
        let Some(settings) = self.settings.get(organization_id).await? else {
            return Ok(None);
        };
        Ok(Some(SmtpSettingsView {
            host: settings.host,
            port: settings.port,
            username: settings.username,
            from_name: settings.from_name,
            from_address: settings.from_address,
            security: settings.security,
            password_set: true,
        }))
    }
}
```

```rust
impl UpdateSmtpSettingsUseCase {
    pub fn new(settings: Arc<dyn SmtpSettingsPort>) -> Self {
        Self { settings }
    }

    pub async fn execute(&self, organization_id: uuid::Uuid, input: UpdateSmtpSettingsInput) -> Result<(), ApplicationError> {
        if input.host.trim().is_empty() {
            return Err(ApplicationError::InvalidSmtpSettings("host must not be empty".to_string()));
        }
        if !(1..=65_535).contains(&input.port) {
            return Err(ApplicationError::InvalidSmtpSettings("port must be between 1 and 65535".to_string()));
        }
        if input.username.trim().is_empty() {
            return Err(ApplicationError::InvalidSmtpSettings("username must not be empty".to_string()));
        }
        if input.from_address.trim().is_empty() || !input.from_address.contains('@') {
            return Err(ApplicationError::InvalidSmtpSettings("from_address must be a valid email address".to_string()));
        }
        if input.from_name.trim().is_empty() {
            return Err(ApplicationError::InvalidSmtpSettings("from_name must not be empty".to_string()));
        }

        let password = match input.password {
            Some(password) if !password.is_empty() => password,
            _ => {
                let existing = self.settings.get(organization_id).await?;
                match existing {
                    Some(existing) => existing.password,
                    None => return Err(ApplicationError::InvalidSmtpSettings("password is required when configuring SMTP for the first time".to_string())),
                }
            }
        };

        self.settings
            .update(organization_id, &SmtpSettings { host: input.host, port: input.port, username: input.username, password, from_name: input.from_name, from_address: input.from_address, security: input.security })
            .await?;
        Ok(())
    }
}
```

Update `FakeSmtpSettings` in that file's `mod tests`:

```rust
struct FakeSmtpSettings {
    settings: Mutex<std::collections::HashMap<uuid::Uuid, SmtpSettings>>,
}

#[async_trait]
impl SmtpSettingsPort for FakeSmtpSettings {
    async fn get(&self, organization_id: uuid::Uuid) -> Result<Option<SmtpSettings>, DomainError> {
        Ok(self.settings.lock().unwrap().get(&organization_id).cloned())
    }
    async fn update(&self, organization_id: uuid::Uuid, settings: &SmtpSettings) -> Result<(), DomainError> {
        self.settings.lock().unwrap().insert(organization_id, settings.clone());
        Ok(())
    }
}
```

Update every `FakeSmtpSettings { settings: Mutex::new(None) }` construction to `FakeSmtpSettings { settings: Mutex::new(std::collections::HashMap::new()) }`, and every call to `.execute(...)`/`settings.get(...)`/`settings.update(...)` in that test module to pass a `Uuid` first — introduce `let org_id = Uuid::new_v4();` per test and use it consistently. `SendTestEmailUseCase` is untouched in this task (it depends on `EmailPort`, not `SmtpSettingsPort` — Task 4).

- [ ] **Step 4: Update `crates/hangar-api/src/routes/admin.rs`'s two SMTP route handlers**

```rust
async fn get_smtp_settings(State(state): State<AppState>, user: AuthUser) -> Result<Json<Option<SmtpSettingsResponse>>, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let settings = state.get_smtp_settings.execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.map_err(|e| application_error_response("failed to get SMTP settings", e))?;
    Ok(Json(settings.map(|s| SmtpSettingsResponse {
        host: s.host,
        port: s.port,
        username: s.username,
        from_name: s.from_name,
        from_address: s.from_address,
        security: s.security,
        password_set: s.password_set,
    })))
}

async fn update_smtp_settings(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<UpdateSmtpSettingsRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state
        .update_smtp_settings
        .execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, UpdateSmtpSettingsInput { host: body.host, port: body.port, username: body.username, password: body.password, from_name: body.from_name, from_address: body.from_address, security: body.security })
        .await
        .map_err(|e| application_error_response("failed to update SMTP settings", e))?;
    Ok(StatusCode::NO_CONTENT)
}
```

(Still super-admin-only and hardcoded — Task 5 makes it org-aware.)

- [ ] **Step 5: Run the full workspace test suite**

```bash
cargo test --workspace
```

Expected: all pass. Fix any remaining compile error by passing `hangar_domain::organization::PUBLIC_ORGANIZATION_ID` (production) or the test's own `org_id` (test code).

- [ ] **Step 6: Commit**

```bash
git add crates/hangar-domain/src/email.rs \
        crates/hangar-infrastructure/src/postgres/smtp_settings_repository.rs \
        crates/hangar-application/src/use_cases/smtp.rs \
        crates/hangar-api/src/routes/admin.rs \
        .sqlx
git commit -m "$(cat <<'EOF'
thread organization_id through SmtpSettingsPort

Same inert-plumbing step as SystemSettingsPort — every caller still
resolves the public organization for now.
EOF
)"
```

---

### Task 4: Thread `organization_id` through `EmailPort::send`

**Files:**
- Modify: `crates/hangar-domain/src/email.rs`
- Modify: `crates/hangar-infrastructure/src/smtp_email_sender.rs`
- Modify: `crates/hangar-application/src/use_cases/admin.rs` (`ImportConfigurationUseCase`, its `FakeEmail`)
- Modify: `crates/hangar-application/src/use_cases/invitation.rs` (`InviteUserUseCase`, `ResendInvitationUseCase`, `FakeEmail`)
- Modify: `crates/hangar-application/src/use_cases/mfa.rs` (`ConfirmTotpUseCase`, `FakeEmail`)
- Modify: `crates/hangar-application/src/use_cases/user.rs` (`ChangePasswordUseCase`, `FakeEmail`)
- Modify: `crates/hangar-application/src/use_cases/webauthn.rs` (`FinishPasskeyRegistrationUseCase`, `FakeEmail`)
- Modify: `crates/hangar-application/src/use_cases/smtp.rs` (`SendTestEmailUseCase`, `FakeEmail`)
- Modify: `crates/hangar-api/src/routes/admin.rs` (`send_test_email` route handler)

**Interfaces:**
- Consumes: `SmtpSettingsPort::get(organization_id)` (Task 3), `BrandingPort::get(organization_id)` (already exists — used today with a hardcoded `PUBLIC_ORGANIZATION_ID`).
- Produces: `EmailPort::send(&self, organization_id: Uuid, to: &str, subject: &str, text_body: &str, html_body: &str) -> Result<(), DomainError>`. `SendTestEmailUseCase::execute(&self, organization_id: Uuid, to: &str)`.

- [ ] **Step 1: Update the trait**

In `crates/hangar-domain/src/email.rs`:

```rust
#[async_trait]
pub trait EmailPort: Send + Sync {
    async fn send(&self, organization_id: Uuid, to: &str, subject: &str, text_body: &str, html_body: &str) -> Result<(), DomainError>;
}
```

- [ ] **Step 2: Update `SmtpEmailSender` — this is where per-org SMTP and per-org branding actually land**

In `crates/hangar-infrastructure/src/smtp_email_sender.rs`, replace the `send` implementation:

```rust
#[async_trait]
impl EmailPort for SmtpEmailSender {
    async fn send(&self, organization_id: Uuid, to: &str, subject: &str, text_body: &str, html_body: &str) -> Result<(), DomainError> {
        let Some(settings) = self.settings.get(organization_id).await? else {
            return Err(DomainError::Infrastructure("SMTP is not configured".to_string()));
        };

        // Only attach the logo when the HTML actually references it.
        let logo = if html_references_logo(html_body) {
            let branding = self.branding.get(organization_id).await?;
            let (logo_bytes, logo_content_type) = match branding.logo {
                Some(asset) => (asset.bytes, asset.content_type),
                None => (DEFAULT_LOGO_BYTES.to_vec(), DEFAULT_LOGO_CONTENT_TYPE.to_string()),
            };
            Some((logo_bytes, logo_content_type))
        } else {
            None
        };

        let message = build_message(&settings.from_address, &settings.from_name, to, subject, text_body, html_body, logo)?;

        let credentials = Credentials::new(settings.username.clone(), settings.password.clone());
        let transport = match settings.security {
            SmtpSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.host)
                .map_err(|e| DomainError::Infrastructure(format!("failed to build SMTP transport: {e}")))?
                .port(settings.port as u16)
                .credentials(credentials)
                .build(),
            SmtpSecurity::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host)
                .map_err(|e| DomainError::Infrastructure(format!("failed to build SMTP transport: {e}")))?
                .port(settings.port as u16)
                .credentials(credentials)
                .build(),
            SmtpSecurity::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host).port(settings.port as u16).credentials(credentials).build(),
        };

        transport.send(message).await.map_err(|e| DomainError::Infrastructure(format!("failed to send email: {e}")))?;
        Ok(())
    }
}
```

Remove the now-unused `use hangar_domain::organization::PUBLIC_ORGANIZATION_ID;` import and the `TODO(organizations)` comment above the old branding-fetch line — both are resolved by this change (the module doc comment at the top of the file, "Sends mail through whatever `SmtpSettings` are currently configured, read fresh from the port on every send," stays accurate and needs no edit).

- [ ] **Step 3: Update every production call site — each already has an `organization_id` in scope**

In `crates/hangar-application/src/use_cases/invitation.rs`, `InviteUserUseCase::execute` (already takes `organization_id` as a parameter):

```rust
let _ = self.email.send(organization_id, email, &content.subject, &content.text, &content.html).await;
```

`ResendInvitationUseCase::execute` (has `user: User` in scope):

```rust
self.email.send(user.organization_id, email, &content.subject, &content.text, &content.html).await?;
```

In `crates/hangar-application/src/use_cases/mfa.rs`, `ConfirmTotpUseCase::execute` (inside the `if let Ok(Some(user)) = ...` block, `user` is in scope):

```rust
let _ = self.email.send(user.organization_id, email, &content.subject, &content.text, &content.html).await;
```

In `crates/hangar-application/src/use_cases/user.rs`, `ChangePasswordUseCase::execute` (`user` in scope from the earlier `find_by_id` call):

```rust
let _ = self.email.send(user.organization_id, email, &content.subject, &content.text, &content.html).await;
```

In `crates/hangar-application/src/use_cases/webauthn.rs`, `FinishPasskeyRegistrationUseCase::execute` (inside the `if let Ok(Some(user)) = ...` block):

```rust
let _ = self.email.send(user.organization_id, email, &content.subject, &content.text, &content.html).await;
```

In `crates/hangar-application/src/use_cases/admin.rs`, `ImportConfigurationUseCase::execute` (has `restore_organization_id` in scope):

```rust
match self.email.send(restore_organization_id, email, &content.subject, &content.text, &content.html).await {
    Ok(()) => report.invited.push(exported.username.clone()),
    Err(e) => report.failed.push(format!("invitation email for {}: {e}", exported.username)),
}
```

In `crates/hangar-application/src/use_cases/smtp.rs`:

```rust
pub struct SendTestEmailUseCase {
    email: Arc<dyn EmailPort>,
}

impl SendTestEmailUseCase {
    pub fn new(email: Arc<dyn EmailPort>) -> Self {
        Self { email }
    }

    pub async fn execute(&self, organization_id: uuid::Uuid, to: &str) -> Result<(), ApplicationError> {
        let message = "This is a test email from Hangar. If you received it, your SMTP settings are working correctly.";
        self.email.send(organization_id, to, "Hangar SMTP test", message, &format!("<p>{message}</p>")).await?;
        Ok(())
    }
}
```

- [ ] **Step 4: Update every `FakeEmail` (five files: `admin.rs`, `invitation.rs`, `mfa.rs`, `user.rs`, `webauthn.rs`, `smtp.rs`) and their tests**

Each of these six files has its own local `struct FakeEmail { sent: Mutex<Vec<(String, String, String, String)>> }` with `impl EmailPort for FakeEmail`. In every one of them, change the recorded tuple to also capture the organization id, and the trait impl to match the new signature:

```rust
struct FakeEmail {
    sent: Mutex<Vec<(uuid::Uuid, String, String, String, String)>>,
}

#[async_trait]
impl EmailPort for FakeEmail {
    async fn send(&self, organization_id: uuid::Uuid, to: &str, subject: &str, text_body: &str, html_body: &str) -> Result<(), DomainError> {
        self.sent.lock().unwrap().push((organization_id, to.to_string(), subject.to_string(), text_body.to_string(), html_body.to_string()));
        Ok(())
    }
}
```

In each file's tests, every existing assertion like `sent[0].0` (previously the recipient `to`) now needs to shift one index — `sent[0].0` is the `organization_id`, `sent[0].1` is `to`, etc. Update every such indexing in that file's test module accordingly. This index shift is itself the regression check that the parameter threads through correctly — `invitation.rs`'s existing `InviteUserUseCase`/`ResendInvitationUseCase` tests already assert on `email.sent`, so once their indices are updated to account for the new leading `organization_id` field, add one assertion to whichever of those existing tests already has an `organization_id` in scope (e.g. the test that calls `use_case.execute(org_id, ...)`): `assert_eq!(sent[0].0, org_id);` right alongside that test's existing assertions on `sent[0].1`/`sent[0].2`/etc. — proving the id that reaches `FakeEmail` is the same one the test passed in, not inventing a new test or a new fake.

- [ ] **Step 5: Update `crates/hangar-api/src/routes/admin.rs`'s `send_test_email` handler**

```rust
async fn send_test_email(State(state): State<AppState>, user: AuthUser, Json(body): Json<SendTestEmailRequest>) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.send_test_email.execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, &body.to).await.map_err(|e| application_error_response("failed to send test email", e))?;
    Ok(StatusCode::NO_CONTENT)
}
```

(Still super-admin-only and hardcoded — Task 5 makes it org-aware.)

- [ ] **Step 6: Run the full workspace test suite**

```bash
cargo test --workspace
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add crates/hangar-domain/src/email.rs \
        crates/hangar-infrastructure/src/smtp_email_sender.rs \
        crates/hangar-application/src/use_cases/admin.rs \
        crates/hangar-application/src/use_cases/invitation.rs \
        crates/hangar-application/src/use_cases/mfa.rs \
        crates/hangar-application/src/use_cases/user.rs \
        crates/hangar-application/src/use_cases/webauthn.rs \
        crates/hangar-application/src/use_cases/smtp.rs \
        crates/hangar-api/src/routes/admin.rs
git commit -m "$(cat <<'EOF'
thread organization_id through EmailPort::send

Every email-sending use case already had the sending user's (or the
invite's target) organization_id in scope — this is the change that
makes SmtpEmailSender actually resolve per-organization SMTP settings
and branding, fixing the pre-existing TODO(organizations) that had it
hardcoded to the public organization.
EOF
)"
```

---

### Task 5: Give organization admins access to system settings and SMTP settings

**Files:**
- Modify: `crates/hangar-api/src/routes/admin.rs` (`get_system_settings`, `update_system_settings`, `get_smtp_settings`, `update_smtp_settings`, `send_test_email`)

**Interfaces:**
- Consumes: `crate::authz::require_organization_admin` (already exists), `crate::organization_middleware::ResolvedOrganization` (already exists, used the same way in `routes/branding.rs`).
- Produces: no new public interface — this task only changes authorization and which `organization_id` these five handlers resolve.

- [ ] **Step 1: Add the same `target_organization_id` helper `branding.rs` already has**

`routes/branding.rs` already defines this exact helper (`fn target_organization_id(user: &AuthUser, resolved_org: &ResolvedOrganization) -> uuid::Uuid`). Add the identical helper to `crates/hangar-api/src/routes/admin.rs`, near the top of the file:

```rust
/// A super-admin manages whichever organization the request's domain resolves to; a
/// non-super-admin can only ever be managing their own organization, regardless of which
/// domain the request came in on. Same helper as `routes/branding.rs`.
fn target_organization_id(user: &AuthUser, resolved_org: &ResolvedOrganization) -> Uuid {
    if user.is_super_admin { resolved_org.0.id } else { user.organization_id }
}
```

Add `use crate::organization_middleware::ResolvedOrganization;` to this file's imports if not already present.

- [ ] **Step 2: Write the failing tests**

Add to `crates/hangar-api/src/routes/admin.rs`'s `mod tests`, following the exact pattern already used for Jetons/Historique (`an_organization_admin_...`/`a_regular_organization_member_cannot_...` tests earlier in this same file):

```rust
#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn an_organization_admin_reads_and_updates_their_own_system_settings(pool: sqlx::PgPool) {
    let state = AppState::build(pool, &test_config());
    let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
    let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
    state.users.set_organization_admin(org_admin_id, true).await.unwrap();
    let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
    let app = build_router(state);

    let update_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("authorization", format!("Bearer {org_admin_token}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({ "max_login_attempts": 3, "login_attempt_window_seconds": 60, "session_ttl_hours": 2, "registration_enabled": false }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_response.status(), axum::http::StatusCode::NO_CONTENT);

    let get_response = app
        .oneshot(Request::builder().uri("/api/admin/settings").header("authorization", format!("Bearer {org_admin_token}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(get_response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(get_response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["max_login_attempts"], 3);
}

#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn an_organization_admins_system_settings_update_does_not_affect_another_organization(pool: sqlx::PgPool) {
    let state = AppState::build(pool, &test_config());
    let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
    state.create_organization.execute("other", "Other Corp").await.unwrap();
    let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
    state.users.set_organization_admin(org_admin_id, true).await.unwrap();
    let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
    let app = build_router(state.clone());

    app.oneshot(
        Request::builder()
            .method("PUT")
            .uri("/api/admin/settings")
            .header("authorization", format!("Bearer {org_admin_token}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({ "max_login_attempts": 3, "login_attempt_window_seconds": 60, "session_ttl_hours": 2, "registration_enabled": false }).to_string()))
            .unwrap(),
    )
    .await
    .unwrap();

    let public_settings = state.get_system_settings.execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap();
    assert_eq!(public_settings, hangar_domain::system_settings::SystemSettings::defaults(), "the public organization's settings must be untouched by another organization's update");
}

#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn a_regular_organization_member_cannot_read_or_update_system_settings(pool: sqlx::PgPool) {
    let state = AppState::build(pool, &test_config());
    let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
    state.create_user.execute(acme_id, "member", "sup3r-s3cret!", false).await.unwrap();
    let member_token = state.authenticate_user.execute("member", "sup3r-s3cret!").await.unwrap();
    let app = build_router(state);

    let get_response = app
        .clone()
        .oneshot(Request::builder().uri("/api/admin/settings").header("authorization", format!("Bearer {member_token}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(get_response.status(), axum::http::StatusCode::FORBIDDEN);

    let update_response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings")
                .header("authorization", format!("Bearer {member_token}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({ "max_login_attempts": 3, "login_attempt_window_seconds": 60, "session_ttl_hours": 2, "registration_enabled": false }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_response.status(), axum::http::StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn an_organization_admin_reads_and_updates_their_own_smtp_settings(pool: sqlx::PgPool) {
    let state = AppState::build(pool, &test_config());
    let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
    let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
    state.users.set_organization_admin(org_admin_id, true).await.unwrap();
    let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
    let app = build_router(state);

    let update_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/admin/settings/smtp")
                .header("authorization", format!("Bearer {org_admin_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "host": "smtp.acme.example", "port": 587, "username": "hangar@acme.example", "password": "s3cret!", "from_name": "Acme", "from_address": "hangar@acme.example", "security": "start_tls" })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_response.status(), axum::http::StatusCode::NO_CONTENT);

    let get_response = app
        .oneshot(Request::builder().uri("/api/admin/settings/smtp").header("authorization", format!("Bearer {org_admin_token}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(get_response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(get_response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["host"], "smtp.acme.example");
}

#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn a_regular_organization_member_cannot_read_smtp_settings_or_send_a_test_email(pool: sqlx::PgPool) {
    let state = AppState::build(pool, &test_config());
    let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
    state.create_user.execute(acme_id, "member", "sup3r-s3cret!", false).await.unwrap();
    let member_token = state.authenticate_user.execute("member", "sup3r-s3cret!").await.unwrap();
    let app = build_router(state);

    let get_response = app
        .clone()
        .oneshot(Request::builder().uri("/api/admin/settings/smtp").header("authorization", format!("Bearer {member_token}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(get_response.status(), axum::http::StatusCode::FORBIDDEN);

    let test_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/admin/settings/smtp/test")
                .header("authorization", format!("Bearer {member_token}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({ "to": "someone@example.com" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(test_response.status(), axum::http::StatusCode::FORBIDDEN);
}
```

- [ ] **Step 3: Run the new tests to verify they fail**

```bash
set -a && source .env && set +a
export DATABASE_URL="postgres://hangar:${POSTGRES_PASSWORD}@localhost:5432/hangar"
cargo test -p hangar-api --bin hangar-api routes::admin::tests::an_organization_admin_reads_and_updates_their_own_system_settings
```

Expected: FAIL — the route still requires `require_super_admin`, so an org-admin (not super-admin) gets 403 on the GET/PUT.

- [ ] **Step 4: Change the five route handlers to `require_organization_admin` + `target_organization_id`**

```rust
async fn get_system_settings(State(state): State<AppState>, user: AuthUser, resolved_org: ResolvedOrganization) -> Result<Json<SystemSettings>, (StatusCode, Json<ErrorResponse>)> {
    let organization_id = target_organization_id(&user, &resolved_org);
    require_organization_admin(&user, organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let settings = state.get_system_settings.execute(organization_id).await.map_err(|e| application_error_response("failed to get system settings", e))?;
    Ok(Json(settings))
}

async fn update_system_settings(
    State(state): State<AppState>,
    user: AuthUser,
    resolved_org: ResolvedOrganization,
    Json(settings): Json<SystemSettings>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let organization_id = target_organization_id(&user, &resolved_org);
    require_organization_admin(&user, organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.update_system_settings.execute(organization_id, settings).await.map_err(|e| application_error_response("failed to update system settings", e))?;
    if organization_id == hangar_domain::organization::PUBLIC_ORGANIZATION_ID {
        apply_system_settings(&state.login_throttle, &state.token_issuer, &settings);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn get_smtp_settings(State(state): State<AppState>, user: AuthUser, resolved_org: ResolvedOrganization) -> Result<Json<Option<SmtpSettingsResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let organization_id = target_organization_id(&user, &resolved_org);
    require_organization_admin(&user, organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let settings = state.get_smtp_settings.execute(organization_id).await.map_err(|e| application_error_response("failed to get SMTP settings", e))?;
    Ok(Json(settings.map(|s| SmtpSettingsResponse {
        host: s.host,
        port: s.port,
        username: s.username,
        from_name: s.from_name,
        from_address: s.from_address,
        security: s.security,
        password_set: s.password_set,
    })))
}

async fn update_smtp_settings(
    State(state): State<AppState>,
    user: AuthUser,
    resolved_org: ResolvedOrganization,
    Json(body): Json<UpdateSmtpSettingsRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let organization_id = target_organization_id(&user, &resolved_org);
    require_organization_admin(&user, organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state
        .update_smtp_settings
        .execute(organization_id, UpdateSmtpSettingsInput { host: body.host, port: body.port, username: body.username, password: body.password, from_name: body.from_name, from_address: body.from_address, security: body.security })
        .await
        .map_err(|e| application_error_response("failed to update SMTP settings", e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn send_test_email(State(state): State<AppState>, user: AuthUser, resolved_org: ResolvedOrganization, Json(body): Json<SendTestEmailRequest>) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let organization_id = target_organization_id(&user, &resolved_org);
    require_organization_admin(&user, organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.send_test_email.execute(organization_id, &body.to).await.map_err(|e| application_error_response("failed to send test email", e))?;
    Ok(StatusCode::NO_CONTENT)
}
```

(The `if organization_id == PUBLIC_ORGANIZATION_ID { apply_system_settings(...) }` guard in `update_system_settings` keeps today's live-reload-without-restart behavior working for the public organization specifically, since `LoginThrottle`/`JwtTokenIssuer` are still global singletons at this point in the plan — Task 7 removes this guard entirely once they stop holding global state.)

- [ ] **Step 5: Run the new tests to verify they pass**

```bash
cargo test -p hangar-api --bin hangar-api routes::admin::tests -- --test-threads=4
```

Expected: all pass, including the five new tests from Step 2 and every pre-existing test in this module (the super-admin-only tests still pass `require_super_admin`'s super-admin branch of `require_organization_admin`, since a super-admin always satisfies it).

- [ ] **Step 6: Run the full workspace test suite**

```bash
cargo test --workspace
```

- [ ] **Step 7: Commit**

```bash
git add crates/hangar-api/src/routes/admin.rs
git commit -m "$(cat <<'EOF'
let organization admins manage their own system and SMTP settings

Same require_organization_admin + target_organization_id pattern
already used for branding — an org-admin now sees and edits only
their own organization's settings; a super-admin keeps managing
whichever organization the request's domain resolves to.
EOF
)"
```

---

### Task 6: Make the login throttle organization-aware

**Files:**
- Modify: `crates/hangar-api/src/login_throttle.rs`
- Modify: `crates/hangar-api/src/routes/auth.rs` (`login`, `verify_mfa`, `finish_mfa_passkey`, `setup_mfa_totp_confirm`, `setup_mfa_passkey_finish`)

**Interfaces:**
- Consumes: `state.users.find_by_username`/`find_by_id` (already exist), `state.system_settings` — wait, `AppState` currently has no field named `system_settings`; it has `get_system_settings: Arc<GetSystemSettingsUseCase>` (Task 2). Use `state.get_system_settings.execute(organization_id)`.
- Produces: `LoginThrottle::is_throttled(&self, key: &str, max_attempts: usize, window: Duration) -> bool`, `LoginThrottle::record_failure(&self, key: &str, max_attempts: usize, window: Duration)`. `LoginThrottle::clear`/`blocked_usernames` keep their current signatures (no limit needed to clear; `blocked_usernames` needs a decision on which limits to report — see Step 2).

- [ ] **Step 1: Update `LoginThrottle` to a pure attempt-tracker**

In `crates/hangar-api/src/login_throttle.rs`, remove the `max_attempts`/`window_millis` fields, `with_limits`, `set_limits`, and the private `max_attempts()`/`window()` accessors. Change the top import line from `use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};` to nothing (delete the line entirely — nothing in this file uses atomics once those fields are gone). Replace `is_throttled`, `record_failure`, and `blocked_usernames` with versions that take the limit as a parameter:

```rust
#[derive(Clone)]
pub struct LoginThrottle {
    attempts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self { attempts: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Expired entries are pruned lazily here, not by a background sweeper.
    pub fn is_throttled(&self, key: &str, max_attempts: usize, window: Duration) -> bool {
        let mut attempts = self.lock();
        let Some(timestamps) = attempts.get_mut(key) else {
            return false;
        };
        prune(timestamps, window);
        if timestamps.is_empty() {
            attempts.remove(key);
            return false;
        }
        timestamps.len() >= max_attempts
    }

    pub fn record_failure(&self, key: &str, max_attempts: usize, window: Duration) {
        let mut attempts = self.lock();
        if !attempts.contains_key(key) && attempts.len() >= MAX_TRACKED_USERNAMES {
            // LRU-by-last-attempt eviction to keep the map bounded.
            if let Some(evict_key) = attempts
                .iter()
                .min_by_key(|(_, timestamps)| timestamps.last())
                .map(|(key, _)| key.clone())
            {
                attempts.remove(&evict_key);
            }
        }
        let timestamps = attempts.entry(key.to_string()).or_default();
        prune(timestamps, window);
        if timestamps.len() <= max_attempts {
            timestamps.push(Instant::now());
        }
    }

    pub fn clear(&self, key: &str) {
        self.lock().remove(key);
    }

    /// Reports every currently-blocked key against the given limits — a caller with
    /// several organizations' worth of tracked keys would need to call this once per
    /// distinct limit it cares about (today, only the admin "blocked usernames" view
    /// calls this, still against the global constants — see routes/admin.rs).
    pub fn blocked_usernames(&self, max_attempts: usize, window: Duration) -> Vec<BlockedUsername> {
        let mut attempts = self.lock();
        let now = Instant::now();
        let mut blocked = Vec::new();
        attempts.retain(|username, timestamps| {
            prune(timestamps, window);
            if timestamps.is_empty() {
                return false;
            }
            if timestamps.len() >= max_attempts {
                let oldest = *timestamps.iter().min().expect("just checked non-empty");
                let remaining = window.saturating_sub(now.duration_since(oldest));
                blocked.push(BlockedUsername { username: username.clone(), remaining_seconds: remaining.as_secs() });
            }
            true
        });
        blocked.sort_by_key(|b| std::cmp::Reverse(b.remaining_seconds));
        blocked
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<Instant>>> {
        self.attempts.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}
```

Update every test in this file's `mod tests` to pass `max_attempts`/`window` explicitly to `is_throttled`/`record_failure`/`blocked_usernames` instead of constructing via `with_limits`: replace `LoginThrottle::with_limits(N, window)` with `LoginThrottle::new()`, and thread `N, window` as the trailing arguments of every `is_throttled("key", N, window)` / `record_failure("key", N, window)` / `blocked_usernames(N, window)` call in that test. Delete `set_limits_applies_to_the_next_check` and `set_limits_preserves_sub_second_windows` entirely — `set_limits` no longer exists, and per-call limits make both tests meaningless (there is no "next check" to apply a stored limit to).

- [ ] **Step 2: Run this file's tests**

```bash
cargo test -p hangar-api --bin hangar-api login_throttle::tests
```

Expected: all pass.

- [ ] **Step 3: Resolve per-organization limits in `login`, and thread `user_id`-resolvable limits through the four MFA-throttle checks**

In `crates/hangar-api/src/routes/auth.rs`, change `login`:

```rust
async fn login(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let (max_attempts, window) = throttle_limits_for_username(&state, &body.username).await;
    // Not recorded as a new failure — that would let an attacker extend their own lockout forever.
    if state.login_throttle.is_throttled(&body.username, max_attempts, window) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: "too many failed login attempts, try again later".to_string() }),
        ));
    }

    match state.authenticate_user.execute(&body.username, &body.password).await {
        Ok(token) => {
            state.login_throttle.clear(&body.username);
            /* ... unchanged from here ... */
        }
        Err(_) => {
            state.login_throttle.record_failure(&body.username, max_attempts, window);
            /* ... unchanged ... */
        }
    }
}
```

(Keep the rest of `login`'s body — the `Ok`/`Err` arms below the throttle check — exactly as it is today; only the two `login_throttle` calls gain the resolved `max_attempts, window` arguments, and the throttled-check at the top gains the same.)

Add this helper near the top of `routes/auth.rs`:

```rust
/// A nonexistent username has no organization to resolve limits from — falls back to
/// the hard-coded defaults, same as before this file had any per-organization concept.
/// Not attacker-observable: an unknown username is throttled identically either way.
async fn throttle_limits_for_username(state: &AppState, username: &str) -> (usize, std::time::Duration) {
    let Ok(username) = hangar_domain::user::Username::parse(username) else {
        return (crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW);
    };
    match state.users.find_by_username(&username).await {
        Ok(Some(user)) => throttle_limits_for_organization(state, user.organization_id).await,
        _ => (crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW),
    }
}

async fn throttle_limits_for_organization(state: &AppState, organization_id: uuid::Uuid) -> (usize, std::time::Duration) {
    match state.get_system_settings.execute(organization_id).await {
        Ok(settings) => (settings.max_login_attempts as usize, std::time::Duration::from_secs(settings.login_attempt_window_seconds as u64)),
        Err(_) => (crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW),
    }
}
```

Now update the four MFA-throttle-key call sites (`verify_mfa`, `finish_mfa_passkey`, `setup_mfa_totp_confirm`, `setup_mfa_passkey_finish`) — each already resolves `user_id` via `mfa_pending_token_issuer.verify(...)` before its throttle check. In each, resolve that user's organization and pass the limits through. For example, in `verify_mfa`:

```rust
async fn verify_mfa(State(state): State<AppState>, Json(body): Json<MfaVerifyRequest>) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = state
        .mfa_pending_token_issuer
        .verify(&body.mfa_token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid or expired mfa token".to_string() })))?;

    let (max_attempts, window) = throttle_limits_for_user_id(&state, user_id).await;
    let throttle_key = format!("mfa:{user_id}");
    if state.login_throttle.is_throttled(&throttle_key, max_attempts, window) {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse { error: "too many failed attempts, try again later".to_string() })));
    }

    /* ... unchanged body below, except record_failure calls (in the Err arm of each
       handler's match, if present) also gain `, max_attempts, window` ... */
}
```

Apply the identical pattern (resolve `(max_attempts, window)` right after `user_id` is known, pass them to that handler's `is_throttled`/`record_failure` calls) to `finish_mfa_passkey`, `setup_mfa_totp_confirm`, and `setup_mfa_passkey_finish`. Add the third helper these reuse:

```rust
async fn throttle_limits_for_user_id(state: &AppState, user_id: uuid::Uuid) -> (usize, std::time::Duration) {
    match state.users.find_by_id(user_id).await {
        Ok(Some(user)) => throttle_limits_for_organization(state, user.organization_id).await,
        _ => (crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW),
    }
}
```

`register`'s IP-keyed throttle (`throttle_key = format!("register:{}", peer_ip(...))`) is explicitly out of scope (see Global Constraints) — leave its `is_throttled`/`record_failure` calls exactly as they are today, but they now need the two extra arguments to compile: pass the global constants directly, `state.login_throttle.is_throttled(&throttle_key, crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW)` and the matching `record_failure` call.

- [ ] **Step 4: Update `routes/admin.rs`'s `list_blocked_usernames`**

This stays on the global constants — the "blocked accounts" admin view was already established as super-admin-only and unattributable to any one organization (Historique + Sécurité sub-project). Change only what's needed to compile:

```rust
async fn list_blocked_usernames(State(state): State<AppState>, user: AuthUser) -> Result<Json<Vec<BlockedUsernameResponse>>, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let blocked = state.login_throttle.blocked_usernames(crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW);
    Ok(Json(blocked.into_iter().map(|b| BlockedUsernameResponse { username: b.username, remaining_seconds: b.remaining_seconds }).collect()))
}
```

- [ ] **Step 5: Write the new organization-scoping test**

Add to `crates/hangar-api/src/routes/auth.rs`'s `mod tests`:

```rust
#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn a_lower_throttle_limit_in_one_organization_does_not_affect_another(pool: sqlx::PgPool) {
    let state = AppState::build(pool, &test_config());
    let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
    let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
    state.create_user.execute(acme_id, "acme-user", "sup3r-s3cret!", false).await.unwrap();
    state.create_user.execute(other_id, "other-user", "sup3r-s3cret!", false).await.unwrap();
    state.update_system_settings.execute(acme_id, hangar_domain::system_settings::SystemSettings { max_login_attempts: 1, login_attempt_window_seconds: 300, session_ttl_hours: 12, registration_enabled: true }).await.unwrap();
    let app = build_router(state);

    // One bad attempt against acme-user is already at acme's 1-attempt limit.
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({ "username": "acme-user", "password": "wrong" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let acme_second_attempt = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({ "username": "acme-user", "password": "wrong" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(acme_second_attempt.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);

    // other-user, on the default 10-attempt limit, is unaffected by acme's lower limit.
    let other_second_attempt = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({ "username": "other-user", "password": "wrong" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(other_second_attempt.status(), axum::http::StatusCode::UNAUTHORIZED, "a second attempt against a different organization's default limit must not be throttled yet");
}
```

- [ ] **Step 6: Run the new test to verify it fails, then implement (Steps 1–4 above), then verify it passes**

```bash
set -a && source .env && set +a
export DATABASE_URL="postgres://hangar:${POSTGRES_PASSWORD}@localhost:5432/hangar"
cargo test -p hangar-api --bin hangar-api routes::auth::tests::a_lower_throttle_limit_in_one_organization_does_not_affect_another
```

Expected: FAILs before Steps 1–4 are applied (the code doesn't compile / the endpoint isn't org-aware yet), passes after.

- [ ] **Step 7: Run the full workspace test suite**

```bash
cargo test --workspace
```

- [ ] **Step 8: Commit**

```bash
git add crates/hangar-api/src/login_throttle.rs crates/hangar-api/src/routes/auth.rs crates/hangar-api/src/routes/admin.rs
git commit -m "$(cat <<'EOF'
resolve login-throttle limits per organization

LoginThrottle becomes a pure attempt-tracker; the login and MFA-verify
handlers resolve the acting user's organization's own
max_login_attempts/login_attempt_window_seconds before every check. A
username that doesn't resolve to a real account (or register's
IP-keyed flood check) keeps using the original hard-coded defaults —
there's no organization to look up for either.
EOF
)"
```

---

### Task 7: Make session TTL organization-aware, and remove the now-dead global-settings plumbing

**Files:**
- Modify: `crates/hangar-domain/src/user.rs` (`TokenIssuerPort`)
- Modify: `crates/hangar-infrastructure/src/jwt_token_issuer.rs`
- Modify: `crates/hangar-application/src/use_cases/user.rs` (`AuthenticateUserUseCase`, its `FakeTokenIssuer`)
- Modify: `crates/hangar-application/src/use_cases/sso.rs` (`ProvisionSsoUserUseCase`, its `FakeTokenIssuer`)
- Modify: `crates/hangar-api/src/routes/auth.rs` (`verify_mfa`, `finish_mfa_passkey`, `setup_mfa_totp_confirm`, `setup_mfa_passkey_finish`, and the test helpers in `auth_middleware.rs`)
- Modify: `crates/hangar-api/src/auth_middleware.rs` (test-only `state.token_issuer.issue(user_id)` call sites)
- Modify: `crates/hangar-api/src/state.rs` (remove `sync_settings_from_storage`/`apply_system_settings`, inject `SystemSettingsPort` into `AuthenticateUserUseCase`/`ProvisionSsoUserUseCase`)
- Modify: `crates/hangar-api/src/main.rs` (remove the `sync_settings_from_storage` call)
- Modify: `crates/hangar-api/src/routes/admin.rs` (remove the now-dead `apply_system_settings` call in `update_system_settings`)
- Modify: `crates/hangar-infrastructure/src/jwt_token_issuer.rs` tests (`set_ttl_changes_the_expiry_of_newly_issued_tokens` no longer applies as written)

**Interfaces:**
- Consumes: `state.get_system_settings.execute(organization_id)` (Task 2).
- Produces: `TokenIssuerPort::issue(&self, user_id: Uuid, ttl: chrono::Duration) -> Result<String, DomainError>`.

- [ ] **Step 1: Update the trait**

In `crates/hangar-domain/src/user.rs`:

```rust
#[async_trait]
pub trait TokenIssuerPort: Send + Sync {
    fn issue(&self, user_id: Uuid, ttl: chrono::Duration) -> Result<String, DomainError>;
    fn verify(&self, token: &str) -> Result<Uuid, DomainError>;
}
```

Add `use chrono::Duration;` — or reference `chrono::Duration` fully qualified as above (matching this file's existing import style; check the top of `user.rs` for whether `chrono` is already imported and follow that convention).

- [ ] **Step 2: Update `JwtTokenIssuer`**

In `crates/hangar-infrastructure/src/jwt_token_issuer.rs`:

```rust
pub struct JwtTokenIssuer {
    secret: String,
}

impl JwtTokenIssuer {
    pub fn new(secret: String) -> Self {
        Self { secret }
    }
}

#[async_trait]
impl TokenIssuerPort for JwtTokenIssuer {
    fn issue(&self, user_id: Uuid, ttl: Duration) -> Result<String, DomainError> {
        let claims = Claims { sub: user_id, exp: (Utc::now() + ttl).timestamp() };
        encode(&Header::default(), &claims, &EncodingKey::from_secret(self.secret.as_bytes())).infra_err()
    }

    fn verify(&self, token: &str) -> Result<Uuid, DomainError> {
        let data = decode::<Claims>(token, &DecodingKey::from_secret(self.secret.as_bytes()), &Validation::default()).infra_err()?;
        Ok(data.claims.sub)
    }
}
```

Remove the now-unused `use std::sync::atomic::{AtomicI64, Ordering};`. Update this file's tests: replace `issuing_then_verifying_returns_the_same_user_id`'s `issuer.issue(user_id)` with `issuer.issue(user_id, Duration::hours(12))`. Replace `set_ttl_changes_the_expiry_of_newly_issued_tokens` entirely — there is no more `set_ttl` to test; the equivalent behavior (a negative TTL produces an already-expired token) is still worth keeping, just expressed as a direct argument:

```rust
#[test]
fn a_negative_ttl_produces_an_already_expired_token() {
    let issuer = JwtTokenIssuer::new("test-secret".to_string());
    let token = issuer.issue(Uuid::new_v4(), Duration::seconds(-300)).unwrap();
    assert!(issuer.verify(&token).is_err(), "a token issued with a negative TTL must already be expired");
}
```

Update `verifying_a_token_signed_with_a_different_secret_fails` and `a_docker_access_token_is_rejected_by_the_session_token_issuer` — both call `.issue(Uuid::new_v4())` — to `.issue(Uuid::new_v4(), Duration::hours(12))`.

- [ ] **Step 3: Update `AuthenticateUserUseCase`**

In `crates/hangar-application/src/use_cases/user.rs`:

```rust
pub struct AuthenticateUserUseCase {
    users: Arc<dyn UserRepositoryPort>,
    hasher: Arc<dyn PasswordHasherPort>,
    tokens: Arc<dyn TokenIssuerPort>,
    system_settings: Arc<dyn hangar_domain::system_settings::SystemSettingsPort>,
}

impl AuthenticateUserUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>, hasher: Arc<dyn PasswordHasherPort>, tokens: Arc<dyn TokenIssuerPort>, system_settings: Arc<dyn hangar_domain::system_settings::SystemSettingsPort>) -> Self {
        Self { users, hasher, tokens, system_settings }
    }

    pub async fn execute(&self, username: &str, password: &str) -> Result<String, ApplicationError> {
        // Every path below runs exactly one `verify` call, or an attacker could enumerate
        // valid usernames by response timing.
        let user = match Username::parse(username) {
            Ok(username) => self.users.find_by_username(&username).await?,
            Err(_) => None,
        };
        let hash = user.as_ref().map_or(DUMMY_HASH_FOR_TIMING, |u| u.password_hash.as_str());
        let password_matches = self.hasher.verify(password, hash);

        let Some(user) = user else {
            return Err(ApplicationError::InvalidCredentials);
        };
        if !password_matches {
            return Err(ApplicationError::InvalidCredentials);
        }
        let settings = self.system_settings.get(user.organization_id).await?;
        Ok(self.tokens.issue(user.id, chrono::Duration::hours(settings.session_ttl_hours as i64))?)
    }
}
```

Update this file's `FakeTokenIssuer` (`impl TokenIssuerPort for FakeTokenIssuer`):

```rust
impl TokenIssuerPort for FakeTokenIssuer {
    fn issue(&self, user_id: Uuid, _ttl: chrono::Duration) -> Result<String, DomainError> {
        Ok(format!("token:{user_id}"))
    }
    fn verify(&self, token: &str) -> Result<Uuid, DomainError> {
        token
            .strip_prefix("token:")
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| DomainError::InvalidUsername("bad token".to_string()))
    }
}
```

Every test in this file constructing `AuthenticateUserUseCase::new(...)` needs a fourth argument — a fake `SystemSettingsPort`. Reuse `FakeSystemSettings` from `crates/hangar-application/src/use_cases/admin.rs` — no, `mod tests` blocks are private per-file, so instead add a minimal local fake in `user.rs`'s own `mod tests`:

```rust
struct FakeSystemSettings;

#[async_trait]
impl hangar_domain::system_settings::SystemSettingsPort for FakeSystemSettings {
    async fn get(&self, _organization_id: Uuid) -> Result<hangar_domain::system_settings::SystemSettings, DomainError> {
        Ok(hangar_domain::system_settings::SystemSettings::defaults())
    }
    async fn update(&self, _organization_id: Uuid, _settings: &hangar_domain::system_settings::SystemSettings) -> Result<(), DomainError> {
        Ok(())
    }
}
```

Pass `Arc::new(FakeSystemSettings)` as the fourth argument everywhere `AuthenticateUserUseCase::new(...)` is called in this file's tests.

- [ ] **Step 4: Update `ProvisionSsoUserUseCase`**

In `crates/hangar-application/src/use_cases/sso.rs`:

```rust
pub struct ProvisionSsoUserUseCase {
    users: Arc<dyn UserRepositoryPort>,
    hasher: Arc<dyn PasswordHasherPort>,
    tokens: Arc<dyn TokenIssuerPort>,
    system_settings: Arc<dyn hangar_domain::system_settings::SystemSettingsPort>,
}

impl ProvisionSsoUserUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>, hasher: Arc<dyn PasswordHasherPort>, tokens: Arc<dyn TokenIssuerPort>, system_settings: Arc<dyn hangar_domain::system_settings::SystemSettingsPort>) -> Self {
        Self { users, hasher, tokens, system_settings }
    }

    pub async fn execute(&self, organization_id: Uuid, identity: &ExternalIdentity) -> Result<String, ApplicationError> {
        if let Some(existing) = self.users.find_by_email(&identity.email).await? {
            if existing.organization_id != organization_id || existing.is_super_admin || existing.is_organization_admin {
                return Err(ApplicationError::InvalidCredentials);
            }
            let settings = self.system_settings.get(existing.organization_id).await?;
            return Ok(self.tokens.issue(existing.id, chrono::Duration::hours(settings.session_ttl_hours as i64))?);
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
        let settings = self.system_settings.get(organization_id).await?;
        Ok(self.tokens.issue(user.id, chrono::Duration::hours(settings.session_ttl_hours as i64))?)
    }
}
```

Apply the identical `FakeSystemSettings` addition described in Step 3 to this file's `mod tests` (it is a separate, private `mod tests`, so it needs its own copy), and pass `Arc::new(FakeSystemSettings)` as the fourth argument everywhere `ProvisionSsoUserUseCase::new(...)` is called in this file's tests. Update `FakeTokenIssuer` here the same way as Step 3.

- [ ] **Step 5: Update `crates/hangar-api/src/state.rs`**

Inject `system_settings.clone()` as the fourth constructor argument at both existing call sites:

```rust
provision_sso_user: Arc::new(ProvisionSsoUserUseCase::new(users_repo.clone(), hasher.clone(), token_issuer.clone(), system_settings.clone())),
```

```rust
authenticate_user: Arc::new(AuthenticateUserUseCase::new(users_repo.clone(), hasher.clone(), token_issuer.clone(), system_settings.clone())),
```

Remove `sync_settings_from_storage` and `apply_system_settings` entirely from this file — nothing needs them once `LoginThrottle`/`JwtTokenIssuer` hold no global settings state:

```rust
// Delete this whole method:
// pub async fn sync_settings_from_storage(&self) { ... }

// Delete this whole free function:
// pub fn apply_system_settings(login_throttle: &LoginThrottle, token_issuer: &JwtTokenIssuer, settings: &hangar_domain::system_settings::SystemSettings) { ... }
```

- [ ] **Step 6: Remove the now-dead call sites**

In `crates/hangar-api/src/main.rs`, delete the line `state.sync_settings_from_storage().await;`.

In `crates/hangar-api/src/routes/admin.rs`'s `update_system_settings` (from Task 5, Step 4), delete the `if organization_id == PUBLIC_ORGANIZATION_ID { apply_system_settings(...) }` block entirely — there is nothing left to push it to:

```rust
async fn update_system_settings(
    State(state): State<AppState>,
    user: AuthUser,
    resolved_org: ResolvedOrganization,
    Json(settings): Json<SystemSettings>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let organization_id = target_organization_id(&user, &resolved_org);
    require_organization_admin(&user, organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.update_system_settings.execute(organization_id, settings).await.map_err(|e| application_error_response("failed to update system settings", e))?;
    Ok(StatusCode::NO_CONTENT)
}
```

Also remove `use crate::state::apply_system_settings;` (or the equivalent import line) from `routes/admin.rs` if it becomes unused — check with `cargo build` in Step 8 and delete whatever the compiler flags as an unused import.

- [ ] **Step 7: Resolve TTL at the four MFA-verify token-issuance call sites**

In `crates/hangar-api/src/routes/auth.rs`, each of `verify_mfa`, `finish_mfa_passkey`, `setup_mfa_totp_confirm`, `setup_mfa_passkey_finish` already resolves `user_id` early (Task 6 added `throttle_limits_for_user_id(&state, user_id)` right after). Right before each handler's `state.token_issuer.issue(user_id)` call, resolve the TTL the same way:

```rust
let user = state.users.find_by_id(user_id).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?.ok_or((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
let settings = state.get_system_settings.execute(user.organization_id).await.map_err(|e| application_error_response("failed to get system settings", e))?;
let token = state.token_issuer.issue(user_id, chrono::Duration::hours(settings.session_ttl_hours as i64)).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
```

(Replacing the existing `let token = state.token_issuer.issue(user_id).map_err(...)?;` line in each of the four handlers with these three lines. This duplicates the `find_by_id` call `throttle_limits_for_user_id` already made earlier in the same handler — acceptable for a self-hosted, low-traffic login path; do not try to thread the already-resolved `User` through, since `throttle_limits_for_user_id` was written in Task 6 to encapsulate its own lookup and changing that now would be a bigger diff than a second cheap indexed read.)

- [ ] **Step 8: Fix the test-only call sites in `auth_middleware.rs`**

In `crates/hangar-api/src/auth_middleware.rs`'s `mod tests`, update the three `state.token_issuer.issue(user_id).unwrap()` calls to `state.token_issuer.issue(user_id, chrono::Duration::hours(12)).unwrap()`.

- [ ] **Step 9: Write the organization-scoping test for session TTL**

Add to `crates/hangar-api/src/routes/auth.rs`'s `mod tests`:

```rust
#[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
async fn a_login_token_carries_the_issuing_users_organizations_session_ttl(pool: sqlx::PgPool) {
    let state = AppState::build(pool, &test_config());
    let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
    state.create_user.execute(acme_id, "acme-user", "sup3r-s3cret!", false).await.unwrap();
    state.update_system_settings.execute(acme_id, hangar_domain::system_settings::SystemSettings { max_login_attempts: 10, login_attempt_window_seconds: 300, session_ttl_hours: 1, registration_enabled: true }).await.unwrap();
    let app = build_router(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({ "username": "acme-user", "password": "sup3r-s3cret!" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = json["token"].as_str().unwrap();

    // Decode the JWT payload without verifying (this test only cares about the claimed
    // expiry, and doesn't have the server's signing secret at hand) to check the token's
    // lifetime is close to 1 hour, not the SystemSettings::defaults() 12 hours.
    let payload_b64 = token.split('.').nth(1).unwrap();
    let payload_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, payload_b64).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    let exp = payload["exp"].as_i64().unwrap();
    let now = chrono::Utc::now().timestamp();
    let ttl_seconds = exp - now;
    assert!(ttl_seconds > 0 && ttl_seconds <= 3600, "expected a ~1 hour TTL from acme's own session_ttl_hours=1, got {ttl_seconds} seconds");
}
```

`hangar-api`'s `Cargo.toml` does not currently depend on `base64` (only `hangar-npm` does, at `0.23.1`). Add `base64 = "0.23.1"` to `crates/hangar-api/Cargo.toml`'s `[dev-dependencies]` section (matching the version already used elsewhere in this workspace) — this test is `#[cfg(test)]`-only, so it belongs in `[dev-dependencies]`, not `[dependencies]`. Run `cargo build -p hangar-api` once after adding it so `Cargo.lock` picks up the new entry.

- [ ] **Step 10: Run the new test to verify it fails, then re-run after Steps 1–8 are applied**

```bash
set -a && source .env && set +a
export DATABASE_URL="postgres://hangar:${POSTGRES_PASSWORD}@localhost:5432/hangar"
cargo test -p hangar-api --bin hangar-api routes::auth::tests::a_login_token_carries_the_issuing_users_organizations_session_ttl
```

Expected: FAILs before Steps 1–8 are applied (doesn't compile / TTL is still the global 12h default), passes after.

- [ ] **Step 11: Run the full workspace test suite, fixing any remaining compile error**

```bash
set -a && source .env && set +a
export DATABASE_URL="postgres://hangar:${POSTGRES_PASSWORD}@localhost:5432/hangar"
cargo build --workspace 2>&1 | head -100
```

Fix each reported error the same way as the rest of this task (an extra `ttl`/`system_settings` argument, or an unused import to delete). Then:

```bash
cargo test --workspace
```

Expected: all pass.

- [ ] **Step 12: Commit**

```bash
git add crates/hangar-domain/src/user.rs \
        crates/hangar-infrastructure/src/jwt_token_issuer.rs \
        crates/hangar-application/src/use_cases/user.rs \
        crates/hangar-application/src/use_cases/sso.rs \
        crates/hangar-api/src/routes/auth.rs \
        crates/hangar-api/src/auth_middleware.rs \
        crates/hangar-api/src/state.rs \
        crates/hangar-api/src/main.rs \
        crates/hangar-api/src/routes/admin.rs \
        crates/hangar-api/Cargo.toml \
        Cargo.lock
git commit -m "$(cat <<'EOF'
resolve session TTL per organization; retire global settings push

TokenIssuerPort::issue now takes an explicit ttl, resolved by the
caller from the issuing user's own organization's system_settings.
JwtTokenIssuer and LoginThrottle (Task 6) no longer hold any global
mutable settings state, so the boot-time
sync_settings_from_storage/apply_system_settings push-on-write
mechanism has nothing left to update — removed.
EOF
)"
```

---

### Task 8: Embed system settings and SMTP settings into the organization admin page

**Files:**
- Modify: `frontend/src/app/admin/organization-detail/organization-detail.ts`
- Modify: `frontend/src/app/admin/organization-detail/organization-detail.html`
- Modify: `frontend/src/app/admin/organization-detail/organization-detail.spec.ts`

**Interfaces:**
- Consumes: `SystemSettingsAdmin` (selector `app-system-settings`, `frontend/src/app/admin/system-settings/system-settings.ts`) and `SmtpSettingsAdmin` (selector `app-smtp-settings`, `frontend/src/app/admin/smtp-settings/smtp-settings.ts`) — both already exist, unmodified, calling `SystemSettingsService`/`SmtpSettingsService` which hit `/api/admin/settings`/`/api/admin/settings/smtp*`, now organization-scoped by the backend (Task 5). Neither component takes an `organizationId` input — same zero-modification pattern as `AuditLog`/`ApiTokensAdmin` from the earlier sub-projects in this series.

- [ ] **Step 1: Embed both components**

In `frontend/src/app/admin/organization-detail/organization-detail.ts`, add imports:

```typescript
import { SystemSettingsAdmin } from '../system-settings/system-settings'
import { SmtpSettingsAdmin } from '../smtp-settings/smtp-settings'
```

Add both to the `@Component` `imports` array (alongside the existing `AuditLog`, `SecurityLog`, `UsageMetrics`, etc.):

```typescript
imports: [
  Card,
  GbtInput,
  Button,
  Select,
  FormsModule,
  OrganizationMembers,
  BrandingSettingsAdmin,
  ApiTokensAdmin,
  AuditLog,
  SecurityLog,
  UsageMetrics,
  SystemSettingsAdmin,
  SmtpSettingsAdmin,
],
```

In `frontend/src/app/admin/organization-detail/organization-detail.html`, add both as new top-level siblings, following this file's established placement (after the existing sections, before the closing `@else if (errorMessage(); ...)` branch):

```html
    <app-system-settings />

    <app-smtp-settings />
  } @else if (errorMessage(); as message) {
```

- [ ] **Step 2: Update the spec file's provider stubs**

In `frontend/src/app/admin/organization-detail/organization-detail.spec.ts`, add imports:

```typescript
import { SystemSettingsAdmin } from '../system-settings/system-settings'
import { SmtpSettingsAdmin } from '../smtp-settings/smtp-settings'
import { SystemSettingsService } from '../application/system-settings.service'
import { SmtpSettingsService } from '../application/smtp-settings.service'
```

Add stub constants near this file's existing `*_STUB` constants:

```typescript
const SYSTEM_SETTINGS_SERVICE_STUB = {
  get: () => of({ max_login_attempts: 10, login_attempt_window_seconds: 300, session_ttl_hours: 12, registration_enabled: true }),
  update: () => of(undefined),
}

const SMTP_SETTINGS_SERVICE_STUB = {
  get: () => of(null),
  update: () => of(undefined),
  sendTestEmail: () => of(undefined),
}
```

(Check `frontend/src/app/admin/application/system-settings.service.ts` and `smtp-settings.service.ts` for the exact method names before writing these stubs — match whatever `get`/`update`/`sendTestEmail` actually return, following the same pattern this spec file already uses for `AUDIT_SERVICE_STUB`/`ADMIN_METRICS_SERVICE_STUB`.)

Add `{ provide: SystemSettingsService, useValue: SYSTEM_SETTINGS_SERVICE_STUB }` and `{ provide: SmtpSettingsService, useValue: SMTP_SETTINGS_SERVICE_STUB }` to every `TestBed.configureTestingModule` provider array in this file (there are five, one per `setup()`/inline-`TestBed.configureTestingModule` call — the same five blocks already extended by each of Marque/Jetons/Historique/Métriques).

- [ ] **Step 3: Write the failing test**

```typescript
it('renders the system and SMTP settings', () => {
  setup()

  const systemSettingsDebugElement = fixture.debugElement.query(By.directive(SystemSettingsAdmin))
  expect(systemSettingsDebugElement).not.toBeNull()
  const smtpSettingsDebugElement = fixture.debugElement.query(By.directive(SmtpSettingsAdmin))
  expect(smtpSettingsDebugElement).not.toBeNull()
})
```

- [ ] **Step 4: Run this spec file to verify the new test fails**

```bash
cd frontend
npx ng test --watch=false --include='**/organization-detail.spec.ts'
```

Expected: FAIL — `SystemSettingsAdmin`/`SmtpSettingsAdmin` aren't imported/embedded yet (or, if run after Step 1/2 are already applied, this step is a no-op check — apply Steps 1–2 first if not already done, then this step should already show PASS; if so, skip directly to Step 5).

- [ ] **Step 5: Run the full frontend test suite**

```bash
npx ng test --watch=false
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/app/admin/organization-detail/organization-detail.ts \
        frontend/src/app/admin/organization-detail/organization-detail.html \
        frontend/src/app/admin/organization-detail/organization-detail.spec.ts
git commit -m "$(cat <<'EOF'
embed system settings and SMTP settings into the organization page

Same zero-modification reuse pattern as every other sub-project in
this series — both components already call the now-organization-
scoped admin endpoints, so no component code changes.
EOF
)"
```

- [ ] **Step 7: Verify live**

Rebuild the docker-compose verification instance and confirm in the browser, as `skolln-admin`, that "Paramètres système" and "Serveur mail" sections appear on `/admin/organizations/:id` and that saving a change (e.g. a lower `max_login_attempts`) round-trips correctly, without affecting the `public` organization's own settings. Stop the docker-compose instance afterward, leaving the user's own `dev.sh` session untouched. This closes out the full "org-scoped admin dashboard" decomposition (Marque, Jetons API, Historique + Sécurité, Métriques, Paramètres système + Serveur mail).

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use hangar_application::use_cases::smtp::UpdateSmtpSettingsInput;
use hangar_domain::audit::{AuditEntry, AuditQueryFilter};
use hangar_domain::email::SmtpSecurity;
use hangar_domain::health::ComponentHealth;
use hangar_domain::package_repository::{RepositoryFormat, RepositoryType};
use hangar_domain::permission::Role;
use hangar_domain::system_settings::SystemSettings;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth_middleware::AuthUser;
use crate::authz::{require_organization_admin, require_super_admin};
use crate::dto::{application_error_response, ErrorResponse};
use crate::organization_middleware::ResolvedOrganization;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/audit/events", get(list_audit_events))
        .route("/api/admin/metrics", get(get_metrics))
        .route("/api/admin/metrics/history", get(get_metrics_history))
        .route("/api/admin/health", get(get_health))
        .route("/api/admin/stats", get(get_stats))
        .route("/api/admin/security/blocked", get(list_blocked_usernames))
        .route("/api/admin/tokens", get(list_all_api_tokens))
        .route("/api/admin/tokens/{id}", axum::routing::delete(admin_revoke_api_token))
        .route("/api/admin/settings", get(get_system_settings).put(update_system_settings))
        .route("/api/admin/settings/smtp", get(get_smtp_settings).put(update_smtp_settings))
        .route("/api/admin/settings/smtp/test", axum::routing::post(send_test_email))
        .route("/api/admin/export/configuration", get(export_configuration))
        .route("/api/admin/import/configuration", axum::routing::post(import_configuration))
}

/// A super-admin manages whichever organization the request's domain resolves to; a non-super-admin can only ever manage their own, regardless of which domain the request came in on. Same helper as `routes/branding.rs`.
fn target_organization_id(user: &AuthUser, resolved_org: &ResolvedOrganization) -> Uuid {
    if user.is_super_admin { resolved_org.0.id } else { user.organization_id }
}

#[derive(Deserialize)]
struct AuditQueryParams {
    aggregate_type: Option<String>,
    exclude_aggregate_type: Option<String>,
    aggregate_id: Option<String>,
    actor_id: Option<Uuid>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct AuditEntryResponse {
    aggregate_type: String,
    aggregate_id: String,
    event_type: String,
    payload: serde_json::Value,
    occurred_at: DateTime<Utc>,
    actor_id: Option<Uuid>,
}

fn internal_error<E>(_: E) -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() }))
}

/// Every repository id belonging to `organization_id` — the "which repos are mine" set metrics scoping filters against.
async fn organization_repository_ids(state: &AppState, organization_id: Uuid) -> Result<std::collections::HashSet<Uuid>, hangar_domain::error::EventStoreError> {
    Ok(state.repositories.list_all().await?.into_iter().filter(|r| r.organization_id == organization_id).map(|r| r.id).collect())
}

/// The organization an audit entry pertains to, if any — pre-auth events like `LoginFailed` resolve to `None` and get dropped for an organization admin.
async fn organization_for_audit_entry(state: &AppState, entry: &AuditEntry) -> Option<Uuid> {
    let repository_id = match entry.aggregate_type.as_str() {
        "PackageRepository" | "DockerRegistry" => Uuid::parse_str(&entry.aggregate_id).ok()?,
        "NpmPackage" => {
            let npm_package_id = Uuid::parse_str(&entry.aggregate_id).ok()?;
            state.npm_packages.find_by_id(npm_package_id).await.ok()??.package_repository_id
        }
        "Permission" => entry.aggregate_id.split(':').nth(1).and_then(|s| Uuid::parse_str(s).ok())?,
        "Security" => {
            let user = state.users.find_by_id(entry.actor_id?).await.ok()??;
            return Some(user.organization_id);
        }
        _ => return None,
    };
    Some(state.repositories.find_by_id(repository_id).await.ok()??.organization_id)
}

async fn list_audit_events(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<AuditQueryParams>,
) -> Result<Json<Vec<AuditEntryResponse>>, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, user.organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let filter = AuditQueryFilter {
        aggregate_type: params.aggregate_type,
        exclude_aggregate_type: params.exclude_aggregate_type,
        aggregate_id: params.aggregate_id,
        actor_id: params.actor_id,
        from: params.from,
        to: params.to,
    };
    let entries = state.query_audit_log.execute(filter).await.map_err(|e| application_error_response("failed to query audit log", e))?;
    let entries = if user.is_super_admin {
        entries
    } else {
        // Resolved concurrently — up to 200 entries, one round trip at a time would add up.
        let organizations = futures::future::join_all(entries.iter().map(|entry| organization_for_audit_entry(&state, entry))).await;
        entries.into_iter().zip(organizations).filter(|(_, org)| *org == Some(user.organization_id)).map(|(entry, _)| entry).collect()
    };
    Ok(Json(
        entries
            .into_iter()
            .map(|e| AuditEntryResponse {
                aggregate_type: e.aggregate_type,
                aggregate_id: e.aggregate_id,
                event_type: e.event_type,
                payload: e.payload,
                occurred_at: e.occurred_at,
                actor_id: e.actor_id,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
struct RepositoryUsageResponse {
    repository_id: Uuid,
    name: String,
    used_bytes: u64,
    /// `None` means unlimited.
    quota_bytes: Option<i64>,
}

async fn get_metrics(State(state): State<AppState>, user: AuthUser) -> Result<Json<Vec<RepositoryUsageResponse>>, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, user.organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let usages = state.get_usage_metrics.execute().await.map_err(|e| application_error_response("failed to get usage metrics", e))?;
    let usages = if user.is_super_admin {
        usages
    } else {
        let org_repository_ids = organization_repository_ids(&state, user.organization_id).await.map_err(internal_error)?;
        usages.into_iter().filter(|u| org_repository_ids.contains(&u.repository_id)).collect()
    };
    Ok(Json(
        usages
            .into_iter()
            .map(|u| RepositoryUsageResponse { repository_id: u.repository_id, name: u.name, used_bytes: u.used_bytes, quota_bytes: u.quota_bytes })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct MetricsHistoryParams {
    /// Defaults to 30.
    days: Option<i64>,
}

#[derive(Serialize)]
struct MetricsSnapshotResponse {
    recorded_at: DateTime<Utc>,
    total_users: i64,
    total_repositories: i64,
    total_storage_bytes: i64,
}

async fn get_metrics_history(
    State(state): State<AppState>,
    user: AuthUser,
    Query(params): Query<MetricsHistoryParams>,
) -> Result<Json<Vec<MetricsSnapshotResponse>>, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let days = params.days.unwrap_or(30).clamp(1, 365);
    let since = Utc::now() - chrono::Duration::days(days);
    let snapshots = state.get_metrics_history.execute(since).await.map_err(|e| application_error_response("failed to get metrics history", e))?;
    Ok(Json(
        snapshots
            .into_iter()
            .map(|s| MetricsSnapshotResponse {
                recorded_at: s.recorded_at,
                total_users: s.total_users,
                total_repositories: s.total_repositories,
                total_storage_bytes: s.total_storage_bytes,
            })
            .collect(),
    ))
}

fn split_component_health(health: ComponentHealth) -> (&'static str, Option<String>) {
    match health {
        ComponentHealth::Up => ("up", None),
        ComponentHealth::Down(reason) => ("down", Some(reason)),
    }
}

#[derive(Serialize)]
struct DatabaseHealthResponse {
    status: &'static str,
    detail: Option<String>,
    response_time_ms: u64,
    active_connections: u32,
    max_connections: u32,
    server_version: Option<String>,
}

#[derive(Serialize)]
struct StorageHealthResponse {
    status: &'static str,
    detail: Option<String>,
    used_bytes: u64,
    free_bytes: u64,
    total_bytes: u64,
}

#[derive(Serialize)]
struct HealthResponse {
    database: DatabaseHealthResponse,
    storage: StorageHealthResponse,
    uptime_seconds: u64,
}

async fn get_health(State(state): State<AppState>, user: AuthUser) -> Result<Json<HealthResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let status = state.get_health_status.execute().await;

    let (db_status, db_detail) = split_component_health(status.database.status);
    let (storage_status, storage_detail) = split_component_health(status.storage.status);

    Ok(Json(HealthResponse {
        database: DatabaseHealthResponse {
            status: db_status,
            detail: db_detail,
            response_time_ms: status.database.response_time_ms,
            active_connections: status.database.active_connections,
            max_connections: status.database.max_connections,
            server_version: status.database.server_version,
        },
        storage: StorageHealthResponse {
            status: storage_status,
            detail: storage_detail,
            used_bytes: status.storage.used_bytes,
            free_bytes: status.storage.free_bytes,
            total_bytes: status.storage.total_bytes,
        },
        uptime_seconds: status.uptime_seconds,
    }))
}

#[derive(Serialize)]
struct AdminStatsResponse {
    total_users: usize,
    total_repositories: usize,
    total_active_permissions: usize,
}

async fn get_stats(State(state): State<AppState>, user: AuthUser) -> Result<Json<AdminStatsResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, user.organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let stats = if user.is_super_admin {
        state.get_admin_stats.execute().await.map_err(|e| application_error_response("failed to get admin stats", e))?
    } else {
        let total_users = state.users.list_all().await.map_err(internal_error)?.into_iter().filter(|u| u.organization_id == user.organization_id).count();
        let org_repository_ids = organization_repository_ids(&state, user.organization_id).await.map_err(internal_error)?;
        let total_active_permissions = state.permissions.list_all().await.map_err(internal_error)?.into_iter().filter(|(_, repository_id, _)| org_repository_ids.contains(repository_id)).count();
        hangar_application::use_cases::admin::AdminStats { total_users, total_repositories: org_repository_ids.len(), total_active_permissions }
    };
    Ok(Json(AdminStatsResponse {
        total_users: stats.total_users,
        total_repositories: stats.total_repositories,
        total_active_permissions: stats.total_active_permissions,
    }))
}

#[derive(Serialize)]
struct BlockedUsernameResponse {
    username: String,
    remaining_seconds: u64,
}

async fn list_blocked_usernames(State(state): State<AppState>, user: AuthUser) -> Result<Json<Vec<BlockedUsernameResponse>>, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let blocked = state.login_throttle.blocked_usernames(crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW);
    Ok(Json(blocked.into_iter().map(|b| BlockedUsernameResponse { username: b.username, remaining_seconds: b.remaining_seconds }).collect()))
}

#[derive(Serialize)]
struct AdminApiTokenResponse {
    id: Uuid,
    user_id: Uuid,
    username: String,
    label: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

async fn list_all_api_tokens(State(state): State<AppState>, user: AuthUser) -> Result<Json<Vec<AdminApiTokenResponse>>, (StatusCode, Json<ErrorResponse>)> {
    require_organization_admin(&user, user.organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let tokens = state.admin_list_api_tokens.execute().await.map_err(|e| application_error_response("failed to list api tokens", e))?;
    let tokens = if user.is_super_admin { tokens } else { tokens.into_iter().filter(|t| t.organization_id == Some(user.organization_id)).collect() };
    Ok(Json(
        tokens
            .into_iter()
            .map(|t| AdminApiTokenResponse {
                id: t.id,
                user_id: t.user_id,
                username: t.username,
                label: t.label,
                created_at: t.created_at,
                last_used_at: t.last_used_at,
                revoked_at: t.revoked_at,
            })
            .collect(),
    ))
}

async fn admin_revoke_api_token(State(state): State<AppState>, user: AuthUser, Path(id): Path<Uuid>) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    if !user.is_super_admin {
        require_organization_admin(&user, user.organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
        let tokens = state.admin_list_api_tokens.execute().await.map_err(|e| application_error_response("failed to list api tokens", e))?;
        let owned_by_this_organization = tokens.iter().any(|t| t.id == id && t.organization_id == Some(user.organization_id));
        if !owned_by_this_organization {
            return Err((StatusCode::NOT_FOUND, Json(ErrorResponse { error: "not found".to_string() })));
        }
    }
    state.admin_revoke_api_token.execute(id).await.map_err(|e| application_error_response("failed to revoke api token", e))?;
    Ok(StatusCode::NO_CONTENT)
}

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
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct SmtpSettingsResponse {
    host: String,
    port: i32,
    username: String,
    from_name: String,
    from_address: String,
    security: SmtpSecurity,
    password_set: bool,
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

#[derive(Deserialize)]
struct UpdateSmtpSettingsRequest {
    host: String,
    port: i32,
    username: String,
    /// `None`/omitted keeps the currently stored password.
    password: Option<String>,
    from_name: String,
    from_address: String,
    security: SmtpSecurity,
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

#[derive(Deserialize)]
struct SendTestEmailRequest {
    to: String,
}

async fn send_test_email(State(state): State<AppState>, user: AuthUser, resolved_org: ResolvedOrganization, Json(body): Json<SendTestEmailRequest>) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let organization_id = target_organization_id(&user, &resolved_org);
    require_organization_admin(&user, organization_id).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    state.send_test_email.execute(organization_id, &body.to).await.map_err(|e| application_error_response("failed to send test email", e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, Deserialize)]
struct ExportedUserResponse {
    id: Uuid,
    username: String,
    is_super_admin: bool,
    created_at: DateTime<Utc>,
    email: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct ExportedRepositoryResponse {
    id: Uuid,
    name: String,
    format: RepositoryFormat,
    repo_type: RepositoryType,
    remote_url: Option<String>,
    remote_username: Option<String>,
    remote_password: Option<String>,
    group_members: Vec<Uuid>,
    quota_bytes: Option<i64>,
    retention_keep_last_n: Option<i32>,
}

#[derive(Serialize, Deserialize)]
struct ExportedPermissionResponse {
    user_id: Uuid,
    repository_id: Uuid,
    role: Role,
}

#[derive(Serialize)]
struct ConfigurationExportResponse {
    exported_at: DateTime<Utc>,
    users: Vec<ExportedUserResponse>,
    repositories: Vec<ExportedRepositoryResponse>,
    permissions: Vec<ExportedPermissionResponse>,
    system_settings: SystemSettings,
}

async fn export_configuration(State(state): State<AppState>, user: AuthUser) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let export = state.export_configuration.execute().await.map_err(|e| application_error_response("failed to export configuration", e))?;
    let filename = format!("hangar-config-{}.json", export.exported_at.format("%Y-%m-%d"));
    let response = ConfigurationExportResponse {
        exported_at: export.exported_at,
        users: export
            .users
            .into_iter()
            .map(|u| ExportedUserResponse { id: u.id, username: u.username, is_super_admin: u.is_super_admin, created_at: u.created_at, email: u.email })
            .collect(),
        repositories: export
            .repositories
            .into_iter()
            .map(|r| ExportedRepositoryResponse {
                id: r.id,
                name: r.name,
                format: r.format,
                repo_type: r.repo_type,
                remote_url: r.remote_url,
                remote_username: r.remote_username,
                remote_password: r.remote_password,
                group_members: r.group_members,
                quota_bytes: r.quota_bytes,
                retention_keep_last_n: r.retention_keep_last_n,
            })
            .collect(),
        permissions: export
            .permissions
            .into_iter()
            .map(|p| ExportedPermissionResponse { user_id: p.user_id, repository_id: p.repository_id, role: p.role })
            .collect(),
        system_settings: export.system_settings,
    };
    Ok(([(header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\""))], Json(response)))
}

#[derive(Deserialize)]
struct ConfigurationImportRequest {
    users: Vec<ExportedUserResponse>,
    repositories: Vec<ExportedRepositoryResponse>,
    permissions: Vec<ExportedPermissionResponse>,
    system_settings: SystemSettings,
}

#[derive(Serialize)]
struct ImportReportResponse {
    users_created: usize,
    repositories_created: usize,
    permissions_granted: usize,
    invited: Vec<String>,
    skipped_no_email: Vec<String>,
    failed: Vec<String>,
    proxy_credentials_needed: Vec<String>,
}

async fn import_configuration(State(state): State<AppState>, user: AuthUser, Json(body): Json<ConfigurationImportRequest>) -> Result<Json<ImportReportResponse>, (StatusCode, Json<ErrorResponse>)> {
    require_super_admin(&user).map_err(|status| (status, Json(ErrorResponse { error: "forbidden".to_string() })))?;
    let import = hangar_application::use_cases::admin::ConfigurationImport {
        users: body
            .users
            .into_iter()
            .map(|u| hangar_application::use_cases::admin::ExportedUser { id: u.id, username: u.username, is_super_admin: u.is_super_admin, created_at: u.created_at, email: u.email })
            .collect(),
        repositories: body
            .repositories
            .into_iter()
            .map(|r| hangar_application::use_cases::admin::ExportedRepository {
                id: r.id,
                name: r.name,
                format: r.format,
                repo_type: r.repo_type,
                remote_url: r.remote_url,
                remote_username: r.remote_username,
                remote_password: r.remote_password,
                group_members: r.group_members,
                quota_bytes: r.quota_bytes,
                retention_keep_last_n: r.retention_keep_last_n,
            })
            .collect(),
        permissions: body
            .permissions
            .into_iter()
            .map(|p| hangar_application::use_cases::admin::ExportedPermission { user_id: p.user_id, repository_id: p.repository_id, role: p.role })
            .collect(),
        system_settings: body.system_settings,
    };
    let report = state.import_configuration.execute(import, user.id).await.map_err(|e| application_error_response("failed to import configuration", e))?;
    Ok(Json(ImportReportResponse {
        users_created: report.users_created,
        repositories_created: report.repositories_created,
        permissions_granted: report.permissions_granted,
        invited: report.invited,
        skipped_no_email: report.skipped_no_email,
        failed: report.failed,
        proxy_credentials_needed: report.proxy_credentials_needed,
    }))
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::{build_router, state::AppState};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use chrono::Utc;
    use hangar_domain::package_repository::{RepositoryFormat, RepositoryType};
    use hangar_domain::permission::Role;
    use tower::ServiceExt;
    use uuid::Uuid;

    fn test_config() -> Config {
        Config {
            database_url: String::new(),
            jwt_secret: "test-secret".to_string(),
            secrets_encryption_key: "test-secret".to_string(),
            storage_root: std::env::temp_dir().to_string_lossy().to_string(),
            bind_addr: "0.0.0.0:0".to_string(),
            cors_allowed_origin: None,
            docker_token_realm: "http://localhost/v2/token".to_string(),
            public_url: "http://localhost:4200".to_string(),
            db_max_connections: hangar_infrastructure::postgres::DEFAULT_DB_MAX_CONNECTIONS,
            hangar_base_domain: "hangar.localhost".to_string(),
        }
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_read_the_audit_log(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/audit/events").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_denied_access_shows_up_in_the_audit_log(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id =
            state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "secret-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "outsider", "sup3r-s3cret!", false).await.unwrap();
        let outsider_token = state.authenticate_user.execute("outsider", "sup3r-s3cret!").await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        app.clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}"))
                    .header("authorization", format!("Bearer {outsider_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/audit/events?aggregate_type=Security")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().iter().any(|e| e["event_type"] == "AccessDenied"));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn the_audit_log_can_exclude_security_events(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "audited-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        for _ in 0..5 {
            state
                .record_security_event
                .execute(
                    hangar_domain::audit::SecurityEvent::LoginFailed { username: "flooder".to_string(), ip: "127.0.0.1".to_string() },
                    None,
                )
                .await
                .unwrap();
        }
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let unfiltered = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/audit/events")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(unfiltered.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().iter().any(|e| e["aggregate_type"] == "Security"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/audit/events?exclude_aggregate_type=Security")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = json.as_array().unwrap();
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|e| e["aggregate_type"] != "Security"));
        assert!(entries.iter().any(|e| e["aggregate_type"] == "PackageRepository"));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_sees_their_own_organizations_repository_events(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        state.create_repository.execute(acme_id, "acme-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, org_admin_id).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/audit/events?exclude_aggregate_type=Security")
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = json.as_array().unwrap();
        assert!(entries.iter().any(|e| e["aggregate_type"] == "PackageRepository"), "an organization admin must see audit events for repositories in their own organization");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_does_not_see_another_organizations_repository_events(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let other_creator = state.create_user.execute(other_id, "other-creator", "sup3r-s3cret!", false).await.unwrap();
        state.create_repository.execute(other_id, "other-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, other_creator).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/audit/events?exclude_aggregate_type=Security")
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty(), "an organization admin must not see another organization's audit events");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_sees_a_package_event_for_their_own_repository(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        state.create_repository.execute(acme_id, "acme-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, org_admin_id).await.unwrap();
        // No explicit permission grant — relies on hangar-npm's own org-admin authz bypass.
        let (_, raw_token) = state.create_api_token.execute(org_admin_id, "ci").await.unwrap();
        let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let publish_body = serde_json::json!({
            "versions": { "1.0.0": { "name": "widget", "version": "1.0.0" } },
            "_attachments": { "widget-1.0.0.tgz": { "data": "dGFyYmFsbC1ieXRlcw==" } },
        });
        let publish_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/npm/acme-repo/widget")
                    .header("host", "acme.hangar.localhost")
                    .header("authorization", format!("Bearer {raw_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(publish_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(publish_response.status(), axum::http::StatusCode::CREATED);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/audit/events?aggregate_type=NpmPackage")
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = json.as_array().unwrap();
        assert!(entries.iter().any(|e| e["event_type"] == "PackagePushed"), "an organization admin must see NpmPackage events for their own organization's repository");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_sees_access_denied_events_by_their_own_members(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let repo_id = state.create_repository.execute(acme_id, "secret-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, org_admin_id).await.unwrap();
        // Same org, no grant on this repo — passes require_same_organization, denied by role.
        let acme_member_id = state.create_user.execute(acme_id, "acme-member", "sup3r-s3cret!", false).await.unwrap();
        let member_token = state.authenticate_user.execute("acme-member", "sup3r-s3cret!").await.unwrap();
        let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        app.clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/repositories/{repo_id}"))
                    .header("authorization", format!("Bearer {member_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/audit/events?aggregate_type=Security")
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = json.as_array().unwrap();
        assert!(entries.iter().any(|e| e["event_type"] == "AccessDenied" && e["actor_id"] == acme_member_id.to_string()), "an organization admin must see AccessDenied events triggered by their own members");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_does_not_see_unattributable_login_failures(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        state
            .record_security_event
            .execute(hangar_domain::audit::SecurityEvent::LoginFailed { username: "flooder".to_string(), ip: "127.0.0.1".to_string() }, None)
            .await
            .unwrap();
        let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/audit/events?aggregate_type=Security")
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().is_empty(), "a LoginFailed event has no resolvable organization and must never be shown to an organization admin");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_regular_organization_member_cannot_read_the_audit_log(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        state.create_user.execute(acme_id, "member", "sup3r-s3cret!", false).await.unwrap();
        let member_token = state.authenticate_user.execute("member", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/audit/events").header("authorization", format!("Bearer {member_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn metrics_include_a_created_repository(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "metered-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/metrics").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn metrics_reflect_a_repositorys_quota(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let repo_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "metered-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        state.set_repository_quota.execute(repo_id, Some(2_000_000), admin_id).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/metrics").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json[0]["quota_bytes"], 2_000_000);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_sees_only_their_own_organizations_repository_usage(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        state.create_repository.execute(acme_id, "acme-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, org_admin_id).await.unwrap();
        let other_creator = state.create_user.execute(other_id, "other-creator", "sup3r-s3cret!", false).await.unwrap();
        state.create_repository.execute(other_id, "other-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, other_creator).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/metrics").header("authorization", format!("Bearer {org_admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let usages = json.as_array().unwrap();
        assert_eq!(usages.len(), 1, "an organization admin must only see usage for repositories in their own organization");
        assert_eq!(usages[0]["name"], "acme-repo");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_regular_organization_member_cannot_read_usage_metrics(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        state.create_user.execute(acme_id, "member", "sup3r-s3cret!", false).await.unwrap();
        let member_token = state.authenticate_user.execute("member", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/metrics").header("authorization", format!("Bearer {member_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn metrics_history_reports_a_recorded_snapshot(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "history-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        state.record_metrics_snapshot.execute().await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/admin/metrics/history")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let snapshots = json.as_array().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0]["total_users"], 1);
        assert_eq!(snapshots[0]["total_repositories"], 1);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_cannot_read_metrics_history(pool: sqlx::PgPool) {
        // Unlike /api/admin/metrics and /api/admin/stats, this stays super-admin-only.
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/metrics/history").header("authorization", format!("Bearer {org_admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn health_reports_the_database_as_up(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/health").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["database"]["status"], "up");
        assert_eq!(json["database"]["max_connections"], 10);
        assert!(json["database"]["active_connections"].as_u64().is_some());
        assert!(json["database"]["server_version"].is_string());
        assert!(json["storage"]["total_bytes"].as_u64().unwrap() > 0);
        assert!(json["uptime_seconds"].as_u64().is_some());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn stats_report_users_repositories_and_permissions(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let member_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "member", "sup3r-s3cret!", false).await.unwrap();
        let repo_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "stat-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        state.grant_permission.execute(member_id, repo_id, Role::Write, admin_id).await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/stats").header("authorization", format!("Bearer {admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["total_users"], 2);
        assert_eq!(json["total_repositories"], 1);
        assert_eq!(json["total_active_permissions"], 1);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_sees_stats_scoped_to_their_own_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let acme_member_id = state.create_user.execute(acme_id, "acme-member", "sup3r-s3cret!", false).await.unwrap();
        let acme_repo_id = state.create_repository.execute(acme_id, "acme-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, org_admin_id).await.unwrap();
        state.grant_permission.execute(acme_member_id, acme_repo_id, Role::Write, org_admin_id).await.unwrap();
        // Noise in another organization — must not leak into acme's counts.
        let other_creator = state.create_user.execute(other_id, "other-creator", "sup3r-s3cret!", false).await.unwrap();
        let other_repo_id = state.create_repository.execute(other_id, "other-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, other_creator).await.unwrap();
        let other_member_id = state.create_user.execute(other_id, "other-member", "sup3r-s3cret!", false).await.unwrap();
        state.grant_permission.execute(other_member_id, other_repo_id, Role::Write, other_creator).await.unwrap();
        let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/stats").header("authorization", format!("Bearer {org_admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // org-admin + acme-member, not the other organization's users.
        assert_eq!(json["total_users"], 2);
        assert_eq!(json["total_repositories"], 1);
        assert_eq!(json["total_active_permissions"], 1);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_read_admin_stats(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/stats").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn lists_a_currently_blocked_username(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        for _ in 0..crate::login_throttle::MAX_LOGIN_ATTEMPTS {
            state.login_throttle.record_failure("victim", crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW);
        }
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/admin/security/blocked")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json[0]["username"], "victim");
        assert!(json[0]["remaining_seconds"].as_u64().unwrap() > 0);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn does_not_list_a_username_below_the_threshold(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        state.login_throttle.record_failure("almost", crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW);
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/admin/security/blocked")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_list_blocked_usernames(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/admin/security/blocked")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn admin_lists_tokens_across_every_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let member_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "member", "sup3r-s3cret!", false).await.unwrap();
        state.create_api_token.execute(admin_id, "admin laptop").await.unwrap();
        state.create_api_token.execute(member_id, "member ci").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/tokens").header("authorization", format!("Bearer {admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let tokens: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let usernames: Vec<&str> = tokens.as_array().unwrap().iter().map(|t| t["username"].as_str().unwrap()).collect();
        assert_eq!(usernames.len(), 2);
        assert!(usernames.contains(&"admin"));
        assert!(usernames.contains(&"member"));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_list_all_api_tokens(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/tokens").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn admin_revokes_a_token_owned_by_a_different_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let member_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "member", "sup3r-s3cret!", false).await.unwrap();
        let (token_id, _) = state.create_api_token.execute(member_id, "member laptop").await.unwrap();
        let app = build_router(state);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/admin/tokens/{token_id}"))
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);

        let list_response = app
            .oneshot(Request::builder().uri("/api/admin/tokens").header("authorization", format!("Bearer {admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(list_response.into_body(), usize::MAX).await.unwrap();
        let tokens: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let revoked = tokens.as_array().unwrap().iter().find(|t| t["id"] == token_id.to_string()).unwrap();
        assert!(!revoked["revoked_at"].is_null());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_revoke_another_users_token(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let owner_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "owner", "sup3r-s3cret!", false).await.unwrap();
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let regular_token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let (token_id, _) = state.create_api_token.execute(owner_id, "owner laptop").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/admin/tokens/{token_id}"))
                    .header("authorization", format!("Bearer {regular_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_lists_only_their_own_organizations_tokens(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let acme_member_id = state.create_user.execute(acme_id, "acme-member", "sup3r-s3cret!", false).await.unwrap();
        let other_member_id = state.create_user.execute(other_id, "other-member", "sup3r-s3cret!", false).await.unwrap();
        state.create_api_token.execute(acme_member_id, "acme laptop").await.unwrap();
        state.create_api_token.execute(other_member_id, "other laptop").await.unwrap();
        let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/tokens").header("authorization", format!("Bearer {org_admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let tokens: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let tokens = tokens.as_array().unwrap();
        assert_eq!(tokens.len(), 1, "an organization admin must only see tokens belonging to users in their own organization");
        assert_eq!(tokens[0]["username"], "acme-member");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_can_revoke_a_token_in_their_own_organization(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let acme_member_id = state.create_user.execute(acme_id, "acme-member", "sup3r-s3cret!", false).await.unwrap();
        let (token_id, _) = state.create_api_token.execute(acme_member_id, "acme laptop").await.unwrap();
        let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/admin/tokens/{token_id}"))
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_organization_admin_cannot_revoke_another_organizations_token(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        let org_admin_id = state.create_user.execute(acme_id, "org-admin", "sup3r-s3cret!", false).await.unwrap();
        state.users.set_organization_admin(org_admin_id, true).await.unwrap();
        let other_member_id = state.create_user.execute(other_id, "other-member", "sup3r-s3cret!", false).await.unwrap();
        let (token_id, _) = state.create_api_token.execute(other_member_id, "other laptop").await.unwrap();
        let org_admin_token = state.authenticate_user.execute("org-admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/admin/tokens/{token_id}"))
                    .header("authorization", format!("Bearer {org_admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND, "must not leak whether the token exists in another organization");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_regular_organization_member_cannot_list_or_revoke_tokens(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let member_id = state.create_user.execute(acme_id, "member", "sup3r-s3cret!", false).await.unwrap();
        let (token_id, _) = state.create_api_token.execute(member_id, "member laptop").await.unwrap();
        let member_token = state.authenticate_user.execute("member", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let list_response = app
            .clone()
            .oneshot(Request::builder().uri("/api/admin/tokens").header("authorization", format!("Bearer {member_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(list_response.status(), axum::http::StatusCode::FORBIDDEN);

        let revoke_response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/admin/tokens/{token_id}"))
                    .header("authorization", format!("Bearer {member_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke_response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn admin_reads_the_default_system_settings_on_a_fresh_instance(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/settings").header("authorization", format!("Bearer {admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let settings: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(settings["max_login_attempts"], 10);
        assert_eq!(settings["login_attempt_window_seconds"], 300);
        assert_eq!(settings["session_ttl_hours"], 12);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_read_system_settings(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/settings").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn admin_updates_system_settings_and_it_takes_effect_immediately(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/settings")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"max_login_attempts":2,"login_attempt_window_seconds":60,"session_ttl_hours":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        let persisted = state.get_system_settings.execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap();
        assert_eq!(persisted.max_login_attempts, 2);

        // "admin" belongs to the public organization, so a login attempt against it is
        // throttled at the just-updated 2-attempt limit — resolved live from settings on
        // every call, not pushed into the throttle ahead of time.
        let login_request = || {
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({ "username": "admin", "password": "wrong" }).to_string()))
                .unwrap()
        };
        app.clone().oneshot(login_request()).await.unwrap();
        app.clone().oneshot(login_request()).await.unwrap();
        let throttled = app.oneshot(login_request()).await.unwrap();
        assert_eq!(throttled.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn updating_system_settings_with_an_out_of_range_value_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/settings")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"max_login_attempts":0,"login_attempt_window_seconds":60,"session_ttl_hours":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_update_system_settings(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/settings")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"max_login_attempts":2,"login_attempt_window_seconds":60,"session_ttl_hours":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn admin_reads_none_for_smtp_settings_on_a_fresh_instance(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/settings/smtp").header("authorization", format!("Bearer {admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let settings: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(settings.is_null());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_read_smtp_settings(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/admin/settings/smtp").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn admin_configures_smtp_settings_and_the_password_is_never_echoed_back(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/settings/smtp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(
                        r#"{"host":"smtp.example.com","port":587,"username":"hangar@example.com","password":"s3cret","from_name":"Hangar","from_address":"hangar@example.com","security":"start_tls"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);

        let response = build_router(state.clone())
            .oneshot(Request::builder().uri("/api/admin/settings/smtp").header("authorization", format!("Bearer {admin_token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let settings: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(settings["host"], "smtp.example.com");
        assert_eq!(settings["from_name"], "Hangar");
        assert_eq!(settings["password_set"], true);
        assert!(settings.get("password").is_none(), "the password must never be echoed back over HTTP");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn configuring_smtp_for_the_first_time_without_a_password_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/settings/smtp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"host":"smtp.example.com","port":587,"username":"hangar@example.com","from_name":"Hangar","from_address":"hangar@example.com","security":"start_tls"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_update_smtp_settings(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/admin/settings/smtp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"host":"smtp.example.com","port":587,"username":"hangar@example.com","password":"s3cret","from_name":"Hangar","from_address":"hangar@example.com","security":"start_tls"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn sending_a_test_email_without_smtp_configured_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/settings/smtp/test")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"to":"someone@example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_send_a_test_email(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/settings/smtp/test")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"to":"someone@example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

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

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn admin_exports_the_full_configuration(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let member_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "member", "sup3r-s3cret!", false).await.unwrap();
        let repo_id = state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "exported-repo", RepositoryFormat::Npm, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        state.grant_permission.execute(member_id, repo_id, Role::Write, admin_id).await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/admin/export/configuration")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let content_disposition = response.headers().get(axum::http::header::CONTENT_DISPOSITION).unwrap().to_str().unwrap().to_string();
        assert!(content_disposition.starts_with("attachment; filename=\"hangar-config-"), "got {content_disposition}");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let usernames: Vec<&str> = json["users"].as_array().unwrap().iter().map(|u| u["username"].as_str().unwrap()).collect();
        assert!(usernames.contains(&"admin"));
        assert!(usernames.contains(&"member"));
        assert!(json["users"][0].get("password_hash").is_none());
        assert!(json["users"][0].get("email").is_some()); // present (even if null), not entirely absent

        let repo_names: Vec<&str> = json["repositories"].as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
        assert!(repo_names.contains(&"exported-repo"));

        assert_eq!(json["permissions"].as_array().unwrap().len(), 1);
        assert_eq!(json["permissions"][0]["role"], "write");

        assert_eq!(json["system_settings"]["max_login_attempts"], 10);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_export_the_configuration(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/admin/export/configuration")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn admin_imports_a_configuration_on_an_empty_instance(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let _admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let admin_token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let body = serde_json::json!({
            "users": [{ "id": Uuid::new_v4(), "username": "restored", "is_super_admin": false, "created_at": Utc::now(), "email": null }],
            "repositories": [{ "id": Uuid::new_v4(), "name": "restored-repo", "format": "npm", "repo_type": "hosted", "remote_url": null, "group_members": [], "quota_bytes": null, "retention_keep_last_n": null }],
            "permissions": [],
            "system_settings": { "max_login_attempts": 10, "login_attempt_window_seconds": 300, "session_ttl_hours": 12 }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/import/configuration")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["users_created"], 1);
        assert_eq!(json["repositories_created"], 1);
        assert!(json["failed"].as_array().unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_non_admin_cannot_import_a_configuration(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "regular", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("regular", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/import/configuration")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"users":[],"repositories":[],"permissions":[],"system_settings":{"max_login_attempts":10,"login_attempt_window_seconds":300,"session_ttl_hours":12}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn importing_onto_a_non_empty_instance_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let admin_token = {
            state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
            state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap()
        };
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "second", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/import/configuration")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {admin_token}"))
                    .body(Body::from(r#"{"users":[],"repositories":[],"permissions":[],"system_settings":{"max_login_attempts":10,"login_attempt_window_seconds":300,"session_ttl_hours":12}}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn importing_malformed_json_returns_bad_request(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("admin", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/import/configuration")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from("not json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}

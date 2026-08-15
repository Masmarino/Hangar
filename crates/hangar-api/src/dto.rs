use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use hangar_application::error::ApplicationError;
use hangar_domain::error::DomainError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LdapLoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SsoProviderType {
    Ldap,
    Oidc,
}

#[derive(Debug, Serialize)]
pub struct SsoConfigResponse {
    /// `None` means this organization uses local accounts — the frontend's login page falls back to `/api/auth/login`.
    #[serde(rename = "type")]
    pub provider_type: Option<SsoProviderType>,
    /// Whether the login page should offer "Créer un compte" — true only when this org is public *and* the super-admin hasn't turned registration off.
    pub registration_enabled: bool,
}

/// Exactly one of `token`/`mfa_token` is set. `mfa_token` is exchanged for a real `token` at `/api/auth/mfa/verify` or `/api/auth/mfa/setup/*`.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: Option<String>,
    pub mfa_token: Option<String>,
    #[serde(default)]
    pub mfa_setup_required: bool,
    /// Which second factor(s) the account actually has enrolled — lets the login page's verify step show only the relevant option, not a meaningless default TOTP field.
    #[serde(default)]
    pub mfa_has_totp: bool,
    #[serde(default)]
    pub mfa_has_passkey: bool,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub id: Uuid,
    pub username: String,
    pub is_super_admin: bool,
    pub is_organization_admin: bool,
    pub organization_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct ActivateAccountRequest {
    pub token: String,
    pub new_password: String,
}

/// Exactly one of `code`/`backup_code` should be set; `code` is tried first if both are present.
#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub mfa_token: String,
    pub code: Option<String>,
    pub backup_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Infrastructure-shaped errors are logged server-side and answered with a flat `500`, never echoing raw backend text to the client.
pub fn application_error_response(context: &str, error: ApplicationError) -> (StatusCode, Json<ErrorResponse>) {
    match error {
        ApplicationError::EventStore(_) | ApplicationError::Storage(_) | ApplicationError::Domain(DomainError::Infrastructure(_)) => {
            tracing::error!("{context}: {error}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() }))
        }
        ApplicationError::LastSuperAdmin => (StatusCode::CONFLICT, Json(ErrorResponse { error: error.to_string() })),
        // A server misconfiguration, not the caller's fault.
        ApplicationError::PasskeysUnavailable => (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorResponse { error: error.to_string() })),
        // Same "don't confirm existence across a trust boundary" convention as authz::require_same_organization's 404 — here the boundary is per-user, not per-organization.
        ApplicationError::ApiTokenNotFound => (StatusCode::NOT_FOUND, Json(ErrorResponse { error: error.to_string() })),
        error => (StatusCode::BAD_REQUEST, Json(ErrorResponse { error: error.to_string() })),
    }
}

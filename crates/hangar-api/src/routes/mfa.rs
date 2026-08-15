use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use hangar_application::error::ApplicationError;
use serde::{Deserialize, Serialize};

use crate::auth_middleware::AuthUser;
use crate::dto::{application_error_response, ErrorResponse};
use crate::state::AppState;
use axum::extract::State;

fn throttled_response() -> (StatusCode, Json<ErrorResponse>) {
    (StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse { error: "too many failed attempts, try again later".to_string() }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/me/mfa", get(get_mfa_status))
        .route("/api/me/mfa/totp/enroll", axum::routing::post(enroll_totp))
        .route("/api/me/mfa/totp/confirm", axum::routing::post(confirm_totp))
        .route("/api/me/mfa/totp", axum::routing::delete(disable_totp))
        .route("/api/me/mfa/backup-codes/regenerate", axum::routing::post(regenerate_backup_codes))
        .route("/api/me/mfa/passkey", get(list_passkeys))
        .route("/api/me/mfa/passkey/register/start", axum::routing::post(start_passkey_registration))
        .route("/api/me/mfa/passkey/register/finish", axum::routing::post(finish_passkey_registration))
        .route("/api/me/mfa/passkey/:id", axum::routing::delete(delete_passkey))
}

#[derive(Serialize)]
struct MfaStatusResponse {
    totp_enabled: bool,
    backup_codes_remaining: i64,
    passkey_count: i64,
}

async fn get_mfa_status(State(state): State<AppState>, user: AuthUser) -> Result<Json<MfaStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let status = state.get_mfa_status.execute(user.id).await.map_err(|e| application_error_response("failed to get MFA status", e))?;
    Ok(Json(MfaStatusResponse { totp_enabled: status.totp_enabled, backup_codes_remaining: status.backup_codes_remaining, passkey_count: status.passkey_count }))
}

#[derive(Serialize)]
struct TotpEnrollmentResponse {
    secret: String,
    otpauth_url: String,
}

async fn enroll_totp(State(state): State<AppState>, user: AuthUser) -> Result<Json<TotpEnrollmentResponse>, (StatusCode, Json<ErrorResponse>)> {
    let enrollment = state.enroll_totp.execute(user.id, &user.username).await.map_err(|e| application_error_response("failed to enroll TOTP", e))?;
    Ok(Json(TotpEnrollmentResponse { secret: enrollment.secret_base32, otpauth_url: enrollment.otpauth_url }))
}

#[derive(Deserialize)]
struct ConfirmTotpRequest {
    code: String,
}

#[derive(Serialize)]
struct BackupCodesResponse {
    backup_codes: Vec<String>,
}

async fn confirm_totp(State(state): State<AppState>, user: AuthUser, Json(body): Json<ConfirmTotpRequest>) -> Result<Json<BackupCodesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let codes = state.confirm_totp.execute(user.id, &user.username, &body.code).await.map_err(|e| application_error_response("failed to confirm TOTP", e))?;
    Ok(Json(BackupCodesResponse { backup_codes: codes }))
}

#[derive(Deserialize)]
struct CurrentPasswordRequest {
    current_password: String,
}

/// Distinct from `/api/auth/login` and `/api/me/password`'s bare-username key, so a stolen bearer token can't lock the real user out of login.
fn manage_throttle_key(user_id: uuid::Uuid) -> String {
    format!("mfa-manage:{user_id}")
}

async fn disable_totp(State(state): State<AppState>, user: AuthUser, Json(body): Json<CurrentPasswordRequest>) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let (max_attempts, window) = crate::routes::auth::throttle_limits_for_organization(&state, user.organization_id).await;
    let throttle_key = manage_throttle_key(user.id);
    if state.login_throttle.is_throttled(&throttle_key, max_attempts, window) {
        return Err(throttled_response());
    }
    match state.disable_totp.execute(user.id, &body.current_password).await {
        Ok(()) => {
            state.login_throttle.clear(&throttle_key);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            if matches!(e, ApplicationError::InvalidCredentials) {
                state.login_throttle.record_failure(&throttle_key, max_attempts, window);
            }
            Err(application_error_response("failed to disable TOTP", e))
        }
    }
}

async fn regenerate_backup_codes(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<CurrentPasswordRequest>,
) -> Result<Json<BackupCodesResponse>, (StatusCode, Json<ErrorResponse>)> {
    let (max_attempts, window) = crate::routes::auth::throttle_limits_for_organization(&state, user.organization_id).await;
    let throttle_key = manage_throttle_key(user.id);
    if state.login_throttle.is_throttled(&throttle_key, max_attempts, window) {
        return Err(throttled_response());
    }
    match state.regenerate_backup_codes.execute(user.id, &body.current_password).await {
        Ok(codes) => {
            state.login_throttle.clear(&throttle_key);
            Ok(Json(BackupCodesResponse { backup_codes: codes }))
        }
        Err(e) => {
            if matches!(e, ApplicationError::InvalidCredentials) {
                state.login_throttle.record_failure(&throttle_key, max_attempts, window);
            }
            Err(application_error_response("failed to regenerate backup codes", e))
        }
    }
}

#[derive(Serialize)]
struct PasskeySummaryResponse {
    id: uuid::Uuid,
    name: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn list_passkeys(State(state): State<AppState>, user: AuthUser) -> Result<Json<Vec<PasskeySummaryResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let passkeys = state.list_passkeys.execute(user.id).await.map_err(|e| application_error_response("failed to list passkeys", e))?;
    Ok(Json(passkeys.into_iter().map(|p| PasskeySummaryResponse { id: p.id, name: p.name, created_at: p.created_at }).collect()))
}

#[derive(Serialize)]
struct PasskeyRegistrationStartResponse {
    challenge_id: uuid::Uuid,
    public_key: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
}

/// Unwraps `CreationChallengeResponse` down to its inner `public_key` field — it already serializes to `{"publicKey": {...}}`, which would otherwise double-nest here.
async fn start_passkey_registration(State(state): State<AppState>, user: AuthUser) -> Result<Json<PasskeyRegistrationStartResponse>, (StatusCode, Json<ErrorResponse>)> {
    let (challenge_id, public_key) = state.start_passkey_registration.execute(user.id, &user.username).await.map_err(|e| application_error_response("failed to start passkey registration", e))?;
    Ok(Json(PasskeyRegistrationStartResponse { challenge_id, public_key: public_key.public_key }))
}

#[derive(Deserialize)]
struct PasskeyRegistrationFinishRequest {
    challenge_id: uuid::Uuid,
    credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
    name: String,
}

async fn finish_passkey_registration(
    State(state): State<AppState>,
    user: AuthUser,
    Json(body): Json<PasskeyRegistrationFinishRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    state
        .finish_passkey_registration
        .execute(user.id, body.challenge_id, &body.credential, &body.name)
        .await
        .map_err(|e| application_error_response("failed to finish passkey registration", e))?;
    Ok(StatusCode::CREATED)
}

async fn delete_passkey(
    State(state): State<AppState>,
    user: AuthUser,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
    Json(body): Json<CurrentPasswordRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let (max_attempts, window) = crate::routes::auth::throttle_limits_for_organization(&state, user.organization_id).await;
    let throttle_key = manage_throttle_key(user.id);
    if state.login_throttle.is_throttled(&throttle_key, max_attempts, window) {
        return Err(throttled_response());
    }
    match state.delete_passkey.execute(user.id, id, &body.current_password).await {
        Ok(()) => {
            state.login_throttle.clear(&throttle_key);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            if matches!(e, ApplicationError::InvalidCredentials) {
                state.login_throttle.record_failure(&throttle_key, max_attempts, window);
            }
            Err(application_error_response("failed to delete passkey", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::{build_router, state::AppState};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use hangar_application::use_cases::mfa::generate_current_totp_code;
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

    /// An IP-literal `HANGAR_BASE_DOMAIN` is not a valid WebAuthn relying-party id — the
    /// webauthn client (built from `hangar_base_domain`, not `public_url`) fails to construct.
    fn ip_literal_base_domain_config() -> Config {
        Config { hangar_base_domain: "0.0.0.0".to_string(), ..test_config() }
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn passkey_registration_returns_503_when_base_domain_is_not_a_valid_domain(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &ip_literal_base_domain_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().method("POST").uri("/api/me/mfa/passkey/register/start").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn mfa_status_starts_disabled(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/me/mfa").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totp_enabled"], false);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn get_mfa_status_requires_authentication(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/me/mfa").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn enrolling_returns_a_secret_and_an_otpauth_url(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().method("POST").uri("/api/me/mfa/totp/enroll").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(!json["secret"].as_str().unwrap().is_empty());
        assert!(json["otpauth_url"].as_str().unwrap().starts_with("otpauth://totp/"));
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn confirming_with_a_valid_code_returns_ten_backup_codes_and_flips_status_to_enabled(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        let enroll_response = app
            .clone()
            .oneshot(Request::builder().method("POST").uri("/api/me/mfa/totp/enroll").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(enroll_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let secret = json["secret"].as_str().unwrap();
        let code = generate_current_totp_code(secret);

        let confirm_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/me/mfa/totp/confirm")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(format!(r#"{{"code":"{code}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(confirm_response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(confirm_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["backup_codes"].as_array().unwrap().len(), 10);

        let status_response = app
            .oneshot(Request::builder().uri("/api/me/mfa").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(status_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["totp_enabled"], true);
        assert_eq!(json["backup_codes_remaining"], 10);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn confirming_with_a_wrong_code_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);
        app.clone()
            .oneshot(Request::builder().method("POST").uri("/api/me/mfa/totp/enroll").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/me/mfa/totp/confirm")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"code":"000000"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    async fn enroll_and_confirm(app: axum::Router, token: &str) {
        let enroll_response = Request::builder().method("POST").uri("/api/me/mfa/totp/enroll").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap();
        let response = app.clone().oneshot(enroll_response).await.unwrap();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let code = generate_current_totp_code(json["secret"].as_str().unwrap());

        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/me/mfa/totp/confirm")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(format!(r#"{{"code":"{code}"}}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn disabling_totp_requires_the_current_password(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state.clone());
        enroll_and_confirm(app.clone(), &token).await;

        let wrong_password_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/me/mfa/totp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"current_password":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_password_response.status(), axum::http::StatusCode::BAD_REQUEST);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/me/mfa/totp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"current_password":"sup3r-s3cret!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);

        assert_eq!(state.get_mfa_status.execute(state.users.find_by_username(&hangar_domain::user::Username::parse("florian").unwrap()).await.unwrap().unwrap().id).await.unwrap().totp_enabled, false);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn hitting_the_failure_threshold_on_disable_totp_rejects_even_the_correct_password(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state.clone());
        enroll_and_confirm(app.clone(), &token).await;

        let disable_request = || {
            Request::builder()
                .method("DELETE")
                .uri("/api/me/mfa/totp")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(r#"{"current_password":"wrong"}"#))
                .unwrap()
        };
        for _ in 0..crate::login_throttle::MAX_LOGIN_ATTEMPTS {
            let response = app.clone().oneshot(disable_request()).await.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/me/mfa/totp")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"current_password":"sup3r-s3cret!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS, "an attacker with a stolen session must not be able to brute-force the real password without limit");

        let login_response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"florian","password":"sup3r-s3cret!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            login_response.status(),
            axum::http::StatusCode::OK,
            "hitting the disable-TOTP throttle must not lock the real user out of login — they share no throttle key"
        );
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn regenerating_backup_codes_returns_a_fresh_set(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);
        enroll_and_confirm(app.clone(), &token).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/me/mfa/backup-codes/regenerate")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"current_password":"sup3r-s3cret!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["backup_codes"].as_array().unwrap().len(), 10);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn passkey_list_starts_empty(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/me/mfa/passkey").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn list_passkeys_requires_authentication(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/me/mfa/passkey").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn starting_passkey_registration_returns_a_challenge(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().method("POST").uri("/api/me/mfa/passkey/register/start").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["challenge_id"].is_string());
        assert_eq!(json["public_key"]["user"]["name"], "florian");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn finishing_passkey_registration_with_an_unknown_challenge_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/me/mfa/passkey/register/finish")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(format!(
                        r#"{{"challenge_id":"{}","name":"My key","credential":{{"id":"AAAA","rawId":"AAAA","response":{{"attestationObject":"","clientDataJSON":""}},"type":"public-key"}}}}"#,
                        uuid::Uuid::new_v4()
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn deleting_a_passkey_requires_the_current_password(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/me/mfa/passkey/{}", uuid::Uuid::new_v4()))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(r#"{"current_password":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}

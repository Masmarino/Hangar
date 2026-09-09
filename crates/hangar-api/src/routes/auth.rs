use std::net::SocketAddr;

use axum::extract::rejection::ExtensionRejection;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use hangar_application::error::ApplicationError;
use hangar_domain::audit::SecurityEvent;
use serde::{Deserialize, Serialize};

use hangar_domain::user::TokenIssuerPort;

use crate::auth_middleware::AuthUser;
use crate::dto::{
    application_error_response, ActivateAccountRequest, ChangePasswordRequest, ErrorResponse, LdapLoginRequest, LoginRequest, LoginResponse, MeResponse, MfaVerifyRequest, RegisterRequest,
    SsoConfigResponse, SsoProviderType,
};
use crate::organization_middleware::ResolvedOrganization;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/register", post(register))
        .route("/api/auth/sso/ldap", post(sso_ldap_login))
        .route("/api/auth/sso/config", get(sso_config))
        .route("/api/auth/sso/oidc/login", get(sso_oidc_login))
        .route("/api/auth/sso/oidc/callback", get(sso_oidc_callback))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/activate", post(activate_account))
        .route("/api/auth/mfa/verify", post(verify_mfa))
        .route("/api/auth/mfa/passkey/start", post(start_mfa_passkey))
        .route("/api/auth/mfa/passkey/finish", post(finish_mfa_passkey))
        .route("/api/auth/mfa/setup/totp/enroll", post(setup_mfa_totp_enroll))
        .route("/api/auth/mfa/setup/totp/confirm", post(setup_mfa_totp_confirm))
        .route("/api/auth/mfa/setup/passkey/start", post(setup_mfa_passkey_start))
        .route("/api/auth/mfa/setup/passkey/finish", post(setup_mfa_passkey_finish))
        .route("/api/me", get(me))
        .route("/api/me/password", axum::routing::put(change_password))
}

/// "unknown" if connect info wasn't attached; behind a reverse proxy this is the proxy's IP, not the client's.
///
/// `Result`, not `Option` — axum 0.8 only extracts `Option<T>` for extractors that opt into
/// `OptionalFromRequestParts`, which `ConnectInfo` doesn't; `Result<T, T::Rejection>` still has the blanket impl.
fn peer_ip(connect_info: Result<ConnectInfo<SocketAddr>, ExtensionRejection>) -> String {
    connect_info.map_or_else(|_| "unknown".to_string(), |ConnectInfo(addr)| addr.ip().to_string())
}

/// Exposed separately, not just OR'd together, so the login page's verify step can show only the factor(s) that actually exist.
struct MfaFactors {
    has_totp: bool,
    has_passkey: bool,
}

impl MfaFactors {
    fn any(&self) -> bool {
        self.has_totp || self.has_passkey
    }
}

async fn mfa_factors(state: &AppState, user_id: uuid::Uuid) -> MfaFactors {
    let has_totp = state.totp_credentials.get(user_id).await.map(|c| c.is_some_and(|c| c.confirmed)).unwrap_or(false);
    let has_passkey = state.webauthn_credentials.count_for_user(user_id).await.map(|n| n > 0).unwrap_or(false);
    MfaFactors { has_totp, has_passkey }
}

/// A nonexistent username has no organization to resolve limits from, so it falls back to the
/// hard-coded defaults. Not attacker-observable: an unknown username is throttled identically either way.
async fn throttle_limits_for_username(state: &AppState, username: &str) -> (usize, std::time::Duration) {
    let Ok(username) = hangar_domain::user::Username::parse(username) else {
        return (crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW);
    };
    match state.users.find_by_username(&username).await {
        Ok(Some(user)) => throttle_limits_for_organization(state, user.organization_id).await,
        Ok(None) => (crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW),
        Err(e) => {
            tracing::warn!("failed to look up user by username for login throttle limits, falling back to global defaults: {e}");
            (crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW)
        }
    }
}

pub(crate) async fn throttle_limits_for_organization(state: &AppState, organization_id: uuid::Uuid) -> (usize, std::time::Duration) {
    match state.get_system_settings.execute(organization_id).await {
        Ok(settings) => (settings.max_login_attempts as usize, std::time::Duration::from_secs(settings.login_attempt_window_seconds as u64)),
        Err(e) => {
            tracing::warn!("failed to load system settings for login throttle limits, falling back to global defaults: {e}");
            (crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW)
        }
    }
}

pub(crate) async fn throttle_limits_for_user_id(state: &AppState, user_id: uuid::Uuid) -> (usize, std::time::Duration) {
    match state.users.find_by_id(user_id).await {
        Ok(Some(user)) => throttle_limits_for_organization(state, user.organization_id).await,
        Ok(None) => (crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW),
        Err(e) => {
            tracing::warn!("failed to look up user by id for login throttle limits, falling back to global defaults: {e}");
            (crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW)
        }
    }
}

async fn login(
    State(state): State<AppState>,
    connect_info: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
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
            let user_id = state.token_issuer.verify(&token).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?.user_id;
            // mfa_setup_required tells the client whether to go to /mfa/setup/* or /mfa/verify.
            let factors = mfa_factors(&state, user_id).await;
            // `JwtMfaPendingTokenIssuer` ignores this ttl and always uses its own fixed, short lifetime.
            let mfa_token = state
                .mfa_pending_token_issuer
                .issue(user_id, chrono::Duration::minutes(5))
                .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
            Ok(Json(LoginResponse {
                token: None,
                mfa_token: Some(mfa_token),
                mfa_setup_required: !factors.any(),
                mfa_has_totp: factors.has_totp,
                mfa_has_passkey: factors.has_passkey,
            }))
        }
        Err(_) => {
            state.login_throttle.record_failure(&body.username, max_attempts, window);
            let _ = state
                .record_security_event
                .execute(SecurityEvent::LoginFailed { username: body.username.clone(), ip: peer_ip(connect_info) }, None)
                .await;
            Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid credentials".to_string() })))
        }
    }
}

/// Unauthenticated — this is how an account is first created. Only for the `public` organization; others provision via admin invitation instead.
async fn register(
    State(state): State<AppState>,
    resolved_org: ResolvedOrganization,
    connect_info: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Counts every attempt, not just failures like `login` — a registration flood costs server work regardless of outcome.
    let throttle_key = format!("register:{}", peer_ip(connect_info));
    if state.login_throttle.is_throttled(&throttle_key, crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: "too many registration attempts, try again later".to_string() }),
        ));
    }
    state.login_throttle.record_failure(&throttle_key, crate::login_throttle::MAX_LOGIN_ATTEMPTS, crate::login_throttle::LOGIN_ATTEMPT_WINDOW);

    if !resolved_org.0.is_public {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "public self-registration is not available on this organization".to_string() })));
    }

    let settings = state
        .get_system_settings
        .execute(resolved_org.0.id)
        .await
        .map_err(|e| application_error_response("failed to check system settings", e))?;
    if !settings.registration_enabled {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "public self-registration is currently disabled".to_string() })));
    }

    let user_id = state
        .register_public_user
        .execute(resolved_org.0.id, &body.username, &body.email, &body.password)
        .await
        .map_err(|e| application_error_response("failed to register user", e))?;

    let mfa_token = state
        .mfa_pending_token_issuer
        .issue(user_id, chrono::Duration::minutes(5))
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    Ok(Json(LoginResponse { token: None, mfa_token: Some(mfa_token), mfa_setup_required: true, mfa_has_totp: false, mfa_has_passkey: false }))
}

/// Unauthenticated — the login page checks this before submitting, to know whether to post to `/api/auth/sso` or `/api/auth/login`. Reveals only the provider type.
async fn sso_config(State(state): State<AppState>, resolved_org: ResolvedOrganization) -> Result<Json<SsoConfigResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state
        .identity_providers
        .get(resolved_org.0.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    let provider_type = config.map(|c| match c {
        hangar_domain::sso::IdentityProviderConfig::Ldap(_) => SsoProviderType::Ldap,
        hangar_domain::sso::IdentityProviderConfig::Oidc(_) => SsoProviderType::Oidc,
    });
    let settings = state
        .get_system_settings
        .execute(resolved_org.0.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    Ok(Json(SsoConfigResponse { provider_type, registration_enabled: resolved_org.0.is_public && settings.registration_enabled }))
}

/// Matches `localhost`, `*.localhost`, and `localhost:<port>` — including this repo's `hangar.localhost` dev domain — but not lookalikes like `localhost.evil.com`.
fn is_local_dev_domain(domain: &str) -> bool {
    domain == "localhost" || domain.ends_with(".localhost") || domain.starts_with("localhost:")
}

/// This organization's own origin — never derived from a caller-supplied header, so a non-public org never gets sent back to the wrong one.
fn organization_origin(state: &AppState, resolved_org: &ResolvedOrganization) -> String {
    let host = if resolved_org.0.is_public { state.hangar_base_domain.clone() } else { format!("{}.{}", resolved_org.0.slug.as_str(), state.hangar_base_domain) };
    format!("{}://{}", if is_local_dev_domain(&state.hangar_base_domain) { "http" } else { "https" }, host)
}

/// Must match the `redirect_uri`/`callback_url` registered with the identity provider exactly.
fn oidc_callback_url(state: &AppState, resolved_org: &ResolvedOrganization) -> String {
    format!("{}/api/auth/sso/oidc/callback", organization_origin(state, resolved_org))
}

/// Unprefixed name, for plain-HTTP local dev only — `__Host-` cookies require `Secure`, which browsers drop over `http://`.
const OIDC_BINDING_COOKIE: &str = "hangar_oidc_binding";
/// `__Host-` prefixed everywhere else — a browser-enforced guarantee this cookie can't be shadowed by a sibling subdomain.
const OIDC_BINDING_COOKIE_HOST_PREFIXED: &str = "__Host-hangar_oidc_binding";
/// Matches `STATE_TOKEN_TTL_MINUTES` in `OpenidConnectAuthAdapter` — no point outliving the token it's bound to.
const OIDC_BINDING_COOKIE_MAX_AGE_SECONDS: i64 = 10 * 60;

fn oidc_binding_cookie_name(state: &AppState) -> &'static str {
    if is_local_dev_domain(&state.hangar_base_domain) { OIDC_BINDING_COOKIE } else { OIDC_BINDING_COOKIE_HOST_PREFIXED }
}

// Parses a raw Set-Cookie string rather than using Cookie::build, which needs a time::Duration
// for Max-Age that axum-extra doesn't re-export. SameSite=Lax, not Strict: the browser still
// needs to send this on the cross-site redirect the identity provider sends it through.
fn oidc_binding_cookie(state: &AppState, value: &str) -> Option<axum_extra::extract::cookie::Cookie<'static>> {
    let name = oidc_binding_cookie_name(state);
    let secure = if is_local_dev_domain(&state.hangar_base_domain) { "" } else { "; Secure" };
    axum_extra::extract::cookie::Cookie::parse(format!("{name}={value}; Path=/; Max-Age={OIDC_BINDING_COOKIE_MAX_AGE_SECONDS}; HttpOnly; SameSite=Lax{secure}")).ok()
}

/// Unauthenticated — redirects the browser to the identity provider to start the OIDC flow, 400 if none is configured. Also sets `hangar_oidc_binding`, a login-CSRF binding secret (RFC 6749 §10.12) tying the callback to this same browser.
async fn sso_oidc_login(
    State(state): State<AppState>,
    resolved_org: ResolvedOrganization,
    jar: axum_extra::extract::cookie::CookieJar,
) -> Result<(axum_extra::extract::cookie::CookieJar, axum::response::Redirect), (StatusCode, Json<ErrorResponse>)> {
    let config = state
        .identity_providers
        .get(resolved_org.0.id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
    let Some(hangar_domain::sso::IdentityProviderConfig::Oidc(oidc_config)) = config else {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "this organization has no OIDC identity provider configured".to_string() })));
    };

    let binding_secret = uuid::Uuid::new_v4().to_string();
    let cookie = oidc_binding_cookie(&state, &binding_secret)
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "failed to start oidc login".to_string() })))?;

    let callback_url = oidc_callback_url(&state, &resolved_org);
    let redirect_url = state
        .oidc_auth
        .build_redirect(&oidc_config, resolved_org.0.id, &callback_url, &binding_secret)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "failed to start oidc login".to_string() })))?;
    Ok((jar.add(cookie), axum::response::Redirect::to(&redirect_url)))
}

#[derive(Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

/// Unauthenticated — the identity provider redirects here after the user authenticates. On success, sends the session token back in the URL fragment (`#token=...`), never a query param, since fragments never reach the server or its access logs.
async fn sso_oidc_callback(
    State(state): State<AppState>,
    resolved_org: ResolvedOrganization,
    jar: axum_extra::extract::cookie::CookieJar,
    axum::extract::Query(query): axum::extract::Query<OidcCallbackQuery>,
) -> Result<(axum_extra::extract::cookie::CookieJar, axum::response::Redirect), (StatusCode, Json<ErrorResponse>)> {
    let (Some(code), Some(raw_state)) = (query.code, query.state) else {
        return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: "missing code or state".to_string() })));
    };

    // Same generic 401 as a bad state/code — a missing cookie shouldn't be distinguishable from a wrong one.
    let Some(binding_secret) = jar.get(oidc_binding_cookie_name(&state)).map(|c| c.value().to_string()) else {
        return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid credentials".to_string() })));
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
        .handle_callback(&oidc_config, &code, &raw_state, &callback_url, resolved_org.0.id, &binding_secret)
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid credentials".to_string() })))?;

    let token = state
        .provision_sso_user
        .execute(resolved_org.0.id, &identity)
        .await
        .map_err(|e| match e {
            // Same 401 whether the exchange failed or the account was blocked afterward.
            ApplicationError::InvalidCredentials => (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid credentials".to_string() })),
            e => application_error_response("failed to provision sso user", e),
        })?;

    // One binding secret, one use — clear it so a replayed callback has nothing to match.
    let cleared = jar.remove(
        axum_extra::extract::cookie::Cookie::build((oidc_binding_cookie_name(&state), ""))
            .path("/")
            .secure(!is_local_dev_domain(&state.hangar_base_domain))
            .build(),
    );

    Ok((cleared, axum::response::Redirect::to(&format!("{}/login#token={}", organization_origin(&state, &resolved_org), token))))
}

/// All LDAP failure modes collapse to 401 — same as local login never distinguishing "unknown user" from "wrong password".
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
        .map_err(|e| match e {
            // Same 401 whether the directory bind failed or the account was blocked afterward.
            ApplicationError::InvalidCredentials => (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid credentials".to_string() })),
            e => application_error_response("failed to provision sso user", e),
        })?;
    Ok(Json(LoginResponse { token: Some(token), mfa_token: None, mfa_setup_required: false, mfa_has_totp: false, mfa_has_passkey: false }))
}

/// Exchanges the short-lived `mfa_token` plus a TOTP/backup code for a real session token. Unauthenticated by design — `mfa_token` itself is the credential.
async fn verify_mfa(State(state): State<AppState>, Json(body): Json<MfaVerifyRequest>) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = state
        .mfa_pending_token_issuer
        .verify(&body.mfa_token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid or expired mfa token".to_string() })))?.user_id;

    let (max_attempts, window) = throttle_limits_for_user_id(&state, user_id).await;
    let throttle_key = format!("mfa:{user_id}");
    if state.login_throttle.is_throttled(&throttle_key, max_attempts, window) {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse { error: "too many failed attempts, try again later".to_string() })));
    }

    let verified = match (&body.code, &body.backup_code) {
        (Some(code), _) => state.verify_totp.execute(user_id, code).await,
        (None, Some(backup_code)) => state.verify_backup_code.execute(user_id, backup_code).await,
        (None, None) => Err(ApplicationError::InvalidMfaCode),
    };

    match verified {
        Ok(()) => {
            state.login_throttle.clear(&throttle_key);
            let user = state.users.find_by_id(user_id).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?.ok_or((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
            let settings = state.get_system_settings.execute(user.organization_id).await.map_err(|e| application_error_response("failed to get system settings", e))?;
            let token = state.token_issuer.issue(user_id, chrono::Duration::hours(settings.session_ttl_hours as i64)).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
            Ok(Json(LoginResponse { token: Some(token), mfa_token: None, mfa_setup_required: false, mfa_has_totp: false, mfa_has_passkey: false }))
        }
        Err(_) => {
            state.login_throttle.record_failure(&throttle_key, max_attempts, window);
            Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid code".to_string() })))
        }
    }
}

#[derive(Deserialize)]
struct MfaPasskeyStartRequest {
    mfa_token: String,
}

#[derive(Serialize)]
struct MfaPasskeyStartResponse {
    challenge_id: uuid::Uuid,
    public_key: webauthn_rs_proto::PublicKeyCredentialRequestOptions,
}

/// Unwraps `RequestChallengeResponse` down to its `public_key` field — it already serializes to `{"publicKey": {...}}`, which would otherwise double-nest here.
async fn start_mfa_passkey(State(state): State<AppState>, Json(body): Json<MfaPasskeyStartRequest>) -> Result<Json<MfaPasskeyStartResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = state
        .mfa_pending_token_issuer
        .verify(&body.mfa_token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid or expired mfa token".to_string() })))?.user_id;

    let (challenge_id, public_key) = state.start_passkey_authentication.execute(user_id).await.map_err(|e| application_error_response("failed to start passkey authentication", e))?;
    Ok(Json(MfaPasskeyStartResponse { challenge_id, public_key: public_key.public_key }))
}

#[derive(Deserialize)]
struct MfaPasskeyFinishRequest {
    mfa_token: String,
    challenge_id: uuid::Uuid,
    credential: webauthn_rs::prelude::PublicKeyCredential,
}

async fn finish_mfa_passkey(State(state): State<AppState>, Json(body): Json<MfaPasskeyFinishRequest>) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = state
        .mfa_pending_token_issuer
        .verify(&body.mfa_token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid or expired mfa token".to_string() })))?.user_id;

    let (max_attempts, window) = throttle_limits_for_user_id(&state, user_id).await;
    let throttle_key = format!("mfa:{user_id}");
    if state.login_throttle.is_throttled(&throttle_key, max_attempts, window) {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse { error: "too many failed attempts, try again later".to_string() })));
    }

    match state.finish_passkey_authentication.execute(user_id, body.challenge_id, &body.credential).await {
        Ok(()) => {
            state.login_throttle.clear(&throttle_key);
            let user = state.users.find_by_id(user_id).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?.ok_or((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
            let settings = state.get_system_settings.execute(user.organization_id).await.map_err(|e| application_error_response("failed to get system settings", e))?;
            let token = state.token_issuer.issue(user_id, chrono::Duration::hours(settings.session_ttl_hours as i64)).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
            Ok(Json(LoginResponse { token: Some(token), mfa_token: None, mfa_setup_required: false, mfa_has_totp: false, mfa_has_passkey: false }))
        }
        Err(_) => {
            state.login_throttle.record_failure(&throttle_key, max_attempts, window);
            Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "passkey verification failed".to_string() })))
        }
    }
}

async fn username_for(state: &AppState, user_id: uuid::Uuid) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let user = state
        .users
        .find_by_id(user_id)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?
        .ok_or((StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid or expired mfa token".to_string() })))?;
    Ok(user.username.as_str().to_string())
}

#[derive(Deserialize)]
struct MfaSetupTokenOnlyRequest {
    mfa_token: String,
}

#[derive(Serialize)]
struct TotpEnrollmentResponse {
    secret: String,
    otpauth_url: String,
}

/// Mandatory-enrollment counterpart to `/api/me/mfa/totp/enroll`, authenticated by `mfa_token` rather than a full session.
async fn setup_mfa_totp_enroll(State(state): State<AppState>, Json(body): Json<MfaSetupTokenOnlyRequest>) -> Result<Json<TotpEnrollmentResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = state
        .mfa_pending_token_issuer
        .verify(&body.mfa_token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid or expired mfa token".to_string() })))?.user_id;
    if mfa_factors(&state, user_id).await.any() {
        return Err(application_error_response("mandatory TOTP setup rejected", ApplicationError::MfaAlreadyEnabled));
    }
    let username = username_for(&state, user_id).await?;
    let enrollment = state.enroll_totp.execute(user_id, &username).await.map_err(|e| application_error_response("failed to enroll TOTP during mandatory setup", e))?;
    Ok(Json(TotpEnrollmentResponse { secret: enrollment.secret_base32, otpauth_url: enrollment.otpauth_url }))
}

#[derive(Deserialize)]
struct MfaSetupTotpConfirmRequest {
    mfa_token: String,
    code: String,
}

#[derive(Serialize)]
struct MfaSetupCompleteResponse {
    token: String,
    backup_codes: Vec<String>,
}

/// Success issues a real session token immediately.
async fn setup_mfa_totp_confirm(State(state): State<AppState>, Json(body): Json<MfaSetupTotpConfirmRequest>) -> Result<Json<MfaSetupCompleteResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = state
        .mfa_pending_token_issuer
        .verify(&body.mfa_token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid or expired mfa token".to_string() })))?.user_id;

    let (max_attempts, window) = throttle_limits_for_user_id(&state, user_id).await;
    let throttle_key = format!("mfa-setup:{user_id}");
    if state.login_throttle.is_throttled(&throttle_key, max_attempts, window) {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse { error: "too many failed attempts, try again later".to_string() })));
    }

    let username = username_for(&state, user_id).await?;
    match state.confirm_totp.execute(user_id, &username, &body.code).await {
        Ok(backup_codes) => {
            state.login_throttle.clear(&throttle_key);
            let user = state.users.find_by_id(user_id).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?.ok_or((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
            let settings = state.get_system_settings.execute(user.organization_id).await.map_err(|e| application_error_response("failed to get system settings", e))?;
            let token = state.token_issuer.issue(user_id, chrono::Duration::hours(settings.session_ttl_hours as i64)).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
            Ok(Json(MfaSetupCompleteResponse { token, backup_codes }))
        }
        Err(e) => {
            state.login_throttle.record_failure(&throttle_key, max_attempts, window);
            Err(application_error_response("failed to confirm TOTP during mandatory setup", e))
        }
    }
}

#[derive(Serialize)]
struct MfaSetupPasskeyStartResponse {
    challenge_id: uuid::Uuid,
    public_key: webauthn_rs_proto::PublicKeyCredentialCreationOptions,
}

/// See `start_mfa_passkey`'s doc comment: same unwrap, same reason.
async fn setup_mfa_passkey_start(State(state): State<AppState>, Json(body): Json<MfaSetupTokenOnlyRequest>) -> Result<Json<MfaSetupPasskeyStartResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = state
        .mfa_pending_token_issuer
        .verify(&body.mfa_token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid or expired mfa token".to_string() })))?.user_id;
    if mfa_factors(&state, user_id).await.any() {
        return Err(application_error_response("mandatory passkey setup rejected", ApplicationError::MfaAlreadyEnabled));
    }
    let username = username_for(&state, user_id).await?;
    let (challenge_id, public_key) =
        state.start_passkey_registration.execute(user_id, &username).await.map_err(|e| application_error_response("failed to start passkey registration during mandatory setup", e))?;
    Ok(Json(MfaSetupPasskeyStartResponse { challenge_id, public_key: public_key.public_key }))
}

#[derive(Deserialize)]
struct MfaSetupPasskeyFinishRequest {
    mfa_token: String,
    challenge_id: uuid::Uuid,
    credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
    name: String,
}

async fn setup_mfa_passkey_finish(State(state): State<AppState>, Json(body): Json<MfaSetupPasskeyFinishRequest>) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user_id = state
        .mfa_pending_token_issuer
        .verify(&body.mfa_token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(ErrorResponse { error: "invalid or expired mfa token".to_string() })))?.user_id;

    let (max_attempts, window) = throttle_limits_for_user_id(&state, user_id).await;
    let throttle_key = format!("mfa-setup:{user_id}");
    if state.login_throttle.is_throttled(&throttle_key, max_attempts, window) {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse { error: "too many failed attempts, try again later".to_string() })));
    }

    match state.finish_passkey_registration.execute(user_id, body.challenge_id, &body.credential, &body.name).await {
        Ok(_credential_id) => {
            state.login_throttle.clear(&throttle_key);
            let user = state.users.find_by_id(user_id).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?.ok_or((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
            let settings = state.get_system_settings.execute(user.organization_id).await.map_err(|e| application_error_response("failed to get system settings", e))?;
            let token = state.token_issuer.issue(user_id, chrono::Duration::hours(settings.session_ttl_hours as i64)).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse { error: "internal error".to_string() })))?;
            Ok(Json(LoginResponse { token: Some(token), mfa_token: None, mfa_setup_required: false, mfa_has_totp: false, mfa_has_passkey: false }))
        }
        Err(e) => {
            state.login_throttle.record_failure(&throttle_key, max_attempts, window);
            Err(application_error_response("failed to finish passkey registration during mandatory setup", e))
        }
    }
}

// JWTs are stateless — logout is client-side (discard the token). Exists for API symmetry, always succeeds.
async fn logout() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Unauthenticated by design — the activation token itself is the credential.
async fn activate_account(State(state): State<AppState>, Json(body): Json<ActivateAccountRequest>) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    state.activate_account.execute(&body.token, &body.new_password).await.map_err(|e| application_error_response("failed to activate account", e))?;
    Ok(StatusCode::NO_CONTENT)
}

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

async fn change_password(
    State(state): State<AppState>,
    user: AuthUser,
    connect_info: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let (max_attempts, window) = throttle_limits_for_organization(&state, user.organization_id).await;
    if state.login_throttle.is_throttled(&user.username, max_attempts, window) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse { error: "too many failed attempts, try again later".to_string() }),
        ));
    }

    match state.change_password.execute(user.id, &body.current_password, &body.new_password).await {
        Ok(()) => {
            state.login_throttle.clear(&user.username);
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => {
            // A rejected weak new password is not a credential-guessing signal.
            if matches!(e, ApplicationError::InvalidCredentials) {
                state.login_throttle.record_failure(&user.username, max_attempts, window);
                let _ = state
                    .record_security_event
                    .execute(
                        SecurityEvent::PasswordChangeFailed { username: user.username.clone(), ip: peer_ip(connect_info) },
                        Some(user.id),
                    )
                    .await;
            }
            Err(application_error_response("failed to change password", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::{build_router, state::AppState};
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
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
    async fn login_succeeds_with_correct_credentials_but_requires_mfa_setup_when_none_is_enrolled(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let response = app
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["token"].is_null());
        assert!(json["mfa_token"].is_string());
        assert_eq!(json["mfa_setup_required"], true);
    }

    async fn enroll_and_confirm_totp(state: &AppState, user_id: uuid::Uuid) {
        let enrollment = state.enroll_totp.execute(user_id, "florian").await.unwrap();
        let code = hangar_application::use_cases::mfa::generate_current_totp_code(&enrollment.secret_base32);
        state.confirm_totp.execute(user_id, "florian", &code).await.unwrap();
    }

    /// Bypasses the real WebAuthn ceremony (unfakeable over HTTP) by inserting the credential directly through the same port `FinishPasskeyRegistrationUseCase` writes to.
    async fn enroll_a_passkey(state: &AppState, user_id: uuid::Uuid) {
        state
            .webauthn_credentials
            .insert(&hangar_domain::webauthn::WebauthnCredential {
                id: Uuid::new_v4(),
                user_id,
                name: "Test key".to_string(),
                passkey_data: vec![0u8; 8],
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn logging_in_with_confirmed_totp_returns_an_mfa_token_instead_of_a_session_token(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        enroll_and_confirm_totp(&state, user_id).await;
        let app = build_router(state);

        let response = app
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

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["token"].is_null(), "no full session token before the second factor is verified");
        assert!(json["mfa_token"].is_string());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_mfa_token_cannot_be_used_as_a_bearer_session_token(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        enroll_and_confirm_totp(&state, user_id).await;
        let app = build_router(state);

        let login_response = app
            .clone()
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
        let body = to_bytes(login_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mfa_token = json["mfa_token"].as_str().unwrap();

        let response = app.oneshot(Request::builder().uri("/api/me").header("authorization", format!("Bearer {mfa_token}")).body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED, "an mfa-pending token must not authenticate a normal API request");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn completing_mfa_verify_with_a_correct_totp_code_issues_a_working_session_token(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        enroll_and_confirm_totp(&state, user_id).await;
        let app = build_router(state.clone());

        let login_response = app
            .clone()
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
        let body = to_bytes(login_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mfa_token = json["mfa_token"].as_str().unwrap();

        // The confirm step already consumed the current step's code; verify with the next one.
        let credential = state.totp_credentials.get(user_id).await.unwrap().unwrap();
        let code = hangar_application::use_cases::mfa::generate_totp_code_after_step(&credential.secret, credential.last_used_step.unwrap());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"mfa_token":"{mfa_token}","code":"{code}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let session_token = json["token"].as_str().unwrap();

        let me_response = app.oneshot(Request::builder().uri("/api/me").header("authorization", format!("Bearer {session_token}")).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(me_response.status(), axum::http::StatusCode::OK, "the token issued by mfa/verify must work as a normal session token");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn mfa_verify_with_a_wrong_code_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        enroll_and_confirm_totp(&state, user_id).await;
        let app = build_router(state);

        let login_response = app
            .clone()
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
        let body = to_bytes(login_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mfa_token = json["mfa_token"].as_str().unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"mfa_token":"{mfa_token}","code":"000000"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn mfa_verify_with_a_session_token_instead_of_an_mfa_token_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let session_token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"mfa_token":"{session_token}","code":"000000"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn starting_mfa_passkey_with_an_invalid_mfa_token_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/passkey/start")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"mfa_token":"not-a-real-token"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn starting_mfa_passkey_with_a_session_token_instead_of_an_mfa_token_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let session_token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/passkey/start")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"mfa_token":"{session_token}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn starting_mfa_passkey_fails_when_the_account_has_no_registered_passkey(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let enrollment = state.enroll_totp.execute(user_id, "florian").await.unwrap();
        let code = hangar_application::use_cases::mfa::generate_current_totp_code(&enrollment.secret_base32);
        state.confirm_totp.execute(user_id, "florian", &code).await.unwrap();
        let app = build_router(state.clone());

        let login_response = app
            .clone()
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
        let body = to_bytes(login_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mfa_token = json["mfa_token"].as_str().unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/passkey/start")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"mfa_token":"{mfa_token}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn finishing_mfa_passkey_with_an_unknown_challenge_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let enrollment = state.enroll_totp.execute(user_id, "florian").await.unwrap();
        let code = hangar_application::use_cases::mfa::generate_current_totp_code(&enrollment.secret_base32);
        state.confirm_totp.execute(user_id, "florian", &code).await.unwrap();
        let mfa_token = state.mfa_pending_token_issuer.issue(user_id, chrono::Duration::minutes(5)).unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/passkey/finish")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"mfa_token":"{mfa_token}","challenge_id":"{}","credential":{{"id":"AAAA","rawId":"AAAA","response":{{"authenticatorData":"","clientDataJSON":"","signature":""}},"type":"public-key"}}}}"#,
                        uuid::Uuid::new_v4()
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    async fn login_response(app: axum::Router, username: &str, password: &str) -> serde_json::Value {
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"username":"{username}","password":"{password}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn enrolling_totp_during_mandatory_setup_issues_a_working_session_token(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let json = login_response(app.clone(), "florian", "sup3r-s3cret!").await;
        assert_eq!(json["mfa_setup_required"], true);
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
        assert_eq!(enroll_response.status(), axum::http::StatusCode::OK);
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
        let body = to_bytes(confirm_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["backup_codes"].as_array().unwrap().len(), 10);
        let session_token = json["token"].as_str().unwrap();

        let me_response = app.oneshot(Request::builder().uri("/api/me").header("authorization", format!("Bearer {session_token}")).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(me_response.status(), axum::http::StatusCode::OK);
    }

    /// mfa_token is issued on password alone, so setup must refuse an account that already has a factor.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn mandatory_totp_setup_is_rejected_once_the_account_already_has_a_passkey(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        state
            .webauthn_credentials
            .insert(&hangar_domain::webauthn::WebauthnCredential { id: uuid::Uuid::new_v4(), user_id, name: "YubiKey".to_string(), passkey_data: b"opaque".to_vec(), created_at: chrono::Utc::now() })
            .await
            .unwrap();
        let mfa_token = state.mfa_pending_token_issuer.issue(user_id, chrono::Duration::minutes(5)).unwrap();
        let app = build_router(state);

        let response = app
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

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn mandatory_passkey_setup_is_rejected_once_the_account_already_has_confirmed_totp(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        enroll_and_confirm_totp(&state, user_id).await;
        let mfa_token = state.mfa_pending_token_issuer.issue(user_id, chrono::Duration::minutes(5)).unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/setup/passkey/start")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"mfa_token":"{mfa_token}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn logging_in_again_after_totp_setup_no_longer_requires_setup(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        enroll_and_confirm_totp(&state, user_id).await;
        let app = build_router(state);

        let json = login_response(app, "florian", "sup3r-s3cret!").await;

        assert_eq!(json["mfa_setup_required"], false);
        assert!(json["mfa_token"].is_string(), "the account now has a confirmed factor, so it goes through verify, not setup");
        assert_eq!(json["mfa_has_totp"], true);
        assert_eq!(json["mfa_has_passkey"], false);
    }

    /// Guards a real bug class: the response must say *which* factor exists, not just *whether* one does — an account with only a passkey must not show a TOTP field.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn logging_in_with_only_a_passkey_reports_has_passkey_but_not_has_totp(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        enroll_a_passkey(&state, user_id).await;
        let app = build_router(state);

        let json = login_response(app, "florian", "sup3r-s3cret!").await;

        assert_eq!(json["mfa_setup_required"], false);
        assert_eq!(json["mfa_has_totp"], false);
        assert_eq!(json["mfa_has_passkey"], true);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn logging_in_with_both_factors_reports_both_as_available(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        enroll_and_confirm_totp(&state, user_id).await;
        enroll_a_passkey(&state, user_id).await;
        let app = build_router(state);

        let json = login_response(app, "florian", "sup3r-s3cret!").await;

        assert_eq!(json["mfa_has_totp"], true);
        assert_eq!(json["mfa_has_passkey"], true);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn confirming_totp_setup_with_a_wrong_code_is_throttled_and_never_issues_a_token(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let json = login_response(app.clone(), "florian", "sup3r-s3cret!").await;
        let mfa_token = json["mfa_token"].as_str().unwrap();
        app.clone()
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

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/setup/totp/confirm")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"mfa_token":"{mfa_token}","code":"000000"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn totp_setup_with_an_invalid_mfa_token_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/setup/totp/enroll")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"mfa_token":"not-a-real-token"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn passkey_setup_start_during_mandatory_enrollment_returns_a_challenge(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let json = login_response(app.clone(), "florian", "sup3r-s3cret!").await;
        let mfa_token = json["mfa_token"].as_str().unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/setup/passkey/start")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"mfa_token":"{mfa_token}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["challenge_id"].is_string());
        assert_eq!(json["public_key"]["user"]["name"], "florian");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn passkey_setup_finish_with_an_unknown_challenge_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let json = login_response(app.clone(), "florian", "sup3r-s3cret!").await;
        let mfa_token = json["mfa_token"].as_str().unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/setup/passkey/finish")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"mfa_token":"{mfa_token}","challenge_id":"{}","name":"My key","credential":{{"id":"AAAA","rawId":"AAAA","response":{{"attestationObject":"","clientDataJSON":""}},"type":"public-key"}}}}"#,
                        uuid::Uuid::new_v4()
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn login_fails_with_wrong_password(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"username":"florian","password":"wrong"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    fn activate_request(token: &str, new_password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/auth/activate")
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"token":"{token}","new_password":"{new_password}"}}"#)))
            .unwrap()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn activating_with_a_valid_token_sets_a_working_password(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "invitee", "placeholder-not-usable", false).await.unwrap();
        state
            .user_invitations
            .upsert(&hangar_domain::invitation::UserInvitation {
                user_id,
                token_hash: hangar_application::use_cases::invitation::hash_invitation_token("raw-test-token"),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
            })
            .await
            .unwrap();
        let app = build_router(state);

        let response = app.clone().oneshot(activate_request("raw-test-token", "new-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);

        let login = app.oneshot(login_request("invitee", "new-s3cret!")).await.unwrap();
        assert_eq!(login.status(), axum::http::StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn activating_with_an_unknown_token_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(activate_request("not-a-real-token", "new-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn activating_with_an_expired_token_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "invitee", "placeholder-not-usable", false).await.unwrap();
        state
            .user_invitations
            .upsert(&hangar_domain::invitation::UserInvitation {
                user_id,
                token_hash: hangar_application::use_cases::invitation::hash_invitation_token("raw-test-token"),
                expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
            })
            .await
            .unwrap();
        let app = build_router(state);

        let response = app.oneshot(activate_request("raw-test-token", "new-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    fn login_request(username: &str, password: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"username":"{username}","password":"{password}"}}"#)))
            .unwrap()
    }

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
    async fn registering_while_registration_is_disabled_is_rejected(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let mut settings = state.get_system_settings.execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap();
        settings.registration_enabled = false;
        state.update_system_settings.execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, settings).await.unwrap();
        let app = build_router(state);

        let response = app.oneshot(register_request("florian", "florian@example.com", "sup3r-s3cret!")).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "public self-registration is currently disabled");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn sso_config_reports_registration_enabled_by_default_and_reflects_the_setting(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let mut settings = state.get_system_settings.execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID).await.unwrap();
        let app = build_router(state.clone());

        let response = app.clone().oneshot(Request::builder().uri("/api/auth/sso/config").body(Body::empty()).unwrap()).await.unwrap();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["registration_enabled"], true, "must default to enabled");

        settings.registration_enabled = false;
        state.update_system_settings.execute(hangar_domain::organization::PUBLIC_ORGANIZATION_ID, settings).await.unwrap();

        let response = app.oneshot(Request::builder().uri("/api/auth/sso/config").body(Body::empty()).unwrap()).await.unwrap();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["registration_enabled"], false);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn sso_config_reports_registration_disabled_on_a_non_public_organization_even_when_the_setting_is_on(pool: sqlx::PgPool) {
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

        let mut request = Request::builder().uri("/api/auth/sso/config").body(Body::empty()).unwrap();
        request.headers_mut().insert("host", "acme.hangar.localhost".parse().unwrap());
        let response = app.oneshot(request).await.unwrap();

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["registration_enabled"], false);
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
    async fn repeated_registration_attempts_from_the_same_ip_are_eventually_throttled(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        for i in 0..crate::login_throttle::MAX_LOGIN_ATTEMPTS {
            let mut request = register_request(&format!("florian{i}"), &format!("florian{i}@example.com"), "sup3r-s3cret!");
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 51234))));
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::OK, "attempt {i} should still succeed, distinct username/email each time");
        }

        let mut request = register_request("one-too-many", "one-too-many@example.com", "sup3r-s3cret!");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 51234))));
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_fresh_ip_is_unaffected_by_another_ips_registration_attempts(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        for i in 0..crate::login_throttle::MAX_LOGIN_ATTEMPTS {
            let mut request = register_request(&format!("attacker{i}"), &format!("attacker{i}@example.com"), "sup3r-s3cret!");
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 51234))));
            app.clone().oneshot(request).await.unwrap();
        }

        let mut request = register_request("florian", "florian@example.com", "sup3r-s3cret!");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([198, 51, 100, 1], 51234))));
        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn registering_a_duplicate_email_fails_with_bad_request_not_a_server_error(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);
        app.clone().oneshot(register_request("florian", "shared@example.com", "sup3r-s3cret!")).await.unwrap();

        let response = app.oneshot(register_request("someoneelse", "shared@example.com", "sup3r-s3cret!")).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn registering_with_a_weak_password_fails(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(register_request("florian", "florian@example.com", "short")).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_few_failed_attempts_do_not_block_a_later_correct_login(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        for _ in 0..(crate::login_throttle::MAX_LOGIN_ATTEMPTS - 1) {
            let response = app.clone().oneshot(login_request("florian", "wrong")).await.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        }

        let response = app.oneshot(login_request("florian", "sup3r-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn hitting_the_failure_threshold_rejects_even_correct_credentials(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        for _ in 0..crate::login_throttle::MAX_LOGIN_ATTEMPTS {
            let response = app.clone().oneshot(login_request("florian", "wrong")).await.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        }

        let response = app.oneshot(login_request("florian", "sup3r-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_successful_login_resets_the_failure_counter(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state);

        for _ in 0..(crate::login_throttle::MAX_LOGIN_ATTEMPTS - 1) {
            app.clone().oneshot(login_request("florian", "wrong")).await.unwrap();
        }
        let response = app.clone().oneshot(login_request("florian", "sup3r-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let response = app.clone().oneshot(login_request("florian", "wrong")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        let response = app.oneshot(login_request("florian", "sup3r-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    async fn login_failure_ips(state: &AppState) -> Vec<String> {
        let entries = state
            .query_audit_log
            .execute(hangar_domain::audit::AuditQueryFilter {
                aggregate_type: Some("Security".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        entries
            .into_iter()
            .filter(|e| e.event_type == "LoginFailed")
            .map(|e| e.payload["ip"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_failed_login_records_the_connecting_peers_ip(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state.clone());

        let mut request = login_request("florian", "wrong");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 51234))));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

        assert_eq!(login_failure_ips(&state).await, vec!["203.0.113.7".to_string()]);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_failed_login_without_connect_info_still_succeeds_at_auditing(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let app = build_router(state.clone());

        let response = app.oneshot(login_request("florian", "wrong")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

        assert_eq!(login_failure_ips(&state).await, vec!["unknown".to_string()]);
    }

    #[sqlx::test]
    async fn me_requires_a_bearer_token(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/api/me").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn me_returns_the_authenticated_user(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", true).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/me")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], user_id.to_string());
        assert_eq!(json["username"], "florian");
        assert_eq!(json["is_super_admin"], true);
    }

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

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn me_returns_the_users_created_at(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "sup3r-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/api/me").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["created_at"].is_string(), "expected created_at in /api/me response, got {json}");
    }

    fn change_password_request(token: &str, current_password: &str, new_password: &str) -> Request<Body> {
        Request::builder()
            .method("PUT")
            .uri("/api/me/password")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(format!(r#"{{"current_password":"{current_password}","new_password":"{new_password}"}}"#)))
            .unwrap()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn changes_the_password_with_the_correct_current_password(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "old-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "old-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app.clone().oneshot(change_password_request(&token, "old-s3cret!", "new-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);

        let login_response = app.oneshot(login_request("florian", "new-s3cret!")).await.unwrap();
        assert_eq!(login_response.status(), axum::http::StatusCode::OK);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn rejects_a_password_change_with_the_wrong_current_password(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "old-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "old-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app.oneshot(change_password_request(&token, "wrong", "new-s3cret!")).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn rejects_a_new_password_shorter_than_the_minimum_via_the_route(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "old-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "old-s3cret!").await.unwrap();
        let app = build_router(state);

        let response = app.oneshot(change_password_request(&token, "old-s3cret!", "short")).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[sqlx::test]
    async fn change_password_requires_a_bearer_token(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/me/password")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"current_password":"a","new_password":"new-s3cret!"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    async fn password_change_failure_ips(state: &AppState) -> Vec<String> {
        let entries = state
            .query_audit_log
            .execute(hangar_domain::audit::AuditQueryFilter {
                aggregate_type: Some("Security".to_string()),
                ..Default::default()
            })
            .await
            .unwrap();
        entries
            .into_iter()
            .filter(|e| e.event_type == "PasswordChangeFailed")
            .map(|e| e.payload["ip"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_few_failed_password_change_attempts_do_not_block_a_later_correct_one(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "old-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "old-s3cret!").await.unwrap();
        let app = build_router(state);

        for _ in 0..(crate::login_throttle::MAX_LOGIN_ATTEMPTS - 1) {
            let response = app.clone().oneshot(change_password_request(&token, "wrong", "new-s3cret!")).await.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        }

        let response = app.oneshot(change_password_request(&token, "old-s3cret!", "new-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn hitting_the_failure_threshold_rejects_even_a_correct_password_change(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "old-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "old-s3cret!").await.unwrap();
        let app = build_router(state);

        for _ in 0..crate::login_throttle::MAX_LOGIN_ATTEMPTS {
            let response = app.clone().oneshot(change_password_request(&token, "wrong", "new-s3cret!")).await.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        }

        let response = app.oneshot(change_password_request(&token, "old-s3cret!", "new-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_failed_password_change_records_a_security_event_with_the_connecting_peers_ip(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "old-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "old-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        let mut request = change_password_request(&token, "wrong", "new-s3cret!");
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 51234))));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

        assert_eq!(password_change_failure_ips(&state).await, vec!["203.0.113.7".to_string()]);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_weak_new_password_does_not_count_against_the_throttle_or_get_audited(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "old-s3cret!", false).await.unwrap();
        let token = state.authenticate_user.execute("florian", "old-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        for _ in 0..crate::login_throttle::MAX_LOGIN_ATTEMPTS {
            let response = app.clone().oneshot(change_password_request(&token, "old-s3cret!", "short")).await.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        }

        assert!(password_change_failure_ips(&state).await.is_empty());

        let response = app.oneshot(change_password_request(&token, "old-s3cret!", "new-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_successful_password_change_after_some_failures_clears_the_throttle(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let user_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "florian", "old-s3cret!", false).await.unwrap();
        enroll_and_confirm_totp(&state, user_id).await;
        let token = state.authenticate_user.execute("florian", "old-s3cret!").await.unwrap();
        let app = build_router(state.clone());

        for _ in 0..(crate::login_throttle::MAX_LOGIN_ATTEMPTS - 1) {
            app.clone().oneshot(change_password_request(&token, "wrong", "new-s3cret!")).await.unwrap();
        }
        let response = app.clone().oneshot(change_password_request(&token, "old-s3cret!", "new-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);

        let token = login_and_get_token(&app, &state, user_id, "new-s3cret!").await;
        let response = app.clone().oneshot(login_request("florian", "wrong")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
        let response = app.oneshot(change_password_request(&token, "old-s3cret!", "new-s3cret!")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    async fn login_and_get_token(app: &Router, state: &AppState, user_id: uuid::Uuid, password: &str) -> String {
        let response = app.clone().oneshot(login_request("florian", password)).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mfa_token = json["mfa_token"].as_str().unwrap().to_string();

        let credential = state.totp_credentials.get(user_id).await.unwrap().unwrap();
        let code = hangar_application::use_cases::mfa::generate_totp_code_after_step(&credential.secret, credential.last_used_step.unwrap());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/auth/mfa/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"mfa_token":"{mfa_token}","code":"{code}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        json["token"].as_str().unwrap().to_string()
    }

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
        // No real directory here, so the connection itself fails — proves that surfaces as 401.
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

        // Cookie is present, so this tests the state-token check, not the missing-cookie one.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/auth/sso/oidc/callback?code=abc&state=not-a-real-token")
                    .header("cookie", "hangar_oidc_binding=some-binding-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    /// Stand-in for `OpenidConnectAuthAdapter`, keeping just the org-scoping and browser-binding checks these route tests care about.
    struct FakeOidcAuth;

    fn fake_state_token(organization_id: Uuid, binding_secret: &str) -> String {
        format!("fake-state.{organization_id}.{binding_secret}")
    }

    #[async_trait::async_trait]
    impl hangar_domain::sso::OidcAuthPort for FakeOidcAuth {
        async fn build_redirect(
            &self,
            _config: &hangar_domain::sso::OidcConfig,
            organization_id: Uuid,
            callback_url: &str,
            binding_secret: &str,
        ) -> Result<String, hangar_domain::error::DomainError> {
            Ok(format!("https://idp.example/authorize?redirect_uri={callback_url}&state={}", fake_state_token(organization_id, binding_secret)))
        }

        async fn handle_callback(
            &self,
            _config: &hangar_domain::sso::OidcConfig,
            _code: &str,
            raw_state: &str,
            _callback_url: &str,
            expected_organization_id: Uuid,
            binding_secret: &str,
        ) -> Result<hangar_domain::sso::ExternalIdentity, hangar_domain::error::DomainError> {
            if raw_state != fake_state_token(expected_organization_id, binding_secret) {
                return Err(hangar_domain::error::DomainError::Infrastructure("oidc state token mismatch".to_string()));
            }
            Ok(hangar_domain::sso::ExternalIdentity { email: "florian@corp.example".to_string(), display_name: None })
        }
    }

    fn state_with_fake_oidc(pool: sqlx::PgPool) -> AppState {
        let mut state = AppState::build(pool, &test_config());
        state.oidc_auth = std::sync::Arc::new(FakeOidcAuth);
        state
    }

    async fn create_non_public_organization(state: &AppState, slug: &str) -> Uuid {
        let id = Uuid::new_v4();
        state
            .organizations
            .create(&hangar_domain::organization::Organization {
                id,
                slug: hangar_domain::organization::OrganizationSlug::parse(slug).unwrap(),
                display_name: slug.to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        id
    }

    fn header_value(response: &axum::response::Response, name: &str) -> String {
        response.headers().get(name).unwrap().to_str().unwrap().to_string()
    }

    /// The value of the `hangar_oidc_binding` cookie the login response set, as a browser would echo it back.
    fn binding_cookie_value(response: &axum::response::Response) -> String {
        let set_cookie = header_value(response, "set-cookie");
        assert!(set_cookie.starts_with("hangar_oidc_binding="), "got: {set_cookie}");
        set_cookie.split(';').next().unwrap().trim_start_matches("hangar_oidc_binding=").to_string()
    }

    /// The `state` query parameter of the identity-provider URL the login response redirected to.
    fn state_token_from_login(response: &axum::response::Response) -> String {
        let location = header_value(response, "location");
        location.split("state=").nth(1).unwrap_or_else(|| panic!("no state parameter in {location}")).to_string()
    }

    fn oidc_login_request(host: &str) -> Request<Body> {
        let mut request = Request::builder().uri("/api/auth/sso/oidc/login").body(Body::empty()).unwrap();
        request.headers_mut().insert("host", host.parse().unwrap());
        request
    }

    fn oidc_callback_request(host: &str, state_token: &str, cookie: Option<&str>) -> Request<Body> {
        let mut request = Request::builder()
            .uri(format!("/api/auth/sso/oidc/callback?code=abc&state={state_token}"))
            .body(Body::empty())
            .unwrap();
        request.headers_mut().insert("host", host.parse().unwrap());
        if let Some(cookie) = cookie {
            request.headers_mut().insert("cookie", format!("hangar_oidc_binding={cookie}").parse().unwrap());
        }
        request
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn the_oidc_login_redirect_sets_a_browser_binding_cookie(pool: sqlx::PgPool) {
        let state = state_with_fake_oidc(pool);
        let public_org = state.organizations.find_public().await.unwrap();
        seed_oidc_config(&state, public_org.id).await;
        let app = build_router(state);

        let response = app.oneshot(oidc_login_request("hangar.localhost")).await.unwrap();

        let set_cookie = header_value(&response, "set-cookie");
        assert!(set_cookie.contains("HttpOnly"), "got: {set_cookie}");
        assert!(set_cookie.contains("SameSite=Lax"), "got: {set_cookie}");
        assert!(set_cookie.contains("Path=/"), "got: {set_cookie}");
        assert!(set_cookie.contains("Max-Age=600"), "got: {set_cookie}");
        assert!(!binding_cookie_value(&response).is_empty());
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_oidc_callback_for_a_non_public_organization_redirects_to_that_organizations_own_origin(pool: sqlx::PgPool) {
        let state = state_with_fake_oidc(pool);
        let acme_id = create_non_public_organization(&state, "acme").await;
        seed_oidc_config(&state, acme_id).await;
        let app = build_router(state);

        let login = app.clone().oneshot(oidc_login_request("acme.hangar.localhost")).await.unwrap();
        let cookie = binding_cookie_value(&login);
        let state_token = state_token_from_login(&login);

        let response = app.oneshot(oidc_callback_request("acme.hangar.localhost", &state_token, Some(&cookie))).await.unwrap();

        let location = header_value(&response, "location");
        assert!(location.starts_with("http://acme.hangar.localhost/login#token="), "got: {location}");
        assert!(!location.starts_with(&test_config().public_url), "the callback must not land on the global public_url, got: {location}");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_callback_only_completes_for_the_browser_that_started_the_login(pool: sqlx::PgPool) {
        let state = state_with_fake_oidc(pool);
        let public_org = state.organizations.find_public().await.unwrap();
        seed_oidc_config(&state, public_org.id).await;
        let app = build_router(state);

        // The attacker's login attempt — its callback URL is what gets handed to the victim.
        let login_a = app.clone().oneshot(oidc_login_request("hangar.localhost")).await.unwrap();
        let cookie_a = binding_cookie_value(&login_a);
        let state_a = state_token_from_login(&login_a);

        // The victim's own browser, with its own binding cookie.
        let login_b = app.clone().oneshot(oidc_login_request("hangar.localhost")).await.unwrap();
        let cookie_b = binding_cookie_value(&login_b);
        assert_ne!(cookie_a, cookie_b, "each login attempt must mint a fresh binding secret");

        let with_the_wrong_cookie = app.clone().oneshot(oidc_callback_request("hangar.localhost", &state_a, Some(&cookie_b))).await.unwrap();
        assert_eq!(with_the_wrong_cookie.status(), axum::http::StatusCode::UNAUTHORIZED);

        let with_no_cookie = app.clone().oneshot(oidc_callback_request("hangar.localhost", &state_a, None)).await.unwrap();
        assert_eq!(with_no_cookie.status(), axum::http::StatusCode::UNAUTHORIZED);

        // ...and the browser that actually started attempt A still completes it.
        let with_the_right_cookie = app.oneshot(oidc_callback_request("hangar.localhost", &state_a, Some(&cookie_a))).await.unwrap();
        let location = header_value(&with_the_right_cookie, "location");
        assert!(location.starts_with("http://hangar.localhost/login#token="), "got: {location}");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_successful_callback_clears_the_binding_cookie(pool: sqlx::PgPool) {
        let state = state_with_fake_oidc(pool);
        let public_org = state.organizations.find_public().await.unwrap();
        seed_oidc_config(&state, public_org.id).await;
        let app = build_router(state);

        let login = app.clone().oneshot(oidc_login_request("hangar.localhost")).await.unwrap();
        let cookie = binding_cookie_value(&login);

        let response = app
            .oneshot(oidc_callback_request("hangar.localhost", &state_token_from_login(&login), Some(&cookie)))
            .await
            .unwrap();

        let set_cookie = header_value(&response, "set-cookie");
        assert!(set_cookie.starts_with("hangar_oidc_binding="), "got: {set_cookie}");
        assert!(set_cookie.contains("Max-Age=0"), "the binding cookie must be cleared after a single use, got: {set_cookie}");
        assert!(set_cookie.contains("Path=/"), "the removal must match the path the cookie was set with, got: {set_cookie}");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_state_token_minted_on_one_subdomain_does_not_complete_on_another(pool: sqlx::PgPool) {
        let state = state_with_fake_oidc(pool);
        let acme_id = create_non_public_organization(&state, "acme").await;
        let other_id = create_non_public_organization(&state, "globex").await;
        seed_oidc_config(&state, acme_id).await;
        seed_oidc_config(&state, other_id).await;
        let app = build_router(state);

        let login = app.clone().oneshot(oidc_login_request("acme.hangar.localhost")).await.unwrap();
        let cookie = binding_cookie_value(&login);
        let state_token = state_token_from_login(&login);

        let response = app.oneshot(oidc_callback_request("globex.hangar.localhost", &state_token, Some(&cookie))).await.unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_lower_throttle_limit_in_one_organization_does_not_affect_another(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        let other_id = state.create_organization.execute("other", "Other Corp").await.unwrap();
        state.create_user.execute(acme_id, "acme-user", "sup3r-s3cret!", false).await.unwrap();
        state.create_user.execute(other_id, "other-user", "sup3r-s3cret!", false).await.unwrap();
        state
            .update_system_settings
            .execute(
                acme_id,
                hangar_domain::system_settings::SystemSettings { max_login_attempts: 1, login_attempt_window_seconds: 300, session_ttl_hours: 12, registration_enabled: true },
            )
            .await
            .unwrap();
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

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn an_unrecognized_username_is_throttled_using_the_global_defaults(pool: sqlx::PgPool) {
        // Also seed an org with a much lower limit — a wrong fallback resolving to it would throttle far earlier and fail this test.
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        state
            .update_system_settings
            .execute(
                acme_id,
                hangar_domain::system_settings::SystemSettings { max_login_attempts: 1, login_attempt_window_seconds: 300, session_ttl_hours: 12, registration_enabled: true },
            )
            .await
            .unwrap();
        let app = build_router(state);

        for _ in 0..crate::login_throttle::MAX_LOGIN_ATTEMPTS {
            let response = app.clone().oneshot(login_request("no-such-user", "wrong")).await.unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED, "should not be throttled before the global limit is reached");
        }

        let response = app.oneshot(login_request("no-such-user", "wrong")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS, "an unrecognized username must fall back to the global throttle constants, not some organization's settings");
    }

    // Can't hit /api/auth/login and read `token` off the response — MFA is mandatory, so that
    // always returns an `mfa_token`. Drives the same mandatory-TOTP-setup flow as the test
    // above to reach a real, HTTP-issued session token via `setup_mfa_totp_confirm`.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_login_token_carries_the_issuing_users_organizations_session_ttl(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let acme_id = state.create_organization.execute("acme", "Acme Corp").await.unwrap();
        state.create_user.execute(acme_id, "acme-user", "sup3r-s3cret!", false).await.unwrap();
        state.update_system_settings.execute(acme_id, hangar_domain::system_settings::SystemSettings { max_login_attempts: 10, login_attempt_window_seconds: 300, session_ttl_hours: 1, registration_enabled: true }).await.unwrap();
        let app = build_router(state.clone());

        let json = login_response(app.clone(), "acme-user", "sup3r-s3cret!").await;
        assert_eq!(json["mfa_setup_required"], true);
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
        let body = to_bytes(confirm_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = json["token"].as_str().unwrap();

        // Decode the JWT payload without verifying — just checking the claimed expiry is close to 1 hour, not the SystemSettings::defaults() 12 hours.
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD_NO_PAD, payload_b64).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        let exp = payload["exp"].as_i64().unwrap();
        let now = chrono::Utc::now().timestamp();
        let ttl_seconds = exp - now;
        assert!(ttl_seconds > 0 && ttl_seconds <= 3600, "expected a ~1 hour TTL from acme's own session_ttl_hours=1, got {ttl_seconds} seconds");
    }
}

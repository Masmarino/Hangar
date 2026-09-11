mod auth_middleware;
mod authz;
mod config;
mod dto;
mod login_throttle;
mod organization_middleware;
mod routes;
mod state;

use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::state::AppState;

/// Well above the 2 MiB branding-upload cap, still bounds memory per `/api/*` request.
const JSON_API_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = Config::from_env();
    let pool = hangar_infrastructure::postgres::connect(&config.database_url, config.db_max_connections).await.expect("failed to connect to postgres");
    hangar_infrastructure::postgres::run_migrations(&pool).await.expect("failed to run migrations");

    let state = AppState::build(pool, &config);
    bootstrap_super_admin(&state).await;
    spawn_metrics_snapshot_timer(&state);
    spawn_retention_sweep_timer(&state);
    let app = build_router_with_cors(
        state,
        config.cors_allowed_origin.clone(),
        config.jwt_secret.clone(),
        config.docker_token_realm.clone(),
        config.public_url.clone(),
    );

    let static_dir = std::env::var("STATIC_DIR").unwrap_or_else(|_| "./static".to_string());
    let app = app.fallback_service(
        tower_http::services::ServeDir::new(&static_dir)
            .not_found_service(tower_http::services::ServeFile::new(format!("{static_dir}/index.html"))),
    );
    // Second pass — the fallback above didn't exist yet at the first one (see with_security_headers).
    let app = with_security_headers(app, config.public_url.starts_with("https://"));

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await.expect("failed to bind");
    tracing::info!("hangar-api listening on {}", config.bind_addr);
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.expect("server error");
}

/// No-op unless both bootstrap env vars are set and the `users` table is empty. Failures are logged, never fatal.
async fn bootstrap_super_admin(state: &AppState) {
    // docker-compose passes unset vars through as an empty string — treat empty as absent.
    let (Some(username), Some(password)) = (
        std::env::var("HANGAR_BOOTSTRAP_ADMIN_USERNAME").ok().filter(|s| !s.is_empty()),
        std::env::var("HANGAR_BOOTSTRAP_ADMIN_PASSWORD").ok().filter(|s| !s.is_empty()),
    ) else {
        return;
    };

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
}

/// Snapshots immediately, then once an hour after that.
fn spawn_metrics_snapshot_timer(state: &AppState) {
    let record_metrics_snapshot = state.record_metrics_snapshot.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            if let Err(e) = record_metrics_snapshot.execute().await {
                tracing::warn!("failed to record metrics snapshot: {e}");
            }
        }
    });
}

/// Runs every 6 hours; no immediate run on startup, unlike the metrics timer.
fn spawn_retention_sweep_timer(state: &AppState) {
    let sweep_retention = state.sweep_retention.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(6 * 60 * 60));
        interval.tick().await; // consume the immediate first tick — no run on startup
        loop {
            interval.tick().await;
            match sweep_retention.execute().await {
                Ok(report) => {
                    if report.npm_versions_deleted > 0 || report.docker_tags_deleted > 0 {
                        tracing::info!(
                            npm_versions_deleted = report.npm_versions_deleted,
                            docker_tags_deleted = report.docker_tags_deleted,
                            "retention sweep pruned old versions/tags"
                        );
                    }
                }
                Err(e) => tracing::warn!("retention sweep failed: {e}"),
            }
        }
    });
}

/// Fully permissive CORS — the default that keeps a separately served Angular dev server working.
pub fn build_router(state: AppState) -> Router {
    build_router_with_cors(state, None, "insecure-dev-only-jwt-secret".to_string(), "http://localhost/v2/token".to_string(), "http://localhost:4200".to_string())
}

pub fn build_router_with_cors(state: AppState, cors_allowed_origin: Option<String>, jwt_secret: String, docker_token_realm: String, public_url: String) -> Router {
    let npm_state = build_npm_state(&state);
    let docker_state = build_docker_state(&state, &jwt_secret, &docker_token_realm);
    // Scoped to this JSON surface only — /npm and /v2 already serve compressed binary content.
    let json_api_routes = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(routes::admin::router())
        .merge(routes::branding::router())
        .merge(routes::auth::router())
        .merge(routes::mfa::router())
        .merge(routes::organizations::router())
        .merge(routes::repositories::router())
        .merge(routes::users::router())
        .merge(routes::api_tokens::router())
        .layer(CompressionLayer::new())
        // Otherwise axum buffers a request body of any size before the 2 MiB branding cap ever runs.
        .layer(axum::extract::DefaultBodyLimit::max(JSON_API_BODY_LIMIT_BYTES));
    let router = Router::new()
        .merge(json_api_routes)
        // .nest_service, not .nest: the nested routers are already state-erased.
        .nest_service("/npm", hangar_npm::router(npm_state))
        .nest_service("/v2", hangar_docker::router(docker_state))
        .layer(TraceLayer::new_for_http())
        .layer(cors_layer(cors_allowed_origin))
        .with_state(state);
    // HSTS only when public_url is https — sending it unconditionally would lock out a plain-HTTP homelab deployment.
    with_security_headers(router, public_url.starts_with("https://"))
}

/// A layer only wraps routes that exist at the point it's added — needs a second call in main() after the static-file fallback.
fn with_security_headers(router: Router, hsts_enabled: bool) -> Router {
    use axum::http::{header, HeaderValue};
    use tower_http::set_header::SetResponseHeaderLayer;

    let router = router
        .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::overriding(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
        .layer(SetResponseHeaderLayer::overriding(header::REFERRER_POLICY, HeaderValue::from_static("same-origin")))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            // style-src needs 'unsafe-inline' — Angular injects per-component <style> tags, no CSP nonces.
            HeaderValue::from_static(
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
            ),
        ));
    if hsts_enabled {
        router.layer(SetResponseHeaderLayer::overriding(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=63072000; includeSubDomains")))
    } else {
        router
    }
}

/// Reuses every adapter/use-case `AppState` already built.
fn build_npm_state(state: &AppState) -> hangar_npm::NpmState {
    let remote_registry: Arc<dyn hangar_domain::npm_remote::RemoteNpmRegistryPort> =
        Arc::new(hangar_infrastructure::http_remote_npm_registry::HttpRemoteNpmRegistry::new());

    hangar_npm::NpmState {
        users: state.users.clone(),
        repositories: state.repositories.clone(),
        permissions: state.permissions.clone(),
        api_tokens: state.api_tokens.clone(),
        organizations: state.organizations.clone(),
        hangar_base_domain: state.hangar_base_domain.clone(),
        publish: Arc::new(hangar_application::use_cases::npm_publish::PublishNpmPackageUseCase::new(
            state.npm_packages.clone(),
            state.storage.clone(),
            state.repositories.clone(),
            state.events.clone(),
        )),
        metadata: Arc::new(hangar_application::use_cases::npm_metadata::GetNpmPackageMetadataUseCase::new(
            state.npm_packages.clone(),
            state.repositories.clone(),
            remote_registry.clone(),
        )),
        download: Arc::new(hangar_application::use_cases::npm_download::DownloadNpmTarballUseCase::new(
            state.npm_packages.clone(),
            state.storage.clone(),
            remote_registry.clone(),
            state.repositories.clone(),
        )),
        unpublish: Arc::new(hangar_application::use_cases::npm_unpublish::UnpublishNpmPackageUseCase::new(
            state.npm_packages.clone(),
            state.storage.clone(),
            state.events.clone(),
        )),
        deprecate: Arc::new(hangar_application::use_cases::npm_deprecate::DeprecateNpmVersionUseCase::new(
            state.npm_packages.clone(),
            state.events.clone(),
        )),
        set_dist_tag: Arc::new(hangar_application::use_cases::npm_dist_tags::SetDistTagUseCase::new(
            state.npm_packages.clone(),
            state.events.clone(),
        )),
        delete_dist_tag: Arc::new(hangar_application::use_cases::npm_dist_tags::DeleteDistTagUseCase::new(state.npm_packages.clone())),
        list_dist_tags: Arc::new(hangar_application::use_cases::npm_dist_tags::ListDistTagsUseCase::new(state.npm_packages.clone())),
        search: Arc::new(hangar_application::use_cases::npm_search::SearchNpmPackagesUseCase::new(state.npm_packages.clone())),
        bulk_audit: Arc::new(hangar_application::use_cases::npm_audit::BulkAuditNpmPackagesUseCase::new(state.npm_audit.clone())),
        scan_dependency_tree: state.scan_dependency_tree.clone(),
        create_api_token: state.create_api_token.clone(),
        list_api_tokens: state.list_api_tokens.clone(),
        revoke_api_token: state.revoke_api_token.clone(),
    }
}

/// Reuses `AppState`'s adapters; `jwt_secret`/`token_realm` arrive as explicit params since `AppState` doesn't store them.
fn build_docker_state(state: &AppState, jwt_secret: &str, token_realm: &str) -> hangar_docker::DockerState {
    let remote: Arc<dyn hangar_domain::docker_remote::RemoteDockerRegistryPort> =
        Arc::new(hangar_infrastructure::http_remote_docker_registry::HttpRemoteDockerRegistry::new());
    let token_issuer: Arc<dyn hangar_domain::docker_registry::DockerTokenIssuerPort> =
        Arc::new(hangar_infrastructure::jwt_docker_token_issuer::JwtDockerTokenIssuer::new(jwt_secret.to_string()));
    let list_catalog = Arc::new(hangar_application::use_cases::docker_list::ListCatalogUseCase::new(state.docker_manifests.clone()));

    hangar_docker::DockerState {
        repositories: state.repositories.clone(),
        permissions: state.permissions.clone(),
        organizations: state.organizations.clone(),
        hangar_base_domain: state.hangar_base_domain.clone(),
        token_issuer: token_issuer.clone(),
        token_realm: token_realm.to_string(),
        token_service: "hangar".to_string(),
        issue_access_token: Arc::new(hangar_application::use_cases::docker_access_token::IssueDockerAccessTokenUseCase::new(
            state.api_tokens.clone(),
            state.users.clone(),
            state.repositories.clone(),
            state.permissions.clone(),
            token_issuer,
        )),
        start_upload: Arc::new(hangar_application::use_cases::docker_upload::StartBlobUploadUseCase::new(state.docker_uploads.clone())),
        patch_upload: Arc::new(hangar_application::use_cases::docker_upload::PatchBlobUploadUseCase::new(state.docker_uploads.clone())),
        complete_upload: Arc::new(hangar_application::use_cases::docker_upload::CompleteBlobUploadUseCase::new(
            state.docker_uploads.clone(),
            state.docker_blobs.clone(),
        )),
        monolithic_upload: Arc::new(hangar_application::use_cases::docker_upload::MonolithicBlobUploadUseCase::new(state.docker_blobs.clone())),
        put_manifest: Arc::new(hangar_application::use_cases::docker_manifest_put::PutManifestUseCase::new(
            state.docker_manifests.clone(),
            state.docker_blobs.clone(),
            state.repositories.clone(),
            state.events.clone(),
        )),
        get_manifest: Arc::new(hangar_application::use_cases::docker_manifest_get::GetManifestUseCase::new(
            state.docker_manifests.clone(),
            state.repositories.clone(),
            remote.clone(),
        )),
        cache_proxied_manifest: Arc::new(hangar_application::use_cases::docker_manifest_cache::CacheProxiedManifestUseCase::new(
            state.docker_manifests.clone(),
        )),
        get_blob: Arc::new(hangar_application::use_cases::docker_blob_get::GetBlobUseCase::new(
            state.docker_blobs.clone(),
            state.docker_manifests.clone(),
            state.repositories.clone(),
            remote,
        )),
        delete_manifest: Arc::new(hangar_application::use_cases::docker_manifest_delete::DeleteManifestUseCase::new(
            state.docker_manifests.clone(),
            state.docker_blobs.clone(),
            state.events.clone(),
        )),
        list_tags: Arc::new(hangar_application::use_cases::docker_list::ListTagsUseCase::new(state.docker_manifests.clone())),
        list_catalog,
        list_registry_catalog: Arc::new(hangar_application::use_cases::docker_list::ListDockerRegistryCatalogUseCase::new(
            state.repositories.clone(),
            state.permissions.clone(),
            state.docker_manifests.clone(),
        )),
        scan_docker_image: state.scan_docker_image.clone(),
    }
}

/// Without `CORS_ALLOWED_ORIGIN`, restricted to localhost/127.0.0.1/[::1] on any port instead of reflecting any origin back.
fn cors_layer(cors_allowed_origin: Option<String>) -> CorsLayer {
    match cors_allowed_origin {
        Some(origin) => CorsLayer::new()
            .allow_origin(origin.parse::<axum::http::HeaderValue>().expect("CORS_ALLOWED_ORIGIN must be a valid origin"))
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any),
        None => CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(|origin, _| is_local_dev_origin(origin)))
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any),
    }
}

fn is_local_dev_origin(origin: &axum::http::HeaderValue) -> bool {
    let Ok(origin) = origin.to_str() else { return false };
    // No path in an Origin header, so exact-prefix-then-digits can't be fooled by "localhost.evil.com".
    for host in ["http://localhost", "http://127.0.0.1", "http://[::1]"] {
        if origin == host {
            return true;
        }
        if let Some(port) = origin.strip_prefix(host).and_then(|rest| rest.strip_prefix(':'))
            && !port.is_empty()
            && port.chars().all(|c| c.is_ascii_digit())
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum_extra::headers::HeaderMapExt;
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

    #[sqlx::test]
    async fn healthz_returns_ok(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap()).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    fn healthz_from(origin: &str) -> Request<Body> {
        Request::builder().uri("/healthz").header("origin", origin).body(Body::empty()).unwrap()
    }

    fn router_with(pool: sqlx::PgPool, config: &Config, cors_allowed_origin: Option<String>) -> Router {
        build_router_with_cors(AppState::build(pool, config), cors_allowed_origin, config.jwt_secret.clone(), config.docker_token_realm.clone(), config.public_url.clone())
    }

    #[test]
    fn is_local_dev_origin_accepts_localhost_127_0_0_1_and_ipv6_loopback_on_any_port() {
        for origin in ["http://localhost", "http://localhost:4200", "http://127.0.0.1", "http://127.0.0.1:8080", "http://[::1]", "http://[::1]:4200"] {
            assert!(super::is_local_dev_origin(&origin.parse().unwrap()), "expected {origin} to be accepted");
        }
    }

    #[test]
    fn is_local_dev_origin_rejects_lookalikes_and_arbitrary_origins() {
        for origin in ["https://evil.example", "http://localhost.evil.example", "http://localhost:1234.evil.example", "http://notlocalhost:4200", "http://localhost:"] {
            assert!(!super::is_local_dev_origin(&origin.parse().unwrap()), "expected {origin} to be rejected");
        }
    }

    #[sqlx::test]
    async fn a_localhost_dev_server_is_allowed_when_no_origin_is_configured(pool: sqlx::PgPool) {
        let app = router_with(pool, &test_config(), None);

        let response = app.oneshot(healthz_from("http://localhost:4200")).await.unwrap();

        // Reflects the exact origin, not "*" — browsers reject "*" for credentialed requests.
        assert_eq!(response.headers().get("access-control-allow-origin").unwrap(), "http://localhost:4200");
    }

    #[sqlx::test]
    async fn a_127_0_0_1_dev_server_is_allowed_when_no_origin_is_configured(pool: sqlx::PgPool) {
        let app = router_with(pool, &test_config(), None);

        let response = app.oneshot(healthz_from("http://127.0.0.1:4200")).await.unwrap();

        assert_eq!(response.headers().get("access-control-allow-origin").unwrap(), "http://127.0.0.1:4200");
    }

    #[sqlx::test]
    async fn an_arbitrary_internet_origin_is_rejected_when_no_origin_is_configured(pool: sqlx::PgPool) {
        let app = router_with(pool, &test_config(), None);

        let response = app.oneshot(healthz_from("https://evil.example")).await.unwrap();

        assert!(response.headers().get("access-control-allow-origin").is_none(), "an unconfigured deployment must not reflect an arbitrary origin");
    }

    #[sqlx::test]
    async fn a_lookalike_hostname_is_not_confused_with_localhost(pool: sqlx::PgPool) {
        let app = router_with(pool, &test_config(), None);

        let response = app.oneshot(healthz_from("http://localhost.evil.example")).await.unwrap();

        assert!(response.headers().get("access-control-allow-origin").is_none());
    }

    #[sqlx::test]
    async fn a_configured_origin_replaces_the_permissive_wildcard(pool: sqlx::PgPool) {
        let app = router_with(pool, &test_config(), Some("https://hangar.example".to_string()));

        let response = app.oneshot(healthz_from("https://hangar.example")).await.unwrap();

        assert_eq!(response.headers().get("access-control-allow-origin").unwrap(), "https://hangar.example");
    }

    #[sqlx::test]
    async fn a_configured_origin_is_not_echoed_back_to_other_origins(pool: sqlx::PgPool) {
        let app = router_with(pool, &test_config(), Some("https://hangar.example".to_string()));

        let response = app.oneshot(healthz_from("https://evil.example")).await.unwrap();

        assert_eq!(response.headers().get("access-control-allow-origin").unwrap(), "https://hangar.example");
    }

    #[sqlx::test]
    async fn every_response_carries_the_baseline_security_headers(pool: sqlx::PgPool) {
        let state = AppState::build(pool, &test_config());
        let app = build_router(state);

        let response = app.oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap()).await.unwrap();

        let headers = response.headers();
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(headers.get("referrer-policy").unwrap(), "same-origin");
        let csp = headers.get("content-security-policy").unwrap().to_str().unwrap();
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[sqlx::test]
    async fn hsts_is_absent_when_public_url_is_plain_http(pool: sqlx::PgPool) {
        let config = test_config();
        let app = build_router_with_cors(AppState::build(pool, &config), None, config.jwt_secret.clone(), config.docker_token_realm.clone(), "http://hangar.example".to_string());

        let response = app.oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap()).await.unwrap();

        assert!(response.headers().get("strict-transport-security").is_none(), "sending HSTS for a plain-HTTP deployment risks locking operators out over HTTP");
    }

    #[sqlx::test]
    async fn hsts_is_present_when_public_url_is_https(pool: sqlx::PgPool) {
        let config = test_config();
        let app = build_router_with_cors(AppState::build(pool, &config), None, config.jwt_secret.clone(), config.docker_token_realm.clone(), "https://hangar.example".to_string());

        let response = app.oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap()).await.unwrap();

        assert!(response.headers().get("strict-transport-security").unwrap().to_str().unwrap().contains("max-age="));
    }

    // A docker route's Location header must resolve through /v2, not a bare / — exercises main()'s nested wiring.
    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn a_docker_blob_uploads_location_header_resolves_back_into_the_nested_v2_router(pool: sqlx::PgPool) {
        use hangar_domain::package_repository::{RepositoryFormat, RepositoryType};

        let config = test_config();
        let state = AppState::build(pool, &config);
        let admin_id = state.create_user.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "admin", "sup3r-s3cret!", true).await.unwrap();
        state.create_repository.execute(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(), "docker-verify-regression", RepositoryFormat::Docker, RepositoryType::Hosted, None, None, None, admin_id).await.unwrap();
        let (_token_id, plaintext_token) = state.create_api_token.execute(admin_id, "docker-test").await.unwrap();
        let app = build_router(state);

        let mut basic_auth_headers = axum::http::HeaderMap::new();
        basic_auth_headers.typed_insert(axum_extra::headers::Authorization::basic("anything", &plaintext_token));
        let basic_auth = basic_auth_headers.get(axum::http::header::AUTHORIZATION).unwrap().clone();
        let token_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v2/token?scope=repository:docker-verify-regression/myimage:pull,push")
                    .header(axum::http::header::AUTHORIZATION, basic_auth)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(token_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(token_response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let bearer = json["token"].as_str().unwrap().to_string();

        let start_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v2/docker-verify-regression/myimage/blobs/uploads/")
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start_response.status(), StatusCode::ACCEPTED);
        let location = start_response.headers().get(axum::http::header::LOCATION).unwrap().to_str().unwrap().to_string();
        assert!(location.starts_with("/v2/"), "Location header {location:?} must be reachable through this router's own /v2 mount");

        let blob_bytes = b"regression-test-blob".to_vec();
        let digest = hangar_domain::docker_registry::Digest::of(&blob_bytes);
        let complete_response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("{location}?digest={}", digest.as_str()))
                    .header(axum::http::header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::from(blob_bytes))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(complete_response.status(), StatusCode::CREATED);
    }
}

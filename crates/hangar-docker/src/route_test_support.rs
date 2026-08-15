// Builds a real DockerState (real Postgres adapters, real filesystem blob storage under a tempdir) for exercising route wiring end-to-end.
use std::path::Path;
use std::sync::Arc;

use hangar_application::use_cases::api_token::hash_api_token;
use hangar_application::use_cases::docker_access_token::IssueDockerAccessTokenUseCase;
use hangar_application::use_cases::docker_blob_get::GetBlobUseCase;
use hangar_application::use_cases::docker_list::{ListCatalogUseCase, ListDockerRegistryCatalogUseCase, ListTagsUseCase};
use hangar_application::use_cases::docker_manifest_cache::CacheProxiedManifestUseCase;
use hangar_application::use_cases::docker_manifest_delete::DeleteManifestUseCase;
use hangar_application::use_cases::docker_manifest_get::GetManifestUseCase;
use hangar_application::use_cases::docker_manifest_put::PutManifestUseCase;
use hangar_application::use_cases::docker_scan::ScanDockerImageUseCase;
use hangar_application::use_cases::docker_upload::{CompleteBlobUploadUseCase, MonolithicBlobUploadUseCase, PatchBlobUploadUseCase, StartBlobUploadUseCase};
use hangar_infrastructure::filesystem_docker_blob_store::FilesystemDockerBlobStore;
use hangar_infrastructure::http_remote_docker_registry::HttpRemoteDockerRegistry;
use hangar_infrastructure::jwt_docker_token_issuer::JwtDockerTokenIssuer;
use hangar_infrastructure::postgres::api_token_repository::PostgresApiTokenRepository;
use hangar_infrastructure::postgres::docker_image_scan_repository::PostgresDockerImageScanRepository;
use hangar_infrastructure::postgres::docker_manifest_repository::PostgresDockerManifestRepository;
use hangar_infrastructure::postgres::docker_upload_session_repository::PostgresDockerUploadSessionRepository;
use hangar_infrastructure::trivy_docker_image_scanner::TrivyDockerImageScanner;
use hangar_infrastructure::postgres::event_publisher::PostgresEventPublisher;
use hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository;
use hangar_infrastructure::postgres::package_repository_store::PostgresPackageRepositoryStore;
use hangar_infrastructure::postgres::permission_store::PostgresPermissionStore;
use hangar_infrastructure::postgres::user_repository::PostgresUserRepository;
use hangar_domain::docker_registry::DockerGrantedScope;
use sqlx::PgPool;
use uuid::Uuid;

use crate::state::DockerState;

pub async fn test_state(pool: PgPool, root: &Path) -> DockerState {
    let organizations: Arc<dyn hangar_domain::organization::OrganizationRepositoryPort> = Arc::new(PostgresOrganizationRepository::new(pool.clone()));
    let repositories = Arc::new(PostgresPackageRepositoryStore::new(pool.clone(), "test-secret".to_string()));
    let permissions = Arc::new(PostgresPermissionStore::new(pool.clone()));
    let users = Arc::new(PostgresUserRepository::new(pool.clone()));
    let api_tokens = Arc::new(PostgresApiTokenRepository::new(pool.clone()));
    let blobs = Arc::new(FilesystemDockerBlobStore::new(pool.clone(), root.join("blobs")));
    let manifests = Arc::new(PostgresDockerManifestRepository::new(pool.clone()));
    let uploads = Arc::new(PostgresDockerUploadSessionRepository::new(pool.clone(), root.join("uploads")));
    let remote: Arc<dyn hangar_domain::docker_remote::RemoteDockerRegistryPort> = Arc::new(HttpRemoteDockerRegistry::new());
    let token_issuer: Arc<dyn hangar_domain::docker_registry::DockerTokenIssuerPort> = Arc::new(JwtDockerTokenIssuer::new("test-secret".to_string()));
    let events: Arc<dyn hangar_domain::audit::EventPublisherPort> = Arc::new(PostgresEventPublisher::new(pool.clone()));
    let docker_image_scans: Arc<dyn hangar_domain::docker_scan::DockerImageScanRepositoryPort> = Arc::new(PostgresDockerImageScanRepository::new(pool.clone()));
    let docker_scanner: Arc<dyn hangar_domain::docker_scan::DockerImageScannerPort> = Arc::new(TrivyDockerImageScanner::new("127.0.0.1:0".to_string()));
    let list_catalog = Arc::new(ListCatalogUseCase::new(manifests.clone()));

    DockerState {
        repositories: repositories.clone(),
        permissions: permissions.clone(),
        organizations: organizations.clone(),
        hangar_base_domain: "hangar.localhost".to_string(),
        token_issuer: token_issuer.clone(),
        token_realm: "http://localhost/v2/token".to_string(),
        token_service: "hangar".to_string(),
        issue_access_token: Arc::new(IssueDockerAccessTokenUseCase::new(api_tokens, users, repositories.clone(), permissions.clone(), token_issuer)),
        start_upload: Arc::new(StartBlobUploadUseCase::new(uploads.clone())),
        patch_upload: Arc::new(PatchBlobUploadUseCase::new(uploads.clone())),
        complete_upload: Arc::new(CompleteBlobUploadUseCase::new(uploads.clone(), blobs.clone())),
        monolithic_upload: Arc::new(MonolithicBlobUploadUseCase::new(blobs.clone())),
        put_manifest: Arc::new(PutManifestUseCase::new(manifests.clone(), blobs.clone(), repositories.clone(), events.clone())),
        cache_proxied_manifest: Arc::new(CacheProxiedManifestUseCase::new(manifests.clone())),
        get_manifest: Arc::new(GetManifestUseCase::new(manifests.clone(), repositories.clone(), remote.clone())),
        get_blob: Arc::new(GetBlobUseCase::new(blobs.clone(), manifests.clone(), repositories.clone(), remote)),
        delete_manifest: Arc::new(DeleteManifestUseCase::new(manifests.clone(), blobs, events)),
        list_tags: Arc::new(ListTagsUseCase::new(manifests.clone())),
        list_catalog,
        list_registry_catalog: Arc::new(ListDockerRegistryCatalogUseCase::new(repositories.clone(), permissions.clone(), manifests.clone())),
        scan_docker_image: Arc::new(ScanDockerImageUseCase::new(
            manifests,
            repositories,
            Arc::new(JwtDockerTokenIssuer::new("test-secret".to_string())),
            docker_scanner,
            docker_image_scans,
        )),
    }
}

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

pub async fn seed_user_with_active_token(pool: &PgPool, organization_id: Uuid, plaintext_token: &str) -> Uuid {
    let user_id = Uuid::new_v4();
    // Usernames cap at 32 chars, so truncate the UUID rather than use it whole.
    sqlx::query!(
        "INSERT INTO users (id, username, password_hash, is_super_admin, organization_id, created_at) VALUES ($1, $2, 'irrelevant', false, $3, now())",
        user_id,
        format!("user-{}", &user_id.simple().to_string()[..8]),
        organization_id,
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

pub async fn seed_organization_admin_with_active_token(pool: &PgPool, organization_id: Uuid, plaintext_token: &str) -> Uuid {
    let user_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO users (id, username, password_hash, is_super_admin, is_organization_admin, organization_id, created_at) VALUES ($1, $2, 'irrelevant', false, true, $3, now())",
        user_id,
        format!("user-{}", &user_id.simple().to_string()[..8]),
        organization_id,
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

/// Defers to `issue_test_token_for_org` with the public org and a non-super-admin holder — use that one directly when the holder's org needs to differ from the request's.
pub fn issue_test_token(state: &DockerState, user_id: Uuid, repository_id: Uuid, repository_name: &str, image_name: &str, actions: &[&str]) -> String {
    issue_test_token_for_org(state, user_id, hangar_domain::organization::PUBLIC_ORGANIZATION_ID, false, repository_id, repository_name, image_name, actions)
}

#[allow(clippy::too_many_arguments)]
pub fn issue_test_token_for_org(
    state: &DockerState,
    user_id: Uuid,
    organization_id: Uuid,
    is_super_admin: bool,
    repository_id: Uuid,
    repository_name: &str,
    image_name: &str,
    actions: &[&str],
) -> String {
    let scope = DockerGrantedScope {
        resource_type: "repository".to_string(),
        name: format!("{repository_name}/{image_name}"),
        actions: actions.iter().map(|a| a.to_string()).collect(),
        granted_repository_id: Some(repository_id),
    };
    state.token_issuer.issue(user_id, organization_id, is_super_admin, Some(scope)).unwrap()
}

pub async fn seed_permission(pool: &PgPool, user_id: Uuid, repository_id: Uuid, role: &str) {
    sqlx::query!(
        "INSERT INTO permission_projections (user_id, repository_id, role, version, updated_at) VALUES ($1, $2, $3, 1, now())",
        user_id,
        repository_id,
        role,
    )
    .execute(pool)
    .await
    .unwrap();
}

use axum::http::StatusCode;
use hangar_domain::package_repository::{PackageRepositorySummary, RepositoryFormat, RepositoryType};
use hangar_domain::permission::{Role, organization_admin_bypass_role};
use uuid::Uuid;

use crate::auth::NpmAuthUser;
use crate::state::NpmState;

pub async fn require_repository_by_name(state: &NpmState, user: &NpmAuthUser, organization_id: Uuid, name: &str) -> Result<PackageRepositorySummary, StatusCode> {
    let repo = state
        .repositories
        .find_by_org_and_name(organization_id, name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    // The repository was looked up within organization_id, but the caller's own organization
    // must also match — otherwise a stale cross-organization permission grant stays usable.
    // 404, not 403, so the caller can't tell "wrong org" from "doesn't exist".
    require_same_organization(user, repo.organization_id)?;
    Ok(repo)
}

/// Copy of `hangar_api::authz::require_same_organization` — can't share across the crate boundary.
pub fn require_same_organization(user: &NpmAuthUser, organization_id: Uuid) -> Result<(), StatusCode> {
    if user.is_super_admin || user.organization_id == organization_id {
        Ok(())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// A non-npm-format repository is unreachable through any npm route — 404, same as nonexistent.
pub fn require_npm_hosted_repository(repo: &PackageRepositorySummary) -> Result<(), StatusCode> {
    if repo.format != RepositoryFormat::Npm {
        return Err(StatusCode::NOT_FOUND);
    }
    Ok(())
}

/// Writes only make sense against a hosted repository — proxy/group have no local storage.
pub fn require_hosted(repo: &PackageRepositorySummary) -> Result<(), StatusCode> {
    if repo.repo_type != RepositoryType::Hosted {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    Ok(())
}

pub async fn require_repository_role(
    state: &NpmState,
    user: &NpmAuthUser,
    repository_id: Uuid,
    repository_organization_id: Uuid,
    minimum_role: Role,
) -> Result<(), StatusCode> {
    if user.is_super_admin {
        return Ok(());
    }
    if organization_admin_bypass_role(user.is_organization_admin, user.organization_id, repository_organization_id).is_some() {
        return Ok(());
    }
    let role = state.permissions.find_role(user.id, repository_id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match role {
        Some(role) if role.satisfies(minimum_role) => Ok(()),
        _ => Err(StatusCode::FORBIDDEN),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(is_super_admin: bool, organization_id: Uuid) -> NpmAuthUser {
        NpmAuthUser { id: Uuid::new_v4(), is_super_admin, is_organization_admin: false, organization_id }
    }

    fn repo(organization_id: Uuid, format: RepositoryFormat, repo_type: RepositoryType) -> PackageRepositorySummary {
        PackageRepositorySummary {
            id: Uuid::new_v4(),
            organization_id,
            name: "widgets".to_string(),
            format,
            repo_type,
            remote_url: None,
            remote_username: None,
            remote_password: None,
            group_members: Vec::new(),
            quota_bytes: None,
            retention_keep_last_n: None,
        }
    }

    #[test]
    fn a_member_of_the_same_organization_passes() {
        let org = Uuid::new_v4();
        assert!(require_same_organization(&user(false, org), org).is_ok());
    }

    #[test]
    fn a_super_admin_passes_for_a_different_organization() {
        assert!(require_same_organization(&user(true, Uuid::new_v4()), Uuid::new_v4()).is_ok());
    }

    #[test]
    fn a_member_of_a_different_organization_is_rejected_with_not_found() {
        let org = Uuid::new_v4();
        let err = require_same_organization(&user(false, Uuid::new_v4()), org).unwrap_err();
        assert_eq!(err, StatusCode::NOT_FOUND);
    }

    #[test]
    fn an_npm_format_repository_passes_require_npm_hosted_repository() {
        let r = repo(Uuid::new_v4(), RepositoryFormat::Npm, RepositoryType::Hosted);
        assert!(require_npm_hosted_repository(&r).is_ok());
    }

    #[test]
    fn a_docker_format_repository_is_unreachable_through_npm_routes() {
        let r = repo(Uuid::new_v4(), RepositoryFormat::Docker, RepositoryType::Hosted);
        let err = require_npm_hosted_repository(&r).unwrap_err();
        assert_eq!(err, StatusCode::NOT_FOUND);
    }

    #[test]
    fn a_hosted_repository_passes_require_hosted() {
        let r = repo(Uuid::new_v4(), RepositoryFormat::Npm, RepositoryType::Hosted);
        assert!(require_hosted(&r).is_ok());
    }

    #[test]
    fn a_proxy_repository_is_rejected_by_require_hosted() {
        let r = repo(Uuid::new_v4(), RepositoryFormat::Npm, RepositoryType::Proxy);
        let err = require_hosted(&r).unwrap_err();
        assert_eq!(err, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn a_group_repository_is_rejected_by_require_hosted() {
        let r = repo(Uuid::new_v4(), RepositoryFormat::Npm, RepositoryType::Group);
        let err = require_hosted(&r).unwrap_err();
        assert_eq!(err, StatusCode::METHOD_NOT_ALLOWED);
    }

    // require_repository_by_name needs a real repository lookup, so these run against Postgres.
    mod db {
        use super::*;
        use hangar_application::use_cases::api_token::{CreateApiTokenUseCase, ListApiTokensUseCase, RevokeApiTokenUseCase};
        use hangar_application::use_cases::npm_audit::BulkAuditNpmPackagesUseCase;
        use hangar_application::use_cases::npm_dependency_scan::ScanDependencyTreeUseCase;
        use hangar_application::use_cases::npm_deprecate::DeprecateNpmVersionUseCase;
        use hangar_application::use_cases::npm_dist_tags::{DeleteDistTagUseCase, ListDistTagsUseCase, SetDistTagUseCase};
        use hangar_application::use_cases::npm_download::DownloadNpmTarballUseCase;
        use hangar_application::use_cases::npm_metadata::GetNpmPackageMetadataUseCase;
        use hangar_application::use_cases::npm_publish::PublishNpmPackageUseCase;
        use hangar_application::use_cases::npm_search::SearchNpmPackagesUseCase;
        use hangar_application::use_cases::npm_unpublish::UnpublishNpmPackageUseCase;
        use hangar_infrastructure::filesystem_storage::FilesystemStorageBackend;
        use hangar_infrastructure::http_npm_audit_client::HttpNpmAuditClient;
        use hangar_infrastructure::http_remote_npm_registry::HttpRemoteNpmRegistry;
        use hangar_infrastructure::postgres::api_token_repository::PostgresApiTokenRepository;
        use hangar_infrastructure::postgres::npm_dependency_audit_repository::PostgresDependencyAuditRepository;
        use hangar_infrastructure::postgres::npm_package_repository::PostgresNpmPackageRepository;
        use hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository;
        use hangar_infrastructure::postgres::package_repository_store::PostgresPackageRepositoryStore;
        use hangar_infrastructure::postgres::permission_store::PostgresPermissionStore;
        use hangar_infrastructure::postgres::user_repository::PostgresUserRepository;
        use hangar_infrastructure::postgres::event_publisher::PostgresEventPublisher;
        use hangar_domain::organization::{Organization, OrganizationSlug};
        use sqlx::PgPool;
        use std::sync::Arc;

        async fn test_state(pool: PgPool, root: &std::path::Path) -> NpmState {
            let users = Arc::new(PostgresUserRepository::new(pool.clone()));
            let repositories = Arc::new(PostgresPackageRepositoryStore::new(pool.clone(), "test-secret".to_string()));
            let permissions = Arc::new(PostgresPermissionStore::new(pool.clone()));
            let api_tokens: Arc<dyn hangar_domain::api_token::ApiTokenRepositoryPort> = Arc::new(PostgresApiTokenRepository::new(pool.clone()));
            let organizations: Arc<dyn hangar_domain::organization::OrganizationRepositoryPort> = Arc::new(PostgresOrganizationRepository::new(pool.clone()));
            let npm_packages: Arc<dyn hangar_domain::npm_package::NpmPackageRepositoryPort> = Arc::new(PostgresNpmPackageRepository::new(pool.clone()));
            let npm_audit: Arc<dyn hangar_domain::npm_audit::NpmAuditPort> = Arc::new(HttpNpmAuditClient::new());
            let dependency_audits: Arc<dyn hangar_domain::npm_audit::DependencyAuditRepositoryPort> = Arc::new(PostgresDependencyAuditRepository::new(pool.clone()));
            let storage: Arc<dyn hangar_domain::storage::StorageBackendPort> = Arc::new(FilesystemStorageBackend::new(root.to_path_buf()));
            let events: Arc<dyn hangar_domain::audit::EventPublisherPort> = Arc::new(PostgresEventPublisher::new(pool.clone()));
            let remote_registry: Arc<dyn hangar_domain::npm_remote::RemoteNpmRegistryPort> = Arc::new(HttpRemoteNpmRegistry::new());

            NpmState {
                users: users.clone(),
                repositories: repositories.clone(),
                permissions: permissions.clone(),
                api_tokens: api_tokens.clone(),
                organizations: organizations.clone(),
                hangar_base_domain: "hangar.localhost".to_string(),
                publish: Arc::new(PublishNpmPackageUseCase::new(npm_packages.clone(), storage.clone(), repositories.clone(), events.clone())),
                metadata: Arc::new(GetNpmPackageMetadataUseCase::new(npm_packages.clone(), repositories.clone(), remote_registry.clone())),
                download: Arc::new(DownloadNpmTarballUseCase::new(npm_packages.clone(), storage.clone(), remote_registry.clone(), repositories.clone())),
                unpublish: Arc::new(UnpublishNpmPackageUseCase::new(npm_packages.clone(), storage.clone(), events.clone())),
                deprecate: Arc::new(DeprecateNpmVersionUseCase::new(npm_packages.clone(), events.clone())),
                set_dist_tag: Arc::new(SetDistTagUseCase::new(npm_packages.clone(), events.clone())),
                delete_dist_tag: Arc::new(DeleteDistTagUseCase::new(npm_packages.clone())),
                list_dist_tags: Arc::new(ListDistTagsUseCase::new(npm_packages.clone())),
                search: Arc::new(SearchNpmPackagesUseCase::new(npm_packages.clone())),
                bulk_audit: Arc::new(BulkAuditNpmPackagesUseCase::new(npm_audit.clone())),
                scan_dependency_tree: Arc::new(ScanDependencyTreeUseCase::new(npm_packages.clone(), remote_registry.clone(), npm_audit.clone(), dependency_audits.clone())),
                create_api_token: Arc::new(CreateApiTokenUseCase::new(api_tokens.clone())),
                list_api_tokens: Arc::new(ListApiTokensUseCase::new(api_tokens.clone())),
                revoke_api_token: Arc::new(RevokeApiTokenUseCase::new(api_tokens.clone())),
            }
        }

        /// Every repository seeded below needs a real organization row (foreign key).
        async fn create_org(state: &NpmState, id: Uuid, slug: &str) {
            state
                .organizations
                .create(&Organization {
                    id,
                    slug: OrganizationSlug::parse(slug).unwrap(),
                    display_name: slug.to_string(),
                    is_public: false,
                    created_at: chrono::Utc::now(),
                })
                .await
                .unwrap();
        }

        async fn seed_repository(pool: &PgPool, organization_id: Uuid, id: Uuid, format: &str, repo_type: &str) {
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

        #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
        async fn a_repository_in_the_callers_own_organization_is_returned(pool: PgPool) {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state(pool.clone(), dir.path()).await;
            let org_id = Uuid::new_v4();
            create_org(&state, org_id, "acme").await;
            let repo_id = Uuid::new_v4();
            seed_repository(&pool, org_id, repo_id, "npm", "hosted").await;
            let repo_name = format!("repo-{repo_id}");
            let caller = user(false, org_id);

            let found = require_repository_by_name(&state, &caller, org_id, &repo_name).await.unwrap();
            assert_eq!(found.id, repo_id);
        }

        #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
        async fn a_nonexistent_repository_is_not_found(pool: PgPool) {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state(pool.clone(), dir.path()).await;
            let caller = user(false, Uuid::new_v4());
            let err = require_repository_by_name(&state, &caller, Uuid::new_v4(), "does-not-exist").await.unwrap_err();
            assert_eq!(err, StatusCode::NOT_FOUND);
        }

        #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
        async fn a_caller_from_a_different_organization_is_rejected_even_though_the_repository_exists(pool: PgPool) {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state(pool.clone(), dir.path()).await;
            let acme_id = Uuid::new_v4();
            create_org(&state, acme_id, "acme").await;
            let repo_id = Uuid::new_v4();
            seed_repository(&pool, acme_id, repo_id, "npm", "hosted").await;
            let repo_name = format!("repo-{repo_id}");
            let other_org_caller = user(false, Uuid::new_v4());

            let err = require_repository_by_name(&state, &other_org_caller, acme_id, &repo_name).await.unwrap_err();
            assert_eq!(err, StatusCode::NOT_FOUND);
        }

        #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
        async fn a_super_admin_can_reach_a_repository_outside_their_own_organization(pool: PgPool) {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state(pool.clone(), dir.path()).await;
            let acme_id = Uuid::new_v4();
            create_org(&state, acme_id, "acme").await;
            let repo_id = Uuid::new_v4();
            seed_repository(&pool, acme_id, repo_id, "npm", "hosted").await;
            let repo_name = format!("repo-{repo_id}");
            let super_admin = user(true, Uuid::new_v4());

            let found = require_repository_by_name(&state, &super_admin, acme_id, &repo_name).await.unwrap();
            assert_eq!(found.id, repo_id);
        }
    }
}

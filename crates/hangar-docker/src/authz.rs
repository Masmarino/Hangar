use axum::http::StatusCode;
use hangar_domain::package_repository::{PackageRepositorySummary, RepositoryFormat, RepositoryType};
use uuid::Uuid;

use crate::auth::DockerAuthUser;
use crate::state::DockerState;

pub async fn require_repository_by_name(state: &DockerState, user: &DockerAuthUser, organization_id: Uuid, name: &str) -> Result<PackageRepositorySummary, StatusCode> {
    let repo = state
        .repositories
        .find_by_org_and_name(organization_id, name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    // The repository was looked up within organization_id, but the token holder's own org must also match, or a stale cross-org grant stays usable. 404, not 403.
    require_same_organization(user, repo.organization_id)?;
    Ok(repo)
}

/// Copy of `hangar_api::authz::require_same_organization` — can't share across the crate boundary.
pub fn require_same_organization(user: &DockerAuthUser, organization_id: Uuid) -> Result<(), StatusCode> {
    if user.is_super_admin || user.organization_id == organization_id {
        Ok(())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// A non-docker-format repository is unreachable through any docker route.
pub fn require_docker_repository(repo: &PackageRepositorySummary) -> Result<(), StatusCode> {
    if repo.format != RepositoryFormat::Docker {
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

/// Checks the token's already-granted scope, not the image-name segment. `resolved_repository_id` also has to match, not just the name — names are only unique per-org, so a
/// name-only check would let a token for one org's "backend" repo validate against another org's same-named one.
pub fn require_granted_action(user: &DockerAuthUser, resolved_repository_id: Uuid, repository_name: &str, action: &str) -> Result<(), StatusCode> {
    let scope = user.granted_scope.as_ref().ok_or(StatusCode::FORBIDDEN)?;
    let scope_repository = scope.name.split('/').next().unwrap_or(&scope.name);
    if scope_repository != repository_name || !scope.actions.iter().any(|a| a == action) {
        return Err(StatusCode::FORBIDDEN);
    }
    if scope.granted_repository_id != Some(resolved_repository_id) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_domain::docker_registry::DockerGrantedScope;

    fn user(is_super_admin: bool, organization_id: Uuid) -> DockerAuthUser {
        DockerAuthUser { user_id: Uuid::new_v4(), is_super_admin, organization_id, granted_scope: None }
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
    fn a_docker_format_repository_passes_require_docker_repository() {
        let r = repo(Uuid::new_v4(), RepositoryFormat::Docker, RepositoryType::Hosted);
        assert!(require_docker_repository(&r).is_ok());
    }

    #[test]
    fn an_npm_format_repository_is_unreachable_through_docker_routes() {
        let r = repo(Uuid::new_v4(), RepositoryFormat::Npm, RepositoryType::Hosted);
        let err = require_docker_repository(&r).unwrap_err();
        assert_eq!(err, StatusCode::NOT_FOUND);
    }

    #[test]
    fn a_hosted_repository_passes_require_hosted() {
        let r = repo(Uuid::new_v4(), RepositoryFormat::Docker, RepositoryType::Hosted);
        assert!(require_hosted(&r).is_ok());
    }

    #[test]
    fn a_proxy_repository_is_rejected_by_require_hosted() {
        let r = repo(Uuid::new_v4(), RepositoryFormat::Docker, RepositoryType::Proxy);
        let err = require_hosted(&r).unwrap_err();
        assert_eq!(err, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn a_group_repository_is_rejected_by_require_hosted() {
        let r = repo(Uuid::new_v4(), RepositoryFormat::Docker, RepositoryType::Group);
        let err = require_hosted(&r).unwrap_err();
        assert_eq!(err, StatusCode::METHOD_NOT_ALLOWED);
    }

    // require_repository_by_name needs a real repository lookup, so these run against Postgres.
    mod db {
        use super::*;
        use crate::route_test_support::{seed_repository, test_state};
        use hangar_domain::organization::{Organization, OrganizationSlug};
        use sqlx::PgPool;

        async fn create_org(state: &DockerState, id: Uuid, slug: &str) {
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

        #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
        async fn a_repository_in_the_callers_own_organization_is_returned(pool: PgPool) {
            let dir = tempfile::tempdir().unwrap();
            let state = test_state(pool.clone(), dir.path()).await;
            let org_id = Uuid::new_v4();
            create_org(&state, org_id, "acme").await;
            let repo_id = Uuid::new_v4();
            seed_repository(&pool, org_id, repo_id, "docker", "hosted").await;
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
            seed_repository(&pool, acme_id, repo_id, "docker", "hosted").await;
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
            seed_repository(&pool, acme_id, repo_id, "docker", "hosted").await;
            let repo_name = format!("repo-{repo_id}");
            let super_admin = user(true, Uuid::new_v4());

            let found = require_repository_by_name(&state, &super_admin, acme_id, &repo_name).await.unwrap();
            assert_eq!(found.id, repo_id);
        }
    }

    #[test]
    fn a_granted_scope_for_a_different_repository_id_is_rejected_even_with_a_matching_name() {
        let repo_a_id = Uuid::new_v4();
        let repo_b_id = Uuid::new_v4();
        let user = DockerAuthUser {
            user_id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            is_super_admin: false,
            granted_scope: Some(DockerGrantedScope {
                resource_type: "repository".to_string(),
                name: "backend/image".to_string(),
                actions: vec!["pull".to_string()],
                granted_repository_id: Some(repo_a_id),
            }),
        };

        // Same name ("backend") but a different resolved repository id.
        let result = require_granted_action(&user, repo_b_id, "backend", "pull");

        assert_eq!(result, Err(StatusCode::FORBIDDEN));
    }

    #[test]
    fn a_granted_scope_for_the_matching_repository_id_and_name_is_accepted() {
        let repo_id = Uuid::new_v4();
        let user = DockerAuthUser {
            user_id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            is_super_admin: false,
            granted_scope: Some(DockerGrantedScope {
                resource_type: "repository".to_string(),
                name: "backend/image".to_string(),
                actions: vec!["pull".to_string()],
                granted_repository_id: Some(repo_id),
            }),
        };

        let result = require_granted_action(&user, repo_id, "backend", "pull");

        assert!(result.is_ok());
    }
}

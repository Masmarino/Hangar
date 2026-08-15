use axum::http::StatusCode;
use hangar_domain::audit::SecurityEvent;
use hangar_domain::permission::{Role, organization_admin_bypass_role};
use uuid::Uuid;

use crate::auth_middleware::AuthUser;
use crate::state::AppState;

/// The caller's effective role on a repository: `Admin` for a super-admin or that org's own admin, otherwise whatever was explicitly granted. Single source of truth — every authz
/// check and every `my_role` response must go through this, not a separate lookup.
pub async fn effective_repository_role(state: &AppState, user: &AuthUser, repository_id: Uuid) -> Result<Option<Role>, StatusCode> {
    if user.is_super_admin {
        return Ok(Some(Role::Admin));
    }

    if user.is_organization_admin {
        let repo = state.repositories.find_by_id(repository_id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if let Some(role) = repo.and_then(|r| organization_admin_bypass_role(user.is_organization_admin, user.organization_id, r.organization_id)) {
            return Ok(Some(role));
        }
    }

    state.permissions.find_role(user.id, repository_id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn require_repository_role(
    state: &AppState,
    user: &AuthUser,
    repository_id: Uuid,
    minimum_role: Role,
    action: &str,
) -> Result<(), StatusCode> {
    let role = effective_repository_role(state, user, repository_id).await?;

    match role {
        Some(role) if role.satisfies(minimum_role) => Ok(()),
        _ => {
            let _ = state
                .record_security_event
                .execute(SecurityEvent::AccessDenied { user_id: user.id, repository_id, action: action.to_string() }, Some(user.id))
                .await;
            Err(StatusCode::FORBIDDEN)
        }
    }
}

pub fn require_super_admin(user: &AuthUser) -> Result<(), StatusCode> {
    if user.is_super_admin {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

pub fn require_same_organization(user: &AuthUser, organization_id: Uuid) -> Result<(), StatusCode> {
    if user.is_super_admin || user.organization_id == organization_id {
        Ok(())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// Super-admin, or that organization's own admin — the authorization shape shared by every "an organization configures its own X" route (branding, identity provider config).
pub fn require_organization_admin(user: &AuthUser, organization_id: Uuid) -> Result<(), StatusCode> {
    require_super_admin(user).or_else(|_| {
        require_same_organization(user, organization_id)?;
        if user.is_organization_admin {
            Ok(())
        } else {
            Err(StatusCode::FORBIDDEN)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn user(is_super_admin: bool, is_organization_admin: bool, organization_id: Uuid) -> AuthUser {
        AuthUser { id: Uuid::new_v4(), username: "test".to_string(), is_super_admin, is_organization_admin, organization_id, created_at: Utc::now() }
    }

    #[test]
    fn a_super_admin_passes_regardless_of_organization() {
        let target_org = Uuid::new_v4();
        assert!(require_organization_admin(&user(true, false, Uuid::new_v4()), target_org).is_ok());
    }

    #[test]
    fn that_organizations_own_admin_passes() {
        let org = Uuid::new_v4();
        assert!(require_organization_admin(&user(false, true, org), org).is_ok());
    }

    #[test]
    fn a_regular_member_of_that_organization_is_rejected() {
        let org = Uuid::new_v4();
        assert!(require_organization_admin(&user(false, false, org), org).is_err());
    }

    #[test]
    fn an_admin_of_a_different_organization_is_rejected() {
        let org = Uuid::new_v4();
        assert!(require_organization_admin(&user(false, true, Uuid::new_v4()), org).is_err());
    }

    #[test]
    fn a_non_admin_of_a_different_organization_gets_not_found_not_forbidden() {
        let org = Uuid::new_v4();
        let err = require_organization_admin(&user(false, false, Uuid::new_v4()), org).unwrap_err();
        assert_eq!(err, StatusCode::NOT_FOUND);
    }
}

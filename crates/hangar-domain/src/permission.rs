use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{DomainError, EventStoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Read,
    Write,
    Admin,
}

impl Role {
    pub fn satisfies(&self, required: Role) -> bool {
        self.rank() >= required.rank()
    }

    fn rank(&self) -> u8 {
        match self {
            Role::Read => 1,
            Role::Write => 2,
            Role::Admin => 3,
        }
    }
}

/// The `Admin` role an org's own admin implicitly holds on every repository in that org — the
/// same bypass a super-admin gets globally. One pure predicate so the rule can't drift between
/// hangar-api, hangar-npm, and hangar-docker, which each have their own caller/state types.
pub fn organization_admin_bypass_role(is_organization_admin: bool, caller_organization_id: Uuid, resource_organization_id: Uuid) -> Option<Role> {
    if is_organization_admin && caller_organization_id == resource_organization_id { Some(Role::Admin) } else { None }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum PermissionEvent {
    Granted { user_id: Uuid, repository_id: Uuid, role: Role },
    Revoked { user_id: Uuid, repository_id: Uuid },
}

impl PermissionEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            PermissionEvent::Granted { .. } => "Granted",
            PermissionEvent::Revoked { .. } => "Revoked",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Permission {
    pub role: Option<Role>,
}

impl Permission {
    pub fn from_events(events: &[PermissionEvent]) -> Self {
        let mut state = Self::default();
        for event in events {
            state.apply(event);
        }
        state
    }

    pub fn apply(&mut self, event: &PermissionEvent) {
        match event {
            PermissionEvent::Granted { role, .. } => self.role = Some(*role),
            PermissionEvent::Revoked { .. } => self.role = None,
        }
    }

    pub fn grant(&self, user_id: Uuid, repository_id: Uuid, role: Role) -> PermissionEvent {
        PermissionEvent::Granted { user_id, repository_id, role }
    }

    pub fn revoke(&self, user_id: Uuid, repository_id: Uuid) -> Result<PermissionEvent, DomainError> {
        if self.role.is_none() {
            return Err(DomainError::NothingToRevoke);
        }
        Ok(PermissionEvent::Revoked { user_id, repository_id })
    }
}

#[async_trait]
pub trait PermissionEventStorePort: Send + Sync {
    /// Returns the current version (0 if the stream doesn't exist yet) and its events.
    async fn load(&self, user_id: Uuid, repository_id: Uuid) -> Result<(u64, Vec<PermissionEvent>), EventStoreError>;

    async fn append(
        &self,
        user_id: Uuid,
        repository_id: Uuid,
        expected_version: u64,
        events: Vec<PermissionEvent>,
        actor_id: Uuid,
    ) -> Result<(), EventStoreError>;
}

#[async_trait]
pub trait PermissionQueryPort: Send + Sync {
    async fn find_role(&self, user_id: Uuid, repository_id: Uuid) -> Result<Option<Role>, EventStoreError>;
    async fn list_for_repository(&self, repository_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError>;
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<(Uuid, Role)>, EventStoreError>;
    /// Every grant across the instance in one query, instead of `list_for_repository` per repository.
    async fn list_all(&self) -> Result<Vec<(Uuid, Uuid, Role)>, EventStoreError>;
    async fn count_all(&self) -> Result<usize, EventStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DomainError;
    use uuid::Uuid;

    #[test]
    fn starts_with_no_role() {
        let permission = Permission::from_events(&[]);
        assert_eq!(permission.role, None);
    }

    #[test]
    fn granting_sets_the_role() {
        let user_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let permission = Permission::from_events(&[]);
        let event = permission.grant(user_id, repository_id, Role::Write);
        let permission = Permission::from_events(&[event]);
        assert_eq!(permission.role, Some(Role::Write));
    }

    #[test]
    fn granting_twice_keeps_the_latest_role() {
        let user_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let e1 = PermissionEvent::Granted { user_id, repository_id, role: Role::Read };
        let e2 = PermissionEvent::Granted { user_id, repository_id, role: Role::Admin };
        let permission = Permission::from_events(&[e1, e2]);
        assert_eq!(permission.role, Some(Role::Admin));
    }

    #[test]
    fn revoking_clears_the_role() {
        let user_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let granted = PermissionEvent::Granted { user_id, repository_id, role: Role::Read };
        let permission = Permission::from_events(&[granted]);
        let event = permission.revoke(user_id, repository_id).unwrap();
        let permission = Permission::from_events(&[granted, event]);
        assert_eq!(permission.role, None);
    }

    #[test]
    fn revoking_without_a_role_fails() {
        let permission = Permission::from_events(&[]);
        let err = permission.revoke(Uuid::new_v4(), Uuid::new_v4()).unwrap_err();
        assert!(matches!(err, DomainError::NothingToRevoke));
    }

    #[test]
    fn an_organization_admin_of_the_same_organization_gets_the_implicit_admin_role() {
        let org = Uuid::new_v4();
        assert_eq!(organization_admin_bypass_role(true, org, org), Some(Role::Admin));
    }

    #[test]
    fn an_organization_admin_of_a_different_organization_gets_no_implicit_role() {
        assert_eq!(organization_admin_bypass_role(true, Uuid::new_v4(), Uuid::new_v4()), None);
    }

    #[test]
    fn a_non_admin_member_of_the_same_organization_gets_no_implicit_role() {
        let org = Uuid::new_v4();
        assert_eq!(organization_admin_bypass_role(false, org, org), None);
    }
}

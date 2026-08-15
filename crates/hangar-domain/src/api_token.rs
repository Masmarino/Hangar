use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainError;

#[derive(Debug, Clone)]
pub struct ApiToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ApiToken {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

#[async_trait]
pub trait ApiTokenRepositoryPort: Send + Sync {
    async fn insert(&self, token: &ApiToken) -> Result<(), DomainError>;
    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ApiToken>, DomainError>;
    /// Every token across every user, including revoked ones (for admin oversight).
    async fn list_all(&self) -> Result<Vec<ApiToken>, DomainError>;
    async fn find_by_hash(&self, token_hash: &str) -> Result<Option<ApiToken>, DomainError>;
    async fn touch_last_used_at(&self, id: Uuid, used_at: DateTime<Utc>) -> Result<(), DomainError>;
    /// Returns `true` if a token owned by `user_id` was actually revoked, `false` if
    /// no row matched (unknown id, or a token owned by someone else) — callers must
    /// not treat that as success.
    async fn revoke(&self, id: Uuid, user_id: Uuid) -> Result<bool, DomainError>;
    /// Admin override — revokes regardless of owner.
    async fn revoke_any(&self, id: Uuid) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_without_a_revocation_date_is_active() {
        let token = ApiToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token_hash: "hash".to_string(),
            label: "my laptop".to_string(),
            created_at: Utc::now(),
            last_used_at: None,
            revoked_at: None,
        };
        assert!(token.is_active());
    }

    #[test]
    fn a_revoked_token_is_not_active() {
        let token = ApiToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token_hash: "hash".to_string(),
            label: "my laptop".to_string(),
            created_at: Utc::now(),
            last_used_at: None,
            revoked_at: Some(Utc::now()),
        };
        assert!(!token.is_active());
    }
}

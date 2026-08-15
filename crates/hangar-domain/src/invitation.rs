use std::collections::HashSet;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainError;

/// A row's presence means the account hasn't activated yet — it has an unusable placeholder password hash. Deleted once activation succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInvitation {
    pub user_id: Uuid,
    /// SHA-256 hex digest of the mailed token — the raw token is never stored.
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait UserInvitationPort: Send + Sync {
    async fn upsert(&self, invitation: &UserInvitation) -> Result<(), DomainError>;
    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<UserInvitation>, DomainError>;
    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<UserInvitation>, DomainError>;
    /// Batched form of `find_by_user_id`: which of these users have a pending invitation.
    async fn list_pending_user_ids(&self, user_ids: &[Uuid]) -> Result<HashSet<Uuid>, DomainError>;
    async fn delete(&self, user_id: Uuid) -> Result<(), DomainError>;
}

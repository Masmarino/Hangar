use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::DomainError;

/// `confirmed = false` means enrolled but not yet verified — only a confirmed credential is consulted at login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCredential {
    pub user_id: Uuid,
    /// Plaintext at this layer — encryption at rest is the Postgres adapter's job.
    pub secret: String,
    pub confirmed: bool,
    /// Anti-replay: `VerifyTotpUseCase` rejects any code whose step isn't strictly greater than this.
    pub last_used_step: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[async_trait]
pub trait TotpCredentialPort: Send + Sync {
    async fn get(&self, user_id: Uuid) -> Result<Option<TotpCredential>, DomainError>;
    async fn upsert(&self, credential: &TotpCredential) -> Result<(), DomainError>;
    /// Atomically advances `last_used_step` only if `step` is newer — `false` means a concurrent call already claimed it.
    async fn set_last_used_step(&self, user_id: Uuid, step: i64) -> Result<bool, DomainError>;
    async fn delete(&self, user_id: Uuid) -> Result<(), DomainError>;
}

#[async_trait]
pub trait BackupCodePort: Send + Sync {
    /// Replaces the whole set — invalidates every prior code.
    async fn replace_all(&self, user_id: Uuid, code_hashes: &[String]) -> Result<(), DomainError>;
    /// Atomic: `true` only if the code existed and was still unused, so two concurrent attempts can't both succeed.
    async fn try_consume(&self, user_id: Uuid, code_hash: &str) -> Result<bool, DomainError>;
    async fn count_unused(&self, user_id: Uuid) -> Result<i64, DomainError>;
    async fn delete_all(&self, user_id: Uuid) -> Result<(), DomainError>;
}

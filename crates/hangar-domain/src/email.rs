use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpSecurity {
    None,
    StartTls,
    Tls,
}

/// Kept separate from `SystemSettings` so `password` never rides along in a settings row that gets echoed back over HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpSettings {
    pub host: String,
    pub port: i32,
    pub username: String,
    /// Plaintext at this layer — encryption at rest is the Postgres adapter's job.
    pub password: String,
    pub from_name: String,
    pub from_address: String,
    pub security: SmtpSecurity,
}

#[async_trait]
pub trait SmtpSettingsPort: Send + Sync {
    /// `None` means never configured — treat as disabled, not an error.
    async fn get(&self, organization_id: Uuid) -> Result<Option<SmtpSettings>, DomainError>;
    async fn update(&self, organization_id: Uuid, settings: &SmtpSettings) -> Result<(), DomainError>;
}

#[async_trait]
pub trait EmailPort: Send + Sync {
    async fn send(&self, organization_id: Uuid, to: &str, subject: &str, text_body: &str, html_body: &str) -> Result<(), DomainError>;
}

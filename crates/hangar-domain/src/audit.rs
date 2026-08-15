use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::EventStoreError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum SecurityEvent {
    LoginFailed { username: String, ip: String },
    AccessDenied { user_id: Uuid, repository_id: Uuid, action: String },
    PasswordChangeFailed { username: String, ip: String },
}

impl SecurityEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            SecurityEvent::LoginFailed { .. } => "LoginFailed",
            SecurityEvent::AccessDenied { .. } => "AccessDenied",
            SecurityEvent::PasswordChangeFailed { .. } => "PasswordChangeFailed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum NpmPackageEvent {
    PackagePushed { package_name: String, version: String },
    PackageVersionUnpublished { package_name: String, version: String },
    PackageDeleted { package_name: String },
    PackageVersionDeprecated { package_name: String, version: String, message: Option<String> },
    DistTagChanged { package_name: String, tag: String, version: String },
}

impl NpmPackageEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            NpmPackageEvent::PackagePushed { .. } => "PackagePushed",
            NpmPackageEvent::PackageVersionUnpublished { .. } => "PackageVersionUnpublished",
            NpmPackageEvent::PackageDeleted { .. } => "PackageDeleted",
            NpmPackageEvent::PackageVersionDeprecated { .. } => "PackageVersionDeprecated",
            NpmPackageEvent::DistTagChanged { .. } => "DistTagChanged",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type")]
pub enum DockerRegistryEvent {
    ImagePushed { image_name: String, digest: String },
    ManifestDeleted { image_name: String, digest: String },
}

impl DockerRegistryEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            DockerRegistryEvent::ImagePushed { .. } => "ImagePushed",
            DockerRegistryEvent::ManifestDeleted { .. } => "ManifestDeleted",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub occurred_at: DateTime<Utc>,
    pub actor_id: Option<Uuid>,
}

#[derive(Debug, Clone, Default)]
pub struct AuditQueryFilter {
    pub aggregate_type: Option<String>,
    /// Applied at the SQL level, before `LIMIT`.
    pub exclude_aggregate_type: Option<String>,
    pub aggregate_id: Option<String>,
    pub actor_id: Option<Uuid>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait EventPublisherPort: Send + Sync {
    async fn publish_security_event(&self, event: SecurityEvent, actor_id: Option<Uuid>) -> Result<(), EventStoreError>;
    async fn query_audit_log(&self, filter: AuditQueryFilter) -> Result<Vec<AuditEntry>, EventStoreError>;
    async fn publish_npm_event(
        &self,
        event: NpmPackageEvent,
        npm_package_id: uuid::Uuid,
        actor_id: Option<uuid::Uuid>,
    ) -> Result<(), EventStoreError>;
    async fn publish_docker_event(
        &self,
        event: DockerRegistryEvent,
        package_repository_id: uuid::Uuid,
        actor_id: Option<uuid::Uuid>,
    ) -> Result<(), EventStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_event_round_trips_through_json() {
        let event = SecurityEvent::LoginFailed { username: "florian".to_string(), ip: "127.0.0.1".to_string() };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: SecurityEvent = serde_json::from_str(&json).unwrap();
        match decoded {
            SecurityEvent::LoginFailed { username, ip } => {
                assert_eq!(username, "florian");
                assert_eq!(ip, "127.0.0.1");
            }
            _ => panic!("expected LoginFailed"),
        }
    }

    #[test]
    fn default_audit_filter_has_no_constraints() {
        let filter = AuditQueryFilter::default();
        assert!(filter.aggregate_type.is_none());
        assert!(filter.exclude_aggregate_type.is_none());
        assert!(filter.aggregate_id.is_none());
        assert!(filter.actor_id.is_none());
        assert!(filter.from.is_none());
        assert!(filter.to.is_none());
    }
}

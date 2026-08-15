use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;

/// Singleton, admin-editable at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemSettings {
    pub max_login_attempts: i32,
    pub login_attempt_window_seconds: i32,
    pub session_ttl_hours: i32,
    /// Gates `POST /api/auth/register` — independent of an organization being public,
    /// which already gates it too. Defaults to `true` (unchanged historical behavior) so an
    /// export/import bundle from before this field existed still enables registration.
    #[serde(default = "default_registration_enabled")]
    pub registration_enabled: bool,
}

fn default_registration_enabled() -> bool {
    true
}

impl SystemSettings {
    pub const fn defaults() -> Self {
        Self { max_login_attempts: 10, login_attempt_window_seconds: 300, session_ttl_hours: 12, registration_enabled: true }
    }
}

#[async_trait]
pub trait SystemSettingsPort: Send + Sync {
    async fn get(&self, organization_id: Uuid) -> Result<SystemSettings, DomainError>;
    async fn update(&self, organization_id: Uuid, settings: &SystemSettings) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_original_hardcoded_values() {
        let defaults = SystemSettings::defaults();
        assert_eq!(defaults.max_login_attempts, 10);
        assert_eq!(defaults.login_attempt_window_seconds, 300);
        assert_eq!(defaults.session_ttl_hours, 12);
        assert!(defaults.registration_enabled);
    }

    /// An export bundle saved before this field existed must still deserialize — and
    /// registration must come back enabled, not silently disabled by a missing field.
    #[test]
    fn deserializing_without_registration_enabled_defaults_it_to_true() {
        let json = r#"{"max_login_attempts":10,"login_attempt_window_seconds":300,"session_ttl_hours":12}"#;
        let settings: SystemSettings = serde_json::from_str(json).unwrap();
        assert!(settings.registration_enabled);
    }
}

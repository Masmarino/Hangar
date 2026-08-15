use std::sync::Arc;

use hangar_domain::email::{EmailPort, SmtpSecurity, SmtpSettings, SmtpSettingsPort};

use crate::error::ApplicationError;

/// What `GetSmtpSettingsUseCase` returns — the password itself never leaves this layer. `password_set` is all a caller needs to render a "leave blank to keep it" field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpSettingsView {
    pub host: String,
    pub port: i32,
    pub username: String,
    pub from_name: String,
    pub from_address: String,
    pub security: SmtpSecurity,
    pub password_set: bool,
}

pub struct GetSmtpSettingsUseCase {
    settings: Arc<dyn SmtpSettingsPort>,
}

impl GetSmtpSettingsUseCase {
    pub fn new(settings: Arc<dyn SmtpSettingsPort>) -> Self {
        Self { settings }
    }

    pub async fn execute(&self, organization_id: uuid::Uuid) -> Result<Option<SmtpSettingsView>, ApplicationError> {
        let Some(settings) = self.settings.get(organization_id).await? else {
            return Ok(None);
        };
        Ok(Some(SmtpSettingsView {
            host: settings.host,
            port: settings.port,
            username: settings.username,
            from_name: settings.from_name,
            from_address: settings.from_address,
            security: settings.security,
            password_set: true,
        }))
    }
}

/// `password: None` means "keep the currently stored password" — the leave-blank-to-keep UX the admin UI relies on. Required on the very first configuration, since there's nothing yet to keep.
pub struct UpdateSmtpSettingsInput {
    pub host: String,
    pub port: i32,
    pub username: String,
    pub password: Option<String>,
    pub from_name: String,
    pub from_address: String,
    pub security: SmtpSecurity,
}

pub struct UpdateSmtpSettingsUseCase {
    settings: Arc<dyn SmtpSettingsPort>,
}

impl UpdateSmtpSettingsUseCase {
    pub fn new(settings: Arc<dyn SmtpSettingsPort>) -> Self {
        Self { settings }
    }

    pub async fn execute(&self, organization_id: uuid::Uuid, input: UpdateSmtpSettingsInput) -> Result<(), ApplicationError> {
        if input.host.trim().is_empty() {
            return Err(ApplicationError::InvalidSmtpSettings("host must not be empty".to_string()));
        }
        if !(1..=65_535).contains(&input.port) {
            return Err(ApplicationError::InvalidSmtpSettings("port must be between 1 and 65535".to_string()));
        }
        if input.username.trim().is_empty() {
            return Err(ApplicationError::InvalidSmtpSettings("username must not be empty".to_string()));
        }
        if input.from_address.trim().is_empty() || !input.from_address.contains('@') {
            return Err(ApplicationError::InvalidSmtpSettings("from_address must be a valid email address".to_string()));
        }
        if input.from_name.trim().is_empty() {
            return Err(ApplicationError::InvalidSmtpSettings("from_name must not be empty".to_string()));
        }

        let password = match input.password {
            Some(password) if !password.is_empty() => password,
            _ => {
                let existing = self.settings.get(organization_id).await?;
                match existing {
                    Some(existing) => existing.password,
                    None => return Err(ApplicationError::InvalidSmtpSettings("password is required when configuring SMTP for the first time".to_string())),
                }
            }
        };

        self.settings
            .update(organization_id, &SmtpSettings { host: input.host, port: input.port, username: input.username, password, from_name: input.from_name, from_address: input.from_address, security: input.security })
            .await?;
        Ok(())
    }
}

pub struct SendTestEmailUseCase {
    email: Arc<dyn EmailPort>,
}

impl SendTestEmailUseCase {
    pub fn new(email: Arc<dyn EmailPort>) -> Self {
        Self { email }
    }

    pub async fn execute(&self, organization_id: uuid::Uuid, to: &str) -> Result<(), ApplicationError> {
        let message = "This is a test email from Hangar. If you received it, your SMTP settings are working correctly.";
        self.email.send(organization_id, to, "Hangar SMTP test", message, &format!("<p>{message}</p>")).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use hangar_domain::error::DomainError;

    use super::*;

    struct FakeSmtpSettings {
        settings: Mutex<std::collections::HashMap<uuid::Uuid, SmtpSettings>>,
    }

    #[async_trait]
    impl SmtpSettingsPort for FakeSmtpSettings {
        async fn get(&self, organization_id: uuid::Uuid) -> Result<Option<SmtpSettings>, DomainError> {
            Ok(self.settings.lock().unwrap().get(&organization_id).cloned())
        }
        async fn update(&self, organization_id: uuid::Uuid, settings: &SmtpSettings) -> Result<(), DomainError> {
            self.settings.lock().unwrap().insert(organization_id, settings.clone());
            Ok(())
        }
    }

    struct FakeEmail {
        sent: Mutex<Vec<(uuid::Uuid, String, String, String, String)>>,
    }

    #[async_trait]
    impl EmailPort for FakeEmail {
        async fn send(&self, organization_id: uuid::Uuid, to: &str, subject: &str, text_body: &str, html_body: &str) -> Result<(), DomainError> {
            self.sent.lock().unwrap().push((organization_id, to.to_string(), subject.to_string(), text_body.to_string(), html_body.to_string()));
            Ok(())
        }
    }

    fn sample_input() -> UpdateSmtpSettingsInput {
        UpdateSmtpSettingsInput {
            host: "smtp.example.com".to_string(),
            port: 587,
            username: "hangar@example.com".to_string(),
            password: Some("s3cret".to_string()),
            from_name: "Hangar".to_string(),
            from_address: "hangar@example.com".to_string(),
            security: SmtpSecurity::StartTls,
        }
    }

    #[tokio::test]
    async fn get_returns_none_when_never_configured() {
        let org_id = uuid::Uuid::new_v4();
        let settings = Arc::new(FakeSmtpSettings { settings: Mutex::new(std::collections::HashMap::new()) });
        let use_case = GetSmtpSettingsUseCase::new(settings);
        assert_eq!(use_case.execute(org_id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn get_never_exposes_the_password() {
        let org_id = uuid::Uuid::new_v4();
        let settings = Arc::new(FakeSmtpSettings { settings: Mutex::new(std::collections::HashMap::new()) });
        UpdateSmtpSettingsUseCase::new(settings.clone()).execute(org_id, sample_input()).await.unwrap();

        let view = GetSmtpSettingsUseCase::new(settings).execute(org_id).await.unwrap().unwrap();
        assert_eq!(view.host, "smtp.example.com");
        assert!(view.password_set);
    }

    #[tokio::test]
    async fn first_time_configuration_requires_a_password() {
        let org_id = uuid::Uuid::new_v4();
        let settings = Arc::new(FakeSmtpSettings { settings: Mutex::new(std::collections::HashMap::new()) });
        let use_case = UpdateSmtpSettingsUseCase::new(settings);
        let err = use_case.execute(org_id, UpdateSmtpSettingsInput { password: None, ..sample_input() }).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidSmtpSettings(_)));
    }

    #[tokio::test]
    async fn leaving_the_password_blank_on_update_keeps_the_existing_password() {
        let org_id = uuid::Uuid::new_v4();
        let settings = Arc::new(FakeSmtpSettings { settings: Mutex::new(std::collections::HashMap::new()) });
        let use_case = UpdateSmtpSettingsUseCase::new(settings.clone());
        use_case.execute(org_id, sample_input()).await.unwrap();

        use_case.execute(org_id, UpdateSmtpSettingsInput { host: "smtp2.example.com".to_string(), password: None, ..sample_input() }).await.unwrap();

        let stored = settings.get(org_id).await.unwrap().unwrap();
        assert_eq!(stored.host, "smtp2.example.com");
        assert_eq!(stored.password, "s3cret");
    }

    #[tokio::test]
    async fn rejects_an_empty_host() {
        let org_id = uuid::Uuid::new_v4();
        let settings = Arc::new(FakeSmtpSettings { settings: Mutex::new(std::collections::HashMap::new()) });
        let use_case = UpdateSmtpSettingsUseCase::new(settings);
        let err = use_case.execute(org_id, UpdateSmtpSettingsInput { host: "  ".to_string(), ..sample_input() }).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidSmtpSettings(_)));
    }

    #[tokio::test]
    async fn rejects_an_out_of_range_port() {
        let org_id = uuid::Uuid::new_v4();
        let settings = Arc::new(FakeSmtpSettings { settings: Mutex::new(std::collections::HashMap::new()) });
        let use_case = UpdateSmtpSettingsUseCase::new(settings);
        let err = use_case.execute(org_id, UpdateSmtpSettingsInput { port: 0, ..sample_input() }).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidSmtpSettings(_)));
    }

    #[tokio::test]
    async fn rejects_a_from_address_without_an_at_sign() {
        let org_id = uuid::Uuid::new_v4();
        let settings = Arc::new(FakeSmtpSettings { settings: Mutex::new(std::collections::HashMap::new()) });
        let use_case = UpdateSmtpSettingsUseCase::new(settings);
        let err = use_case.execute(org_id, UpdateSmtpSettingsInput { from_address: "not-an-email".to_string(), ..sample_input() }).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidSmtpSettings(_)));
    }

    #[tokio::test]
    async fn rejects_an_empty_from_name() {
        let org_id = uuid::Uuid::new_v4();
        let settings = Arc::new(FakeSmtpSettings { settings: Mutex::new(std::collections::HashMap::new()) });
        let use_case = UpdateSmtpSettingsUseCase::new(settings);
        let err = use_case.execute(org_id, UpdateSmtpSettingsInput { from_name: "  ".to_string(), ..sample_input() }).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidSmtpSettings(_)));
    }

    #[tokio::test]
    async fn from_name_round_trips_through_get() {
        let org_id = uuid::Uuid::new_v4();
        let settings = Arc::new(FakeSmtpSettings { settings: Mutex::new(std::collections::HashMap::new()) });
        UpdateSmtpSettingsUseCase::new(settings.clone()).execute(org_id, UpdateSmtpSettingsInput { from_name: "Acme Corp".to_string(), ..sample_input() }).await.unwrap();

        let view = GetSmtpSettingsUseCase::new(settings).execute(org_id).await.unwrap().unwrap();
        assert_eq!(view.from_name, "Acme Corp");
    }

    #[tokio::test]
    async fn send_test_email_delegates_to_the_email_port() {
        let org_id = uuid::Uuid::new_v4();
        let email = Arc::new(FakeEmail { sent: Mutex::new(Vec::new()) });
        let use_case = SendTestEmailUseCase::new(email.clone());
        use_case.execute(org_id, "admin@example.com").await.unwrap();

        let sent = email.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, org_id);
        assert_eq!(sent[0].1, "admin@example.com");
    }
}

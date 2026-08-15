use std::sync::Arc;

use hangar_domain::sso::ExternalIdentity;
use hangar_domain::user::{PasswordHasherPort, TokenIssuerPort, User, UserRepositoryPort, Username};
use uuid::Uuid;

use crate::error::ApplicationError;
use crate::use_cases::invitation::unusable_password_hash;

fn derive_username_candidate(email: &str) -> String {
    let local_part = email.split('@').next().unwrap_or(email).to_lowercase();
    let filtered: String = local_part.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
    let starts_with_letter = filtered.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
    let mut candidate = if starts_with_letter { filtered } else { format!("u{filtered}") };
    if candidate.len() < 3 {
        candidate.push_str("-user");
    }
    candidate.chars().take(32).collect()
}

pub struct ProvisionSsoUserUseCase {
    users: Arc<dyn UserRepositoryPort>,
    hasher: Arc<dyn PasswordHasherPort>,
    tokens: Arc<dyn TokenIssuerPort>,
    system_settings: Arc<dyn hangar_domain::system_settings::SystemSettingsPort>,
}

impl ProvisionSsoUserUseCase {
    pub fn new(
        users: Arc<dyn UserRepositoryPort>,
        hasher: Arc<dyn PasswordHasherPort>,
        tokens: Arc<dyn TokenIssuerPort>,
        system_settings: Arc<dyn hangar_domain::system_settings::SystemSettingsPort>,
    ) -> Self {
        Self { users, hasher, tokens, system_settings }
    }

    pub async fn execute(&self, organization_id: Uuid, identity: &ExternalIdentity) -> Result<String, ApplicationError> {
        if let Some(existing) = self.users.find_by_email(&identity.email).await? {
            // Only reusable within the same organization and with no elevated privilege —
            // otherwise a user-controlled directory attribute (mail) could match a
            // different org's account or an admin account, handing out a session (and
            // bypassing MFA, since SSO never goes through the MFA-pending flow).
            if existing.organization_id != organization_id || existing.is_super_admin || existing.is_organization_admin {
                return Err(ApplicationError::InvalidCredentials);
            }
            let settings = self.system_settings.get(existing.organization_id).await?;
            return Ok(self.tokens.issue(existing.id, chrono::Duration::hours(settings.session_ttl_hours as i64))?);
        }

        let base = derive_username_candidate(&identity.email);
        let mut candidate = base.clone();
        let mut suffix = 1u32;
        let username = loop {
            let parsed = Username::parse(&candidate)?;
            if self.users.find_by_username(&parsed).await?.is_none() {
                break candidate;
            }
            suffix += 1;
            let suffix_str = format!("-{suffix}");
            let truncated_base: String = base.chars().take(32 - suffix_str.len()).collect();
            candidate = format!("{truncated_base}{suffix_str}");
        };

        let user = User {
            id: Uuid::new_v4(),
            username: Username::parse(&username)?,
            password_hash: unusable_password_hash(self.hasher.as_ref()).await?,
            is_super_admin: false,
            is_organization_admin: false,
            organization_id,
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: Some(identity.email.clone()),
        };
        self.users.insert(&user).await?;
        let settings = self.system_settings.get(organization_id).await?;
        Ok(self.tokens.issue(user.id, chrono::Duration::hours(settings.session_ttl_hours as i64))?)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use hangar_domain::error::DomainError;
    use hangar_domain::organization::OrganizationRepositoryPort;

    use super::*;

    struct FakeUsers {
        users: Mutex<HashMap<Uuid, User>>,
    }

    impl FakeUsers {
        fn new() -> Self {
            Self { users: Mutex::new(HashMap::new()) }
        }

        fn seeded(users: Vec<User>) -> Self {
            Self { users: Mutex::new(users.into_iter().map(|u| (u.id, u)).collect()) }
        }
    }

    #[async_trait]
    impl UserRepositoryPort for FakeUsers {
        async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().get(&id).cloned())
        }
        async fn find_by_username(&self, username: &Username) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().values().find(|u| &u.username == username).cloned())
        }
        async fn find_by_email(&self, email: &str) -> Result<Option<User>, DomainError> {
            Ok(self.users.lock().unwrap().values().find(|u| u.email.as_deref() == Some(email)).cloned())
        }
        async fn list_all(&self) -> Result<Vec<User>, DomainError> {
            Ok(self.users.lock().unwrap().values().cloned().collect())
        }
        async fn insert(&self, user: &User) -> Result<(), DomainError> {
            self.users.lock().unwrap().insert(user.id, user.clone());
            Ok(())
        }
        async fn delete(&self, id: Uuid) -> Result<(), DomainError> {
            self.users.lock().unwrap().remove(&id);
            Ok(())
        }
        async fn update_password(&self, id: Uuid, new_password_hash: String) -> Result<(), DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.password_hash = new_password_hash;
            }
            Ok(())
        }
        async fn set_super_admin(&self, id: Uuid, is_super_admin: bool) -> Result<(), DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.is_super_admin = is_super_admin;
            }
            Ok(())
        }
        async fn set_organization_admin(&self, id: Uuid, is_organization_admin: bool) -> Result<(), DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.is_organization_admin = is_organization_admin;
            }
            Ok(())
        }
        async fn delete_unless_last_super_admin(&self, id: Uuid) -> Result<bool, DomainError> {
            self.users.lock().unwrap().remove(&id);
            Ok(true)
        }
        async fn set_super_admin_unless_last(&self, id: Uuid, is_super_admin: bool) -> Result<bool, DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.is_super_admin = is_super_admin;
            }
            Ok(true)
        }
    }

    struct FakeHasher;

    #[async_trait]
    impl PasswordHasherPort for FakeHasher {
        async fn hash(&self, plain_password: &str) -> Result<String, DomainError> {
            Ok(format!("hashed:{plain_password}"))
        }
        async fn verify(&self, plain_password: &str, hash: &str) -> bool {
            hash == format!("hashed:{plain_password}")
        }
    }

    struct FakeTokenIssuer;

    #[async_trait]
    impl TokenIssuerPort for FakeTokenIssuer {
        fn issue(&self, user_id: Uuid, _ttl: chrono::Duration) -> Result<String, DomainError> {
            Ok(format!("token:{user_id}"))
        }
        fn verify(&self, token: &str) -> Result<hangar_domain::user::VerifiedToken, DomainError> {
            let user_id = token.strip_prefix("token:").and_then(|s| Uuid::parse_str(s).ok()).ok_or_else(|| DomainError::InvalidUsername("bad token".to_string()))?;
            Ok(hangar_domain::user::VerifiedToken { user_id, issued_at: chrono::Utc::now() })
        }
    }

    struct FakeSystemSettings;

    #[async_trait]
    impl hangar_domain::system_settings::SystemSettingsPort for FakeSystemSettings {
        async fn get(&self, _organization_id: Uuid) -> Result<hangar_domain::system_settings::SystemSettings, DomainError> {
            Ok(hangar_domain::system_settings::SystemSettings::defaults())
        }
        async fn update(&self, _organization_id: Uuid, _settings: &hangar_domain::system_settings::SystemSettings) -> Result<(), DomainError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn provisions_a_fresh_member_account_on_first_login() {
        let use_case = ProvisionSsoUserUseCase::new(Arc::new(FakeUsers::new()), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let organization_id = Uuid::new_v4();
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: Some("Florian".to_string()) };

        let token = use_case.execute(organization_id, &identity).await.unwrap();

        assert!(token.starts_with("token:"));
    }

    #[tokio::test]
    async fn a_provisioned_account_is_never_an_admin_regardless_of_display_name_content() {
        let users = Arc::new(FakeUsers::new());
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let organization_id = Uuid::new_v4();
        // A directory attribute an attacker fully controls must never influence the role.
        let identity = ExternalIdentity { email: "attacker@corp.example".to_string(), display_name: Some("Admin Super-Admin Root".to_string()) };

        use_case.execute(organization_id, &identity).await.unwrap();

        let created = users.users.lock().unwrap().values().find(|u| u.email.as_deref() == Some("attacker@corp.example")).cloned().unwrap();
        assert!(!created.is_super_admin);
        assert!(!created.is_organization_admin);
    }

    #[tokio::test]
    async fn a_provisioned_account_has_no_usable_password() {
        let users = Arc::new(FakeUsers::new());
        let hasher = Arc::new(FakeHasher);
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), hasher.clone(), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: None };

        use_case.execute(Uuid::new_v4(), &identity).await.unwrap();

        let created = users.users.lock().unwrap().values().next().cloned().unwrap();
        assert!(!hasher.verify("anything", &created.password_hash).await, "no plaintext should ever verify against a JIT-provisioned account's placeholder hash");
    }

    #[tokio::test]
    async fn logging_in_again_with_the_same_email_reuses_the_existing_account() {
        let users = Arc::new(FakeUsers::new());
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: None };
        let organization_id = Uuid::new_v4();

        use_case.execute(organization_id, &identity).await.unwrap();
        let first_count = users.users.lock().unwrap().len();
        use_case.execute(organization_id, &identity).await.unwrap();
        let second_count = users.users.lock().unwrap().len();

        assert_eq!(first_count, second_count, "a second login with the same email must not create a second account");
    }

    #[tokio::test]
    async fn reusing_an_existing_account_from_a_different_organization_is_rejected() {
        let organization_a = Uuid::new_v4();
        let organization_b = Uuid::new_v4();
        let existing = User {
            id: Uuid::new_v4(),
            username: Username::parse("florian").unwrap(),
            password_hash: "placeholder".to_string(),
            is_super_admin: false,
            is_organization_admin: false,
            organization_id: organization_a,
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: Some("florian@corp.example".to_string()),
        };
        let users = Arc::new(FakeUsers::seeded(vec![existing]));
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: None };

        let err = use_case.execute(organization_b, &identity).await.unwrap_err();

        assert!(matches!(err, ApplicationError::InvalidCredentials), "got {err:?}");
    }

    #[tokio::test]
    async fn reusing_an_existing_super_admin_account_is_rejected_even_in_the_same_organization() {
        let organization_id = Uuid::new_v4();
        let existing = User {
            id: Uuid::new_v4(),
            username: Username::parse("florian").unwrap(),
            password_hash: "placeholder".to_string(),
            is_super_admin: true,
            is_organization_admin: false,
            organization_id,
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: Some("florian@corp.example".to_string()),
        };
        let users = Arc::new(FakeUsers::seeded(vec![existing]));
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: None };

        let err = use_case.execute(organization_id, &identity).await.unwrap_err();

        assert!(matches!(err, ApplicationError::InvalidCredentials), "got {err:?}");
    }

    #[tokio::test]
    async fn reusing_an_existing_organization_admin_account_is_rejected_even_in_the_same_organization() {
        let organization_id = Uuid::new_v4();
        let existing = User {
            id: Uuid::new_v4(),
            username: Username::parse("florian").unwrap(),
            password_hash: "placeholder".to_string(),
            is_super_admin: false,
            is_organization_admin: true,
            organization_id,
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: Some("florian@corp.example".to_string()),
        };
        let users = Arc::new(FakeUsers::seeded(vec![existing]));
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: None };

        let err = use_case.execute(organization_id, &identity).await.unwrap_err();

        assert!(matches!(err, ApplicationError::InvalidCredentials), "got {err:?}");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn reusing_a_super_admin_account_from_a_different_organization_is_rejected_against_a_real_database(pool: sqlx::PgPool) {
        let organizations = Arc::new(hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository::new(pool.clone()));
        let organization_a = Uuid::new_v4();
        let organization_b = Uuid::new_v4();
        organizations
            .create(&hangar_domain::organization::Organization {
                id: organization_a,
                slug: hangar_domain::organization::OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        organizations
            .create(&hangar_domain::organization::Organization {
                id: organization_b,
                slug: hangar_domain::organization::OrganizationSlug::parse("globex").unwrap(),
                display_name: "Globex".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();

        let users = Arc::new(hangar_infrastructure::postgres::user_repository::PostgresUserRepository::new(pool.clone()));
        users
            .insert(&User {
                id: Uuid::new_v4(),
                username: Username::parse("acme-super-admin").unwrap(),
                password_hash: "placeholder".to_string(),
                is_super_admin: true,
                is_organization_admin: false,
                organization_id: organization_a,
                created_at: chrono::Utc::now(),
                tokens_valid_after: chrono::Utc::now(),
                email: Some("root@acme.example".to_string()),
            })
            .await
            .unwrap();

        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let identity = ExternalIdentity { email: "root@acme.example".to_string(), display_name: None };

        let err = use_case.execute(organization_b, &identity).await.unwrap_err();

        assert!(matches!(err, ApplicationError::InvalidCredentials), "got {err:?}");
    }

    #[tokio::test]
    async fn derives_a_username_from_the_email_local_part() {
        let users = Arc::new(FakeUsers::new());
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let identity = ExternalIdentity { email: "florian.dupont@corp.example".to_string(), display_name: None };

        use_case.execute(Uuid::new_v4(), &identity).await.unwrap();

        let created = users.users.lock().unwrap().values().next().cloned().unwrap();
        assert_eq!(created.username.as_str(), "floriandupont");
    }

    #[tokio::test]
    async fn a_colliding_username_gets_a_numeric_suffix() {
        let existing = User {
            id: Uuid::new_v4(),
            username: Username::parse("florian").unwrap(),
            password_hash: "placeholder".to_string(),
            is_super_admin: false,
            is_organization_admin: false,
            organization_id: Uuid::new_v4(),
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: Some("someone-else@corp.example".to_string()),
        };
        let users = Arc::new(FakeUsers::seeded(vec![existing]));
        let use_case = ProvisionSsoUserUseCase::new(users.clone(), Arc::new(FakeHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: None };

        use_case.execute(Uuid::new_v4(), &identity).await.unwrap();

        let created = users.users.lock().unwrap().values().find(|u| u.email.as_deref() == Some("florian@corp.example")).cloned().unwrap();
        assert_eq!(created.username.as_str(), "florian-2");
    }
}

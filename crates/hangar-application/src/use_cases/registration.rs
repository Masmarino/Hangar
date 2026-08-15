use std::sync::Arc;

use hangar_domain::user::{Password, PasswordHasherPort, User, UserRepositoryPort, Username};
use uuid::Uuid;

use crate::error::ApplicationError;
use crate::use_cases::invitation::validate_email;

pub struct RegisterPublicUserUseCase {
    users: Arc<dyn UserRepositoryPort>,
    hasher: Arc<dyn PasswordHasherPort>,
}

impl RegisterPublicUserUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>, hasher: Arc<dyn PasswordHasherPort>) -> Self {
        Self { users, hasher }
    }

    /// The route handler rejects anything but the public organization before calling this.
    /// Unlike `InviteUserUseCase`, hashes the real password immediately — no activation step.
    pub async fn execute(&self, organization_id: Uuid, username: &str, email: &str, password: &str) -> Result<Uuid, ApplicationError> {
        let username = Username::parse(username)?;
        validate_email(email)?;
        let password = Password::parse(password)?;
        if self.users.find_by_username(&username).await?.is_some() {
            return Err(ApplicationError::UsernameTaken);
        }

        let user = User {
            id: Uuid::new_v4(),
            username,
            password_hash: self.hasher.hash(password.as_str()).await?,
            is_super_admin: false,
            is_organization_admin: false,
            organization_id,
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: Some(email.to_string()),
        };
        self.users.insert(&user).await?;
        Ok(user.id)
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

    fn setup() -> (Arc<FakeUsers>, Arc<FakeHasher>) {
        (Arc::new(FakeUsers::new()), Arc::new(FakeHasher))
    }

    #[tokio::test]
    async fn registers_a_user_with_an_immediately_usable_password() {
        let (users, hasher) = setup();
        let use_case = RegisterPublicUserUseCase::new(users.clone(), hasher.clone());
        let organization_id = Uuid::new_v4();

        let id = use_case.execute(organization_id, "florian", "florian@example.com", "sup3r-s3cret!").await.unwrap();

        let user = users.find_by_id(id).await.unwrap().unwrap();
        assert_eq!(user.organization_id, organization_id);
        assert_eq!(user.email.as_deref(), Some("florian@example.com"));
        assert!(!user.is_super_admin);
        assert!(!user.is_organization_admin);
        assert!(hasher.verify("sup3r-s3cret!", &user.password_hash).await, "the real password must work immediately, unlike an invited account's placeholder hash");
    }

    #[tokio::test]
    async fn rejects_a_duplicate_username() {
        let (users, hasher) = setup();
        let use_case = RegisterPublicUserUseCase::new(users, hasher);
        use_case.execute(Uuid::new_v4(), "florian", "a@example.com", "sup3r-s3cret!").await.unwrap();

        let err = use_case.execute(Uuid::new_v4(), "florian", "b@example.com", "sup3r-s3cret!").await.unwrap_err();
        assert!(matches!(err, ApplicationError::UsernameTaken));
    }

    #[tokio::test]
    async fn rejects_an_invalid_email() {
        let (users, hasher) = setup();
        let use_case = RegisterPublicUserUseCase::new(users, hasher);

        let err = use_case.execute(Uuid::new_v4(), "florian", "not-an-email", "sup3r-s3cret!").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidEmail(_)));
    }

    #[tokio::test]
    async fn rejects_a_password_shorter_than_the_minimum() {
        let (users, hasher) = setup();
        let use_case = RegisterPublicUserUseCase::new(users, hasher);

        let err = use_case.execute(Uuid::new_v4(), "florian", "florian@example.com", "short").await.unwrap_err();
        assert!(matches!(err, ApplicationError::Domain(DomainError::PasswordTooShort)), "got {err:?}");
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn registering_persists_the_user_scoped_to_the_given_organization(pool: sqlx::PgPool) {
        let organizations = Arc::new(hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository::new(pool.clone()));
        let organization_id = Uuid::new_v4();
        organizations
            .create(&hangar_domain::organization::Organization {
                id: organization_id,
                slug: hangar_domain::organization::OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let users = Arc::new(hangar_infrastructure::postgres::user_repository::PostgresUserRepository::new(pool.clone()));
        let (_, hasher) = setup();
        let use_case = RegisterPublicUserUseCase::new(users.clone(), hasher);

        let user_id = use_case.execute(organization_id, "acme-member", "member@acme.example", "sup3r-s3cret!").await.unwrap();

        let created = users.find_by_id(user_id).await.unwrap().unwrap();
        assert_eq!(created.organization_id, organization_id);
        assert!(!created.is_organization_admin);
        assert!(!created.is_super_admin);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn registering_with_an_already_used_email_fails_cleanly_instead_of_hitting_the_db_constraint_raw(pool: sqlx::PgPool) {
        let organizations = Arc::new(hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository::new(pool.clone()));
        let organization_id = Uuid::new_v4();
        organizations
            .create(&hangar_domain::organization::Organization {
                id: organization_id,
                slug: hangar_domain::organization::OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: chrono::Utc::now(),
            })
            .await
            .unwrap();
        let users = Arc::new(hangar_infrastructure::postgres::user_repository::PostgresUserRepository::new(pool.clone()));
        let (_, hasher) = setup();
        let use_case = RegisterPublicUserUseCase::new(users.clone(), hasher.clone());
        use_case.execute(organization_id, "first-member", "shared@acme.example", "sup3r-s3cret!").await.unwrap();

        let err = use_case.execute(organization_id, "second-member", "shared@acme.example", "sup3r-s3cret!").await.unwrap_err();

        assert!(matches!(err, ApplicationError::Domain(DomainError::EmailTaken)), "got {err:?}");
    }
}

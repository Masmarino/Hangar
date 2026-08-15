use std::sync::Arc;

use hangar_domain::email::EmailPort;
use hangar_domain::user::{Password, PasswordHasherPort, TokenIssuerPort, User, UserRepositoryPort, Username};
use uuid::Uuid;

use crate::error::ApplicationError;

/// Burns the same CPU time as a real verification, keeping "unknown username" and "known username, wrong password" indistinguishable by response time.
const DUMMY_HASH_FOR_TIMING: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

pub struct CreateUserUseCase {
    users: Arc<dyn UserRepositoryPort>,
    hasher: Arc<dyn PasswordHasherPort>,
}

impl CreateUserUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>, hasher: Arc<dyn PasswordHasherPort>) -> Self {
        Self { users, hasher }
    }

    pub async fn execute(&self, organization_id: Uuid, username: &str, password: &str, is_super_admin: bool) -> Result<Uuid, ApplicationError> {
        let username = Username::parse(username)?;
        let password = Password::parse(password)?;
        if self.users.find_by_username(&username).await?.is_some() {
            return Err(ApplicationError::UsernameTaken);
        }
        let user = User {
            id: Uuid::new_v4(),
            username,
            password_hash: self.hasher.hash(password.as_str()).await?,
            is_super_admin,
            is_organization_admin: false,
            organization_id,
            created_at: chrono::Utc::now(),
            tokens_valid_after: chrono::Utc::now(),
            email: None,
        };
        self.users.insert(&user).await?;
        Ok(user.id)
    }
}

pub struct AuthenticateUserUseCase {
    users: Arc<dyn UserRepositoryPort>,
    hasher: Arc<dyn PasswordHasherPort>,
    tokens: Arc<dyn TokenIssuerPort>,
    system_settings: Arc<dyn hangar_domain::system_settings::SystemSettingsPort>,
}

impl AuthenticateUserUseCase {
    pub fn new(
        users: Arc<dyn UserRepositoryPort>,
        hasher: Arc<dyn PasswordHasherPort>,
        tokens: Arc<dyn TokenIssuerPort>,
        system_settings: Arc<dyn hangar_domain::system_settings::SystemSettingsPort>,
    ) -> Self {
        Self { users, hasher, tokens, system_settings }
    }

    pub async fn execute(&self, username: &str, password: &str) -> Result<String, ApplicationError> {
        // Every path below runs exactly one `verify` call, or an attacker could enumerate valid usernames by response timing.
        let user = match Username::parse(username) {
            Ok(username) => self.users.find_by_username(&username).await?,
            Err(_) => None,
        };
        let hash = user.as_ref().map_or(DUMMY_HASH_FOR_TIMING, |u| u.password_hash.as_str());
        let password_matches = self.hasher.verify(password, hash).await;

        let Some(user) = user else {
            return Err(ApplicationError::InvalidCredentials);
        };
        if !password_matches {
            return Err(ApplicationError::InvalidCredentials);
        }
        let settings = self.system_settings.get(user.organization_id).await?;
        Ok(self.tokens.issue(user.id, chrono::Duration::hours(settings.session_ttl_hours as i64))?)
    }
}

pub struct DeleteUserUseCase {
    users: Arc<dyn UserRepositoryPort>,
}

impl DeleteUserUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>) -> Self {
        Self { users }
    }

    pub async fn execute(&self, id: Uuid) -> Result<(), ApplicationError> {
        // Refuses to delete the only super-admin; guard and write are atomic in the repository.
        if self.users.delete_unless_last_super_admin(id).await? {
            Ok(())
        } else {
            Err(ApplicationError::LastSuperAdmin)
        }
    }
}

pub struct SetSuperAdminUseCase {
    users: Arc<dyn UserRepositoryPort>,
}

impl SetSuperAdminUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>) -> Self {
        Self { users }
    }

    pub async fn execute(&self, id: Uuid, is_super_admin: bool) -> Result<(), ApplicationError> {
        // Only a demotion of a current super-admin needs the "not the last one" check.
        if self.users.set_super_admin_unless_last(id, is_super_admin).await? {
            Ok(())
        } else {
            Err(ApplicationError::LastSuperAdmin)
        }
    }
}

pub struct SetOrganizationAdminUseCase {
    users: Arc<dyn UserRepositoryPort>,
}

impl SetOrganizationAdminUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>) -> Self {
        Self { users }
    }

    // Unlike SetSuperAdminUseCase, no "unless last" guard: an organization can validly end up with zero org-admins — the super-admin can always still manage it.
    pub async fn execute(&self, id: Uuid, is_organization_admin: bool) -> Result<(), ApplicationError> {
        self.users.set_organization_admin(id, is_organization_admin).await?;
        Ok(())
    }
}

pub struct ChangePasswordUseCase {
    users: Arc<dyn UserRepositoryPort>,
    hasher: Arc<dyn PasswordHasherPort>,
    email: Arc<dyn EmailPort>,
}

impl ChangePasswordUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>, hasher: Arc<dyn PasswordHasherPort>, email: Arc<dyn EmailPort>) -> Self {
        Self { users, hasher, email }
    }

    pub async fn execute(&self, user_id: Uuid, current_password: &str, new_password: &str) -> Result<(), ApplicationError> {
        let user = self.users.find_by_id(user_id).await?.ok_or(ApplicationError::InvalidCredentials)?;
        if !self.hasher.verify(current_password, &user.password_hash).await {
            return Err(ApplicationError::InvalidCredentials);
        }
        let new_password = Password::parse(new_password)?;
        let new_hash = self.hasher.hash(new_password.as_str()).await?;
        self.users.update_password(user_id, new_hash).await?;

        // Best-effort: the password change already succeeded, a delivery failure must not undo it.
        if let Some(email) = user.email.as_deref() {
            let content = crate::email_templates::password_changed(user.username.as_str());
            if let Err(e) = self.email.send(user.organization_id, email, &content.subject, &content.text, &content.html).await {
                tracing::warn!("failed to send password-change notification email to {email}: {e}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hangar_domain::error::DomainError;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct FakeEmail {
        sent: Mutex<Vec<(Uuid, String, String, String, String)>>,
    }

    impl FakeEmail {
        fn new() -> Self {
            Self { sent: Mutex::new(Vec::new()) }
        }
    }

    #[async_trait]
    impl EmailPort for FakeEmail {
        async fn send(&self, organization_id: Uuid, to: &str, subject: &str, text_body: &str, html_body: &str) -> Result<(), DomainError> {
            self.sent.lock().unwrap().push((organization_id, to.to_string(), subject.to_string(), text_body.to_string(), html_body.to_string()));
            Ok(())
        }
    }

    struct FakeUserRepository {
        users: Mutex<HashMap<Uuid, User>>,
    }

    impl FakeUserRepository {
        fn new() -> Self {
            Self { users: Mutex::new(HashMap::new()) }
        }
    }

    #[async_trait]
    impl UserRepositoryPort for FakeUserRepository {
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

        async fn delete_unless_last_super_admin(&self, id: Uuid) -> Result<bool, DomainError> {
            let mut users = self.users.lock().unwrap();
            if users.get(&id).is_some_and(|u| u.is_super_admin)
                && users.values().filter(|u| u.id != id && u.is_super_admin).count() == 0
            {
                return Ok(false);
            }
            users.remove(&id);
            Ok(true)
        }

        async fn set_super_admin_unless_last(&self, id: Uuid, is_super_admin: bool) -> Result<bool, DomainError> {
            let mut users = self.users.lock().unwrap();
            if !is_super_admin
                && users.get(&id).is_some_and(|u| u.is_super_admin)
                && users.values().filter(|u| u.id != id && u.is_super_admin).count() == 0
            {
                return Ok(false);
            }
            if let Some(user) = users.get_mut(&id) {
                user.is_super_admin = is_super_admin;
            }
            Ok(true)
        }

        async fn set_organization_admin(&self, id: Uuid, is_organization_admin: bool) -> Result<(), DomainError> {
            if let Some(user) = self.users.lock().unwrap().get_mut(&id) {
                user.is_organization_admin = is_organization_admin;
            }
            Ok(())
        }
    }

    struct FakePasswordHasher;

    #[async_trait]
    impl PasswordHasherPort for FakePasswordHasher {
        async fn hash(&self, plain_password: &str) -> Result<String, DomainError> {
            Ok(format!("hashed:{plain_password}"))
        }
        async fn verify(&self, plain_password: &str, hash: &str) -> bool {
            hash == format!("hashed:{plain_password}")
        }
    }

    /// Same as [`FakePasswordHasher`], but counts `verify` calls.
    struct RecordingPasswordHasher {
        verify_calls: AtomicUsize,
    }

    impl RecordingPasswordHasher {
        fn new() -> Self {
            Self { verify_calls: AtomicUsize::new(0) }
        }

        fn verify_calls(&self) -> usize {
            self.verify_calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl PasswordHasherPort for RecordingPasswordHasher {
        async fn hash(&self, plain_password: &str) -> Result<String, DomainError> {
            Ok(format!("hashed:{plain_password}"))
        }
        async fn verify(&self, plain_password: &str, hash: &str) -> bool {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
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
            let user_id = token
                .strip_prefix("token:")
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| DomainError::InvalidUsername("bad token".to_string()))?;
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
    async fn creates_a_user_successfully() {
        let use_case = CreateUserUseCase::new(Arc::new(FakeUserRepository::new()), Arc::new(FakePasswordHasher));
        let id = use_case.execute(Uuid::new_v4(), "florian", "sup3r-s3cret!", false).await.unwrap();
        assert_ne!(id, Uuid::nil());
    }

    #[tokio::test]
    async fn rejects_a_duplicate_username() {
        let users = Arc::new(FakeUserRepository::new());
        let use_case = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        use_case.execute(Uuid::new_v4(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let err = use_case.execute(Uuid::new_v4(), "florian", "another-s3cret!", false).await.unwrap_err();
        assert!(matches!(err, ApplicationError::UsernameTaken));
    }

    #[tokio::test]
    async fn authenticates_with_correct_credentials() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        create.execute(Uuid::new_v4(), "florian", "sup3r-s3cret!", false).await.unwrap();

        let authenticate = AuthenticateUserUseCase::new(users, Arc::new(FakePasswordHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let token = authenticate.execute("florian", "sup3r-s3cret!").await.unwrap();
        assert!(token.starts_with("token:"));
    }

    #[tokio::test]
    async fn rejects_wrong_password() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        create.execute(Uuid::new_v4(), "florian", "sup3r-s3cret!", false).await.unwrap();

        let authenticate = AuthenticateUserUseCase::new(users, Arc::new(FakePasswordHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let err = authenticate.execute("florian", "wrong").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidCredentials));
    }

    /// Timing itself is too flaky to assert on; instead proves the mechanism: exactly one verify call regardless of whether the username exists.
    #[tokio::test]
    async fn an_unknown_username_still_costs_one_password_verification() {
        let users = Arc::new(FakeUserRepository::new());
        CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher))
            .execute(Uuid::new_v4(), "florian", "sup3r-s3cret!", false)
            .await
            .unwrap();

        let known_hasher = Arc::new(RecordingPasswordHasher::new());
        let authenticate = AuthenticateUserUseCase::new(users.clone(), known_hasher.clone(), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let err = authenticate.execute("florian", "wrong-password").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidCredentials));
        assert_eq!(known_hasher.verify_calls(), 1);

        let unknown_hasher = Arc::new(RecordingPasswordHasher::new());
        let authenticate = AuthenticateUserUseCase::new(users.clone(), unknown_hasher.clone(), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let err = authenticate.execute("nobody-here", "wrong-password").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidCredentials));
        assert_eq!(unknown_hasher.verify_calls(), 1, "unknown usernames must still pay the hashing cost");

        let malformed_hasher = Arc::new(RecordingPasswordHasher::new());
        let authenticate = AuthenticateUserUseCase::new(users, malformed_hasher.clone(), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let err = authenticate.execute("!!", "wrong-password").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidCredentials));
        assert_eq!(malformed_hasher.verify_calls(), 1);
    }

    #[tokio::test]
    async fn rejects_a_password_shorter_than_the_minimum() {
        let use_case = CreateUserUseCase::new(Arc::new(FakeUserRepository::new()), Arc::new(FakePasswordHasher));

        let err = use_case.execute(Uuid::new_v4(), "florian", "s3cret!", false).await.unwrap_err();

        assert!(matches!(err, ApplicationError::Domain(DomainError::PasswordTooShort)), "got {err:?}");
    }

    #[tokio::test]
    async fn accepts_a_password_of_exactly_the_minimum_length() {
        let use_case = CreateUserUseCase::new(Arc::new(FakeUserRepository::new()), Arc::new(FakePasswordHasher));

        let id = use_case.execute(Uuid::new_v4(), "florian", "s3cret!8", false).await.unwrap();

        assert_ne!(id, Uuid::nil());
    }

    #[tokio::test]
    async fn deletes_a_user() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let id = create.execute(Uuid::new_v4(), "florian", "sup3r-s3cret!", false).await.unwrap();

        let delete = DeleteUserUseCase::new(users.clone());
        delete.execute(id).await.unwrap();

        assert!(users.find_by_id(id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn refuses_to_delete_the_only_super_admin() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let admin_id = create.execute(Uuid::new_v4(), "admin", "sup3r-s3cret!", true).await.unwrap();
        // A plain user must not count as a replacement administrator.
        create.execute(Uuid::new_v4(), "regular", "sup3r-s3cret!", false).await.unwrap();

        let delete = DeleteUserUseCase::new(users.clone());
        let err = delete.execute(admin_id).await.unwrap_err();

        assert!(matches!(err, ApplicationError::LastSuperAdmin));
        assert!(users.find_by_id(admin_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn deletes_a_super_admin_when_another_one_remains() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let first_admin = create.execute(Uuid::new_v4(), "admin", "sup3r-s3cret!", true).await.unwrap();
        create.execute(Uuid::new_v4(), "second-admin", "sup3r-s3cret!", true).await.unwrap();

        let delete = DeleteUserUseCase::new(users.clone());
        delete.execute(first_admin).await.unwrap();

        assert!(users.find_by_id(first_admin).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn deleting_an_unknown_user_stays_idempotent() {
        let users = Arc::new(FakeUserRepository::new());
        let delete = DeleteUserUseCase::new(users.clone());

        delete.execute(Uuid::new_v4()).await.unwrap();
    }

    #[tokio::test]
    async fn changes_the_password_with_the_correct_current_password() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let id = create.execute(Uuid::new_v4(), "florian", "old-s3cret!", false).await.unwrap();

        let change_password = ChangePasswordUseCase::new(users.clone(), Arc::new(FakePasswordHasher), Arc::new(FakeEmail::new()));
        change_password.execute(id, "old-s3cret!", "new-s3cret!").await.unwrap();

        let authenticate = AuthenticateUserUseCase::new(users, Arc::new(FakePasswordHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        let token = authenticate.execute("florian", "new-s3cret!").await.unwrap();
        assert!(token.starts_with("token:"));
    }

    #[tokio::test]
    async fn sends_a_notification_email_when_the_user_has_one_on_file() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let id = create.execute(Uuid::new_v4(), "florian", "old-s3cret!", false).await.unwrap();
        let mut user = users.find_by_id(id).await.unwrap().unwrap();
        user.email = Some("florian@example.com".to_string());
        users.insert(&user).await.unwrap();

        let email = Arc::new(FakeEmail::new());
        let change_password = ChangePasswordUseCase::new(users, Arc::new(FakePasswordHasher), email.clone());
        change_password.execute(id, "old-s3cret!", "new-s3cret!").await.unwrap();

        let sent = email.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1, "florian@example.com");
        assert!(sent[0].3.contains("modifié"));
        assert!(sent[0].4.contains("florian"));
    }

    #[tokio::test]
    async fn skips_the_email_when_the_user_has_none_on_file() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let id = create.execute(Uuid::new_v4(), "florian", "old-s3cret!", false).await.unwrap();

        let email = Arc::new(FakeEmail::new());
        let change_password = ChangePasswordUseCase::new(users, Arc::new(FakePasswordHasher), email.clone());
        change_password.execute(id, "old-s3cret!", "new-s3cret!").await.unwrap();

        assert!(email.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rejects_the_wrong_current_password() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let id = create.execute(Uuid::new_v4(), "florian", "old-s3cret!", false).await.unwrap();

        let change_password = ChangePasswordUseCase::new(users.clone(), Arc::new(FakePasswordHasher), Arc::new(FakeEmail::new()));
        let err = change_password.execute(id, "wrong", "new-s3cret!").await.unwrap_err();

        assert!(matches!(err, ApplicationError::InvalidCredentials));
        let authenticate = AuthenticateUserUseCase::new(users, Arc::new(FakePasswordHasher), Arc::new(FakeTokenIssuer), Arc::new(FakeSystemSettings));
        assert!(authenticate.execute("florian", "old-s3cret!").await.is_ok(), "old password must still work after a rejected change");
    }

    #[tokio::test]
    async fn rejects_a_new_password_shorter_than_the_minimum() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let id = create.execute(Uuid::new_v4(), "florian", "old-s3cret!", false).await.unwrap();

        let change_password = ChangePasswordUseCase::new(users.clone(), Arc::new(FakePasswordHasher), Arc::new(FakeEmail::new()));
        let err = change_password.execute(id, "old-s3cret!", "short").await.unwrap_err();

        assert!(matches!(err, ApplicationError::Domain(DomainError::PasswordTooShort)), "got {err:?}");
    }

    #[tokio::test]
    async fn promotes_a_regular_user_to_super_admin() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let id = create.execute(Uuid::new_v4(), "florian", "sup3r-s3cret!", false).await.unwrap();

        let use_case = SetSuperAdminUseCase::new(users.clone());
        use_case.execute(id, true).await.unwrap();

        assert!(users.find_by_id(id).await.unwrap().unwrap().is_super_admin);
    }

    #[tokio::test]
    async fn refuses_to_demote_the_only_super_admin() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let admin_id = create.execute(Uuid::new_v4(), "admin", "sup3r-s3cret!", true).await.unwrap();

        let use_case = SetSuperAdminUseCase::new(users.clone());
        let err = use_case.execute(admin_id, false).await.unwrap_err();

        assert!(matches!(err, ApplicationError::LastSuperAdmin));
        assert!(users.find_by_id(admin_id).await.unwrap().unwrap().is_super_admin);
    }

    #[tokio::test]
    async fn demotes_a_super_admin_when_another_one_remains() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let first_admin = create.execute(Uuid::new_v4(), "admin", "sup3r-s3cret!", true).await.unwrap();
        create.execute(Uuid::new_v4(), "second-admin", "sup3r-s3cret!", true).await.unwrap();

        let use_case = SetSuperAdminUseCase::new(users.clone());
        use_case.execute(first_admin, false).await.unwrap();

        assert!(!users.find_by_id(first_admin).await.unwrap().unwrap().is_super_admin);
    }

    #[tokio::test]
    async fn promoting_an_already_super_admin_user_is_a_no_op() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let admin_id = create.execute(Uuid::new_v4(), "admin", "sup3r-s3cret!", true).await.unwrap();

        let use_case = SetSuperAdminUseCase::new(users.clone());
        use_case.execute(admin_id, true).await.unwrap();

        assert!(users.find_by_id(admin_id).await.unwrap().unwrap().is_super_admin);
    }

    #[tokio::test]
    async fn promotes_a_regular_member_to_organization_admin() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let id = create.execute(Uuid::new_v4(), "florian", "sup3r-s3cret!", false).await.unwrap();

        let use_case = SetOrganizationAdminUseCase::new(users.clone());
        use_case.execute(id, true).await.unwrap();

        assert!(users.find_by_id(id).await.unwrap().unwrap().is_organization_admin);
    }

    #[tokio::test]
    async fn demotes_an_organization_admin() {
        let users = Arc::new(FakeUserRepository::new());
        let create = CreateUserUseCase::new(users.clone(), Arc::new(FakePasswordHasher));
        let id = create.execute(Uuid::new_v4(), "florian", "sup3r-s3cret!", false).await.unwrap();
        let use_case = SetOrganizationAdminUseCase::new(users.clone());
        use_case.execute(id, true).await.unwrap();

        use_case.execute(id, false).await.unwrap();

        assert!(!users.find_by_id(id).await.unwrap().unwrap().is_organization_admin);
    }
}

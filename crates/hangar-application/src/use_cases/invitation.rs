use std::sync::Arc;

use chrono::{Duration, Utc};
use hangar_domain::email::EmailPort;
use hangar_domain::error::DomainError;
use hangar_domain::invitation::{UserInvitation, UserInvitationPort};
use hangar_domain::organization::{Organization, OrganizationRepositoryPort};
use hangar_domain::user::{Password, PasswordHasherPort, User, UserRepositoryPort, Username};
use rand::Rng;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ApplicationError;

/// `https://<slug>.<hangar_base_domain>` (or the bare base domain for the public org) — the origin an invited/imported user's own org is served from.
/// Mirrors `organization_origin` in `hangar-api`'s `routes/auth.rs`, kept in sync by hand since hangar-application can't depend on hangar-api.
pub(crate) fn organization_origin(hangar_base_domain: &str, organization: &Organization) -> String {
    let host = if organization.is_public { hangar_base_domain.to_string() } else { format!("{}.{}", organization.slug.as_str(), hangar_base_domain) };
    format!("{}://{}", if hangar_base_domain.starts_with("localhost") { "http" } else { "https" }, host)
}

pub(crate) async fn require_organization(organizations: &dyn OrganizationRepositoryPort, organization_id: Uuid) -> Result<Organization, ApplicationError> {
    organizations
        .find_by_id(organization_id)
        .await?
        .ok_or_else(|| ApplicationError::Domain(DomainError::Infrastructure(format!("organization {organization_id} not found"))))
}

pub(crate) const INVITATION_TTL_HOURS: i64 = 24;

pub(crate) fn generate_invitation_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// `pub` so tests elsewhere can seed a `UserInvitation` with a known token hash.
pub fn hash_invitation_token(plaintext: &str) -> String {
    hex::encode(Sha256::digest(plaintext.as_bytes()))
}

/// Hashes fresh random bytes so `AuthenticateUserUseCase` needs no special case for a pending account — a normal failed `verify` already rejects it.
pub(crate) async fn unusable_password_hash(hasher: &dyn PasswordHasherPort) -> Result<String, ApplicationError> {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    Ok(hasher.hash(&hex::encode(bytes)).await?)
}

pub(crate) fn validate_email(email: &str) -> Result<(), ApplicationError> {
    if email.trim().is_empty() || !email.contains('@') {
        return Err(ApplicationError::InvalidEmail(email.to_string()));
    }
    Ok(())
}

pub struct InviteUserUseCase {
    users: Arc<dyn UserRepositoryPort>,
    invitations: Arc<dyn UserInvitationPort>,
    hasher: Arc<dyn PasswordHasherPort>,
    email: Arc<dyn EmailPort>,
    organizations: Arc<dyn OrganizationRepositoryPort>,
    /// No trailing slash. The base domain organization subdomains are resolved against — see `organization_origin` above.
    hangar_base_domain: String,
}

impl InviteUserUseCase {
    pub fn new(
        users: Arc<dyn UserRepositoryPort>,
        invitations: Arc<dyn UserInvitationPort>,
        hasher: Arc<dyn PasswordHasherPort>,
        email: Arc<dyn EmailPort>,
        organizations: Arc<dyn OrganizationRepositoryPort>,
        hangar_base_domain: String,
    ) -> Self {
        Self { users, invitations, hasher, email, organizations, hangar_base_domain }
    }

    /// `organization_id` is normally the acting admin's own org, but a super-admin inviting an org's first local admin can pass any organization.
    pub async fn execute(&self, organization_id: Uuid, is_organization_admin: bool, username: &str, email: &str, is_super_admin: bool) -> Result<Uuid, ApplicationError> {
        let username = Username::parse(username)?;
        validate_email(email)?;
        if self.users.find_by_username(&username).await?.is_some() {
            return Err(ApplicationError::UsernameTaken);
        }

        let user = User {
            id: Uuid::new_v4(),
            username,
            password_hash: unusable_password_hash(self.hasher.as_ref()).await?,
            is_super_admin,
            is_organization_admin,
            organization_id,
            created_at: Utc::now(),
            tokens_valid_after: Utc::now(),
            email: Some(email.to_string()),
        };
        self.users.insert(&user).await?;

        let token = generate_invitation_token();
        self.invitations.upsert(&UserInvitation { user_id: user.id, token_hash: hash_invitation_token(&token), expires_at: Utc::now() + Duration::hours(INVITATION_TTL_HOURS) }).await?;

        // After persisting the user, not before — if the org lookup ever fails, the account still exists and can be reached via ResendInvitationUseCase.
        let organization = require_organization(self.organizations.as_ref(), organization_id).await?;
        let origin = organization_origin(&self.hangar_base_domain, &organization);

        // A delivery failure shouldn't fail account creation — retry via ResendInvitationUseCase.
        let activation_url = format!("{origin}/activate?token={token}");
        let content = crate::email_templates::account_created(user.username.as_str(), &activation_url);
        if let Err(e) = self.email.send(organization_id, email, &content.subject, &content.text, &content.html).await {
            tracing::warn!("failed to send account-activation email to {email}: {e}");
        }

        Ok(user.id)
    }
}

pub struct ResendInvitationUseCase {
    users: Arc<dyn UserRepositoryPort>,
    invitations: Arc<dyn UserInvitationPort>,
    email: Arc<dyn EmailPort>,
    organizations: Arc<dyn OrganizationRepositoryPort>,
    hangar_base_domain: String,
}

impl ResendInvitationUseCase {
    pub fn new(
        users: Arc<dyn UserRepositoryPort>,
        invitations: Arc<dyn UserInvitationPort>,
        email: Arc<dyn EmailPort>,
        organizations: Arc<dyn OrganizationRepositoryPort>,
        hangar_base_domain: String,
    ) -> Self {
        Self { users, invitations, email, organizations, hangar_base_domain }
    }

    /// An already-activated account has no invitation row left, so this also returns `InvitationNotFound` for it, same as for an unknown user id.
    pub async fn execute(&self, user_id: Uuid) -> Result<(), ApplicationError> {
        let user = self.users.find_by_id(user_id).await?.ok_or(ApplicationError::InvitationNotFound)?;
        if self.invitations.find_by_user_id(user_id).await?.is_none() {
            return Err(ApplicationError::InvitationNotFound);
        }
        let Some(email) = user.email.as_deref() else {
            return Err(ApplicationError::InvitationNotFound);
        };

        let token = generate_invitation_token();
        self.invitations.upsert(&UserInvitation { user_id, token_hash: hash_invitation_token(&token), expires_at: Utc::now() + Duration::hours(INVITATION_TTL_HOURS) }).await?;

        // The user's own organization, not whatever the acting admin resolved against.
        let organization = require_organization(self.organizations.as_ref(), user.organization_id).await?;
        let origin = organization_origin(&self.hangar_base_domain, &organization);
        let activation_url = format!("{origin}/activate?token={token}");
        let content = crate::email_templates::account_created(user.username.as_str(), &activation_url);
        self.email.send(user.organization_id, email, &content.subject, &content.text, &content.html).await?;
        Ok(())
    }
}

pub struct ActivateAccountUseCase {
    users: Arc<dyn UserRepositoryPort>,
    invitations: Arc<dyn UserInvitationPort>,
    hasher: Arc<dyn PasswordHasherPort>,
}

impl ActivateAccountUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>, invitations: Arc<dyn UserInvitationPort>, hasher: Arc<dyn PasswordHasherPort>) -> Self {
        Self { users, invitations, hasher }
    }

    pub async fn execute(&self, token: &str, new_password: &str) -> Result<(), ApplicationError> {
        let invitation = self.invitations.find_by_token_hash(&hash_invitation_token(token)).await?.ok_or(ApplicationError::InvitationNotFound)?;
        if invitation.expires_at < Utc::now() {
            return Err(ApplicationError::InvitationExpired);
        }
        let password = Password::parse(new_password)?;
        let hash = self.hasher.hash(password.as_str()).await?;
        self.users.update_password(invitation.user_id, hash).await?;
        self.invitations.delete(invitation.user_id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use hangar_domain::error::DomainError;
    use hangar_domain::organization::{OrganizationRepositoryPort, OrganizationSlug};

    use super::*;

    const TEST_BASE_DOMAIN: &str = "hangar.example.com";

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

    struct FakeInvitations {
        by_user: Mutex<HashMap<Uuid, UserInvitation>>,
    }

    impl FakeInvitations {
        fn new() -> Self {
            Self { by_user: Mutex::new(HashMap::new()) }
        }
    }

    #[async_trait]
    impl UserInvitationPort for FakeInvitations {
        async fn upsert(&self, invitation: &UserInvitation) -> Result<(), DomainError> {
            self.by_user.lock().unwrap().insert(invitation.user_id, invitation.clone());
            Ok(())
        }
        async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<UserInvitation>, DomainError> {
            Ok(self.by_user.lock().unwrap().values().find(|i| i.token_hash == token_hash).cloned())
        }
        async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<UserInvitation>, DomainError> {
            Ok(self.by_user.lock().unwrap().get(&user_id).cloned())
        }
        async fn list_pending_user_ids(&self, user_ids: &[Uuid]) -> Result<std::collections::HashSet<Uuid>, DomainError> {
            let by_user = self.by_user.lock().unwrap();
            Ok(user_ids.iter().filter(|id| by_user.contains_key(id)).copied().collect())
        }
        async fn delete(&self, user_id: Uuid) -> Result<(), DomainError> {
            self.by_user.lock().unwrap().remove(&user_id);
            Ok(())
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

    struct FakeOrganizations {
        by_id: Mutex<HashMap<Uuid, Organization>>,
    }

    impl FakeOrganizations {
        fn new() -> Self {
            Self { by_id: Mutex::new(HashMap::new()) }
        }
    }

    #[async_trait]
    impl OrganizationRepositoryPort for FakeOrganizations {
        async fn create(&self, org: &Organization) -> Result<(), DomainError> {
            self.by_id.lock().unwrap().insert(org.id, org.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>, DomainError> {
            Ok(self.by_id.lock().unwrap().get(&id).cloned())
        }
        async fn find_by_slug(&self, slug: &OrganizationSlug) -> Result<Option<Organization>, DomainError> {
            Ok(self.by_id.lock().unwrap().values().find(|o| &o.slug == slug).cloned())
        }
        async fn find_public(&self) -> Result<Organization, DomainError> {
            self.by_id.lock().unwrap().values().find(|o| o.is_public).cloned().ok_or_else(|| DomainError::Infrastructure("no public organization seeded".to_string()))
        }
        async fn list_all(&self) -> Result<Vec<Organization>, DomainError> {
            Ok(self.by_id.lock().unwrap().values().cloned().collect())
        }
    }

    /// Seeds one public organization on `TEST_BASE_DOMAIN`, for tests that don't care about multi-tenant routing specifically.
    async fn setup() -> (Arc<FakeUsers>, Arc<FakeInvitations>, Arc<FakeHasher>, Arc<FakeEmail>, Arc<FakeOrganizations>, Uuid) {
        let organizations = Arc::new(FakeOrganizations::new());
        let organization_id = Uuid::new_v4();
        organizations
            .create(&Organization { id: organization_id, slug: OrganizationSlug::parse("public").unwrap(), display_name: "Public".to_string(), is_public: true, created_at: Utc::now() })
            .await
            .unwrap();
        (Arc::new(FakeUsers::new()), Arc::new(FakeInvitations::new()), Arc::new(FakeHasher), Arc::new(FakeEmail::new()), organizations, organization_id)
    }

    #[tokio::test]
    async fn invites_a_user_and_sends_an_activation_email() {
        let (users, invitations, hasher, email, organizations, organization_id) = setup().await;
        let use_case = InviteUserUseCase::new(users.clone(), invitations.clone(), hasher, email.clone(), organizations, TEST_BASE_DOMAIN.to_string());

        let id = use_case.execute(organization_id, false, "florian", "florian@example.com", false).await.unwrap();

        let user = users.find_by_id(id).await.unwrap().unwrap();
        assert_eq!(user.email.as_deref(), Some("florian@example.com"));
        assert!(invitations.find_by_user_id(id).await.unwrap().is_some());

        let sent = email.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, organization_id);
        assert_eq!(sent[0].1, "florian@example.com");
        assert!(sent[0].3.contains("https://hangar.example.com/activate?token="));
    }

    #[tokio::test]
    async fn invites_a_user_into_the_given_organization() {
        let (users, invitations, hasher, email, organizations, _default_organization_id) = setup().await;
        let organization_id = Uuid::new_v4();
        organizations
            .create(&Organization { id: organization_id, slug: OrganizationSlug::parse("acme").unwrap(), display_name: "Acme".to_string(), is_public: false, created_at: Utc::now() })
            .await
            .unwrap();
        let use_case = InviteUserUseCase::new(users.clone(), invitations, hasher, email, organizations, TEST_BASE_DOMAIN.to_string());

        let id = use_case.execute(organization_id, false, "florian", "florian@example.com", false).await.unwrap();

        let user = users.find_by_id(id).await.unwrap().unwrap();
        assert_eq!(user.organization_id, organization_id);
    }

    #[tokio::test]
    async fn invites_a_user_into_a_non_public_organization_links_to_that_organizations_own_subdomain() {
        let (users, invitations, hasher, email, organizations, _default_organization_id) = setup().await;
        let organization_id = Uuid::new_v4();
        organizations
            .create(&Organization { id: organization_id, slug: OrganizationSlug::parse("acme").unwrap(), display_name: "Acme".to_string(), is_public: false, created_at: Utc::now() })
            .await
            .unwrap();
        let use_case = InviteUserUseCase::new(users, invitations, hasher, email.clone(), organizations, TEST_BASE_DOMAIN.to_string());

        use_case.execute(organization_id, false, "florian", "florian@example.com", false).await.unwrap();

        let sent = email.sent.lock().unwrap();
        assert!(sent[0].3.contains("https://acme.hangar.example.com/activate?token="), "expected the acme subdomain, got: {}", sent[0].3);
    }

    #[tokio::test]
    async fn rejects_a_duplicate_username() {
        let (users, invitations, hasher, email, organizations, organization_id) = setup().await;
        let use_case = InviteUserUseCase::new(users, invitations, hasher, email, organizations, TEST_BASE_DOMAIN.to_string());
        use_case.execute(organization_id, false, "florian", "a@example.com", false).await.unwrap();

        let err = use_case.execute(organization_id, false, "florian", "b@example.com", false).await.unwrap_err();
        assert!(matches!(err, ApplicationError::UsernameTaken));
    }

    #[tokio::test]
    async fn rejects_an_invalid_email() {
        let (users, invitations, hasher, email, organizations, organization_id) = setup().await;
        let use_case = InviteUserUseCase::new(users, invitations, hasher, email, organizations, TEST_BASE_DOMAIN.to_string());

        let err = use_case.execute(organization_id, false, "florian", "not-an-email", false).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidEmail(_)));
    }

    #[tokio::test]
    async fn an_invited_user_cannot_log_in_before_activating() {
        let (users, invitations, hasher, email, organizations, organization_id) = setup().await;
        let invite = InviteUserUseCase::new(users.clone(), invitations, hasher.clone(), email, organizations, TEST_BASE_DOMAIN.to_string());
        let id = invite.execute(organization_id, false, "florian", "florian@example.com", false).await.unwrap();

        let user = users.find_by_id(id).await.unwrap().unwrap();
        assert!(!hasher.verify("anything", &user.password_hash).await, "no plaintext should verify against the placeholder hash");
    }

    /// Recovers the token the same way a real invitee would: from the sent email's link.
    fn extract_token_from_last_email(email: &FakeEmail) -> String {
        let body = email.sent.lock().unwrap().last().unwrap().3.clone();
        body.split("token=").nth(1).unwrap().split_whitespace().next().unwrap().to_string()
    }

    #[tokio::test]
    async fn activates_an_account_with_a_valid_token() {
        let (users, invitations, hasher, email, organizations, organization_id) = setup().await;
        let invite = InviteUserUseCase::new(users.clone(), invitations.clone(), hasher.clone(), email.clone(), organizations, TEST_BASE_DOMAIN.to_string());
        let id = invite.execute(organization_id, false, "florian", "florian@example.com", false).await.unwrap();
        let token = extract_token_from_last_email(&email);

        let activate = ActivateAccountUseCase::new(users.clone(), invitations.clone(), hasher.clone());
        activate.execute(&token, "new-s3cret!").await.unwrap();

        let user = users.find_by_id(id).await.unwrap().unwrap();
        assert!(hasher.verify("new-s3cret!", &user.password_hash).await);
        assert!(invitations.find_by_user_id(id).await.unwrap().is_none(), "the invitation must be consumed after activation");
    }

    #[tokio::test]
    async fn rejects_an_unknown_token() {
        let (users, invitations, hasher, _email, _organizations, _organization_id) = setup().await;
        let activate = ActivateAccountUseCase::new(users, invitations, hasher);

        let err = activate.execute("not-a-real-token", "new-s3cret!").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvitationNotFound));
    }

    #[tokio::test]
    async fn rejects_an_expired_token() {
        let (users, invitations, hasher, _email, _organizations, organization_id) = setup().await;
        let user_id = Uuid::new_v4();
        users
            .insert(&User {
                id: user_id,
                username: Username::parse("florian").unwrap(),
                password_hash: "placeholder".to_string(),
                is_super_admin: false,
                is_organization_admin: false,
                organization_id,
                created_at: Utc::now(),
                tokens_valid_after: Utc::now(),
                email: Some("florian@example.com".to_string()),
            })
            .await
            .unwrap();
        invitations.upsert(&UserInvitation { user_id, token_hash: hash_invitation_token("raw-token"), expires_at: Utc::now() - Duration::hours(1) }).await.unwrap();

        let activate = ActivateAccountUseCase::new(users, invitations, hasher);
        let err = activate.execute("raw-token", "new-s3cret!").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvitationExpired));
    }

    #[tokio::test]
    async fn resends_an_invitation_with_a_fresh_token() {
        let (users, invitations, hasher, email, organizations, organization_id) = setup().await;
        let invite = InviteUserUseCase::new(users.clone(), invitations.clone(), hasher.clone(), email.clone(), organizations.clone(), TEST_BASE_DOMAIN.to_string());
        let id = invite.execute(organization_id, false, "florian", "florian@example.com", false).await.unwrap();
        let first_token_hash = invitations.find_by_user_id(id).await.unwrap().unwrap().token_hash;

        let resend = ResendInvitationUseCase::new(users, invitations.clone(), email.clone(), organizations, TEST_BASE_DOMAIN.to_string());
        resend.execute(id).await.unwrap();

        let second_token_hash = invitations.find_by_user_id(id).await.unwrap().unwrap().token_hash;
        assert_ne!(first_token_hash, second_token_hash);
        assert_eq!(email.sent.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn resending_for_an_unknown_user_fails() {
        let (users, invitations, _hasher, email, organizations, _organization_id) = setup().await;
        let resend = ResendInvitationUseCase::new(users, invitations, email, organizations, TEST_BASE_DOMAIN.to_string());

        let err = resend.execute(Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvitationNotFound));
    }

    #[tokio::test]
    async fn resending_for_an_already_activated_user_fails() {
        let (users, invitations, hasher, email, organizations, organization_id) = setup().await;
        let invite = InviteUserUseCase::new(users.clone(), invitations.clone(), hasher.clone(), email.clone(), organizations.clone(), TEST_BASE_DOMAIN.to_string());
        let id = invite.execute(organization_id, false, "florian", "florian@example.com", false).await.unwrap();
        invitations.delete(id).await.unwrap(); // simulates a completed activation

        let resend = ResendInvitationUseCase::new(users, invitations, email, organizations, TEST_BASE_DOMAIN.to_string());
        let err = resend.execute(id).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvitationNotFound));
    }

    #[tokio::test]
    async fn resending_links_to_the_invitees_own_organization_not_a_default_one() {
        let (users, invitations, hasher, email, organizations, _default_organization_id) = setup().await;
        let organization_id = Uuid::new_v4();
        organizations
            .create(&Organization { id: organization_id, slug: OrganizationSlug::parse("acme").unwrap(), display_name: "Acme".to_string(), is_public: false, created_at: Utc::now() })
            .await
            .unwrap();
        let invite = InviteUserUseCase::new(users.clone(), invitations.clone(), hasher, email.clone(), organizations.clone(), TEST_BASE_DOMAIN.to_string());
        let id = invite.execute(organization_id, false, "florian", "florian@example.com", false).await.unwrap();

        let resend = ResendInvitationUseCase::new(users, invitations, email.clone(), organizations, TEST_BASE_DOMAIN.to_string());
        resend.execute(id).await.unwrap();

        let sent = email.sent.lock().unwrap();
        assert!(sent[1].3.contains("https://acme.hangar.example.com/activate?token="), "expected the acme subdomain, got: {}", sent[1].3);
    }

    #[sqlx::test(migrations = "../hangar-infrastructure/migrations")]
    async fn inviting_a_user_assigns_them_to_the_given_organization_and_admin_flag(pool: sqlx::PgPool) {
        let organizations = Arc::new(hangar_infrastructure::postgres::organization_repository::PostgresOrganizationRepository::new(pool.clone()));
        let organization_id = Uuid::new_v4();
        organizations
            .create(&hangar_domain::organization::Organization {
                id: organization_id,
                slug: hangar_domain::organization::OrganizationSlug::parse("acme").unwrap(),
                display_name: "Acme".to_string(),
                is_public: false,
                created_at: Utc::now(),
            })
            .await
            .unwrap();
        let users = Arc::new(hangar_infrastructure::postgres::user_repository::PostgresUserRepository::new(pool.clone()));
        let (_, invitations, hasher, email, _fake_organizations, _fake_organization_id) = setup().await;
        let use_case = InviteUserUseCase::new(users.clone(), invitations, hasher, email, organizations, "localhost".to_string());

        let user_id = use_case.execute(organization_id, true, "acme-admin", "admin@acme.example", false).await.unwrap();

        let created = users.find_by_id(user_id).await.unwrap().unwrap();
        assert_eq!(created.organization_id, organization_id);
        assert!(created.is_organization_admin);
        assert!(!created.is_super_admin);
    }
}

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use hangar_domain::email::EmailPort;
use hangar_domain::user::{PasswordHasherPort, UserRepositoryPort};
use hangar_domain::webauthn::{WebauthnCredential, WebauthnCredentialPort};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::error::ApplicationError;

const CEREMONY_TTL_MINUTES: i64 = 5;

enum CeremonyState {
    Registration(PasskeyRegistration),
    Authentication(PasskeyAuthentication),
}

struct CeremonyEntry {
    user_id: Uuid,
    state: CeremonyState,
    expires_at: DateTime<Utc>,
}

/// Holds in-progress WebAuthn ceremonies between `start` and `finish`. Deliberately in-process, not persisted — a restart mid-ceremony just makes the client retry.
pub struct PasskeyCeremonyStore {
    entries: Mutex<HashMap<Uuid, CeremonyEntry>>,
}

impl Default for PasskeyCeremonyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PasskeyCeremonyStore {
    pub fn new() -> Self {
        Self { entries: Mutex::new(HashMap::new()) }
    }

    fn sweep_expired(entries: &mut HashMap<Uuid, CeremonyEntry>) {
        let now = Utc::now();
        entries.retain(|_, entry| entry.expires_at > now);
    }

    fn insert(&self, user_id: Uuid, state: CeremonyState) -> Uuid {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        Self::sweep_expired(&mut entries);
        let challenge_id = Uuid::new_v4();
        entries.insert(challenge_id, CeremonyEntry { user_id, state, expires_at: Utc::now() + Duration::minutes(CEREMONY_TTL_MINUTES) });
        challenge_id
    }

    /// Single use, like a nonce — removes the entry, not just reads it.
    fn take(&self, challenge_id: Uuid, expected_user_id: Uuid) -> Option<CeremonyEntry> {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        Self::sweep_expired(&mut entries);
        let entry = entries.remove(&challenge_id)?;
        if entry.user_id != expected_user_id {
            return None;
        }
        Some(entry)
    }
}

fn deserialize_passkey(credential: &WebauthnCredential) -> Result<Passkey, ApplicationError> {
    serde_json::from_slice(&credential.passkey_data).map_err(|e| ApplicationError::Domain(hangar_domain::error::DomainError::Infrastructure(format!("corrupted stored passkey: {e}"))))
}

fn serialize_passkey(passkey: &Passkey) -> Vec<u8> {
    serde_json::to_vec(passkey).expect("Passkey serialization is infallible")
}

/// `Option`, not a bare `Webauthn`: an invalid `PUBLIC_URL` makes the client fail to construct, and passkeys degrade to unavailable rather than crashing server startup.
fn require_webauthn(webauthn: &Option<Webauthn>) -> Result<&Webauthn, ApplicationError> {
    webauthn.as_ref().ok_or(ApplicationError::PasskeysUnavailable)
}

pub struct StartPasskeyRegistrationUseCase {
    webauthn: Arc<Option<Webauthn>>,
    credentials: Arc<dyn WebauthnCredentialPort>,
    ceremonies: Arc<PasskeyCeremonyStore>,
}

impl StartPasskeyRegistrationUseCase {
    pub fn new(webauthn: Arc<Option<Webauthn>>, credentials: Arc<dyn WebauthnCredentialPort>, ceremonies: Arc<PasskeyCeremonyStore>) -> Self {
        Self { webauthn, credentials, ceremonies }
    }

    pub async fn execute(&self, user_id: Uuid, username: &str) -> Result<(Uuid, CreationChallengeResponse), ApplicationError> {
        let webauthn = require_webauthn(&self.webauthn)?;
        let existing = self.credentials.list_for_user(user_id).await?;
        let exclude: Vec<CredentialID> = existing.iter().map(deserialize_passkey).collect::<Result<Vec<_>, _>>()?.iter().map(|pk| pk.cred_id().clone()).collect();

        let (ccr, registration) = webauthn
            .start_passkey_registration(user_id, username, username, if exclude.is_empty() { None } else { Some(exclude) })
            .map_err(|e| ApplicationError::Domain(hangar_domain::error::DomainError::Infrastructure(e.to_string())))?;

        let challenge_id = self.ceremonies.insert(user_id, CeremonyState::Registration(registration));
        Ok((challenge_id, ccr))
    }
}

pub struct FinishPasskeyRegistrationUseCase {
    webauthn: Arc<Option<Webauthn>>,
    credentials: Arc<dyn WebauthnCredentialPort>,
    ceremonies: Arc<PasskeyCeremonyStore>,
    users: Arc<dyn UserRepositoryPort>,
    email: Arc<dyn EmailPort>,
}

impl FinishPasskeyRegistrationUseCase {
    pub fn new(webauthn: Arc<Option<Webauthn>>, credentials: Arc<dyn WebauthnCredentialPort>, ceremonies: Arc<PasskeyCeremonyStore>, users: Arc<dyn UserRepositoryPort>, email: Arc<dyn EmailPort>) -> Self {
        Self { webauthn, credentials, ceremonies, users, email }
    }

    pub async fn execute(&self, user_id: Uuid, challenge_id: Uuid, response: &RegisterPublicKeyCredential, name: &str) -> Result<Uuid, ApplicationError> {
        let webauthn = require_webauthn(&self.webauthn)?;
        let entry = self.ceremonies.take(challenge_id, user_id).ok_or(ApplicationError::InvalidMfaCode)?;
        let CeremonyState::Registration(registration) = entry.state else {
            return Err(ApplicationError::InvalidMfaCode);
        };

        let passkey = webauthn.finish_passkey_registration(response, &registration).map_err(|_| ApplicationError::InvalidMfaCode)?;

        let credential = WebauthnCredential { id: Uuid::new_v4(), user_id, name: name.to_string(), passkey_data: serialize_passkey(&passkey), created_at: Utc::now() };
        self.credentials.insert(&credential).await?;

        // Best-effort: registration already succeeded, a delivery failure must not undo it.
        if let Ok(Some(user)) = self.users.find_by_id(user_id).await {
            if let Some(email) = user.email.as_deref() {
                let content = crate::email_templates::mfa_enrolled(user.username.as_str(), "une clé d'accès (passkey)");
                if let Err(e) = self.email.send(user.organization_id, email, &content.subject, &content.text, &content.html).await {
                    tracing::warn!("failed to send passkey-enrollment confirmation email to {email}: {e}");
                }
            }
        }
        Ok(credential.id)
    }
}

pub struct StartPasskeyAuthenticationUseCase {
    webauthn: Arc<Option<Webauthn>>,
    credentials: Arc<dyn WebauthnCredentialPort>,
    ceremonies: Arc<PasskeyCeremonyStore>,
}

impl StartPasskeyAuthenticationUseCase {
    pub fn new(webauthn: Arc<Option<Webauthn>>, credentials: Arc<dyn WebauthnCredentialPort>, ceremonies: Arc<PasskeyCeremonyStore>) -> Self {
        Self { webauthn, credentials, ceremonies }
    }

    pub async fn execute(&self, user_id: Uuid) -> Result<(Uuid, RequestChallengeResponse), ApplicationError> {
        let webauthn = require_webauthn(&self.webauthn)?;
        let existing = self.credentials.list_for_user(user_id).await?;
        if existing.is_empty() {
            return Err(ApplicationError::MfaNotEnrolled);
        }
        let passkeys: Vec<Passkey> = existing.iter().map(deserialize_passkey).collect::<Result<_, _>>()?;

        let (rcr, authentication) =
            webauthn.start_passkey_authentication(&passkeys).map_err(|e| ApplicationError::Domain(hangar_domain::error::DomainError::Infrastructure(e.to_string())))?;

        let challenge_id = self.ceremonies.insert(user_id, CeremonyState::Authentication(authentication));
        Ok((challenge_id, rcr))
    }
}

pub struct FinishPasskeyAuthenticationUseCase {
    webauthn: Arc<Option<Webauthn>>,
    credentials: Arc<dyn WebauthnCredentialPort>,
    ceremonies: Arc<PasskeyCeremonyStore>,
}

impl FinishPasskeyAuthenticationUseCase {
    pub fn new(webauthn: Arc<Option<Webauthn>>, credentials: Arc<dyn WebauthnCredentialPort>, ceremonies: Arc<PasskeyCeremonyStore>) -> Self {
        Self { webauthn, credentials, ceremonies }
    }

    pub async fn execute(&self, user_id: Uuid, challenge_id: Uuid, response: &PublicKeyCredential) -> Result<(), ApplicationError> {
        let webauthn = require_webauthn(&self.webauthn)?;
        let entry = self.ceremonies.take(challenge_id, user_id).ok_or(ApplicationError::InvalidMfaCode)?;
        let CeremonyState::Authentication(authentication) = entry.state else {
            return Err(ApplicationError::InvalidMfaCode);
        };

        let auth_result = webauthn.finish_passkey_authentication(response, &authentication).map_err(|_| ApplicationError::InvalidMfaCode)?;

        if auth_result.needs_update() {
            let existing = self.credentials.list_for_user(user_id).await?;
            for stored in existing {
                let mut passkey = deserialize_passkey(&stored)?;
                if passkey.cred_id() == auth_result.cred_id() && passkey.update_credential(&auth_result).unwrap_or(false) {
                    self.credentials.update_passkey_data(stored.id, serialize_passkey(&passkey)).await?;
                    break;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeySummary {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

pub struct ListPasskeysUseCase {
    credentials: Arc<dyn WebauthnCredentialPort>,
}

impl ListPasskeysUseCase {
    pub fn new(credentials: Arc<dyn WebauthnCredentialPort>) -> Self {
        Self { credentials }
    }

    pub async fn execute(&self, user_id: Uuid) -> Result<Vec<PasskeySummary>, ApplicationError> {
        let credentials = self.credentials.list_for_user(user_id).await?;
        Ok(credentials.into_iter().map(|c| PasskeySummary { id: c.id, name: c.name, created_at: c.created_at }).collect())
    }
}

pub struct DeletePasskeyUseCase {
    users: Arc<dyn UserRepositoryPort>,
    hasher: Arc<dyn PasswordHasherPort>,
    credentials: Arc<dyn WebauthnCredentialPort>,
}

impl DeletePasskeyUseCase {
    pub fn new(users: Arc<dyn UserRepositoryPort>, hasher: Arc<dyn PasswordHasherPort>, credentials: Arc<dyn WebauthnCredentialPort>) -> Self {
        Self { users, hasher, credentials }
    }

    pub async fn execute(&self, user_id: Uuid, credential_id: Uuid, current_password: &str) -> Result<(), ApplicationError> {
        let user = self.users.find_by_id(user_id).await?.ok_or(ApplicationError::InvalidCredentials)?;
        if !self.hasher.verify(current_password, &user.password_hash).await {
            return Err(ApplicationError::InvalidCredentials);
        }
        self.credentials.delete(credential_id, user_id).await?;
        Ok(())
    }
}

/// Built from `HANGAR_BASE_DOMAIN`, not `PUBLIC_URL` — `rp_id` needs the shared base domain for `allow_subdomains(true)` to validate every org's subdomain against one client instance.
/// The port still has to come from somewhere, though, so a non-default one is taken from `public_url` instead of silently defaulting to 80/443.
fn rp_origin_url(hangar_base_domain: &str, public_url: &str) -> Result<Url, String> {
    let scheme = if hangar_base_domain.starts_with("localhost") { "http" } else { "https" };
    let port_suffix = Url::parse(public_url).ok().and_then(|u| u.port()).map(|p| format!(":{p}")).unwrap_or_default();
    Url::parse(&format!("{scheme}://{hangar_base_domain}{port_suffix}")).map_err(|e| format!("HANGAR_BASE_DOMAIN ({hangar_base_domain}) is not usable as a URL: {e}"))
}

/// Returns `Err` instead of panicking on an unusable `HANGAR_BASE_DOMAIN`.
pub fn build_webauthn_client(hangar_base_domain: &str, rp_name: &str, public_url: &str) -> Result<Webauthn, String> {
    let rp_origin = rp_origin_url(hangar_base_domain, public_url)?;
    WebauthnBuilder::new(hangar_base_domain, &rp_origin)
        .map_err(|e| format!("HANGAR_BASE_DOMAIN ({hangar_base_domain}) is not usable as a WebAuthn relying party: {e}"))?
        .rp_name(rp_name)
        .allow_subdomains(true)
        .build()
        .map_err(|e| format!("failed to build the WebAuthn client: {e}"))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap as StdHashMap;
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;
    use hangar_domain::error::DomainError;
    use hangar_domain::user::{User, Username};
    use serde_json::json;

    use super::*;

    struct FakeCredentials {
        by_user: StdMutex<StdHashMap<Uuid, Vec<WebauthnCredential>>>,
    }

    impl FakeCredentials {
        fn new() -> Self {
            Self { by_user: StdMutex::new(StdHashMap::new()) }
        }
    }

    #[async_trait]
    impl WebauthnCredentialPort for FakeCredentials {
        async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<WebauthnCredential>, DomainError> {
            Ok(self.by_user.lock().unwrap().get(&user_id).cloned().unwrap_or_default())
        }
        async fn insert(&self, credential: &WebauthnCredential) -> Result<(), DomainError> {
            self.by_user.lock().unwrap().entry(credential.user_id).or_default().push(credential.clone());
            Ok(())
        }
        async fn update_passkey_data(&self, id: Uuid, passkey_data: Vec<u8>) -> Result<(), DomainError> {
            for creds in self.by_user.lock().unwrap().values_mut() {
                if let Some(c) = creds.iter_mut().find(|c| c.id == id) {
                    c.passkey_data = passkey_data;
                    return Ok(());
                }
            }
            Ok(())
        }
        async fn delete(&self, id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
            if let Some(creds) = self.by_user.lock().unwrap().get_mut(&user_id) {
                creds.retain(|c| c.id != id);
            }
            Ok(())
        }
        async fn count_for_user(&self, user_id: Uuid) -> Result<i64, DomainError> {
            Ok(self.by_user.lock().unwrap().get(&user_id).map(|c| c.len()).unwrap_or(0) as i64)
        }
    }

    struct FakeUsers {
        users: StdMutex<StdHashMap<Uuid, User>>,
    }

    impl FakeUsers {
        fn new() -> Self {
            Self { users: StdMutex::new(StdHashMap::new()) }
        }

        fn with_user(user: User) -> Self {
            let mut users = StdHashMap::new();
            users.insert(user.id, user);
            Self { users: StdMutex::new(users) }
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
        async fn update_password(&self, _id: Uuid, _new_password_hash: String) -> Result<(), DomainError> {
            Ok(())
        }
        async fn set_super_admin(&self, _id: Uuid, _is_super_admin: bool) -> Result<(), DomainError> {
            Ok(())
        }
        async fn set_organization_admin(&self, _id: Uuid, _is_organization_admin: bool) -> Result<(), DomainError> {
            Ok(())
        }
        async fn delete_unless_last_super_admin(&self, id: Uuid) -> Result<bool, DomainError> {
            self.users.lock().unwrap().remove(&id);
            Ok(true)
        }
        async fn set_super_admin_unless_last(&self, _id: Uuid, _is_super_admin: bool) -> Result<bool, DomainError> {
            Ok(true)
        }
    }

    struct FakeEmail {
        sent: StdMutex<Vec<(Uuid, String, String, String, String)>>,
    }

    impl FakeEmail {
        fn new() -> Self {
            Self { sent: StdMutex::new(Vec::new()) }
        }
    }

    #[async_trait]
    impl EmailPort for FakeEmail {
        async fn send(&self, organization_id: Uuid, to: &str, subject: &str, text_body: &str, html_body: &str) -> Result<(), DomainError> {
            self.sent.lock().unwrap().push((organization_id, to.to_string(), subject.to_string(), text_body.to_string(), html_body.to_string()));
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

    fn sample_user() -> User {
        User { id: Uuid::new_v4(), username: Username::parse("florian").unwrap(), password_hash: "hashed:s3cret!".to_string(), is_super_admin: false, is_organization_admin: false, organization_id: Uuid::new_v4(), created_at: Utc::now(), tokens_valid_after: Utc::now(), email: None }
    }

    fn test_webauthn() -> Arc<Option<Webauthn>> {
        Arc::new(Some(build_webauthn_client("hangar.example.com", "Hangar", "https://hangar.example.com").unwrap()))
    }

    /// Deserializes cleanly but is cryptographically meaningless — good enough for tests that only need `finish_*` to reach (and fail) the crypto check.
    fn fake_register_response() -> RegisterPublicKeyCredential {
        serde_json::from_value(json!({
            "id": "AAAA",
            "rawId": "AAAA",
            "response": { "attestationObject": "", "clientDataJSON": "" },
            "type": "public-key",
        }))
        .unwrap()
    }

    fn fake_auth_response() -> PublicKeyCredential {
        serde_json::from_value(json!({
            "id": "AAAA",
            "rawId": "AAAA",
            "response": { "authenticatorData": "", "clientDataJSON": "", "signature": "" },
            "type": "public-key",
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn starting_registration_returns_a_challenge_id_and_creation_options() {
        let credentials = Arc::new(FakeCredentials::new());
        let ceremonies = Arc::new(PasskeyCeremonyStore::new());
        let use_case = StartPasskeyRegistrationUseCase::new(test_webauthn(), credentials, ceremonies);

        let (challenge_id, ccr) = use_case.execute(Uuid::new_v4(), "florian").await.unwrap();

        assert_ne!(challenge_id, Uuid::nil());
        assert_eq!(ccr.public_key.user.name, "florian");
    }

    #[test]
    fn build_webauthn_client_rejects_an_ip_literal_base_domain() {
        let err = build_webauthn_client("0.0.0.0", "Hangar", "http://0.0.0.0:8080").unwrap_err();
        assert!(!err.is_empty());
    }

    /// Guards a real bug: a bare `scheme://hangar_base_domain` silently assumes the scheme's
    /// default port, breaking every passkey ceremony served on a non-default one (this
    /// project's own `docker-compose.yml` exposes 8080).
    #[test]
    fn rp_origin_includes_a_non_default_port_taken_from_public_url() {
        let origin = rp_origin_url("localhost", "http://localhost:8080").unwrap();
        assert_eq!(origin.as_str(), "http://localhost:8080/");
    }

    /// A real PUBLIC_URL is typically just `https://hangar.example.com`, no port since 443 is the default — the RP origin must match exactly, no spurious `:443`.
    #[test]
    fn rp_origin_omits_the_port_when_public_url_uses_the_schemes_default_port() {
        let origin = rp_origin_url("hangar.example.com", "https://hangar.example.com").unwrap();
        assert_eq!(origin.as_str(), "https://hangar.example.com/");
    }

    /// PUBLIC_URL missing or unparsable must not prevent the server from starting — falls back to no port suffix.
    #[test]
    fn rp_origin_falls_back_to_no_port_when_public_url_is_unusable() {
        let origin = rp_origin_url("localhost", "not a url").unwrap();
        assert_eq!(origin.as_str(), "http://localhost/");
    }

    #[tokio::test]
    async fn passkey_registration_uses_the_shared_base_domain_as_the_relying_party_id() {
        let webauthn = test_webauthn();
        let credentials = Arc::new(FakeCredentials::new());
        let ceremonies = Arc::new(PasskeyCeremonyStore::new());
        let use_case = StartPasskeyRegistrationUseCase::new(webauthn, credentials, ceremonies);

        let (_challenge_id, ccr) = use_case.execute(Uuid::new_v4(), "florian").await.unwrap();

        assert_eq!(ccr.public_key.rp.id, "hangar.example.com");
    }

    #[tokio::test]
    async fn starting_registration_fails_gracefully_when_webauthn_is_unavailable() {
        let webauthn: Arc<Option<Webauthn>> = Arc::new(None);
        let credentials = Arc::new(FakeCredentials::new());
        let ceremonies = Arc::new(PasskeyCeremonyStore::new());
        let use_case = StartPasskeyRegistrationUseCase::new(webauthn, credentials, ceremonies);

        let err = use_case.execute(Uuid::new_v4(), "florian").await.unwrap_err();
        assert!(matches!(err, ApplicationError::PasskeysUnavailable));
    }

    #[tokio::test]
    async fn finishing_registration_with_an_unknown_challenge_id_fails() {
        let credentials = Arc::new(FakeCredentials::new());
        let ceremonies = Arc::new(PasskeyCeremonyStore::new());
        let use_case = FinishPasskeyRegistrationUseCase::new(test_webauthn(), credentials, ceremonies, Arc::new(FakeUsers::new()), Arc::new(FakeEmail::new()));

        let err = use_case.execute(Uuid::new_v4(), Uuid::new_v4(), &fake_register_response(), "My key").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidMfaCode));
    }

    #[tokio::test]
    async fn finishing_registration_with_a_challenge_belonging_to_a_different_user_fails() {
        let webauthn = test_webauthn();
        let credentials = Arc::new(FakeCredentials::new());
        let ceremonies = Arc::new(PasskeyCeremonyStore::new());
        let start = StartPasskeyRegistrationUseCase::new(webauthn.clone(), credentials.clone(), ceremonies.clone());
        let (challenge_id, _ccr) = start.execute(Uuid::new_v4(), "florian").await.unwrap();

        let finish = FinishPasskeyRegistrationUseCase::new(webauthn, credentials, ceremonies, Arc::new(FakeUsers::new()), Arc::new(FakeEmail::new()));
        let someone_else = Uuid::new_v4();
        let err = finish.execute(someone_else, challenge_id, &fake_register_response(), "My key").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidMfaCode));
    }

    #[tokio::test]
    async fn a_challenge_id_can_only_be_finished_once() {
        let webauthn = test_webauthn();
        let credentials = Arc::new(FakeCredentials::new());
        let ceremonies = Arc::new(PasskeyCeremonyStore::new());
        let user_id = Uuid::new_v4();
        let start = StartPasskeyRegistrationUseCase::new(webauthn.clone(), credentials.clone(), ceremonies.clone());
        let (challenge_id, _ccr) = start.execute(user_id, "florian").await.unwrap();

        let finish = FinishPasskeyRegistrationUseCase::new(webauthn, credentials, ceremonies, Arc::new(FakeUsers::new()), Arc::new(FakeEmail::new()));
        // Proves `take()` removes the entry: the second attempt must fail at ceremony lookup, not crypto.
        let _ = finish.execute(user_id, challenge_id, &fake_register_response(), "My key").await;
        let err = finish.execute(user_id, challenge_id, &fake_register_response(), "My key").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidMfaCode));
    }

    #[tokio::test]
    async fn finishing_registration_with_a_cryptographically_invalid_response_fails() {
        let webauthn = test_webauthn();
        let credentials = Arc::new(FakeCredentials::new());
        let ceremonies = Arc::new(PasskeyCeremonyStore::new());
        let user_id = Uuid::new_v4();
        let start = StartPasskeyRegistrationUseCase::new(webauthn.clone(), credentials.clone(), ceremonies.clone());
        let (challenge_id, _ccr) = start.execute(user_id, "florian").await.unwrap();

        let finish = FinishPasskeyRegistrationUseCase::new(webauthn, credentials.clone(), ceremonies, Arc::new(FakeUsers::new()), Arc::new(FakeEmail::new()));
        let err = finish.execute(user_id, challenge_id, &fake_register_response(), "My key").await.unwrap_err();

        assert!(matches!(err, ApplicationError::InvalidMfaCode));
        assert_eq!(credentials.count_for_user(user_id).await.unwrap(), 0, "a failed registration must not persist a credential");
    }

    #[tokio::test]
    async fn starting_authentication_fails_when_no_passkeys_are_registered() {
        let credentials = Arc::new(FakeCredentials::new());
        let ceremonies = Arc::new(PasskeyCeremonyStore::new());
        let use_case = StartPasskeyAuthenticationUseCase::new(test_webauthn(), credentials, ceremonies);

        let err = use_case.execute(Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::MfaNotEnrolled));
    }

    #[tokio::test]
    async fn finishing_authentication_with_an_unknown_challenge_id_fails() {
        let credentials = Arc::new(FakeCredentials::new());
        let ceremonies = Arc::new(PasskeyCeremonyStore::new());
        let use_case = FinishPasskeyAuthenticationUseCase::new(test_webauthn(), credentials, ceremonies);

        let err = use_case.execute(Uuid::new_v4(), Uuid::new_v4(), &fake_auth_response()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidMfaCode));
    }

    #[tokio::test]
    async fn list_passkeys_returns_the_users_registered_credentials() {
        let credentials = Arc::new(FakeCredentials::new());
        let user_id = Uuid::new_v4();
        credentials.insert(&WebauthnCredential { id: Uuid::new_v4(), user_id, name: "MacBook".to_string(), passkey_data: b"opaque".to_vec(), created_at: Utc::now() }).await.unwrap();

        let summaries = ListPasskeysUseCase::new(credentials).execute(user_id).await.unwrap();

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].name, "MacBook");
    }

    #[tokio::test]
    async fn deleting_a_passkey_requires_the_current_password() {
        let credentials = Arc::new(FakeCredentials::new());
        let user = sample_user();
        let users = Arc::new(FakeUsers::with_user(user.clone()));
        let credential_id = Uuid::new_v4();
        credentials.insert(&WebauthnCredential { id: credential_id, user_id: user.id, name: "MacBook".to_string(), passkey_data: b"opaque".to_vec(), created_at: Utc::now() }).await.unwrap();

        let use_case = DeletePasskeyUseCase::new(users, Arc::new(FakeHasher), credentials.clone());
        let err = use_case.execute(user.id, credential_id, "wrong-password").await.unwrap_err();
        assert!(matches!(err, ApplicationError::InvalidCredentials));
        assert_eq!(credentials.count_for_user(user.id).await.unwrap(), 1);

        use_case.execute(user.id, credential_id, "s3cret!").await.unwrap();
        assert_eq!(credentials.count_for_user(user.id).await.unwrap(), 0);
    }
}

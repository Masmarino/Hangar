use std::sync::Arc;

use base64::Engine;
use chrono::Utc;
use hangar_domain::api_token::{ApiToken, ApiTokenRepositoryPort};
use rand::Rng;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::ApplicationError;

pub fn generate_api_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("hgr_{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

pub fn hash_api_token(plaintext: &str) -> String {
    hex::encode(Sha256::digest(plaintext.as_bytes()))
}

pub struct CreateApiTokenUseCase {
    tokens: Arc<dyn ApiTokenRepositoryPort>,
}

impl CreateApiTokenUseCase {
    pub fn new(tokens: Arc<dyn ApiTokenRepositoryPort>) -> Self {
        Self { tokens }
    }

    /// Returns `(token_id, plaintext_token)` — the plaintext is available
    /// only here, at creation. Callers must surface it to the user
    /// immediately and never attempt to retrieve it again.
    pub async fn execute(&self, user_id: Uuid, label: &str) -> Result<(Uuid, String), ApplicationError> {
        let plaintext = generate_api_token();
        let token = ApiToken {
            id: Uuid::new_v4(),
            user_id,
            token_hash: hash_api_token(&plaintext),
            label: label.to_string(),
            created_at: Utc::now(),
            last_used_at: None,
            revoked_at: None,
        };
        self.tokens.insert(&token).await?;
        Ok((token.id, plaintext))
    }
}

pub struct ListApiTokensUseCase {
    tokens: Arc<dyn ApiTokenRepositoryPort>,
}

impl ListApiTokensUseCase {
    pub fn new(tokens: Arc<dyn ApiTokenRepositoryPort>) -> Self {
        Self { tokens }
    }

    pub async fn execute(&self, user_id: Uuid) -> Result<Vec<ApiToken>, ApplicationError> {
        Ok(self.tokens.list_for_user(user_id).await?)
    }
}

pub struct RevokeApiTokenUseCase {
    tokens: Arc<dyn ApiTokenRepositoryPort>,
}

impl RevokeApiTokenUseCase {
    pub fn new(tokens: Arc<dyn ApiTokenRepositoryPort>) -> Self {
        Self { tokens }
    }

    /// Errs with `ApiTokenNotFound` if `token_id` doesn't exist or isn't owned by
    /// `user_id` — the repository update is scoped by both, so "zero rows
    /// affected" must not be reported to the caller as a successful revoke.
    pub async fn execute(&self, token_id: Uuid, user_id: Uuid) -> Result<(), ApplicationError> {
        if self.tokens.revoke(token_id, user_id).await? {
            Ok(())
        } else {
            Err(ApplicationError::ApiTokenNotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FakeTokens {
        tokens: Mutex<HashMap<Uuid, hangar_domain::api_token::ApiToken>>,
    }
    impl FakeTokens {
        fn new() -> Self { Self { tokens: Mutex::new(HashMap::new()) } }
    }
    #[async_trait::async_trait]
    impl hangar_domain::api_token::ApiTokenRepositoryPort for FakeTokens {
        async fn insert(&self, token: &hangar_domain::api_token::ApiToken) -> Result<(), hangar_domain::error::DomainError> {
            self.tokens.lock().unwrap().insert(token.id, token.clone());
            Ok(())
        }
        async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<hangar_domain::api_token::ApiToken>, hangar_domain::error::DomainError> {
            Ok(self.tokens.lock().unwrap().values().filter(|t| t.user_id == user_id).cloned().collect())
        }
        async fn list_all(&self) -> Result<Vec<hangar_domain::api_token::ApiToken>, hangar_domain::error::DomainError> {
            Ok(self.tokens.lock().unwrap().values().cloned().collect())
        }
        async fn find_by_hash(&self, token_hash: &str) -> Result<Option<hangar_domain::api_token::ApiToken>, hangar_domain::error::DomainError> {
            Ok(self.tokens.lock().unwrap().values().find(|t| t.token_hash == token_hash).cloned())
        }
        async fn touch_last_used_at(&self, id: Uuid, used_at: chrono::DateTime<chrono::Utc>) -> Result<(), hangar_domain::error::DomainError> {
            if let Some(t) = self.tokens.lock().unwrap().get_mut(&id) { t.last_used_at = Some(used_at); }
            Ok(())
        }
        async fn revoke(&self, id: Uuid, user_id: Uuid) -> Result<bool, hangar_domain::error::DomainError> {
            if let Some(t) = self.tokens.lock().unwrap().get_mut(&id) {
                if t.user_id == user_id {
                    t.revoked_at = Some(chrono::Utc::now());
                    return Ok(true);
                }
            }
            Ok(false)
        }
        async fn revoke_any(&self, id: Uuid) -> Result<(), hangar_domain::error::DomainError> {
            if let Some(t) = self.tokens.lock().unwrap().get_mut(&id) {
                t.revoked_at = Some(chrono::Utc::now());
            }
            Ok(())
        }
    }

    #[test]
    fn generated_tokens_have_the_hgr_prefix_and_are_reasonably_long() {
        let token = generate_api_token();
        assert!(token.starts_with("hgr_"));
        assert!(token.len() > 20);
    }

    #[test]
    fn hashing_is_deterministic() {
        assert_eq!(hash_api_token("same-input"), hash_api_token("same-input"));
        assert_ne!(hash_api_token("a"), hash_api_token("b"));
    }

    #[tokio::test]
    async fn creating_a_token_stores_only_its_hash() {
        let tokens = Arc::new(FakeTokens::new());
        let use_case = CreateApiTokenUseCase::new(tokens.clone());
        let user_id = Uuid::new_v4();
        let (id, plaintext) = use_case.execute(user_id, "my laptop").await.unwrap();

        let stored = tokens.list_for_user(user_id).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, id);
        assert_ne!(stored[0].token_hash, plaintext, "the stored value must be a hash, never the plaintext token");
        assert_eq!(stored[0].token_hash, hash_api_token(&plaintext));
    }

    #[tokio::test]
    async fn revoking_someone_elses_token_is_rejected_and_does_not_revoke_it() {
        let tokens = Arc::new(FakeTokens::new());
        let create = CreateApiTokenUseCase::new(tokens.clone());
        let owner = Uuid::new_v4();
        let (id, _) = create.execute(owner, "laptop").await.unwrap();

        let revoke = RevokeApiTokenUseCase::new(tokens.clone());
        let err = revoke.execute(id, Uuid::new_v4()).await.unwrap_err(); // different user_id
        assert!(matches!(err, ApplicationError::ApiTokenNotFound));

        let stored = tokens.list_for_user(owner).await.unwrap();
        assert!(stored[0].revoked_at.is_none(), "revoke must not affect a token owned by a different user");
    }

    #[tokio::test]
    async fn revoking_an_unknown_token_id_is_rejected() {
        let tokens = Arc::new(FakeTokens::new());
        let revoke = RevokeApiTokenUseCase::new(tokens.clone());
        let err = revoke.execute(Uuid::new_v4(), Uuid::new_v4()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::ApiTokenNotFound));
    }
}

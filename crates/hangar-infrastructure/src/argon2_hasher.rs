use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use async_trait::async_trait;
use hangar_domain::error::DomainError;
use hangar_domain::user::PasswordHasherPort;

use crate::error_ext::InfraErr;

pub struct Argon2PasswordHasher;

#[async_trait]
impl PasswordHasherPort for Argon2PasswordHasher {
    async fn hash(&self, plain_password: &str) -> Result<String, DomainError> {
        let plain_password = plain_password.to_string();
        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            Argon2::default().hash_password(plain_password.as_bytes(), &salt).map(|hash| hash.to_string()).infra_err()
        })
        .await
        .map_err(|e| DomainError::Infrastructure(format!("password hashing task panicked: {e}")))?
    }

    async fn verify(&self, plain_password: &str, hash: &str) -> bool {
        let plain_password = plain_password.to_string();
        let hash = hash.to_string();
        tokio::task::spawn_blocking(move || {
            let Ok(parsed_hash) = PasswordHash::new(&hash) else {
                return false;
            };
            Argon2::default().verify_password(plain_password.as_bytes(), &parsed_hash).is_ok()
        })
        .await
        .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hashing_then_verifying_the_same_password_succeeds() {
        let hasher = Argon2PasswordHasher;
        let hash = hasher.hash("sup3r-s3cret!").await.unwrap();
        assert!(hasher.verify("sup3r-s3cret!", &hash).await);
    }

    #[tokio::test]
    async fn verifying_a_wrong_password_fails() {
        let hasher = Argon2PasswordHasher;
        let hash = hasher.hash("sup3r-s3cret!").await.unwrap();
        assert!(!hasher.verify("wrong-password", &hash).await);
    }
}

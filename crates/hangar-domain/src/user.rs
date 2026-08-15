use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Username(String);

impl Username {
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let len_ok = (3..=32).contains(&raw.len());
        let starts_with_letter = raw.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        let chars_ok = raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

        if len_ok && starts_with_letter && chars_ok {
            Ok(Self(raw.to_string()))
        } else {
            Err(DomainError::InvalidUsername(raw.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Mirrors the frontend's own minimum, enforced again here since the API is reachable without the UI.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// No `Debug`/`Clone` — a plaintext password should be hard to log or copy around.
pub struct Password(String);

impl Password {
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        if raw.chars().count() < MIN_PASSWORD_LENGTH {
            return Err(DomainError::PasswordTooShort);
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub username: Username,
    pub password_hash: String,
    pub is_super_admin: bool,
    pub is_organization_admin: bool,
    pub organization_id: Uuid,
    pub created_at: DateTime<Utc>,
    /// Tokens issued before this instant are rejected; bumped on password change so a stolen session token stops working.
    pub tokens_valid_after: DateTime<Utc>,
    /// `None` only for accounts created before this field existed.
    pub email: Option<String>,
}

#[async_trait]
pub trait UserRepositoryPort: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, DomainError>;
    async fn find_by_username(&self, username: &Username) -> Result<Option<User>, DomainError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, DomainError>;
    async fn list_all(&self) -> Result<Vec<User>, DomainError>;
    async fn insert(&self, user: &User) -> Result<(), DomainError>;
    async fn delete(&self, id: Uuid) -> Result<(), DomainError>;
    /// Also bumps `tokens_valid_after` to now, revoking every token issued before this call.
    async fn update_password(&self, id: Uuid, new_password_hash: String) -> Result<(), DomainError>;
    async fn set_super_admin(&self, id: Uuid, is_super_admin: bool) -> Result<(), DomainError>;

    /// `false` if this would leave zero super-admins (a no-op then).
    async fn delete_unless_last_super_admin(&self, id: Uuid) -> Result<bool, DomainError>;

    /// `false` if the demotion would leave zero super-admins (a no-op then).
    async fn set_super_admin_unless_last(&self, id: Uuid, is_super_admin: bool) -> Result<bool, DomainError>;

    async fn set_organization_admin(&self, id: Uuid, is_organization_admin: bool) -> Result<(), DomainError>;
}

#[async_trait]
pub trait PasswordHasherPort: Send + Sync {
    /// Runs on a blocking thread pool internally — Argon2 is too slow for an async worker.
    async fn hash(&self, plain_password: &str) -> Result<String, DomainError>;
    async fn verify(&self, plain_password: &str, hash: &str) -> bool;
}

/// What a valid token proves: whose it is, and when it was minted — lets callers reject tokens minted before a password change.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedToken {
    pub user_id: Uuid,
    pub issued_at: DateTime<Utc>,
}

#[async_trait]
pub trait TokenIssuerPort: Send + Sync {
    fn issue(&self, user_id: Uuid, ttl: chrono::Duration) -> Result<String, DomainError>;
    fn verify(&self, token: &str) -> Result<VerifiedToken, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_valid_username() {
        let username = Username::parse("florian_01").unwrap();
        assert_eq!(username.as_str(), "florian_01");
    }

    #[test]
    fn rejects_a_username_shorter_than_3_chars() {
        let err = Username::parse("ab").unwrap_err();
        assert!(matches!(err, DomainError::InvalidUsername(_)));
    }

    #[test]
    fn rejects_a_username_with_invalid_characters() {
        let err = Username::parse("florian!").unwrap_err();
        assert!(matches!(err, DomainError::InvalidUsername(_)));
    }

    #[test]
    fn rejects_a_username_not_starting_with_a_letter() {
        let err = Username::parse("1florian").unwrap_err();
        assert!(matches!(err, DomainError::InvalidUsername(_)));
    }

    #[test]
    fn accepts_a_password_of_the_minimum_length() {
        let password = Password::parse("12345678").unwrap();
        assert_eq!(password.as_str(), "12345678");
    }

    #[test]
    fn rejects_a_password_below_the_minimum_length() {
        assert!(matches!(Password::parse("1234567"), Err(DomainError::PasswordTooShort)));
    }
}

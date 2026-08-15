use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use hangar_domain::error::DomainError;
use hangar_domain::user::{TokenIssuerPort, VerifiedToken};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error_ext::InfraErr;

/// Both issuers sign with the same secret; this claim keeps a partially-authenticated (password-only) token from being accepted anywhere a full session token is required, and vice versa.
const MFA_PENDING_TOKEN_TYPE: &str = "mfa-pending";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    sub: Uuid,
    exp: i64,
    iat: i64,
    typ: String,
}

pub struct JwtMfaPendingTokenIssuer {
    secret: String,
    ttl: Duration,
}

impl JwtMfaPendingTokenIssuer {
    pub fn new(secret: String) -> Self {
        Self { secret, ttl: Duration::minutes(5) }
    }
}

#[async_trait]
impl TokenIssuerPort for JwtMfaPendingTokenIssuer {
    // `ttl` is ignored: an mfa-pending token is a short-lived "password verified" proof,
    // never a session token, so it always uses its own fixed 5-minute lifetime regardless
    // of any organization's configured session TTL.
    fn issue(&self, user_id: Uuid, _ttl: Duration) -> Result<String, DomainError> {
        let now = Utc::now();
        let claims = Claims { sub: user_id, exp: (now + self.ttl).timestamp(), iat: now.timestamp(), typ: MFA_PENDING_TOKEN_TYPE.to_string() };
        encode(&Header::default(), &claims, &EncodingKey::from_secret(self.secret.as_bytes())).infra_err()
    }

    fn verify(&self, token: &str) -> Result<VerifiedToken, DomainError> {
        let data = decode::<Claims>(token, &DecodingKey::from_secret(self.secret.as_bytes()), &Validation::default()).infra_err()?;
        if data.claims.typ != MFA_PENDING_TOKEN_TYPE {
            return Err(DomainError::Infrastructure("not an mfa-pending token".to_string()));
        }
        let issued_at =
            DateTime::from_timestamp(data.claims.iat, 0).ok_or_else(|| DomainError::Infrastructure("invalid token: bad iat".to_string()))?;
        Ok(VerifiedToken { user_id: data.claims.sub, issued_at })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuing_then_verifying_returns_the_same_user_id() {
        let issuer = JwtMfaPendingTokenIssuer::new("test-secret".to_string());
        let user_id = Uuid::new_v4();
        let token = issuer.issue(user_id, Duration::minutes(5)).unwrap();
        assert_eq!(issuer.verify(&token).unwrap().user_id, user_id);
    }

    #[test]
    fn verifying_a_token_signed_with_a_different_secret_fails() {
        let issuer_a = JwtMfaPendingTokenIssuer::new("secret-a".to_string());
        let issuer_b = JwtMfaPendingTokenIssuer::new("secret-b".to_string());
        let token = issuer_a.issue(Uuid::new_v4(), Duration::minutes(5)).unwrap();
        assert!(issuer_b.verify(&token).is_err());
    }

    #[test]
    fn a_session_token_is_rejected_by_the_mfa_pending_token_issuer() {
        let secret = "shared-secret".to_string();
        let session_issuer = crate::jwt_token_issuer::JwtTokenIssuer::new(secret.clone());
        let mfa_issuer = JwtMfaPendingTokenIssuer::new(secret);
        let session_token = session_issuer.issue(Uuid::new_v4(), Duration::hours(12)).unwrap();

        assert!(mfa_issuer.verify(&session_token).is_err(), "a session token must NOT verify as an mfa-pending token");
    }

    #[test]
    fn an_mfa_pending_token_is_rejected_by_the_session_token_issuer() {
        let secret = "shared-secret".to_string();
        let session_issuer = crate::jwt_token_issuer::JwtTokenIssuer::new(secret.clone());
        let mfa_issuer = JwtMfaPendingTokenIssuer::new(secret);
        let mfa_token = mfa_issuer.issue(Uuid::new_v4(), Duration::minutes(5)).unwrap();

        assert!(session_issuer.verify(&mfa_token).is_err(), "an mfa-pending token must NOT verify as a session token");
    }
}

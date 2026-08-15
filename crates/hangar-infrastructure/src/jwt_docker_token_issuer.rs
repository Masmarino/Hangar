use async_trait::async_trait;
use chrono::{Duration, Utc};
use hangar_domain::docker_registry::{DockerAccessClaims, DockerGrantedScope, DockerTokenIssuerPort};
use hangar_domain::error::DomainError;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error_ext::InfraErr;

#[derive(Debug, Serialize, Deserialize)]
struct ScopeClaim {
    resource_type: String,
    name: String,
    actions: Vec<String>,
    granted_repository_id: Option<Uuid>,
}

/// Both issuers sign with the same secret; this claim keeps a Docker access token from being accepted as a full session token, and vice versa.
const DOCKER_ACCESS_TOKEN_TYPE: &str = "docker-access";

/// `deny_unknown_fields`, matching the other two issuers sharing this secret.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    sub: Uuid,
    exp: i64,
    scope: Option<ScopeClaim>,
    typ: String,
    org: Uuid,
    super_admin: bool,
}

pub struct JwtDockerTokenIssuer {
    secret: String,
    ttl: Duration,
}

impl JwtDockerTokenIssuer {
    pub fn new(secret: String) -> Self {
        Self { secret, ttl: Duration::minutes(5) }
    }
}

#[async_trait]
impl DockerTokenIssuerPort for JwtDockerTokenIssuer {
    fn issue(&self, user_id: Uuid, organization_id: Uuid, is_super_admin: bool, granted_scope: Option<DockerGrantedScope>) -> Result<String, DomainError> {
        let claims = Claims {
            sub: user_id,
            exp: (Utc::now() + self.ttl).timestamp(),
            scope: granted_scope
                .map(|s| ScopeClaim { resource_type: s.resource_type, name: s.name, actions: s.actions, granted_repository_id: s.granted_repository_id }),
            typ: DOCKER_ACCESS_TOKEN_TYPE.to_string(),
            org: organization_id,
            super_admin: is_super_admin,
        };
        encode(&Header::default(), &claims, &EncodingKey::from_secret(self.secret.as_bytes())).infra_err()
    }

    fn verify(&self, token: &str) -> Result<DockerAccessClaims, DomainError> {
        let data = decode::<Claims>(token, &DecodingKey::from_secret(self.secret.as_bytes()), &Validation::default()).infra_err()?;
        if data.claims.typ != DOCKER_ACCESS_TOKEN_TYPE {
            return Err(DomainError::Infrastructure("not a docker access token".to_string()));
        }
        Ok(DockerAccessClaims {
            user_id: data.claims.sub,
            organization_id: data.claims.org,
            is_super_admin: data.claims.super_admin,
            granted_scope: data.claims.scope.map(|s| DockerGrantedScope {
                resource_type: s.resource_type,
                name: s.name,
                actions: s.actions,
                granted_repository_id: s.granted_repository_id,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuing_then_verifying_with_no_scope_round_trips_the_user_id() {
        let issuer = JwtDockerTokenIssuer::new("test-secret".to_string());
        let user_id = Uuid::new_v4();
        let token = issuer.issue(user_id, Uuid::new_v4(), false, None).unwrap();
        let claims = issuer.verify(&token).unwrap();
        assert_eq!(claims.user_id, user_id);
        assert!(claims.granted_scope.is_none());
    }

    #[test]
    fn issuing_then_verifying_with_a_scope_round_trips_the_granted_actions() {
        let issuer = JwtDockerTokenIssuer::new("test-secret".to_string());
        let user_id = Uuid::new_v4();
        let repository_id = Uuid::new_v4();
        let scope = DockerGrantedScope {
            resource_type: "repository".to_string(),
            name: "myrepo/myimage".to_string(),
            actions: vec!["pull".to_string()],
            granted_repository_id: Some(repository_id),
        };
        let token = issuer.issue(user_id, Uuid::new_v4(), false, Some(scope.clone())).unwrap();

        let claims = issuer.verify(&token).unwrap();

        let granted = claims.granted_scope.unwrap();
        assert_eq!(granted.actions, scope.actions);
        assert_eq!(granted.granted_repository_id, Some(repository_id));
    }

    #[test]
    fn issuing_then_verifying_round_trips_the_organization_and_super_admin_flag() {
        let issuer = JwtDockerTokenIssuer::new("test-secret".to_string());
        let organization_id = Uuid::new_v4();
        let token = issuer.issue(Uuid::new_v4(), organization_id, true, None).unwrap();

        let claims = issuer.verify(&token).unwrap();

        assert_eq!(claims.organization_id, organization_id);
        assert!(claims.is_super_admin);
    }

    #[test]
    fn verifying_a_token_signed_with_a_different_secret_fails() {
        let issuer_a = JwtDockerTokenIssuer::new("secret-a".to_string());
        let issuer_b = JwtDockerTokenIssuer::new("secret-b".to_string());
        let token = issuer_a.issue(Uuid::new_v4(), Uuid::new_v4(), false, None).unwrap();
        assert!(issuer_b.verify(&token).is_err());
    }

    #[test]
    fn a_session_token_is_rejected_by_the_docker_token_issuer() {
        let secret = "shared-secret".to_string();
        let session_issuer = crate::jwt_token_issuer::JwtTokenIssuer::new(secret.clone());
        let docker_issuer = JwtDockerTokenIssuer::new(secret);
        let session_token = hangar_domain::user::TokenIssuerPort::issue(&session_issuer, Uuid::new_v4(), Duration::hours(12)).unwrap();

        assert!(docker_issuer.verify(&session_token).is_err(), "a session token must NOT verify as a docker access token");
    }
}

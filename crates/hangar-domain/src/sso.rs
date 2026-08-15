use async_trait::async_trait;
use uuid::Uuid;

use crate::error::DomainError;

/// Deliberately minimal — never a role/group/admin claim, so a compromised IdP can't escalate a JIT-provisioned account beyond a plain member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIdentity {
    pub email: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityProviderConfig {
    Ldap(LdapConfig),
    Oidc(OidcConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapConfig {
    /// e.g. `ldap://dc.corp.example:389` or `ldaps://dc.corp.example:636`.
    pub server_url: String,
    pub bind_dn: String,
    /// Plaintext in memory; encrypted at rest via `secret_box` in `hangar-infrastructure`.
    pub bind_password: String,
    pub user_search_base: String,
    /// e.g. `(uid={username})` — `{username}` is substituted verbatim, so the `LdapAuthPort` adapter must escape it against LDAP filter injection.
    pub user_search_filter: String,
    pub email_attribute: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    /// e.g. `https://accounts.example.com` — discovery reads `{issuer_url}/.well-known/openid-configuration`.
    pub issuer_url: String,
    pub client_id: String,
    /// Plaintext in memory; encrypted at rest the same way as `LdapConfig::bind_password`.
    pub client_secret: String,
}

#[async_trait]
pub trait LdapAuthPort: Send + Sync {
    /// Binds as the service account, searches for one matching entry, then re-binds with its DN and the submitted password. Every failure mode collapses to the same `Err`.
    async fn authenticate(&self, config: &LdapConfig, username: &str, password: &str) -> Result<ExternalIdentity, DomainError>;
}

#[async_trait]
pub trait OidcAuthPort: Send + Sync {
    /// Returns the redirect URL. The nonce and PKCE verifier are embedded in a signed, self-contained `state` token (no server-side session store) — `handle_callback` decodes
    /// and verifies it. `binding_secret` is a fresh value also handed to the browser as a cookie (login-CSRF defense, RFC 6749 §10.12) — otherwise a captured callback URL would work in any browser.
    async fn build_redirect(&self, config: &OidcConfig, organization_id: Uuid, callback_url: &str, binding_secret: &str) -> Result<String, DomainError>;

    /// `expected_organization_id` must match the id embedded in `raw_state`, and `binding_secret` must match the one the token was minted with — either mismatch fails closed.
    async fn handle_callback(
        &self,
        config: &OidcConfig,
        code: &str,
        raw_state: &str,
        callback_url: &str,
        expected_organization_id: Uuid,
        binding_secret: &str,
    ) -> Result<ExternalIdentity, DomainError>;
}

#[async_trait]
pub trait IdentityProviderRepositoryPort: Send + Sync {
    /// `None` means the organization uses local accounts only.
    async fn get(&self, organization_id: Uuid) -> Result<Option<IdentityProviderConfig>, DomainError>;
    /// Replaces any existing configuration for this organization (one active provider at a time).
    async fn set(&self, organization_id: Uuid, config: &IdentityProviderConfig) -> Result<(), DomainError>;
    /// Idempotent: clearing an organization with no configuration is a no-op, not an error.
    async fn clear(&self, organization_id: Uuid) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> LdapConfig {
        LdapConfig {
            server_url: "ldap://dc.corp.example:389".to_string(),
            bind_dn: "cn=service,dc=corp,dc=example".to_string(),
            bind_password: "s3cret!".to_string(),
            user_search_base: "ou=people,dc=corp,dc=example".to_string(),
            user_search_filter: "(uid={username})".to_string(),
            email_attribute: "mail".to_string(),
        }
    }

    #[test]
    fn identity_provider_config_wraps_an_ldap_config_by_value() {
        let config = IdentityProviderConfig::Ldap(sample_config());
        let IdentityProviderConfig::Ldap(inner) = config else { panic!("expected Ldap variant") };
        assert_eq!(inner.server_url, "ldap://dc.corp.example:389");
    }

    #[test]
    fn external_identity_carries_email_and_optional_display_name() {
        let identity = ExternalIdentity { email: "florian@corp.example".to_string(), display_name: Some("Florian".to_string()) };
        assert_eq!(identity.email, "florian@corp.example");
        assert_eq!(identity.display_name.as_deref(), Some("Florian"));
    }

    #[test]
    fn identity_provider_config_wraps_an_oidc_config_by_value() {
        let config = IdentityProviderConfig::Oidc(OidcConfig {
            issuer_url: "https://accounts.example.com".to_string(),
            client_id: "hangar".to_string(),
            client_secret: "s3cret!".to_string(),
        });
        let IdentityProviderConfig::Oidc(inner) = config else { panic!("expected Oidc variant") };
        assert_eq!(inner.issuer_url, "https://accounts.example.com");
    }
}

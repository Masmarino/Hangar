use async_trait::async_trait;
use chrono::{Duration, Utc};
use hangar_domain::error::DomainError;
use hangar_domain::sso::{ExternalIdentity, OidcAuthPort, OidcConfig};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreIdTokenClaims, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenResponse,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error_ext::InfraErr;

const OIDC_STATE_TOKEN_TYPE: &str = "oidc-state";
/// Generous enough for a slow identity-provider login screen, short enough that a captured but unused redirect URL stops being useful quickly.
const STATE_TOKEN_TTL_MINUTES: i64 = 10;

/// The exact typestate combo `CoreClient::from_provider_metadata` produces: set for what discovery always returns, maybe-set for what it usually returns, not-set for what this
/// flow never uses. Has to be named explicitly — the bare `CoreClient` alias defaults every parameter to `EndpointNotSet`.
type OidcCoreClient = CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateClaims {
    typ: String,
    exp: i64,
    organization_id: Uuid,
    nonce: String,
    pkce_verifier: String,
    /// SHA-256 of the browser's binding cookie — hashed so the state token, which travels through the identity provider's logs, never carries the raw cookie value.
    binding_hash: String,
}

pub struct OpenidConnectAuthAdapter {
    jwt_secret: String,
}

impl OpenidConnectAuthAdapter {
    pub fn new(jwt_secret: String) -> Self {
        Self { jwt_secret }
    }

    fn binding_hash(binding_secret: &str) -> String {
        hex::encode(Sha256::digest(binding_secret.as_bytes()))
    }

    fn encode_state(&self, organization_id: Uuid, nonce: &Nonce, pkce_verifier: &PkceCodeVerifier, binding_secret: &str) -> Result<String, DomainError> {
        let claims = StateClaims {
            typ: OIDC_STATE_TOKEN_TYPE.to_string(),
            exp: (Utc::now() + Duration::minutes(STATE_TOKEN_TTL_MINUTES)).timestamp(),
            organization_id,
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
            binding_hash: Self::binding_hash(binding_secret),
        };
        encode(&Header::default(), &claims, &EncodingKey::from_secret(self.jwt_secret.as_bytes())).infra_err()
    }

    fn decode_state(&self, raw_state: &str, expected_organization_id: Uuid, expected_binding_secret: &str) -> Result<StateClaims, DomainError> {
        let data = decode::<StateClaims>(raw_state, &DecodingKey::from_secret(self.jwt_secret.as_bytes()), &Validation::default()).infra_err()?;
        if data.claims.typ != OIDC_STATE_TOKEN_TYPE {
            return Err(DomainError::Infrastructure("not an oidc-state token".to_string()));
        }
        // A token minted for one organization must never complete a session for another.
        if data.claims.organization_id != expected_organization_id {
            return Err(DomainError::Infrastructure("oidc state token organization mismatch".to_string()));
        }
        // Only the browser that started this login can complete it — otherwise a captured callback URL would log the victim in from any browser.
        if data.claims.binding_hash != Self::binding_hash(expected_binding_secret) {
            return Err(DomainError::Infrastructure("oidc state token browser binding mismatch".to_string()));
        }
        Ok(data.claims)
    }

    /// Redirects disabled — following them on the discovery/token requests would open this up to SSRF.
    fn http_client(&self) -> Result<openidconnect::reqwest::Client, DomainError> {
        openidconnect::reqwest::ClientBuilder::new().redirect(openidconnect::reqwest::redirect::Policy::none()).build().infra_err()
    }

    async fn build_client(&self, config: &OidcConfig, callback_url: &str) -> Result<OidcCoreClient, DomainError> {
        // Admin-configured URL, same SSRF guard as the remote npm/docker registry URLs.
        crate::ssrf_guard::ensure_public_host(&config.issuer_url).await?;
        let issuer_url = IssuerUrl::new(config.issuer_url.clone()).infra_err()?;
        let http_client = self.http_client()?;
        let metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client).await.infra_err()?;
        let redirect_url = RedirectUrl::new(callback_url.to_string()).infra_err()?;
        Ok(CoreClient::from_provider_metadata(metadata, ClientId::new(config.client_id.clone()), Some(ClientSecret::new(config.client_secret.clone())))
            .set_redirect_uri(redirect_url))
    }
}

#[async_trait]
impl OidcAuthPort for OpenidConnectAuthAdapter {
    async fn build_redirect(&self, config: &OidcConfig, organization_id: Uuid, callback_url: &str, binding_secret: &str) -> Result<String, DomainError> {
        let client = self.build_client(config, callback_url).await?;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let nonce = Nonce::new_random();
        let state_token = self.encode_state(organization_id, &nonce, &pkce_verifier, binding_secret)?;

        let (auth_url, _csrf, _nonce) = client
            .authorize_url(CoreAuthenticationFlow::AuthorizationCode, move || CsrfToken::new(state_token.clone()), move || nonce.clone())
            .add_scope(openidconnect::Scope::new("openid".to_string()))
            .add_scope(openidconnect::Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok(auth_url.to_string())
    }

    async fn handle_callback(
        &self,
        config: &OidcConfig,
        code: &str,
        raw_state: &str,
        callback_url: &str,
        expected_organization_id: Uuid,
        binding_secret: &str,
    ) -> Result<ExternalIdentity, DomainError> {
        let claims = self.decode_state(raw_state, expected_organization_id, binding_secret)?;
        let client = self.build_client(config, callback_url).await?;
        let http_client = self.http_client()?;

        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .infra_err()?
            .set_pkce_verifier(PkceCodeVerifier::new(claims.pkce_verifier))
            .request_async(&http_client)
            .await
            .infra_err()?;

        // id_token_verifier() checks the signature and client_id; claims() also checks the nonce.
        let expected_nonce = Nonce::new(claims.nonce);
        let id_token = token_response.id_token().ok_or_else(|| DomainError::Infrastructure("oidc token response had no id_token".to_string()))?;
        let id_token_verifier = client.id_token_verifier();
        let id_token_claims = id_token.claims(&id_token_verifier, &expected_nonce).infra_err()?;

        external_identity_from_claims(id_token_claims)
    }
}

/// Split out of `handle_callback` so it can be unit-tested without a live identity provider.
fn external_identity_from_claims(id_token_claims: &CoreIdTokenClaims) -> Result<ExternalIdentity, DomainError> {
    let email = id_token_claims
        .email()
        .ok_or_else(|| DomainError::Infrastructure("oidc id token missing the email claim".to_string()))?
        .to_string();

    // Provisioning matches accounts by email, so an unverified claim would let a self-asserted email log someone in as a colleague. Absent counts as unverified.
    if id_token_claims.email_verified() != Some(true) {
        return Err(DomainError::Infrastructure("oidc identity provider did not verify the user's email address".to_string()));
    }

    Ok(ExternalIdentity { email, display_name: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openidconnect::{Audience, EmptyAdditionalClaims, EndUserEmail, StandardClaims, SubjectIdentifier};

    const TEST_BINDING: &str = "test-browser-binding-secret";

    #[test]
    fn a_state_token_round_trips_its_claims() {
        let adapter = OpenidConnectAuthAdapter::new("jwt-secret".to_string());
        let organization_id = Uuid::new_v4();
        let nonce = Nonce::new("test-nonce".to_string());
        let pkce_verifier = PkceCodeVerifier::new("test-pkce-verifier".to_string());

        let token = adapter.encode_state(organization_id, &nonce, &pkce_verifier, TEST_BINDING).unwrap();
        let claims = adapter.decode_state(&token, organization_id, TEST_BINDING).unwrap();

        assert_eq!(claims.organization_id, organization_id);
        assert_eq!(claims.nonce, "test-nonce");
        assert_eq!(claims.pkce_verifier, "test-pkce-verifier");
    }

    #[test]
    fn a_state_token_minted_for_one_organization_is_rejected_for_another() {
        let adapter = OpenidConnectAuthAdapter::new("jwt-secret".to_string());
        let nonce = Nonce::new("test-nonce".to_string());
        let pkce_verifier = PkceCodeVerifier::new("test-pkce-verifier".to_string());
        let token = adapter.encode_state(Uuid::new_v4(), &nonce, &pkce_verifier, TEST_BINDING).unwrap();

        let result = adapter.decode_state(&token, Uuid::new_v4(), TEST_BINDING);

        assert!(result.is_err(), "a state token must not verify against a different organization id than the one it was minted for");
    }

    #[test]
    fn a_state_token_bound_to_one_browser_is_rejected_for_a_different_browser() {
        let adapter = OpenidConnectAuthAdapter::new("jwt-secret".to_string());
        let organization_id = Uuid::new_v4();
        let nonce = Nonce::new("test-nonce".to_string());
        let pkce_verifier = PkceCodeVerifier::new("test-pkce-verifier".to_string());
        let token = adapter.encode_state(organization_id, &nonce, &pkce_verifier, "browser-a-binding").unwrap();

        let result = adapter.decode_state(&token, organization_id, "browser-b-binding");

        assert!(result.is_err(), "a state token must not verify for a browser other than the one that started the login attempt");
    }

    /// Built by hand rather than via `encode_state` so the claims carry an already-expired `exp`, well past the 60s clock-skew leeway `Validation::default()` allows.
    #[test]
    fn a_state_token_past_its_expiry_is_rejected() {
        let adapter = OpenidConnectAuthAdapter::new("jwt-secret".to_string());
        let organization_id = Uuid::new_v4();
        let claims = StateClaims {
            typ: OIDC_STATE_TOKEN_TYPE.to_string(),
            exp: (Utc::now() - Duration::minutes(30)).timestamp(),
            organization_id,
            nonce: "test-nonce".to_string(),
            pkce_verifier: "test-pkce-verifier".to_string(),
            binding_hash: OpenidConnectAuthAdapter::binding_hash(TEST_BINDING),
        };
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(adapter.jwt_secret.as_bytes())).unwrap();

        let result = adapter.decode_state(&token, organization_id, TEST_BINDING);

        assert!(result.is_err(), "a state token past its exp must be rejected even if otherwise validly signed, org-scoped and browser-bound");
    }

    #[test]
    fn a_state_token_signed_with_a_different_secret_is_rejected() {
        let adapter_a = OpenidConnectAuthAdapter::new("secret-a".to_string());
        let adapter_b = OpenidConnectAuthAdapter::new("secret-b".to_string());
        let organization_id = Uuid::new_v4();
        let nonce = Nonce::new("test-nonce".to_string());
        let pkce_verifier = PkceCodeVerifier::new("test-pkce-verifier".to_string());
        let token = adapter_a.encode_state(organization_id, &nonce, &pkce_verifier, TEST_BINDING).unwrap();

        assert!(adapter_b.decode_state(&token, organization_id, TEST_BINDING).is_err());
    }

    fn claims_with(email: Option<&str>, email_verified: Option<bool>) -> CoreIdTokenClaims {
        let mut standard = StandardClaims::new(SubjectIdentifier::new("subject-1".to_string()));
        standard = standard.set_email(email.map(|e| EndUserEmail::new(e.to_string()))).set_email_verified(email_verified);
        CoreIdTokenClaims::new(
            IssuerUrl::new("https://accounts.example.com".to_string()).unwrap(),
            vec![Audience::new("hangar".to_string())],
            Utc::now() + Duration::minutes(5),
            Utc::now(),
            standard,
            EmptyAdditionalClaims {},
        )
    }

    #[test]
    fn a_verified_email_claim_yields_an_external_identity() {
        let identity = external_identity_from_claims(&claims_with(Some("florian@corp.example"), Some(true))).unwrap();

        assert_eq!(identity.email, "florian@corp.example");
    }

    #[test]
    fn an_unverified_email_claim_is_rejected() {
        let err = external_identity_from_claims(&claims_with(Some("florian@corp.example"), Some(false))).unwrap_err();

        assert!(err.to_string().contains("did not verify"), "got: {err}");
    }

    #[test]
    fn an_absent_email_verified_claim_is_rejected_like_an_unverified_one() {
        let err = external_identity_from_claims(&claims_with(Some("florian@corp.example"), None)).unwrap_err();

        assert!(err.to_string().contains("did not verify"), "got: {err}");
    }

    #[test]
    fn a_missing_email_claim_is_rejected() {
        let err = external_identity_from_claims(&claims_with(None, Some(true))).unwrap_err();

        assert!(err.to_string().contains("missing the email claim"), "got: {err}");
    }

    #[tokio::test]
    async fn an_issuer_url_pointing_at_a_private_address_is_rejected_before_discovery() {
        let adapter = OpenidConnectAuthAdapter::new("jwt-secret".to_string());
        // Port 1 on loopback: nothing listens there, so without the guard this would fail with a connection error instead of the SSRF rejection asserted below.
        let config = OidcConfig { issuer_url: "http://127.0.0.1:1".to_string(), client_id: "hangar".to_string(), client_secret: "s3cret!".to_string() };

        let err = adapter
            .build_redirect(&config, Uuid::new_v4(), "https://acme.hangar.example/api/auth/sso/oidc/callback", TEST_BINDING)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("private or reserved"), "got: {err}");
    }

    #[tokio::test]
    async fn an_issuer_url_pointing_at_the_cloud_metadata_endpoint_is_rejected() {
        let adapter = OpenidConnectAuthAdapter::new("jwt-secret".to_string());
        let config = OidcConfig { issuer_url: "http://169.254.169.254/".to_string(), client_id: "hangar".to_string(), client_secret: "s3cret!".to_string() };

        let err = adapter
            .build_redirect(&config, Uuid::new_v4(), "https://acme.hangar.example/api/auth/sso/oidc/callback", TEST_BINDING)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("private or reserved"), "got: {err}");
    }
}

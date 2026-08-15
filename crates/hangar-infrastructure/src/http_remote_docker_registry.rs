use async_trait::async_trait;
use hangar_domain::docker_registry::{Digest, DockerImageName};
use hangar_domain::docker_remote::RemoteDockerRegistryPort;
use hangar_domain::error::DomainError;

use crate::capped_response::read_capped;
use crate::ssrf_guard::ensure_public_host;

const ACCEPTED_MANIFEST_MEDIA_TYPES: &str = "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json";
/// Matches `hangar-docker`'s own manifest-push cap (`dispatch::MANIFEST_BODY_LIMIT_BYTES`).
const MAX_MANIFEST_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
/// Matches `hangar-docker`'s own blob-upload cap (`BLOB_BODY_LIMIT_BYTES`).
const MAX_BLOB_RESPONSE_BYTES: usize = 2 * 1024 * 1024 * 1024;
const MAX_TOKEN_RESPONSE_BYTES: usize = 1024 * 1024;

pub struct HttpRemoteDockerRegistry {
    client: reqwest::Client,
}

impl HttpRemoteDockerRegistry {
    pub fn new() -> Self {
        // No redirect-following, or a malicious upstream could 302 past the SSRF guard.
        Self { client: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("reqwest client config is static and always valid") }
    }

    /// On a 401 with a Bearer challenge, fetches a token and retries once. `Ok(None)` for a genuine 404 (either response) — not an error.
    async fn get_with_bearer_challenge(
        &self,
        url: &str,
        accept: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Option<reqwest::Response>, DomainError> {
        ensure_public_host(url).await?;
        let first =
            self.client.get(url).header("Accept", accept).send().await.map_err(|e| DomainError::Infrastructure(format!("requesting {url}: {e}")))?;
        if first.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if first.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Self::require_success(first, url).await.map(Some);
        }

        let challenge = extract_challenge_or_error(&first, url)?;
        // The realm comes from the remote's own response, not admin config — validate it too.
        ensure_public_host(&challenge.realm).await?;

        let mut token_request = self.client.get(&challenge.realm).query(&[("service", challenge.service.as_str())]);
        if let Some(scope) = &challenge.scope {
            token_request = token_request.query(&[("scope", scope.as_str())]);
        }
        // Basic-auths the token request itself, not the registry request that follows.
        if let Some(username) = username {
            token_request = token_request.basic_auth(username, password);
        }
        let token_response = token_request
            .send()
            .await
            .map_err(|e| DomainError::Infrastructure(format!("fetching token from {}: {e}", challenge.realm)))?;
        let token_body = parse_token_response(Self::require_success(token_response, &challenge.realm).await?, &challenge.realm).await?;

        let retried = self
            .client
            .get(url)
            .header("Accept", accept)
            .bearer_auth(&token_body.token)
            .send()
            .await
            .map_err(|e| DomainError::Infrastructure(format!("requesting {url}: {e}")))?;
        if retried.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Self::require_success(retried, url).await.map(Some)
    }

    async fn require_success(response: reqwest::Response, url: &str) -> Result<reqwest::Response, DomainError> {
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(DomainError::Infrastructure(format!("remote registry returned {} for {url}", response.status())))
        }
    }
}

impl Default for HttpRemoteDockerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RemoteDockerRegistryPort for HttpRemoteDockerRegistry {
    async fn fetch_manifest(
        &self,
        base_url: &str,
        image_name: &DockerImageName,
        reference: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Option<(Vec<u8>, String)>, DomainError> {
        let url = format!("{}/v2/{}/manifests/{}", base_url.trim_end_matches('/'), image_name.as_str(), reference);
        let response = self.get_with_bearer_challenge(&url, ACCEPTED_MANIFEST_MEDIA_TYPES, username, password).await?;
        map_manifest_response(response, &url).await
    }

    async fn fetch_blob(
        &self,
        base_url: &str,
        image_name: &DockerImageName,
        digest: &Digest,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Option<Vec<u8>>, DomainError> {
        let url = format!("{}/v2/{}/blobs/{}", base_url.trim_end_matches('/'), image_name.as_str(), digest.as_str());
        let response = self.get_with_bearer_challenge(&url, "application/octet-stream", username, password).await?;
        map_blob_response(response, &url).await
    }
}

/// Split out of `get_with_bearer_challenge` so it can be tested against an already-obtained response.
fn extract_challenge_or_error(response: &reqwest::Response, url: &str) -> Result<BearerChallenge, DomainError> {
    response
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_bearer_challenge)
        .ok_or_else(|| DomainError::Infrastructure(format!("{url} returned 401 without a Bearer challenge")))
}

/// JSON-parse mapping for the token-endpoint response, split out for the same reason as `extract_challenge_or_error` above.
async fn parse_token_response(response: reqwest::Response, realm: &str) -> Result<TokenResponse, DomainError> {
    let bytes = read_capped(response, realm, "token response", MAX_TOKEN_RESPONSE_BYTES).await?;
    serde_json::from_slice(&bytes).map_err(|e| DomainError::Infrastructure(format!("parsing token response from {realm}: {e}")))
}

/// Body-read mapping for `fetch_manifest`, split out for the same reason as `extract_challenge_or_error` above.
async fn map_manifest_response(response: Option<reqwest::Response>, url: &str) -> Result<Option<(Vec<u8>, String)>, DomainError> {
    let Some(response) = response else {
        return Ok(None);
    };
    let content_type = response.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("application/octet-stream").to_string();
    let bytes = read_capped(response, url, "manifest body", MAX_MANIFEST_RESPONSE_BYTES).await?;
    Ok(Some((bytes, content_type)))
}

/// Body-read mapping for `fetch_blob`, split out for the same reason as `extract_challenge_or_error` above.
async fn map_blob_response(response: Option<reqwest::Response>, url: &str) -> Result<Option<Vec<u8>>, DomainError> {
    let Some(response) = response else {
        return Ok(None);
    };
    read_capped(response, url, "blob body", MAX_BLOB_RESPONSE_BYTES).await.map(Some)
}

#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    token: String,
}

#[derive(Debug)]
struct BearerChallenge {
    realm: String,
    service: String,
    scope: Option<String>,
}

/// `scope` is optional — some unscoped 401s omit it.
fn parse_bearer_challenge(header_value: &str) -> Option<BearerChallenge> {
    let rest = header_value.strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for part in split_challenge_params(rest) {
        let (key, value) = part.split_once('=')?;
        let value = value.trim_matches('"').to_string();
        match key {
            "realm" => realm = Some(value),
            "service" => service = Some(value),
            "scope" => scope = Some(value),
            _ => {}
        }
    }
    Some(BearerChallenge { realm: realm?, service: service?, scope })
}

/// Splits `key="value",key2="value2"` on commas outside quotes — a plain `.split(',')` would break on a quoted comma.
fn split_challenge_params(rest: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in rest.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ',' if !in_quotes => parts.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts.into_iter().map(|p| p.trim().to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_realm_service_and_scope_from_a_bearer_challenge() {
        let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#;
        let challenge = parse_bearer_challenge(header).unwrap();
        assert_eq!(challenge.realm, "https://auth.docker.io/token");
        assert_eq!(challenge.service, "registry.docker.io");
        assert_eq!(challenge.scope.as_deref(), Some("repository:library/alpine:pull"));
    }

    #[test]
    fn parses_a_challenge_with_no_scope() {
        let header = r#"Bearer realm="https://auth.example/token",service="registry.example""#;
        let challenge = parse_bearer_challenge(header).unwrap();
        assert!(challenge.scope.is_none());
    }

    #[test]
    fn returns_none_for_a_non_bearer_challenge() {
        assert!(parse_bearer_challenge(r#"Basic realm="registry""#).is_none());
    }

    // Ground truth against real Docker Hub, which requires the anonymous Bearer challenge flow.
    #[tokio::test]
    #[ignore = "requires network access to registry-1.docker.io"]
    async fn fetches_a_real_manifest_from_docker_hub_via_the_bearer_challenge_flow() {
        let registry = HttpRemoteDockerRegistry::new();
        let image_name = hangar_domain::docker_registry::DockerImageName::parse("library/alpine").unwrap();
        let (bytes, content_type) = registry.fetch_manifest("https://registry-1.docker.io", &image_name, "latest", None, None).await.unwrap().unwrap();
        assert!(!bytes.is_empty());
        assert!(content_type.contains("manifest") || content_type.contains("json"));
    }

    #[tokio::test]
    async fn the_configured_client_does_not_follow_a_redirect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: http://internal.example/\r\nContent-Length: 0\r\n\r\n")
                .await;
        });

        let client = HttpRemoteDockerRegistry::new().client;
        let response = client.get(format!("http://{addr}/")).send().await.unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::FOUND, "the client must return the redirect itself, not silently follow it");
    }

    // These tests bypass ensure_public_host to fetch directly from a local wiremock server (which is loopback).
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn get(url: &str) -> reqwest::Response {
        reqwest::Client::new().get(url).send().await.expect("request to local mock server must succeed")
    }

    #[tokio::test]
    async fn require_success_maps_a_404_response_to_a_domain_error_naming_the_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/v2/lib/manifests/latest")).respond_with(ResponseTemplate::new(404)).mount(&server).await;
        let url = format!("{}/v2/lib/manifests/latest", server.uri());

        let err = HttpRemoteDockerRegistry::require_success(get(&url).await, &url).await.unwrap_err();

        assert!(err.to_string().contains("404"), "got: {err}");
        assert!(err.to_string().contains("remote registry returned"), "got: {err}");
    }

    #[tokio::test]
    async fn require_success_maps_a_500_response_to_a_domain_error_naming_the_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/v2/lib/manifests/latest")).respond_with(ResponseTemplate::new(500)).mount(&server).await;
        let url = format!("{}/v2/lib/manifests/latest", server.uri());

        let err = HttpRemoteDockerRegistry::require_success(get(&url).await, &url).await.unwrap_err();

        assert!(err.to_string().contains("500"), "got: {err}");
        assert!(err.to_string().contains("remote registry returned"), "got: {err}");
    }

    #[tokio::test]
    async fn require_success_passes_through_a_200_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/v2/lib/manifests/latest")).respond_with(ResponseTemplate::new(200).set_body_string("ok")).mount(&server).await;
        let url = format!("{}/v2/lib/manifests/latest", server.uri());

        let response = HttpRemoteDockerRegistry::require_success(get(&url).await, &url).await.unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn extract_challenge_or_error_rejects_a_401_with_no_www_authenticate_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/v2/lib/manifests/latest")).respond_with(ResponseTemplate::new(401)).mount(&server).await;
        let url = format!("{}/v2/lib/manifests/latest", server.uri());

        let err = extract_challenge_or_error(&get(&url).await, &url).unwrap_err();

        assert!(err.to_string().contains("without a Bearer challenge"), "got: {err}");
    }

    #[tokio::test]
    async fn extract_challenge_or_error_rejects_a_401_with_a_non_bearer_challenge() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/lib/manifests/latest"))
            .respond_with(ResponseTemplate::new(401).insert_header("www-authenticate", r#"Basic realm="registry""#))
            .mount(&server)
            .await;
        let url = format!("{}/v2/lib/manifests/latest", server.uri());

        let err = extract_challenge_or_error(&get(&url).await, &url).unwrap_err();

        assert!(err.to_string().contains("without a Bearer challenge"), "got: {err}");
    }

    #[tokio::test]
    async fn extract_challenge_or_error_parses_a_valid_bearer_challenge() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/lib/manifests/latest"))
            .respond_with(ResponseTemplate::new(401).insert_header(
                "www-authenticate",
                r#"Bearer realm="https://auth.example/token",service="registry.example""#,
            ))
            .mount(&server)
            .await;
        let url = format!("{}/v2/lib/manifests/latest", server.uri());

        let challenge = extract_challenge_or_error(&get(&url).await, &url).unwrap();

        assert_eq!(challenge.realm, "https://auth.example/token");
        assert_eq!(challenge.service, "registry.example");
    }

    #[tokio::test]
    async fn parse_token_response_rejects_a_non_json_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/token")).respond_with(ResponseTemplate::new(200).set_body_string("not json")).mount(&server).await;
        let url = format!("{}/token", server.uri());

        let err = parse_token_response(get(&url).await, &url).await.unwrap_err();

        assert!(err.to_string().contains("parsing token response"), "got: {err}");
    }

    #[tokio::test]
    async fn parse_token_response_accepts_a_valid_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"token": "abc123"})))
            .mount(&server)
            .await;
        let url = format!("{}/token", server.uri());

        let token = parse_token_response(get(&url).await, &url).await.unwrap();

        assert_eq!(token.token, "abc123");
    }

    #[tokio::test]
    async fn map_manifest_response_passes_none_through_unchanged() {
        assert!(map_manifest_response(None, "http://example/whatever").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn map_manifest_response_returns_bytes_and_content_type_for_a_200_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/lib/manifests/latest"))
            .respond_with(ResponseTemplate::new(200).insert_header("content-type", "application/vnd.docker.distribution.manifest.v2+json").set_body_bytes(b"{}".to_vec()))
            .mount(&server)
            .await;
        let url = format!("{}/v2/lib/manifests/latest", server.uri());

        let (bytes, content_type) = map_manifest_response(Some(get(&url).await), &url).await.unwrap().unwrap();

        assert_eq!(bytes, b"{}".to_vec());
        assert_eq!(content_type, "application/vnd.docker.distribution.manifest.v2+json");
    }

    #[tokio::test]
    async fn map_blob_response_passes_none_through_unchanged() {
        assert!(map_blob_response(None, "http://example/whatever").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn map_blob_response_returns_bytes_for_a_200_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/v2/lib/blobs/sha256:abc")).respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1, 2, 3])).mount(&server).await;
        let url = format!("{}/v2/lib/blobs/sha256:abc", server.uri());

        let bytes = map_blob_response(Some(get(&url).await), &url).await.unwrap().unwrap();

        assert_eq!(bytes, vec![1, 2, 3]);
    }
}

use async_trait::async_trait;
use hangar_domain::error::DomainError;
use hangar_domain::npm_package::NpmPackageName;
use hangar_domain::npm_remote::RemoteNpmRegistryPort;

use crate::capped_response::read_capped;
use crate::ssrf_guard::ensure_public_host;

const MAX_METADATA_RESPONSE_BYTES: usize = 50 * 1024 * 1024;
/// Matches the npm publish body limit (`hangar-npm`'s own router).
const MAX_TARBALL_RESPONSE_BYTES: usize = 200 * 1024 * 1024;

pub struct HttpRemoteNpmRegistry {
    client: reqwest::Client,
}

impl HttpRemoteNpmRegistry {
    pub fn new() -> Self {
        // No redirect-following, or a malicious upstream could 302 past the SSRF guard.
        Self { client: reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().expect("reqwest client config is static and always valid") }
    }
}

impl Default for HttpRemoteNpmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RemoteNpmRegistryPort for HttpRemoteNpmRegistry {
    async fn fetch_metadata(
        &self,
        base_url: &str,
        package_name: &NpmPackageName,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<serde_json::Value, DomainError> {
        // npm scoped package names (@scope/name) are sent URL-encoded (@scope%2fname), not as a literal nested path segment.
        let encoded_name = urlencoding_replace_slash(package_name.as_str());
        let url = format!("{}/{}", base_url.trim_end_matches('/'), encoded_name);
        ensure_public_host(&url).await?;
        let response = apply_credentials(self.client.get(&url).header("Accept", "application/json"), username, password)
            .send()
            .await
            .map_err(|e| DomainError::Infrastructure(format!("fetching npm metadata from {url}: {e}")))?;
        map_metadata_response(response, &url).await
    }

    async fn fetch_tarball(&self, base_url: &str, tarball_url: &str, username: Option<&str>, password: Option<&str>) -> Result<Vec<u8>, DomainError> {
        let url = if tarball_url.starts_with("http://") || tarball_url.starts_with("https://") {
            tarball_url.to_string()
        } else {
            format!("{}/{}", base_url.trim_end_matches('/'), tarball_url.trim_start_matches('/'))
        };
        ensure_public_host(&url).await?;
        let response = apply_credentials(self.client.get(&url), username, password)
            .send()
            .await
            .map_err(|e| DomainError::Infrastructure(format!("fetching npm tarball from {url}: {e}")))?;
        map_tarball_response(response, &url).await
    }
}

/// Split out of `fetch_metadata` so it can be tested against an already-obtained response.
async fn map_metadata_response(response: reqwest::Response, url: &str) -> Result<serde_json::Value, DomainError> {
    if !response.status().is_success() {
        return Err(DomainError::Infrastructure(format!("remote registry returned {} for {url}", response.status())));
    }
    let bytes = read_capped(response, url, "npm metadata", MAX_METADATA_RESPONSE_BYTES).await?;
    serde_json::from_slice(&bytes).map_err(|e| DomainError::Infrastructure(format!("parsing npm metadata from {url}: {e}")))
}

/// Non-2xx / body-read mapping for `fetch_tarball`, split out for the same reason as `map_metadata_response` above.
async fn map_tarball_response(response: reqwest::Response, url: &str) -> Result<Vec<u8>, DomainError> {
    if !response.status().is_success() {
        return Err(DomainError::Infrastructure(format!("remote registry returned {} for {url}", response.status())));
    }
    read_capped(response, url, "npm tarball body", MAX_TARBALL_RESPONSE_BYTES).await
}

fn urlencoding_replace_slash(name: &str) -> String {
    name.replace('/', "%2f")
}

/// A username authenticates as HTTP Basic; a password alone as a Bearer token.
fn apply_credentials(request: reqwest::RequestBuilder, username: Option<&str>, password: Option<&str>) -> reqwest::RequestBuilder {
    match (username, password) {
        (Some(username), password) => request.basic_auth(username, password),
        (None, Some(token)) => request.bearer_auth(token),
        (None, None) => request,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_domain::npm_package::NpmPackageName;

    // Ground truth against a real, stable public package.
    #[tokio::test]
    #[ignore = "requires network access to registry.npmjs.org"]
    async fn fetches_real_metadata_from_npmjs() {
        let registry = HttpRemoteNpmRegistry::new();
        let doc = registry.fetch_metadata("https://registry.npmjs.org", &NpmPackageName::parse("is-odd").unwrap(), None, None).await.unwrap();
        assert!(doc.get("dist-tags").is_some());
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

        let client = HttpRemoteNpmRegistry::new().client;
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
    async fn maps_a_404_metadata_response_to_a_domain_error_naming_the_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/is-odd")).respond_with(ResponseTemplate::new(404)).mount(&server).await;
        let url = format!("{}/is-odd", server.uri());

        let err = map_metadata_response(get(&url).await, &url).await.unwrap_err();

        assert!(err.to_string().contains("404"), "got: {err}");
        assert!(err.to_string().contains("remote registry returned"), "got: {err}");
    }

    #[tokio::test]
    async fn maps_a_500_metadata_response_to_a_domain_error_naming_the_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/is-odd")).respond_with(ResponseTemplate::new(500)).mount(&server).await;
        let url = format!("{}/is-odd", server.uri());

        let err = map_metadata_response(get(&url).await, &url).await.unwrap_err();

        assert!(err.to_string().contains("500"), "got: {err}");
        assert!(err.to_string().contains("remote registry returned"), "got: {err}");
    }

    #[tokio::test]
    async fn maps_a_200_response_with_a_non_json_body_to_a_parse_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/is-odd")).respond_with(ResponseTemplate::new(200).set_body_string("not json")).mount(&server).await;
        let url = format!("{}/is-odd", server.uri());

        let err = map_metadata_response(get(&url).await, &url).await.unwrap_err();

        assert!(err.to_string().contains("parsing npm metadata"), "got: {err}");
    }

    #[tokio::test]
    async fn maps_a_200_response_with_a_valid_body_to_the_parsed_json() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/is-odd"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"dist-tags": {"latest": "3.0.1"}})))
            .mount(&server)
            .await;
        let url = format!("{}/is-odd", server.uri());

        let doc = map_metadata_response(get(&url).await, &url).await.unwrap();

        assert_eq!(doc["dist-tags"]["latest"], "3.0.1");
    }

    #[tokio::test]
    async fn maps_a_404_tarball_response_to_a_domain_error_naming_the_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/is-odd.tgz")).respond_with(ResponseTemplate::new(404)).mount(&server).await;
        let url = format!("{}/is-odd.tgz", server.uri());

        let err = map_tarball_response(get(&url).await, &url).await.unwrap_err();

        assert!(err.to_string().contains("404"), "got: {err}");
        assert!(err.to_string().contains("remote registry returned"), "got: {err}");
    }

    #[tokio::test]
    async fn maps_a_500_tarball_response_to_a_domain_error_naming_the_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/is-odd.tgz")).respond_with(ResponseTemplate::new(500)).mount(&server).await;
        let url = format!("{}/is-odd.tgz", server.uri());

        let err = map_tarball_response(get(&url).await, &url).await.unwrap_err();

        assert!(err.to_string().contains("500"), "got: {err}");
        assert!(err.to_string().contains("remote registry returned"), "got: {err}");
    }

    #[tokio::test]
    async fn maps_a_200_tarball_response_to_its_raw_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/is-odd.tgz")).respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0x1f, 0x8b, 0x03])).mount(&server).await;
        let url = format!("{}/is-odd.tgz", server.uri());

        let bytes = map_tarball_response(get(&url).await, &url).await.unwrap();

        assert_eq!(bytes, vec![0x1f, 0x8b, 0x03]);
    }
}

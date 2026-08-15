//! Reads an HTTP response body with an explicit byte ceiling, instead of `reqwest`'s own `.bytes()`/`.json()`, which buffer the entire body regardless of size. Used for every remote
//! registry response — a malicious or compromised upstream must not be able to exhaust memory by returning an arbitrarily large body.

use futures_util::StreamExt;
use hangar_domain::error::DomainError;

pub async fn read_capped(response: reqwest::Response, url: &str, what: &str, max_bytes: usize) -> Result<Vec<u8>, DomainError> {
    let mut stream = response.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| DomainError::Infrastructure(format!("reading {what} from {url}: {e}")))?;
        if buf.len() + chunk.len() > max_bytes {
            return Err(DomainError::Infrastructure(format!("{what} from {url} exceeds the {max_bytes}-byte limit")));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn get(url: &str) -> reqwest::Response {
        reqwest::Client::new().get(url).send().await.expect("request to local mock server must succeed")
    }

    #[tokio::test]
    async fn a_body_within_the_limit_is_read_in_full() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/small")).respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1, 2, 3])).mount(&server).await;
        let url = format!("{}/small", server.uri());

        let bytes = read_capped(get(&url).await, &url, "test body", 1024).await.unwrap();

        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn a_body_exceeding_the_limit_is_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/big")).respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 2048])).mount(&server).await;
        let url = format!("{}/big", server.uri());

        let err = read_capped(get(&url).await, &url, "test body", 1024).await.unwrap_err();

        assert!(err.to_string().contains("exceeds the 1024-byte limit"), "got: {err}");
    }
}

use async_trait::async_trait;

use crate::docker_registry::{Digest, DockerImageName};
use crate::error::DomainError;

#[async_trait]
pub trait RemoteDockerRegistryPort: Send + Sync {
    /// `Ok(None)` means the remote genuinely returned 404 — expected, not an
    /// error. `Err` is reserved for real fetch failures. `username`/`password`
    /// authenticate to the upstream's token endpoint; `None` means anonymous.
    async fn fetch_manifest(
        &self,
        base_url: &str,
        image_name: &DockerImageName,
        reference: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Option<(Vec<u8>, String)>, DomainError>;

    /// Same `Ok(None)` == 404 convention as `fetch_manifest`.
    async fn fetch_blob(
        &self,
        base_url: &str,
        image_name: &DockerImageName,
        digest: &Digest,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<Option<Vec<u8>>, DomainError>;
}

use async_trait::async_trait;

use crate::error::DomainError;
use crate::npm_package::NpmPackageName;

#[async_trait]
pub trait RemoteNpmRegistryPort: Send + Sync {
    /// Raw JSON document as received. With a username, `username`/`password`
    /// authenticate as HTTP Basic; with only a password, as a Bearer token
    /// (`.npmrc`-style `_authToken`).
    async fn fetch_metadata(
        &self,
        base_url: &str,
        package_name: &NpmPackageName,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<serde_json::Value, DomainError>;

    async fn fetch_tarball(&self, base_url: &str, tarball_url: &str, username: Option<&str>, password: Option<&str>) -> Result<Vec<u8>, DomainError>;
}

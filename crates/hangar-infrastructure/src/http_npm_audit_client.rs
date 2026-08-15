use std::collections::HashMap;

use async_trait::async_trait;
use hangar_domain::error::DomainError;
use hangar_domain::npm_audit::{parse_advisories, NpmAdvisory, NpmAuditPort};
use hangar_domain::npm_package::{NpmPackageName, NpmVersion};

use crate::capped_response::read_capped;

const ADVISORY_BULK_ENDPOINT: &str = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";
/// A bulk advisory response is normally well under a MB even for a large dependency tree.
const MAX_ADVISORY_RESPONSE_BYTES: usize = 20 * 1024 * 1024;

/// Calls the same bulk advisory endpoint the real `npm audit` CLI uses.
pub struct HttpNpmAuditClient {
    client: reqwest::Client,
}

impl HttpNpmAuditClient {
    pub fn new() -> Self {
        Self { client: reqwest::Client::new() }
    }
}

impl Default for HttpNpmAuditClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NpmAuditPort for HttpNpmAuditClient {
    async fn check(&self, name: &NpmPackageName, versions: &[NpmVersion]) -> Result<Vec<NpmAdvisory>, DomainError> {
        if versions.is_empty() {
            return Ok(Vec::new());
        }
        let mut packages = HashMap::new();
        packages.insert(name.as_str().to_string(), versions.iter().map(|v| v.as_str()).collect());

        let raw = self.check_bulk_raw(&packages).await?;
        Ok(parse_advisories(&raw).remove(name.as_str()).unwrap_or_default())
    }

    async fn check_bulk_raw(&self, packages: &HashMap<String, Vec<String>>) -> Result<serde_json::Value, DomainError> {
        if packages.is_empty() || packages.values().all(|versions| versions.is_empty()) {
            return Ok(serde_json::Value::Object(Default::default()));
        }

        let response = self
            .client
            .post(ADVISORY_BULK_ENDPOINT)
            .json(packages)
            .send()
            .await
            .map_err(|e| DomainError::Infrastructure(format!("querying npm advisory database: {e}")))?;
        if !response.status().is_success() {
            return Err(DomainError::Infrastructure(format!("npm advisory database returned {}", response.status())));
        }
        let bytes = read_capped(response, ADVISORY_BULK_ENDPOINT, "npm advisory response", MAX_ADVISORY_RESPONSE_BYTES).await?;
        serde_json::from_slice(&bytes).map_err(|e| DomainError::Infrastructure(format!("parsing npm advisory response: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground truth against a long-published, immutable, known-vulnerable version.
    #[tokio::test]
    #[ignore = "requires network access to registry.npmjs.org"]
    async fn finds_known_advisories_for_a_real_vulnerable_package() {
        let client = HttpNpmAuditClient::new();
        let advisories =
            client.check(&NpmPackageName::parse("minimist").unwrap(), &[NpmVersion::parse("0.0.8").unwrap()]).await.unwrap();

        assert!(!advisories.is_empty());
        assert!(advisories.iter().any(|a| a.title.to_lowercase().contains("prototype pollution")));
    }

    #[tokio::test]
    #[ignore = "requires network access to registry.npmjs.org"]
    async fn finds_nothing_for_a_version_with_no_known_advisories() {
        let client = HttpNpmAuditClient::new();
        let advisories = client.check(&NpmPackageName::parse("minimist").unwrap(), &[NpmVersion::parse("1.2.8").unwrap()]).await.unwrap();

        assert!(advisories.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access to registry.npmjs.org"]
    async fn bulk_raw_matches_the_real_npm_audit_cli_wire_shape_for_multiple_packages() {
        let client = HttpNpmAuditClient::new();
        let mut packages = HashMap::new();
        packages.insert("minimist".to_string(), vec!["0.0.8".to_string()]);
        packages.insert("left-pad".to_string(), vec!["1.3.0".to_string()]);

        let raw = client.check_bulk_raw(&packages).await.unwrap();

        let minimist_advisories = raw.get("minimist").and_then(|v| v.as_array()).unwrap();
        assert!(!minimist_advisories.is_empty());
        assert!(minimist_advisories[0].get("cvss").and_then(|c| c.get("score")).is_some());
        assert!(raw.get("left-pad").is_none());
    }

    #[tokio::test]
    async fn returns_no_results_without_a_network_call_for_an_empty_version_list() {
        let client = HttpNpmAuditClient::new();
        let advisories = client.check(&NpmPackageName::parse("left-pad").unwrap(), &[]).await.unwrap();

        assert!(advisories.is_empty());
    }

    #[tokio::test]
    async fn bulk_raw_returns_an_empty_object_without_a_network_call_for_no_packages() {
        let client = HttpNpmAuditClient::new();
        let raw = client.check_bulk_raw(&HashMap::new()).await.unwrap();

        assert_eq!(raw, serde_json::json!({}));
    }
}

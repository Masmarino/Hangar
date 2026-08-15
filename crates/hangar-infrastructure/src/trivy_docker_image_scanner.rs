use async_trait::async_trait;
use hangar_domain::docker_scan::{DockerImageScannerPort, DockerVulnerability};
use hangar_domain::error::DomainError;
use serde::Deserialize;
use tokio::process::Command;

/// Shells out to `trivy`, pointed at this deployment's own registry over loopback, authenticated with an internally-minted token (`--insecure` since it speaks plain HTTP internally).
pub struct TrivyDockerImageScanner {
    /// e.g. `127.0.0.1:8080` — not derived from the host external clients use.
    registry_host: String,
}

impl TrivyDockerImageScanner {
    pub fn new(registry_host: String) -> Self {
        Self { registry_host }
    }
}

#[async_trait]
impl DockerImageScannerPort for TrivyDockerImageScanner {
    async fn scan(
        &self,
        repository_name: &str,
        image_name: &str,
        reference: &str,
        platform: Option<&str>,
        registry_token: &str,
    ) -> Result<Vec<DockerVulnerability>, DomainError> {
        let image_ref = build_image_ref(&self.registry_host, repository_name, image_name, reference);

        let mut command = Command::new("trivy");
        command.arg("image").arg("--format").arg("json").arg("--quiet").arg("--insecure");
        // Via env, not `--registry-token`: a CLI arg is visible to any co-located process.
        command.env("TRIVY_REGISTRY_TOKEN", registry_token);
        if let Some(platform) = platform {
            command.arg("--platform").arg(platform);
        }
        command.arg(&image_ref);

        let output = command.output().await.map_err(|e| DomainError::Infrastructure(format!("running trivy: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DomainError::Infrastructure(format!("trivy scan of {image_ref} failed: {}", stderr.trim())));
        }
        parse_trivy_output(&output.stdout)
    }
}

/// A tag uses `:`, a digest uses `@` — conflating the two produces a reference `trivy`/`go-containerregistry` reject outright.
fn build_image_ref(registry_host: &str, repository_name: &str, image_name: &str, reference: &str) -> String {
    let separator = if reference.starts_with("sha256:") { "@" } else { ":" };
    format!("{registry_host}/{repository_name}/{image_name}{separator}{reference}")
}

#[derive(Debug, Deserialize)]
struct TrivyReport {
    #[serde(rename = "Results", default)]
    results: Vec<TrivyResult>,
}

#[derive(Debug, Deserialize)]
struct TrivyResult {
    #[serde(rename = "Vulnerabilities", default)]
    vulnerabilities: Vec<TrivyVulnerability>,
}

#[derive(Debug, Deserialize)]
struct TrivyVulnerability {
    #[serde(rename = "VulnerabilityID")]
    vulnerability_id: String,
    #[serde(rename = "PkgName")]
    pkg_name: String,
    #[serde(rename = "InstalledVersion")]
    installed_version: String,
    #[serde(rename = "FixedVersion", default)]
    fixed_version: Option<String>,
    #[serde(rename = "Severity", default)]
    severity: Option<String>,
    #[serde(rename = "Title", default)]
    title: Option<String>,
    #[serde(rename = "PrimaryURL", default)]
    primary_url: Option<String>,
}

fn parse_trivy_output(bytes: &[u8]) -> Result<Vec<DockerVulnerability>, DomainError> {
    let report: TrivyReport = serde_json::from_slice(bytes).map_err(|e| DomainError::Infrastructure(format!("parsing trivy output: {e}")))?;
    Ok(report
        .results
        .into_iter()
        .flat_map(|r| r.vulnerabilities)
        .map(|v| DockerVulnerability {
            id: v.vulnerability_id,
            package_name: v.pkg_name,
            installed_version: v.installed_version,
            fixed_version: v.fixed_version,
            severity: v.severity.unwrap_or_else(|| "UNKNOWN".to_string()),
            title: v.title,
            primary_url: v.primary_url,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_tag_reference_with_a_colon() {
        assert_eq!(build_image_ref("127.0.0.1:8080", "myrepo", "myimage", "latest"), "127.0.0.1:8080/myrepo/myimage:latest");
    }

    #[test]
    fn builds_a_digest_reference_with_an_at_sign() {
        let digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(build_image_ref("127.0.0.1:8080", "myrepo", "myimage", digest), format!("127.0.0.1:8080/myrepo/myimage@{digest}"));
    }

    #[test]
    fn parses_real_trivy_json_output_into_flat_vulnerabilities() {
        let fixture = serde_json::json!({
            "Results": [
                {
                    "Target": "myimage (alpine 3.15.4)",
                    "Class": "os-pkgs",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2022-4450",
                            "PkgName": "libcrypto1.1",
                            "InstalledVersion": "1.1.1n-r0",
                            "FixedVersion": "1.1.1t-r0",
                            "Severity": "HIGH",
                            "Title": "openssl: double free after calling PEM_read_bio_ex",
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2022-4450"
                        }
                    ]
                },
                {
                    "Target": "myimage (clean layer)",
                    "Class": "os-pkgs"
                }
            ]
        });
        let vulnerabilities = parse_trivy_output(fixture.to_string().as_bytes()).unwrap();

        assert_eq!(vulnerabilities.len(), 1);
        assert_eq!(vulnerabilities[0].id, "CVE-2022-4450");
        assert_eq!(vulnerabilities[0].package_name, "libcrypto1.1");
        assert_eq!(vulnerabilities[0].fixed_version, Some("1.1.1t-r0".to_string()));
        assert_eq!(vulnerabilities[0].severity, "HIGH");
    }

    #[test]
    fn a_report_with_no_results_at_all_parses_to_an_empty_list() {
        let vulnerabilities = parse_trivy_output(b"{}").unwrap();
        assert!(vulnerabilities.is_empty());
    }

    #[test]
    fn a_vulnerability_missing_a_severity_defaults_to_unknown() {
        let fixture = serde_json::json!({
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-0000-0000",
                    "PkgName": "somepkg",
                    "InstalledVersion": "1.0.0"
                }]
            }]
        });
        let vulnerabilities = parse_trivy_output(fixture.to_string().as_bytes()).unwrap();
        assert_eq!(vulnerabilities[0].severity, "UNKNOWN");
        assert_eq!(vulnerabilities[0].fixed_version, None);
    }
}

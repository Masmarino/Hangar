use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use chrono::Utc;
use hangar_domain::npm_audit::{parse_advisories, DependencyAuditFinding, DependencyAuditRepositoryPort, DependencyAuditResult, NpmAuditPort};
use hangar_domain::npm_package::{NpmPackageName, NpmPackageRepositoryPort, NpmVersion};
use hangar_domain::npm_remote::RemoteNpmRegistryPort;
use uuid::Uuid;

use crate::error::ApplicationError;

const PUBLIC_REGISTRY_BASE_URL: &str = "https://registry.npmjs.org";

const MAX_DEPTH: usize = 10;

/// Once hit, the walk stops and the result is marked `truncated`, not silently partial.
const MAX_PACKAGES: usize = 500;

/// Walks a published version's `dependencies` transitively against the public npm registry, then audits the whole collected set in one bulk call. Persists the result so a page view never waits for a live, potentially multi-second walk.
pub struct ScanDependencyTreeUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
    remote_registry: Arc<dyn RemoteNpmRegistryPort>,
    audit: Arc<dyn NpmAuditPort>,
    results: Arc<dyn DependencyAuditRepositoryPort>,
}

impl ScanDependencyTreeUseCase {
    pub fn new(
        packages: Arc<dyn NpmPackageRepositoryPort>,
        remote_registry: Arc<dyn RemoteNpmRegistryPort>,
        audit: Arc<dyn NpmAuditPort>,
        results: Arc<dyn DependencyAuditRepositoryPort>,
    ) -> Self {
        Self { packages, remote_registry, audit, results }
    }

    pub async fn execute(&self, repository_id: Uuid, name: &NpmPackageName, version: &NpmVersion) -> Result<DependencyAuditResult, ApplicationError> {
        let package = self.packages.find_package(repository_id, name).await?.ok_or(ApplicationError::NpmPackageNotFound)?;
        let root_version = self.packages.find_version(package.id, version).await?.ok_or(ApplicationError::NpmVersionNotFound)?;

        let mut visited: HashSet<(String, String)> = HashSet::new();
        let mut to_audit: HashMap<String, Vec<String>> = HashMap::new();
        let mut packument_cache: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        let mut truncated = false;

        let mut queue: VecDeque<(String, String, usize)> =
            extract_dependencies(&root_version.manifest).into_iter().map(|(dep_name, range)| (dep_name, range, 1)).collect();

        while let Some((dep_name, range, depth)) = queue.pop_front() {
            if depth > MAX_DEPTH {
                truncated = true;
                continue;
            }
            if visited.len() >= MAX_PACKAGES {
                truncated = true;
                break;
            }

            let packument = match packument_cache.get(&dep_name) {
                Some(cached) => cached.clone(),
                None => {
                    let fetched = match NpmPackageName::parse(&dep_name) {
                        Ok(parsed) => self.remote_registry.fetch_metadata(PUBLIC_REGISTRY_BASE_URL, &parsed, None, None).await.ok(),
                        Err(_) => None,
                    };
                    packument_cache.insert(dep_name.clone(), fetched.clone());
                    fetched
                }
            };
            let Some(packument) = packument else { continue };
            let Some(versions) = packument.get("versions").and_then(|v| v.as_object()) else { continue };
            let Some((resolved_version, resolved_manifest)) = resolve_range(&range, versions) else { continue };

            if !visited.insert((dep_name.clone(), resolved_version.clone())) {
                continue;
            }

            to_audit.entry(dep_name.clone()).or_default().push(resolved_version.clone());

            for (child_name, child_range) in extract_dependencies(resolved_manifest) {
                queue.push_back((child_name, child_range, depth + 1));
            }
        }

        let raw = if to_audit.is_empty() { serde_json::json!({}) } else { self.audit.check_bulk_raw(&to_audit).await? };
        let advisories_by_name = parse_advisories(&raw);

        let mut findings = Vec::new();
        for (dep_name, dep_version) in &visited {
            let Some(advisories) = advisories_by_name.get(dep_name) else { continue };
            for advisory in advisories {
                if version_satisfies_range(dep_version, &advisory.vulnerable_versions) {
                    findings.push(DependencyAuditFinding {
                        dependency_name: dep_name.clone(),
                        dependency_version: dep_version.clone(),
                        advisory: advisory.clone(),
                    });
                }
            }
        }
        findings.sort_by(|a, b| a.dependency_name.cmp(&b.dependency_name).then(a.dependency_version.cmp(&b.dependency_version)).then(a.advisory.id.cmp(&b.advisory.id)));

        let result = DependencyAuditResult {
            id: Uuid::new_v4(),
            npm_package_version_id: root_version.id,
            scanned_at: Utc::now(),
            packages_scanned: visited.len() as i32,
            truncated,
            findings,
        };
        self.results.save(&result).await?;
        Ok(result)
    }
}

/// Never triggers a fresh walk itself.
pub struct GetDependencyAuditResultUseCase {
    packages: Arc<dyn NpmPackageRepositoryPort>,
    results: Arc<dyn DependencyAuditRepositoryPort>,
}

impl GetDependencyAuditResultUseCase {
    pub fn new(packages: Arc<dyn NpmPackageRepositoryPort>, results: Arc<dyn DependencyAuditRepositoryPort>) -> Self {
        Self { packages, results }
    }

    pub async fn execute(
        &self,
        repository_id: Uuid,
        name: &NpmPackageName,
        version: &NpmVersion,
    ) -> Result<Option<DependencyAuditResult>, ApplicationError> {
        let Some(package) = self.packages.find_package(repository_id, name).await? else { return Ok(None) };
        let Some(root_version) = self.packages.find_version(package.id, version).await? else { return Ok(None) };
        Ok(self.results.find_latest_for_version(root_version.id).await?)
    }
}

fn extract_dependencies(manifest: &serde_json::Value) -> Vec<(String, String)> {
    manifest
        .get("dependencies")
        .and_then(|d| d.as_object())
        .map(|deps| deps.iter().filter_map(|(k, v)| v.as_str().map(|range| (k.clone(), range.to_string()))).collect())
        .unwrap_or_default()
}

/// node-semver treats a bare `"1.2.3"` as an exact match, not a caret range like Rust's `semver` crate — force an explicit `=` on. `x`/`X` wildcards normalize to `*`.
fn normalize_comparator(part: &str) -> String {
    let part = part.replace(['x', 'X'], "*");
    if part.starts_with(['^', '~', '>', '<', '=']) {
        part
    } else {
        format!("={part}")
    }
}

/// Unsupported syntax (hyphen ranges, git/file/tag references) returns `None` — the caller skips it.
fn parse_range_clause(clause: &str) -> Option<semver::VersionReq> {
    let clause = clause.trim();
    if clause.is_empty() || clause == "*" || clause == "latest" {
        return semver::VersionReq::parse("*").ok();
    }
    let normalized = clause.split_whitespace().map(normalize_comparator).collect::<Vec<_>>().join(", ");
    semver::VersionReq::parse(&normalized).ok()
}

/// Highest published version satisfying `range`, with its manifest for recursion.
fn resolve_range<'a>(range: &str, versions: &'a serde_json::Map<String, serde_json::Value>) -> Option<(String, &'a serde_json::Value)> {
    let mut best: Option<(semver::Version, String, &serde_json::Value)> = None;
    for clause in range.split("||") {
        let Some(req) = parse_range_clause(clause) else { continue };
        for (version_str, manifest) in versions {
            let Ok(parsed) = semver::Version::parse(version_str) else { continue };
            if req.matches(&parsed) && best.as_ref().is_none_or(|(current_best, _, _)| parsed > *current_best) {
                best = Some((parsed, version_str.clone(), manifest));
            }
        }
    }
    best.map(|(_, version_str, manifest)| (version_str, manifest))
}

fn version_satisfies_range(version_str: &str, range: &str) -> bool {
    let Ok(version) = semver::Version::parse(version_str) else { return false };
    range.split("||").filter_map(parse_range_clause).any(|req| req.matches(&version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::use_cases::npm_test_support::{FakeDependencyAuditResults, FakeNpmAudit, FakePackages, FakeRemoteRegistry};
    use hangar_domain::npm_audit::NpmAdvisory;
    use hangar_domain::npm_package::{NpmPackage, NpmPackageOrigin, NpmPackageVersion};

    fn manifest_with_deps(deps: &[(&str, &str)]) -> serde_json::Value {
        let mut deps_obj = serde_json::Map::new();
        for (name, range) in deps {
            deps_obj.insert(name.to_string(), serde_json::Value::String(range.to_string()));
        }
        serde_json::json!({ "dependencies": deps_obj })
    }

    fn packument(versions: &[(&str, serde_json::Value)]) -> serde_json::Value {
        let mut versions_obj = serde_json::Map::new();
        for (v, manifest) in versions {
            versions_obj.insert(v.to_string(), manifest.clone());
        }
        serde_json::json!({ "dist-tags": {}, "versions": versions_obj })
    }

    fn sample_advisory(id: i64, vulnerable_versions: &str) -> NpmAdvisory {
        NpmAdvisory {
            id,
            url: format!("https://github.com/advisories/GHSA-{id}"),
            title: "Prototype Pollution".to_string(),
            severity: "critical".to_string(),
            vulnerable_versions: vulnerable_versions.to_string(),
            cwe: vec!["CWE-1321".to_string()],
            cvss_score: Some(9.8),
        }
    }

    struct Harness {
        packages: Arc<FakePackages>,
        remote: Arc<FakeRemoteRegistry>,
        audit: Arc<FakeNpmAudit>,
        results: Arc<FakeDependencyAuditResults>,
        repository_id: Uuid,
        name: NpmPackageName,
    }

    impl Harness {
        fn new() -> Self {
            Self {
                packages: Arc::new(FakePackages::new()),
                remote: Arc::new(FakeRemoteRegistry::new()),
                audit: Arc::new(FakeNpmAudit::new(vec![])),
                results: Arc::new(FakeDependencyAuditResults::new()),
                repository_id: Uuid::new_v4(),
                name: NpmPackageName::parse("root-pkg").unwrap(),
            }
        }

        async fn seed_root(&self, manifest: serde_json::Value) -> Uuid {
            let package =
                NpmPackage { id: Uuid::new_v4(), package_repository_id: self.repository_id, name: self.name.clone(), created_at: Utc::now(), updated_at: Utc::now(), metadata_fetched_at: None, cached_metadata: None };
            self.packages.create_package(&package).await.unwrap();
            let version_id = Uuid::new_v4();
            self.packages
                .insert_version(&NpmPackageVersion {
                    id: version_id,
                    npm_package_id: package.id,
                    version: NpmVersion::parse("1.0.0").unwrap(),
                    manifest,
                    shasum: "s".to_string(),
                    integrity: "i".to_string(),
                    tarball_storage_key: "k".to_string(),
                    tarball_size_bytes: 1,
                    deprecated: false,
                    deprecated_message: None,
                    published_by: None,
                    published_at: Utc::now(),
                    origin: NpmPackageOrigin::Local,
                })
                .await
                .unwrap();
            version_id
        }

        fn use_case(&self) -> ScanDependencyTreeUseCase {
            ScanDependencyTreeUseCase::new(self.packages.clone(), self.remote.clone(), self.audit.clone(), self.results.clone())
        }
    }

    #[tokio::test]
    async fn a_direct_dependency_with_a_known_advisory_is_reported() {
        let h = Harness::new();
        h.seed_root(manifest_with_deps(&[("minimist", "^0.0.8")])).await;
        h.remote.set_package("minimist", packument(&[("0.0.8", serde_json::json!({}))]));
        h.audit.set_bulk_response(serde_json::json!({ "minimist": [sample_advisory(1, "<0.2.4")] }));

        let result = h.use_case().execute(h.repository_id, &h.name, &NpmVersion::parse("1.0.0").unwrap()).await.unwrap();

        assert_eq!(result.packages_scanned, 1);
        assert!(!result.truncated);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].dependency_name, "minimist");
        assert_eq!(result.findings[0].dependency_version, "0.0.8");
        assert_eq!(h.audit.checked_packages(), Some(HashMap::from([("minimist".to_string(), vec!["0.0.8".to_string()])])));
        assert_eq!(h.results.saved().len(), 1);
    }

    #[tokio::test]
    async fn a_transitive_dependency_two_levels_deep_is_walked_and_audited() {
        let h = Harness::new();
        h.seed_root(manifest_with_deps(&[("a", "^1.0.0")])).await;
        h.remote.set_package("a", packument(&[("1.0.0", manifest_with_deps(&[("b", "^2.0.0")]))]));
        h.remote.set_package("b", packument(&[("2.0.0", serde_json::json!({}))]));
        h.audit.set_bulk_response(serde_json::json!({ "b": [sample_advisory(2, "<3.0.0")] }));

        let result = h.use_case().execute(h.repository_id, &h.name, &NpmVersion::parse("1.0.0").unwrap()).await.unwrap();

        assert_eq!(result.packages_scanned, 2);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].dependency_name, "b");
        let checked = h.audit.checked_packages().unwrap();
        assert_eq!(checked.get("a"), Some(&vec!["1.0.0".to_string()]));
        assert_eq!(checked.get("b"), Some(&vec!["2.0.0".to_string()]));
    }

    #[tokio::test]
    async fn a_dependency_cycle_does_not_loop_forever_and_each_pair_is_visited_once() {
        let h = Harness::new();
        h.seed_root(manifest_with_deps(&[("a", "^1.0.0")])).await;
        h.remote.set_package("a", packument(&[("1.0.0", manifest_with_deps(&[("b", "^1.0.0")]))]));
        h.remote.set_package("b", packument(&[("1.0.0", manifest_with_deps(&[("a", "^1.0.0")]))]));

        let result = h.use_case().execute(h.repository_id, &h.name, &NpmVersion::parse("1.0.0").unwrap()).await.unwrap();

        assert_eq!(result.packages_scanned, 2);
        assert!(!result.truncated);
    }

    #[tokio::test]
    async fn an_unresolvable_range_is_skipped_without_failing_the_scan() {
        let h = Harness::new();
        h.seed_root(manifest_with_deps(&[("a", "^9.0.0")])).await;
        h.remote.set_package("a", packument(&[("1.0.0", serde_json::json!({}))]));

        let result = h.use_case().execute(h.repository_id, &h.name, &NpmVersion::parse("1.0.0").unwrap()).await.unwrap();

        assert_eq!(result.packages_scanned, 0);
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn a_package_missing_from_the_public_registry_is_skipped_without_failing_the_scan() {
        let h = Harness::new();
        h.seed_root(manifest_with_deps(&[("totally-unpublished-pkg", "^1.0.0")])).await;
        *h.remote.metadata_response.lock().unwrap() = None;

        let result = h.use_case().execute(h.repository_id, &h.name, &NpmVersion::parse("1.0.0").unwrap()).await.unwrap();

        assert_eq!(result.packages_scanned, 0);
    }

    #[tokio::test]
    async fn a_chain_deeper_than_the_depth_cap_is_reported_as_truncated() {
        let h = Harness::new();
        // Build a chain dep-0 -> dep-1 -> ... -> dep-14, deeper than MAX_DEPTH (10).
        let chain_len = 15;
        h.seed_root(manifest_with_deps(&[("dep-0", "^1.0.0")])).await;
        for i in 0..chain_len {
            let next = format!("dep-{}", i + 1);
            let manifest = if i + 1 < chain_len { manifest_with_deps(&[(next.as_str(), "^1.0.0")]) } else { serde_json::json!({}) };
            h.remote.set_package(&format!("dep-{i}"), packument(&[("1.0.0", manifest)]));
        }

        let result = h.use_case().execute(h.repository_id, &h.name, &NpmVersion::parse("1.0.0").unwrap()).await.unwrap();

        assert!(result.truncated);
        assert_eq!(result.packages_scanned, MAX_DEPTH as i32);
    }

    #[tokio::test]
    async fn more_unique_packages_than_the_count_cap_is_reported_as_truncated() {
        let h = Harness::new();
        let extra = MAX_PACKAGES + 5;
        let deps: Vec<(String, String)> = (0..extra).map(|i| (format!("dep-{i}"), "^1.0.0".to_string())).collect();
        let deps_refs: Vec<(&str, &str)> = deps.iter().map(|(n, r)| (n.as_str(), r.as_str())).collect();
        h.seed_root(manifest_with_deps(&deps_refs)).await;
        for (name, _) in &deps {
            h.remote.set_package(name, packument(&[("1.0.0", serde_json::json!({}))]));
        }

        let result = h.use_case().execute(h.repository_id, &h.name, &NpmVersion::parse("1.0.0").unwrap()).await.unwrap();

        assert!(result.truncated);
        assert_eq!(result.packages_scanned, MAX_PACKAGES as i32);
    }

    #[tokio::test]
    async fn scanning_an_unknown_package_fails_with_not_found() {
        let h = Harness::new();
        let err = h.use_case().execute(h.repository_id, &h.name, &NpmVersion::parse("1.0.0").unwrap()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::NpmPackageNotFound));
    }

    #[tokio::test]
    async fn scanning_an_unknown_version_fails_with_not_found() {
        let h = Harness::new();
        h.seed_root(serde_json::json!({})).await;
        let err = h.use_case().execute(h.repository_id, &h.name, &NpmVersion::parse("9.9.9").unwrap()).await.unwrap_err();
        assert!(matches!(err, ApplicationError::NpmVersionNotFound));
    }

    #[tokio::test]
    async fn get_dependency_audit_result_returns_none_when_never_scanned() {
        let h = Harness::new();
        h.seed_root(manifest_with_deps(&[])).await;
        let use_case = GetDependencyAuditResultUseCase::new(h.packages.clone(), h.results.clone());

        let result = use_case.execute(h.repository_id, &h.name, &NpmVersion::parse("1.0.0").unwrap()).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_dependency_audit_result_returns_the_last_scan() {
        let h = Harness::new();
        h.seed_root(manifest_with_deps(&[("minimist", "^0.0.8")])).await;
        h.remote.set_package("minimist", packument(&[("0.0.8", serde_json::json!({}))]));

        h.use_case().execute(h.repository_id, &h.name, &NpmVersion::parse("1.0.0").unwrap()).await.unwrap();
        let use_case = GetDependencyAuditResultUseCase::new(h.packages.clone(), h.results.clone());
        let result = use_case.execute(h.repository_id, &h.name, &NpmVersion::parse("1.0.0").unwrap()).await.unwrap();

        assert!(result.is_some());
        assert_eq!(result.unwrap().packages_scanned, 1);
    }

    #[test]
    fn resolve_range_treats_a_bare_version_as_an_exact_match() {
        let versions = versions_map(&[("1.0.0", serde_json::json!({})), ("1.2.3", serde_json::json!({})), ("2.0.0", serde_json::json!({}))]);
        let (resolved, _) = resolve_range("1.2.3", &versions).unwrap();
        assert_eq!(resolved, "1.2.3");
    }

    #[test]
    fn resolve_range_picks_the_highest_version_matching_a_caret_range() {
        let versions = versions_map(&[("1.0.0", serde_json::json!({})), ("1.5.0", serde_json::json!({})), ("2.0.0", serde_json::json!({}))]);
        let (resolved, _) = resolve_range("^1.0.0", &versions).unwrap();
        assert_eq!(resolved, "1.5.0");
    }

    #[test]
    fn resolve_range_supports_tilde_ranges() {
        let versions = versions_map(&[("1.2.0", serde_json::json!({})), ("1.2.9", serde_json::json!({})), ("1.3.0", serde_json::json!({}))]);
        let (resolved, _) = resolve_range("~1.2.0", &versions).unwrap();
        assert_eq!(resolved, "1.2.9");
    }

    #[test]
    fn resolve_range_supports_or_combined_ranges() {
        let versions = versions_map(&[("1.0.0", serde_json::json!({})), ("3.0.0", serde_json::json!({}))]);
        let (resolved, _) = resolve_range("^1.0.0 || ^3.0.0", &versions).unwrap();
        assert_eq!(resolved, "3.0.0");
    }

    #[test]
    fn resolve_range_returns_none_when_nothing_matches() {
        let versions = versions_map(&[("1.0.0", serde_json::json!({}))]);
        assert!(resolve_range("^2.0.0", &versions).is_none());
    }

    #[test]
    fn version_satisfies_range_matches_a_vulnerable_versions_string() {
        assert!(version_satisfies_range("0.0.8", "<0.2.4"));
        assert!(!version_satisfies_range("1.2.8", "<0.2.4"));
    }

    fn versions_map(versions: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
        let mut map = serde_json::Map::new();
        for (v, m) in versions {
            map.insert(v.to_string(), m.clone());
        }
        map
    }
}

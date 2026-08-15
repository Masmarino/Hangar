use async_trait::async_trait;
use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NpmPackageName(String);

impl NpmPackageName {
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        if raw.is_empty() || raw.len() > 214 {
            return Err(DomainError::Validation("package name must be 1-214 characters".into()));
        }
        let unscoped = if let Some(rest) = raw.strip_prefix('@') {
            let mut parts = rest.splitn(2, '/');
            let scope = parts.next().unwrap_or_default();
            let name = parts.next().ok_or_else(|| {
                DomainError::Validation("scoped package name must be @scope/name".into())
            })?;
            if scope.is_empty() || name.is_empty() {
                return Err(DomainError::Validation("scoped package name must be @scope/name".into()));
            }
            Self::validate_segment(scope)?;
            name
        } else {
            raw
        };
        Self::validate_segment(unscoped)?;
        Ok(Self(raw.to_string()))
    }

    fn validate_segment(segment: &str) -> Result<(), DomainError> {
        // "." and ".." pass every char check below, so reject them explicitly too.
        let valid = !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.');
        if valid {
            Ok(())
        } else {
            Err(DomainError::Validation(format!(
                "invalid package name segment: {segment}"
            )))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The part after `@scope/`, or the whole name if unscoped — e.g. `foo` for both `foo` and `@bar/foo`.
    pub fn local_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NpmVersion(#[serde(with = "version_serde")] Version);

impl NpmVersion {
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        Version::parse(raw)
            .map(Self)
            .map_err(|e| DomainError::Validation(format!("invalid semver version: {e}")))
    }

    pub fn as_str(&self) -> String {
        self.0.to_string()
    }
}

mod version_serde {
    use semver::Version;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Version, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Version, D::Error> {
        let raw = String::deserialize(d)?;
        Version::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NpmPackageOrigin {
    Local,
    ProxyCache,
}

#[derive(Debug, Clone)]
pub struct NpmPackage {
    pub id: Uuid,
    pub package_repository_id: Uuid,
    pub name: NpmPackageName,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub metadata_fetched_at: Option<DateTime<Utc>>,
    pub cached_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct NpmPackageVersion {
    pub id: Uuid,
    pub npm_package_id: Uuid,
    pub version: NpmVersion,
    pub manifest: serde_json::Value,
    pub shasum: String,
    pub integrity: String,
    pub tarball_storage_key: String,
    pub tarball_size_bytes: i64,
    pub deprecated: bool,
    pub deprecated_message: Option<String>,
    pub published_by: Option<Uuid>,
    pub published_at: DateTime<Utc>,
    pub origin: NpmPackageOrigin,
}

/// Lighter than [`NpmPackageVersion`] — no `manifest`, a full package.json a browse/retention sweep never reads.
#[derive(Debug, Clone)]
pub struct NpmPackageVersionSummary {
    pub npm_package_id: Uuid,
    pub version: NpmVersion,
    pub tarball_size_bytes: i64,
    pub deprecated: bool,
    pub published_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NpmDistTag {
    pub npm_package_id: Uuid,
    pub tag: String,
    pub version: NpmVersion,
}

#[async_trait]
pub trait NpmPackageRepositoryPort: Send + Sync {
    async fn find_package(
        &self,
        repository_id: Uuid,
        name: &NpmPackageName,
    ) -> Result<Option<NpmPackage>, DomainError>;

    async fn find_by_id(&self, id: Uuid) -> Result<Option<NpmPackage>, DomainError>;

    async fn create_package(&self, package: &NpmPackage) -> Result<(), DomainError>;

    async fn touch_metadata_fetched_at(
        &self,
        npm_package_id: Uuid,
        fetched_at: DateTime<Utc>,
    ) -> Result<(), DomainError>;

    async fn set_cached_metadata(&self, npm_package_id: Uuid, metadata: serde_json::Value) -> Result<(), DomainError>;

    async fn list_versions(&self, npm_package_id: Uuid) -> Result<Vec<NpmPackageVersion>, DomainError>;
    /// Batched form of `list_versions` across several packages in one query.
    async fn list_versions_for_packages(&self, npm_package_ids: &[Uuid]) -> Result<Vec<NpmPackageVersionSummary>, DomainError>;

    async fn find_version(
        &self,
        npm_package_id: Uuid,
        version: &NpmVersion,
    ) -> Result<Option<NpmPackageVersion>, DomainError>;

    async fn insert_version(&self, version: &NpmPackageVersion) -> Result<(), DomainError>;

    async fn delete_version(&self, npm_package_id: Uuid, version: &NpmVersion) -> Result<(), DomainError>;

    async fn delete_package(&self, npm_package_id: Uuid) -> Result<(), DomainError>;

    async fn set_deprecated(
        &self,
        npm_package_id: Uuid,
        version: &NpmVersion,
        message: Option<&str>,
    ) -> Result<(), DomainError>;

    async fn list_dist_tags(&self, npm_package_id: Uuid) -> Result<Vec<NpmDistTag>, DomainError>;
    /// Batched form of `list_dist_tags` across several packages in one query.
    async fn list_dist_tags_for_packages(&self, npm_package_ids: &[Uuid]) -> Result<Vec<NpmDistTag>, DomainError>;

    async fn set_dist_tag(&self, npm_package_id: Uuid, tag: &str, version: &NpmVersion) -> Result<(), DomainError>;

    async fn delete_dist_tag(&self, npm_package_id: Uuid, tag: &str) -> Result<(), DomainError>;

    async fn search(
        &self,
        repository_id: Uuid,
        query: &str,
        limit: i64,
    ) -> Result<Vec<NpmPackage>, DomainError>;

    async fn increment_download_counter(&self, npm_package_version_id: Uuid) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_simple_package_name() {
        assert!(NpmPackageName::parse("left-pad").is_ok());
    }

    #[test]
    fn accepts_a_scoped_package_name() {
        let name = NpmPackageName::parse("@hangar/cli").unwrap();
        assert_eq!(name.as_str(), "@hangar/cli");
    }

    #[test]
    fn rejects_an_empty_name() {
        assert!(NpmPackageName::parse("").is_err());
    }

    #[test]
    fn rejects_a_name_with_uppercase_letters() {
        assert!(NpmPackageName::parse("Left-Pad").is_err());
    }

    #[test]
    fn rejects_a_scope_without_a_slash() {
        assert!(NpmPackageName::parse("@hangar").is_err());
    }

    #[test]
    fn rejects_a_dot_or_dot_dot_segment() {
        assert!(NpmPackageName::parse(".").is_err());
        assert!(NpmPackageName::parse("..").is_err());
        assert!(NpmPackageName::parse("@../..").is_err());
    }

    #[test]
    fn parses_a_valid_semver_version() {
        assert!(NpmVersion::parse("1.2.3").is_ok());
        assert!(NpmVersion::parse("1.2.3-beta.1").is_ok());
    }

    #[test]
    fn rejects_an_invalid_version() {
        assert!(NpmVersion::parse("not-a-version").is_err());
    }

    #[test]
    fn orders_versions_by_semver_not_string() {
        let v9 = NpmVersion::parse("9.0.0").unwrap();
        let v10 = NpmVersion::parse("10.0.0").unwrap();
        assert!(v9 < v10, "9.0.0 must sort before 10.0.0 under semver, not string order");
    }
}

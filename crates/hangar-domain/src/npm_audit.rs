use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;
use crate::npm_package::{NpmPackageName, NpmVersion};

/// One advisory from npm's public security advisory database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NpmAdvisory {
    pub id: i64,
    pub url: String,
    pub title: String,
    pub severity: String,
    pub vulnerable_versions: String,
    pub cwe: Vec<String>,
    pub cvss_score: Option<f64>,
}

/// Parses npm's `{package: [advisory, ...]}` bulk response. A malformed entry is dropped rather than failing the whole response.
pub fn parse_advisories(raw: &serde_json::Value) -> HashMap<String, Vec<NpmAdvisory>> {
    let Some(obj) = raw.as_object() else {
        return HashMap::new();
    };
    obj.iter()
        .map(|(name, advisories)| {
            let parsed = advisories.as_array().map(|arr| arr.iter().filter_map(parse_one_advisory).collect()).unwrap_or_default();
            (name.clone(), parsed)
        })
        .collect()
}

fn parse_one_advisory(value: &serde_json::Value) -> Option<NpmAdvisory> {
    Some(NpmAdvisory {
        id: value.get("id")?.as_i64()?,
        url: value.get("url")?.as_str()?.to_string(),
        title: value.get("title")?.as_str()?.to_string(),
        severity: value.get("severity")?.as_str()?.to_string(),
        vulnerable_versions: value.get("vulnerable_versions")?.as_str()?.to_string(),
        cwe: value
            .get("cwe")
            .and_then(|c| c.as_array())
            .map(|entries| entries.iter().filter_map(|c| c.as_str().map(str::to_string)).collect())
            .unwrap_or_default(),
        cvss_score: value.get("cvss").and_then(|c| c.get("score")).and_then(|s| s.as_f64()),
    })
}

#[async_trait]
pub trait NpmAuditPort: Send + Sync {
    async fn check(&self, name: &NpmPackageName, versions: &[NpmVersion]) -> Result<Vec<NpmAdvisory>, DomainError>;

    /// Same query for many packages, returned as npm's raw JSON — real
    /// `npm audit` CLI clients expect this exact shape back.
    async fn check_bulk_raw(&self, packages: &HashMap<String, Vec<String>>) -> Result<serde_json::Value, DomainError>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DependencyAuditFinding {
    pub dependency_name: String,
    pub dependency_version: String,
    pub advisory: NpmAdvisory,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DependencyAuditResult {
    pub id: Uuid,
    pub npm_package_version_id: Uuid,
    pub scanned_at: DateTime<Utc>,
    pub packages_scanned: i32,
    /// `true` if the walk was capped before covering the whole tree.
    pub truncated: bool,
    pub findings: Vec<DependencyAuditFinding>,
}

#[async_trait]
pub trait DependencyAuditRepositoryPort: Send + Sync {
    async fn save(&self, result: &DependencyAuditResult) -> Result<(), DomainError>;

    /// `None` means never scanned, distinct from "scanned, no findings".
    async fn find_latest_for_version(&self, npm_package_version_id: Uuid) -> Result<Option<DependencyAuditResult>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn well_formed_advisory(id: i64) -> serde_json::Value {
        json!({
            "id": id,
            "url": format!("https://example.com/advisories/{id}"),
            "title": "Prototype Pollution",
            "severity": "high",
            "vulnerable_versions": "<1.2.3",
            "cwe": ["CWE-1321"],
            "cvss": { "score": 7.5 },
        })
    }

    #[test]
    fn well_formed_batch_parses_every_advisory() {
        let raw = json!({
            "left-pad": [well_formed_advisory(1), well_formed_advisory(2)],
            "minimist": [well_formed_advisory(3)],
        });

        let parsed = parse_advisories(&raw);

        assert_eq!(parsed.len(), 2);
        let left_pad = &parsed["left-pad"];
        assert_eq!(left_pad.len(), 2);
        assert_eq!(
            left_pad[0],
            NpmAdvisory {
                id: 1,
                url: "https://example.com/advisories/1".to_string(),
                title: "Prototype Pollution".to_string(),
                severity: "high".to_string(),
                vulnerable_versions: "<1.2.3".to_string(),
                cwe: vec!["CWE-1321".to_string()],
                cvss_score: Some(7.5),
            }
        );
        assert_eq!(parsed["minimist"][0].id, 3);
    }

    #[test]
    fn advisory_missing_cvss_score_still_parses_with_none() {
        // `cvss.score` is read with `.and_then`, never `?`, so a missing/absent score
        // must not drop the whole advisory - only `cvss_score` becomes `None`.
        let mut advisory = well_formed_advisory(1);
        advisory.as_object_mut().unwrap().remove("cvss");

        let parsed = parse_one_advisory(&advisory).expect("advisory without cvss.score should still parse");

        assert_eq!(parsed.id, 1);
        assert_eq!(parsed.cvss_score, None);
    }

    #[test]
    fn advisory_with_cvss_object_missing_score_field_still_parses_with_none() {
        let mut advisory = well_formed_advisory(1);
        advisory["cvss"] = json!({ "vector": "AV:N/AC:L" });

        let parsed = parse_one_advisory(&advisory).expect("advisory with cvss but no score should still parse");

        assert_eq!(parsed.cvss_score, None);
    }

    #[test]
    fn non_array_cwe_field_defaults_to_empty_rather_than_dropping_the_advisory() {
        let mut advisory = well_formed_advisory(1);
        advisory["cwe"] = json!("CWE-1321"); // a bare string, not an array

        let parsed = parse_one_advisory(&advisory).expect("advisory with non-array cwe should still parse");

        assert_eq!(parsed.cwe, Vec::<String>::new());
    }

    #[test]
    fn advisory_missing_id_is_dropped() {
        let mut advisory = well_formed_advisory(1);
        advisory.as_object_mut().unwrap().remove("id");

        assert_eq!(parse_one_advisory(&advisory), None);
    }

    #[test]
    fn advisory_with_wrong_type_id_is_dropped() {
        let mut advisory = well_formed_advisory(1);
        advisory["id"] = json!("not-a-number");

        assert_eq!(parse_one_advisory(&advisory), None);
    }

    #[test]
    fn advisory_missing_a_required_string_field_is_dropped() {
        for field in ["url", "title", "severity", "vulnerable_versions"] {
            let mut advisory = well_formed_advisory(1);
            advisory.as_object_mut().unwrap().remove(field);
            assert_eq!(parse_one_advisory(&advisory), None, "expected advisory missing `{field}` to be dropped");
        }
    }

    #[test]
    fn non_object_advisory_entry_is_dropped() {
        assert_eq!(parse_one_advisory(&json!("just a string")), None);
        assert_eq!(parse_one_advisory(&json!(null)), None);
        assert_eq!(parse_one_advisory(&json!([1, 2, 3])), None);
    }

    #[test]
    fn one_malformed_entry_does_not_take_down_the_rest_of_a_mixed_batch() {
        let raw = json!({
            "left-pad": [
                well_formed_advisory(1),
                json!({ "url": "https://example.com/advisories/missing-id", "title": "x", "severity": "low", "vulnerable_versions": "*" }),
                well_formed_advisory(2),
                json!("garbage"),
                well_formed_advisory(3),
            ],
        });

        let parsed = parse_advisories(&raw);

        let ids: Vec<i64> = parsed["left-pad"].iter().map(|a| a.id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn package_whose_advisories_field_is_not_an_array_yields_an_empty_list() {
        let raw = json!({ "left-pad": "not-an-array" });

        let parsed = parse_advisories(&raw);

        assert_eq!(parsed["left-pad"], Vec::<NpmAdvisory>::new());
    }

    #[test]
    fn non_object_top_level_value_yields_no_advisories() {
        assert_eq!(parse_advisories(&json!([1, 2, 3])), HashMap::new());
        assert_eq!(parse_advisories(&json!("not an object")), HashMap::new());
    }
}

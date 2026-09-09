use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use hangar_domain::permission::Role;
use serde::Deserialize;
use serde_json::json;

use crate::authz::{require_npm_hosted_repository, require_repository_by_name, require_repository_role};
use crate::auth::NpmAuthUser;
use crate::errors::npm_error_response;
use crate::organization_resolution::ResolvedOrganization;
use crate::state::NpmState;

pub fn router() -> Router<NpmState> {
    Router::new().route("/{repository}/-/v1/search", get(search))
}

#[derive(Deserialize)]
struct SearchQuery {
    text: String,
    #[serde(default = "default_size")]
    size: i64,
}

fn default_size() -> i64 {
    20
}

/// Matches the real npm registry's own default/max — negative or unbounded otherwise.
fn clamp_size(size: i64) -> i64 {
    size.clamp(1, 250)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_negative_size_is_clamped_to_the_minimum() {
        assert_eq!(clamp_size(-1), 1);
        assert_eq!(clamp_size(i64::MIN), 1);
    }

    #[test]
    fn an_excessive_size_is_clamped_to_the_maximum() {
        assert_eq!(clamp_size(10_000), 250);
        assert_eq!(clamp_size(i64::MAX), 250);
    }

    #[test]
    fn an_in_range_size_is_left_untouched() {
        assert_eq!(clamp_size(20), 20);
    }
}

async fn search(
    State(state): State<NpmState>,
    axum::extract::Path(repository): axum::extract::Path<String>,
    Query(params): Query<SearchQuery>,
    resolved_org: ResolvedOrganization,
    user: NpmAuthUser,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repo = require_repository_by_name(&state, &user, resolved_org.0.id, &repository).await.map_err(|s| (s, Json(json!({ "error": "repository not found or inaccessible" }))))?;
    require_npm_hosted_repository(&repo).map_err(|s| (s, Json(json!({ "error": "repository not found or inaccessible" }))))?;
    require_repository_role(&state, &user, repo.id, repo.organization_id, Role::Read).await.map_err(|s| (s, Json(json!({ "error": "forbidden" }))))?;

    let size = clamp_size(params.size);
    let packages = state.search.execute(repo.id, &params.text, size).await.map_err(npm_error_response)?;
    let objects: Vec<serde_json::Value> = packages
        .into_iter()
        // Real `npm search` unconditionally calls `.map()` on `maintainers` —
        // an empty array (not a missing key) is required or the CLI crashes.
        .map(|p| json!({ "package": { "name": p.name.as_str(), "maintainers": [] } }))
        .collect();
    Ok(Json(json!({ "objects": objects, "total": objects.len() })))
}

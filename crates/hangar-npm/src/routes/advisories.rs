use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use hangar_domain::permission::Role;
use serde_json::json;

use crate::auth::NpmAuthUser;
use crate::authz::{require_npm_hosted_repository, require_repository_by_name, require_repository_role};
use crate::errors::npm_error_response;
use crate::organization_resolution::ResolvedOrganization;
use crate::state::NpmState;

pub fn router() -> Router<NpmState> {
    Router::new().route("/:repository/-/npm/v1/security/advisories/bulk", post(bulk_advisories))
}

/// Real `npm audit`'s own endpoint — forwards straight to npm's advisory database rather than looking anything up locally.
async fn bulk_advisories(
    State(state): State<NpmState>,
    Path(repository): Path<String>,
    resolved_org: ResolvedOrganization,
    user: NpmAuthUser,
    Json(packages): Json<HashMap<String, Vec<String>>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let repo = require_repository_by_name(&state, &user, resolved_org.0.id, &repository).await.map_err(|s| (s, Json(json!({ "error": "repository not found or inaccessible" }))))?;
    require_npm_hosted_repository(&repo).map_err(|s| (s, Json(json!({ "error": "repository not found or inaccessible" }))))?;
    require_repository_role(&state, &user, repo.id, repo.organization_id, Role::Read).await.map_err(|s| (s, Json(json!({ "error": "forbidden" }))))?;

    let result = state.bulk_audit.execute(&packages).await.map_err(npm_error_response)?;
    Ok(Json(result))
}

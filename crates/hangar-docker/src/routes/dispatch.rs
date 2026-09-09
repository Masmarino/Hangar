use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;

use crate::auth::DockerAuthUser;
use crate::organization_resolution::ResolvedOrganization;
use crate::routes::blobs;
use crate::routes::manifests;
use crate::routes::path::{DockerOperation, parse_operation};
use crate::routes::tags;
use crate::state::DockerState;

/// A manifest is normally a few KB — this keeps a push from riding the router's 2 GB blob limit.
const MANIFEST_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;

/// Raw `Body` bypasses the router's DefaultBodyLimit, so the cap must be applied explicitly.
async fn read_capped(body: Body, limit: usize) -> Result<Bytes, Response> {
    axum::body::to_bytes(body, limit).await.map_err(|_| StatusCode::PAYLOAD_TOO_LARGE.into_response())
}

pub fn router() -> Router<DockerState> {
    Router::new().route(
        "/{repository}/{*rest}",
        get(handle_get).head(handle_head).post(handle_post).put(handle_put).patch(handle_patch).delete(handle_delete),
    )
}

#[derive(Deserialize)]
pub struct BlobQueryParams {
    digest: Option<String>,
}

async fn handle_get(
    State(state): State<DockerState>,
    Path((repository, rest)): Path<(String, String)>,
    resolved_org: ResolvedOrganization,
    user: DockerAuthUser,
) -> Response {
    let organization_id = resolved_org.0.id;
    match parse_operation(&rest) {
        Some(DockerOperation::Blob { image_name, digest }) => blobs::get_blob(state, organization_id, repository, image_name, digest, user).await,
        Some(DockerOperation::Manifest { image_name, reference }) => {
            manifests::get_manifest(state, organization_id, repository, image_name, reference, user).await
        }
        Some(DockerOperation::TagsList { image_name }) => tags::list_tags(state, organization_id, repository, image_name, user).await,
        Some(_) => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Only the blob case gets the lightweight `head_blob` treatment; other HEAD requests fall back to the same GET handlers.
async fn handle_head(
    State(state): State<DockerState>,
    Path((repository, rest)): Path<(String, String)>,
    resolved_org: ResolvedOrganization,
    user: DockerAuthUser,
) -> Response {
    let organization_id = resolved_org.0.id;
    match parse_operation(&rest) {
        Some(DockerOperation::Blob { image_name, digest }) => blobs::head_blob(state, organization_id, repository, image_name, digest, user).await,
        Some(DockerOperation::Manifest { image_name, reference }) => {
            manifests::get_manifest(state, organization_id, repository, image_name, reference, user).await
        }
        Some(DockerOperation::TagsList { image_name }) => tags::list_tags(state, organization_id, repository, image_name, user).await,
        Some(_) => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn handle_post(
    State(state): State<DockerState>,
    Path((repository, rest)): Path<(String, String)>,
    Query(params): Query<BlobQueryParams>,
    resolved_org: ResolvedOrganization,
    user: DockerAuthUser,
    body: Bytes,
) -> Response {
    match parse_operation(&rest) {
        Some(DockerOperation::BlobUploadStart { image_name }) => {
            blobs::start_or_monolithic_upload(state, resolved_org.0.id, repository, image_name, params.digest, user, body).await
        }
        Some(_) => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn handle_patch(
    State(state): State<DockerState>,
    Path((repository, rest)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
    resolved_org: ResolvedOrganization,
    user: DockerAuthUser,
    chunk: Bytes,
) -> Response {
    match parse_operation(&rest) {
        Some(DockerOperation::BlobUploadChunk { image_name, upload_id }) => {
            let content_range = headers.get(axum::http::header::CONTENT_RANGE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            blobs::patch_chunk(state, resolved_org.0.id, repository, image_name, upload_id, content_range, user, chunk).await
        }
        Some(_) => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn handle_put(
    State(state): State<DockerState>,
    Path((repository, rest)): Path<(String, String)>,
    Query(params): Query<BlobQueryParams>,
    headers: axum::http::HeaderMap,
    resolved_org: ResolvedOrganization,
    user: DockerAuthUser,
    body: Body,
) -> Response {
    match parse_operation(&rest) {
        Some(DockerOperation::BlobUploadChunk { image_name, upload_id }) => {
            let body = match read_capped(body, crate::BLOB_BODY_LIMIT_BYTES).await {
                Ok(body) => body,
                Err(response) => return response,
            };
            blobs::complete_upload(state, resolved_org.0.id, repository, image_name, upload_id, params.digest, user, body).await
        }
        Some(DockerOperation::Manifest { image_name, reference }) => {
            // A manifest gets its own, much tighter cap — see MANIFEST_BODY_LIMIT_BYTES's doc comment.
            let body = match read_capped(body, MANIFEST_BODY_LIMIT_BYTES).await {
                Ok(body) => body,
                Err(response) => return response,
            };
            let content_type = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
            manifests::put_manifest(state, resolved_org.0.id, repository, image_name, reference, content_type, user, body).await
        }
        Some(_) => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn handle_delete(
    State(state): State<DockerState>,
    Path((repository, rest)): Path<(String, String)>,
    resolved_org: ResolvedOrganization,
    user: DockerAuthUser,
) -> Response {
    match parse_operation(&rest) {
        Some(DockerOperation::Manifest { image_name, reference }) => {
            manifests::delete_manifest(state, resolved_org.0.id, repository, image_name, reference, user).await
        }
        Some(_) => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

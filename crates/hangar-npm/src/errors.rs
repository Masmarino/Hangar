use axum::Json;
use axum::http::StatusCode;
use hangar_application::error::ApplicationError;
use serde_json::json;

pub fn bad_request(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message })))
}

pub fn npm_error_response(error: ApplicationError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match &error {
        ApplicationError::PackageVersionExists => StatusCode::CONFLICT,
        ApplicationError::NpmPackageNotFound | ApplicationError::NpmVersionNotFound => StatusCode::NOT_FOUND,
        ApplicationError::InvalidNpmPayload(_) => StatusCode::BAD_REQUEST,
        ApplicationError::StorageQuotaExceeded => StatusCode::INSUFFICIENT_STORAGE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    if status == StatusCode::INTERNAL_SERVER_ERROR {
        tracing::error!(error = %error, "npm route internal error");
    }
    (status, Json(json!({ "error": error.to_string() })))
}

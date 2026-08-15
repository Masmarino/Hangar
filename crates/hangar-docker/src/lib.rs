pub mod auth;
pub mod authz;
pub mod errors;
pub mod organization_resolution;
pub mod routes;
pub mod state;

#[cfg(test)]
pub mod route_test_support;

pub use state::DockerState;

/// Image layers can reach several GB — also passed explicitly to `handle_put`'s manual body read.
pub const BLOB_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024 * 1024;

pub fn router(state: DockerState) -> axum::Router {
    axum::Router::new()
        .merge(routes::handshake::router())
        .merge(routes::dispatch::router())
        .merge(routes::catalog::router())
        .layer(axum::extract::DefaultBodyLimit::max(BLOB_BODY_LIMIT_BYTES))
        .with_state(state)
}

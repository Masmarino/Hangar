pub mod auth;
pub mod authz;
pub mod errors;
pub mod organization_resolution;
pub mod routes;
pub mod state;

pub use state::NpmState;

pub fn router(state: NpmState) -> axum::Router {
    axum::Router::new()
        .merge(routes::metadata::router())
        .merge(routes::publish::router())
        .merge(routes::unpublish::router())
        .merge(routes::dist_tags::router())
        .merge(routes::search::router())
        .merge(routes::advisories::router())
        // Real `npm audit` sends its bulk advisory request gzip-compressed
        // unconditionally — without this, axum rejects it with a 400.
        .layer(tower_http::decompression::RequestDecompressionLayer::new())
        // Scoped here, not globally, so real npm tarballs aren't rejected
        // without widening every other endpoint's limit too. Outer layer so
        // it caps the raw body before decompression runs.
        .layer(axum::extract::DefaultBodyLimit::max(200 * 1024 * 1024))
        .with_state(state)
}

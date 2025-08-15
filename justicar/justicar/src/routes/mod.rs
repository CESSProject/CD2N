mod internal_route;
mod service_route;
use crate::handlers::{internal_handler, service_handler};
use crate::models::CD2NState;
use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post,put},
    Router,
};
use tower_http::limit::RequestBodyLimitLayer;

pub async fn create_routes(state: CD2NState) -> Router {
    Router::new()
        .merge(service_route::service_routes(state.clone()).await)
        .merge(internal_route::handover_routes(state.clone()).await)
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(
            250 * 1024 * 1024, /* 250mb */
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
}

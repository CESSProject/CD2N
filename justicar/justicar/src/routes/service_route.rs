use super::*;

pub async fn service_routes(state: CD2NState) -> Router {
    Router::new()
        .route("/audit", post(service_handler::supplier_data_audit))
        .route(
            "/query_information",
            get(service_handler::query_information),
        )
        .route(
            "/download_traffic_query",
            get(service_handler::download_traffic_query),
        )
        .route("/echo", post(service_handler::test_echo))
        .with_state(state)
}

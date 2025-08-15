use super::*;

pub async fn handover_routes(state: CD2NState) -> Router {
    Router::new()
        .route(
            "/generate_challenge",
            get(internal_handler::generate_challenge),
        )
        .route(
            "/handover_accept_challenge",
            post(internal_handler::handover_accept_challenge),
        )
        .route("/handover_start", post(internal_handler::handover_start))
        .route(
            "/handover_receive",
            post(internal_handler::handover_receive),
        )
        .route(
            "/set_handover_status",
            put(internal_handler::set_handover_status),
        )
        .route(
            "/get_handover_status",
            get(internal_handler::get_handover_status),
        )
        .with_state(state)
}

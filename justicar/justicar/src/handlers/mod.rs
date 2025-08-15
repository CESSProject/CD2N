pub(crate) mod internal_handler;
pub(crate) mod service_handler;
use crate::{
    models::{
        secret::{secret_from_cdn_state, secret_to_cdn_state, Secret},
        service::{
            HandoverStatus, QueryDownloadTraffic, QueryDownloadTrafficResponse,
            QueryInformationResponse, RewardDatabase, SupplierDataAuditResponse, SupplierReward,
            TestEcho, TestEchoResponse, TOTAL_USER_USED_TRAFFIC,
        },
        CD2NState, RA,
    },
    utils::seal::Sealing,
};
use anyhow::anyhow;
use axum::{
    extract::{ConnectInfo, Multipart, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use eth::interact_contract::ContractInteract;
pub struct AppError(StatusCode, anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, self.1.to_string()).into_response()
    }
}

pub fn return_error<E>(err: E, status_code: StatusCode) -> AppError
where
    E: Into<anyhow::Error>,
{
    AppError(status_code, err.into())
}

pub fn system_initialize(handover_over: bool) -> Result<(), AppError> {
    if !handover_over {
        return Ok(());
    }

    Err(return_error(
        anyhow!("Please wait for CDN to fully start"),
        StatusCode::FORBIDDEN,
    ))
}

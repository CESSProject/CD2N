use super::*;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use handover::handover::{
    ExternalStatusGet, HandoverChallenge, HandoverChallengeResponse, HandoverSecretData,
    RemoteAttestation,
};
use sgx_attestation::{
    dcap,
    types::{AttestationReport, Collateral},
};
use std::{collections::HashMap, net::SocketAddr, time::Duration};
#[async_trait]
impl ExternalStatusGet for CD2NState {
    async fn get_block_number(&self) -> handover::HandoverResult<u64> {
        let contract = self.contract.lock().await.clone();
        Ok(contract
            .get_current_block_number()
            .await
            .map_err(|e| handover::SgxError::InternalError(e.to_string()))?)
    }

    async fn get_mrenclave_update_block_number_map(
        &self,
    ) -> handover::HandoverResult<HashMap<String, u128>> {
        let contract = self.contract.lock().await.clone();
        let mrenclave_list = contract
            .get_mrenclave_list()
            .await
            .map_err(|e| handover::SgxError::InternalError(e.to_string()))?;
        let update_block_number_list = contract
            .get_update_block_number()
            .await
            .map_err(|e| handover::SgxError::InternalError(e.to_string()))?;
        let mut record_map = HashMap::new();
        for i in 0..mrenclave_list.len() {
            record_map.insert(mrenclave_list[i].clone(), update_block_number_list[i]);
        }

        Ok(record_map)
    }

    async fn get_mrsigner_list(&self) -> handover::HandoverResult<Vec<String>> {
        let contract = self.contract.lock().await.clone();
        let mrsigner_list = contract
            .get_mrsigner_list()
            .await
            .map_err(|e| handover::SgxError::InternalError(e.to_string()))?;
        Ok(mrsigner_list)
    }
}

#[async_trait]
impl RemoteAttestation for RA {
    async fn create_remote_attestation_report(
        &self,
        payload: &[u8],
        pccs_url: &str,
        ra_timeout: Duration,
    ) -> handover::HandoverResult<Vec<u8>> {
        let att_report =
            dcap::report::create_attestation_report(payload, pccs_url, ra_timeout).await?;

        let report_vec = serde_json::to_vec(&att_report)?;
        Ok(report_vec)
    }

    ///Only verify the legitimacy of the report and do not make any business judgments.
    ///Of course, you can do so if you want.
    fn verify_remote_attestation_report(
        &self,
        payload: &[u8],
        attestation_report: Vec<u8>,
    ) -> handover::HandoverResult<(bool, String, String)> {
        let att_report: AttestationReport = serde_json::from_slice(&attestation_report)?;
        let (raw_quote, quote_collateral) = if let AttestationReport::SgxDcap {
            quote: raw_quote,
            collateral: c,
        } = att_report
        {
            let quote_collateral = match c.unwrap() {
                Collateral::SgxV30(quote_collateral) => quote_collateral,
            };
            (raw_quote, quote_collateral)
        } else {
            return Err(anyhow!("Attestation format not supported!").into());
        };
        let now = chrono::Utc::now().timestamp() as u64;
        let (
            report_data,
            _, /*todo:tcb hash limit?*/
            _, /*todo:tcb status limit?*/
            _, /*todo:advisory ids prohibition?*/
            mr_enclave,
            mr_signer,
        ) = dcap::verify(&raw_quote, &quote_collateral, now)
            .map_err(|e| anyhow!("failed to verify quote: {:?}", e))?;

        let mut pad_payload = [0u8; 64];
        pad_payload[..payload.len()].copy_from_slice(payload);

        let mr_enclave = hex::encode_upper(mr_enclave);
        let mr_signer = hex::encode_upper(mr_signer);

        if report_data != pad_payload {
            Ok((false, mr_enclave, mr_signer))
        } else {
            Ok((true, mr_enclave, mr_signer))
        }
    }
}

pub async fn generate_challenge(
    State(state): State<CD2NState>,
) -> Result<Json<HandoverChallenge>, AppError> {
    let challenge = state
        .handover_handler
        .clone()
        .lock()
        .await
        .generate_challenge(&state.clone())
        .await
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(challenge))
}

pub async fn handover_accept_challenge(
    State(state): State<CD2NState>,
    Json(params): Json<HandoverChallenge>,
) -> Result<Json<HandoverChallengeResponse>, AppError> {
    let ra = RA {};
    let handover_challenge_response = state
        .handover_handler
        .clone()
        .lock()
        .await
        .handover_accept_challenge(params, &ra)
        .await
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(Json(handover_challenge_response))
}

pub async fn handover_start(
    State(state): State<CD2NState>,
    Json(params): Json<HandoverChallengeResponse>,
) -> Result<Json<HandoverSecretData>, AppError> {
    let ra = RA {};
    let secret = secret_from_cdn_state(state.clone())
        .await
        .context("Get secret from cdn state failed")
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    let secret_data = serde_json::to_vec(&secret)
        .context("serde secret to json failed")
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    let handover_secret_data = state
        .handover_handler
        .clone()
        .lock()
        .await
        .handover_start(secret_data, params, &ra, &state)
        .await
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(Json(handover_secret_data))
}

pub async fn handover_receive(
    State(mut state): State<CD2NState>,
    Json(params): Json<HandoverSecretData>,
) -> Result<Json<()>, AppError> {
    let ra = RA {};
    let handover_secret_data = state
        .handover_handler
        .clone()
        .lock()
        .await
        .handover_receive(params, &ra, &state)
        .await
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    let mut secret: Secret = serde_json::from_slice(&handover_secret_data)
        .context("Failed to parse json secret")
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    secret_to_cdn_state(secret.clone(), &mut state)
        .await
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;
    //save incentive record file into storage
    state
        .incentive_record_storage
        .lock()
        .await
        .seal_data(&secret.reward_database)
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;
    //save runtime info file into storage
    secret.reward_database = RewardDatabase::default();
    state
        .runtime_info_storage_path
        .seal_data(&secret)
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(Json(()))
}

pub async fn set_handover_status(
    State(mut state): State<CD2NState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Result<Json<()>, AppError> {
    if addr.ip().is_loopback() {
        *state.need_handover.lock().await = false;

        let mut secret = secret_from_cdn_state(state.clone())
            .await
            .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;
        //save runtime info file into storage
        secret.reward_database = RewardDatabase::default();
        state
            .runtime_info_storage_path
            .seal_data(&secret)
            .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;
    } else {
        return Err(return_error(
            anyhow!("oops..Only loopback address is allowed"),
            StatusCode::FORBIDDEN,
        ));
    }
    Ok(Json(()))
}

pub async fn get_handover_status(
    State(state): State<CD2NState>,
) -> Result<Json<HandoverStatus>, AppError> {
    Ok(Json(HandoverStatus {
        handover_over: state.need_handover.lock().await.clone(),
    }))
}

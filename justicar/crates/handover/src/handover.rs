use crate::HandoverResult as Result;
use crate::{utils, SgxError};
use anyhow::{anyhow, bail};
use async_trait::async_trait;
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, time::Duration};

pub struct HandoverHandler {
    ecdh_secret_key: Option<utils::EcdhSecretKey>,
    echd_public_key: Option<utils::EcdhPublicKey>,
    /// The last challenge create by this justicar
    handover_last_challenge: Option<HandoverChallenge>,

    /// The following content can be configue
    pub dev_mode: bool,
    pub pccs_url: String,
    pub ra_timeout: u64,
}

impl Default for HandoverHandler {
    fn default() -> Self {
        HandoverHandler {
            ecdh_secret_key: None,
            echd_public_key: None,
            handover_last_challenge: None,
            dev_mode: false,
            pccs_url: "".to_string(),
            ra_timeout: 1800,
        }
    }
}

impl HandoverHandler {
    pub fn new(dev_mode: bool, pccs_url: String, ra_timeout: u64) -> Self {
        HandoverHandler {
            ecdh_secret_key: None,
            echd_public_key: None,
            handover_last_challenge: None,
            dev_mode,
            pccs_url,
            ra_timeout,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct HandoverChallenge {
    pub sgx_target_info: Vec<u8>,
    pub block_number: u64,
    pub dev_mode: bool,
    pub nonce: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct ChallengeHandlerInfo {
    pub challenge: HandoverChallenge,
    pub sgx_local_report: Vec<u8>,
    pub ecdh_pubkey: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct HandoverChallengeResponse {
    challenge_handler: ChallengeHandlerInfo,
    attestation: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EncryptedDataInfo {
    /// for key agreement
    pub ecdh_pubkey: [u8; 32],
    /// secret data encrypted by ecdh sharded key
    pub encrypted_data: Vec<u8>,
    /// IV nonce
    pub iv: [u8; 12],

    pub dev_mode: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HandoverSecretData {
    encrypted_data_info: EncryptedDataInfo,
    attestation: Option<Vec<u8>>,
}

impl HandoverHandler {
    /// 1st step:[Server] get challenge
    pub async fn generate_challenge(
        &mut self,
        contract: &impl ExternalStatusGet,
    ) -> Result<HandoverChallenge> {
        let sgx_target_info = if self.dev_mode {
            vec![]
        } else {
            let my_target_info = crate::target_info()?;
            crate::encode(&my_target_info).to_vec()
        };
        let challenge = HandoverChallenge {
            sgx_target_info,
            block_number: contract.get_block_number().await?,
            dev_mode: self.dev_mode,
            nonce: crate::utils::generate_random_byte::<32>(),
        };
        self.handover_last_challenge = Some(challenge.clone());
        Ok(challenge)
    }

    /// 2nd step:[Client] accept challenge and generate report in response
    pub async fn handover_accept_challenge(
        &mut self,
        challenge: HandoverChallenge,
        ra: &impl RemoteAttestation,
    ) -> Result<HandoverChallengeResponse> {
        // do the secret exchange safely by using ECDH key exchange
        let (ecdh_secret_key, echd_public_key) = utils::gen_ecdh_key_pair();
        let dev_mode = challenge.dev_mode;
        self.ecdh_secret_key = Some(ecdh_secret_key);
        self.echd_public_key = Some(echd_public_key);

        // generate local attestation report to ensure the two justicar on same instance
        let sgx_local_report = if !dev_mode {
            let its_target_info = unsafe { crate::decode(&challenge.sgx_target_info)? };
            // the report data does not matter since we only care about the origin
            let report = crate::report(its_target_info, &[0; 64])?;
            crate::encode(&report).to_vec()
        } else {
            info!("create local attestation report in dev mode");
            vec![]
        };

        // generate remote attestation report,make the old justicar trust that the secret exchange with this one is credible
        let challenge_handler = ChallengeHandlerInfo {
            challenge,
            sgx_local_report,
            ecdh_pubkey: echd_public_key.to_bytes(),
        };

        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&challenge_handler)?);

        let handler_hash: [u8; 32] = hasher.finalize().into();

        let attestation = if !dev_mode {
            Some(
                ra.create_remote_attestation_report(
                    &handler_hash,
                    &self.pccs_url,
                    Duration::from_secs(self.ra_timeout),
                )
                .await?,
            )
        } else {
            info!("dev mode does not need remote attestation");
            None
        };

        Ok(HandoverChallengeResponse {
            challenge_handler,
            attestation,
        })
    }

    /// 3rd step:[Server] Get response from client then verify it and encrypt secret data with ECDH key exchange.
    pub async fn handover_start(
        &mut self,
        secret_data: Vec<u8>,
        response: HandoverChallengeResponse,
        ra: &impl RemoteAttestation,
        contract: &impl ExternalStatusGet,
    ) -> Result<HandoverSecretData> {
        let dev_mode = self.dev_mode;

        // 1. verify client RA report to ensure it's in sgx
        // this also ensure the message integrity
        let challenge_handler = response.challenge_handler;
        let (client_mrenclave, client_mrsigner) = if !dev_mode && response.attestation.is_some() {
            let mut hasher = Sha256::new();
            hasher.update(serde_json::to_vec(&challenge_handler)?);
            let payload_hash: [u8; 32] = hasher.finalize().into();
            let remote_attestation_report = response.attestation.unwrap();
            let (pass, client_mrenclave, client_mrsigner) = ra.verify_remote_attestation_report(
                &payload_hash,
                remote_attestation_report.clone(),
            )?;
            if !pass {
                return Err(anyhow!("Verify client side remote attestation report failed!").into());
            }

            (client_mrenclave, client_mrsigner)
        } else {
            info!("dev mod, client remote attestion report check skip");
            ("".to_string(), "".to_string())
        };

        // 2. verify challenge validity to prevent replay attack
        let challenge = challenge_handler.challenge;
        // if !(self.handover_last_challenge.take().as_ref() == Some(&challenge)) {
        //     return Err(anyhow!("the challenge from client is invalid!").into());
        // }

        // 3. verify sgx local attestation report to ensure the handover justicar are on the same machine
        if !dev_mode {
            let recv_local_report = unsafe { crate::decode(&challenge_handler.sgx_local_report)? };
            crate::verify(recv_local_report)?;
        } else {
            info!("dev mode,client local attestation report check skip");
        }

        // 4. verify challenge block height and report timestamp
        // only challenge within 150 blocks (30 minutes) is accepted
        let current_block_number = contract.get_block_number().await?;
        let challenge_height = challenge.block_number;
        if !(challenge_height <= current_block_number
            && current_block_number - challenge_height <= 150)
        {
            //todo:return with error
            return Err(SgxError::CryptoError("The challenge is expired!".to_string()).into());
        }
        // 5. check both side version time, never handover to previous version of justicar
        if !dev_mode {
            //server side
            let my_la_report = {
                // target_info and reportdata not important, we just need the report metadata
                let target_info = crate::target_info().expect("should not fail in SGX; qed.");
                crate::report(&target_info, &[0; 64])?
            };

            let server_mrenclave_list = contract.get_mrenclave_update_block_number_map().await?;

            let server_mrenclave_record = server_mrenclave_list
                .get_key_value(&hex::encode_upper(my_la_report.body.mr_enclave.m));
            let server_mrsigner_list = contract.get_mrsigner_list().await?;
            let server_mrsigner_record_exsist =
                server_mrsigner_list.contains(&hex::encode_upper(my_la_report.body.mr_signer.m));
            if server_mrenclave_record.is_none() || !server_mrsigner_record_exsist {
                return Err(SgxError::InternalError(
                    "Server side justicar not allowed on contract!".to_string(),
                )
                .into());
            };

            //client side

            let client_mrenclave_list = contract.get_mrenclave_update_block_number_map().await?;
            let client_mrenclave_record = client_mrenclave_list.get_key_value(&client_mrenclave);
            let client_mrsigner_list = contract.get_mrsigner_list().await?;
            if client_mrenclave_record.is_none() || !client_mrsigner_list.contains(&client_mrsigner)
            {
                return Err(SgxError::InternalError(
                    "Server side justicar not allowed on contract!".to_string(),
                )
                .into());
            };

            if server_mrenclave_record.unwrap().1 > client_mrenclave_record.unwrap().1 {
                return Err(anyhow!(
                    "The version of justicar on the server is later than that on the client"
                )
                .into());
            }
        } else {
            info!("dev mod,client justicar blocknumber check skip");
        }

        // 6. Key exchange using remote attestation and ECDH
        let ecdh_pubkey = challenge_handler.ecdh_pubkey;
        let iv = utils::generate_random_byte::<12>();
        let (my_ecdh_secret_key, my_echd_public_key) = utils::gen_ecdh_key_pair();
        let client_ecdh_public_key = utils::convert_bytes_to_ecdh_public_key(ecdh_pubkey);
        let shared_secret_key =
            utils::echd_key_agreement(my_ecdh_secret_key, client_ecdh_public_key);

        let encrypted_data =
            utils::encrypt_secret_with_shared_key(&secret_data, &shared_secret_key, &iv)?;

        let encrypted_data_info = EncryptedDataInfo {
            ecdh_pubkey: *my_echd_public_key.as_bytes(),
            encrypted_data,
            iv,
            dev_mode,
        };

        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&encrypted_data_info)?);
        let encrypted_data_info_hash: [u8; 32] = hasher.finalize().into();

        let attestation = if !dev_mode {
            Some(
                ra.create_remote_attestation_report(
                    &encrypted_data_info_hash,
                    &self.pccs_url,
                    Duration::from_secs(self.ra_timeout),
                )
                .await?,
            )
        } else {
            info!("dev mod ,server remote attestion report check skip");
            None
        };

        Ok(HandoverSecretData {
            encrypted_data_info,
            attestation,
        })
    }
    /// 4th step:[Client] receieve the encrypted secret data and verify the remote attestation report from server side then decrypt it.
    pub async fn handover_receive(
        &mut self,
        request: HandoverSecretData,
        ra: &impl RemoteAttestation,
        contract: &impl ExternalStatusGet,
    ) -> Result<Vec<u8>> {
        let encrypted_data_info = request.encrypted_data_info;
        let server_attestation = request.attestation;
        let dev_mode = encrypted_data_info.dev_mode;
        // check the remote attestation report from server side
        if !dev_mode {
            let mut hasher = Sha256::new();
            hasher.update(serde_json::to_vec(&encrypted_data_info)?);
            let payload_hash: [u8; 32] = hasher.finalize().into();

            let raw_attestation =
                server_attestation.ok_or_else(|| anyhow!("Server attestation not found"))?;
            let (pass, server_mrenclave, server_mrsigner) =
                ra.verify_remote_attestation_report(&payload_hash, raw_attestation.clone())?;
            if !pass {
                return Err(anyhow!("server remote attestation report check failed").into());
            };

            let mrenclave_list = contract.get_mrenclave_update_block_number_map().await?;
            let mrsigner_list = contract.get_mrsigner_list().await?;
            //Check whether they are online at the same time
            let server_load_mrenclave_block_number = mrenclave_list.get(&server_mrenclave);
            if server_load_mrenclave_block_number.is_none()
                || !mrsigner_list.contains(&server_mrsigner)
            {
                return Err(anyhow!(
                    "Server load record not found,mrenclave :{:?}",
                    &server_mrenclave
                )
                .into());
            }
        } else {
            info!("dev mod,server remote attestion report check skip");
        }
        let encrypted_data = encrypted_data_info.encrypted_data;
        let server_ecdh_pubkey = encrypted_data_info.ecdh_pubkey;
        let my_ecdh_secret_key = self
            .ecdh_secret_key
            .take()
            .ok_or_else(|| SgxError::CryptoError("No secret key found".to_string()))?;
        let shared_secret = utils::echd_key_agreement(
            my_ecdh_secret_key,
            utils::convert_bytes_to_ecdh_public_key(server_ecdh_pubkey),
        );

        let secret_data = utils::decrypt_secret_with_shared_key(
            &encrypted_data,
            &shared_secret,
            &encrypted_data_info.iv,
        )?;

        self.ecdh_secret_key = None;
        self.echd_public_key = None;
        self.handover_last_challenge = None;

        Ok(secret_data)
    }
}

#[async_trait]
pub trait RemoteAttestation {
    async fn create_remote_attestation_report(
        &self,
        payload: &[u8],
        pccs_url: &str,
        ra_timeout: Duration,
    ) -> Result<Vec<u8>>;

    ///Only verify the legitimacy of the report and do not make any business judgments.
    ///Of course, you can do so if you want.
    fn verify_remote_attestation_report(
        &self,
        payload: &[u8],
        attestation_report: Vec<u8>,
    ) -> Result<(bool, String, String)>;
}
#[async_trait]
pub trait ExternalStatusGet {
    async fn get_block_number(&self) -> Result<u64>;
    async fn get_mrenclave_update_block_number_map(&self) -> Result<HashMap<String, u128>>;
    async fn get_mrsigner_list(&self) -> Result<Vec<String>>;
}

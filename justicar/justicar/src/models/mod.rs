pub(crate) mod args;
pub(crate) mod secret;
pub(crate) mod service;
use crate::utils::{
    bloom::Bloom,
    seal::Sealing,
    wallet::{generate_new_wallet, Wallet},
};
use anyhow::Result;
use eth::client::Eth;
use handover::handover::HandoverHandler;
use log::info;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::Mutex;

pub const REWARD_RECORD_FILE: &str = "reward_record.seal";
pub const RUNTIME_INFO_FILE: &str = "runtime_info.seal";

#[derive(Clone)]
pub struct CD2NState {
    pub handover_handler: Arc<Mutex<HandoverHandler>>,
    pub contract: Arc<Mutex<Eth>>,
    pub wallet: Arc<Mutex<Wallet>>,
    pub bloom: Arc<Mutex<Bloom>>,
    pub incentive_record_storage: Arc<Mutex<IncentiveRecordStorage>>,

    pub need_handover: Arc<Mutex<bool>>,
    pub rpc_url: String,
    pub contract_addr: String,
    pub runtime_info_storage_path: PathBuf,
}

pub struct RA;

impl CD2NState {
    pub async fn _new(
        dev_mode: bool,
        pccs_url: String,
        ra_timeout: u64,
        rpc_url: String,
        safe_storage_path: String,
        contract_addr: String,
    ) -> Result<Self> {
        let wallet = generate_new_wallet()?;
        Ok(CD2NState {
            handover_handler: Arc::new(Mutex::new(HandoverHandler::new(
                dev_mode, pccs_url, ra_timeout,
            ))),
            contract: Arc::new(Mutex::new(
                Eth::get_contract_conn(&rpc_url, contract_addr.clone(), wallet.mnemonic.clone())
                    .await?,
            )),
            wallet: Arc::new(Mutex::new(wallet)),
            bloom: Arc::new(Mutex::new(Bloom::create_bloom_filter(0.01, 100_000_000))),
            incentive_record_storage: Arc::new(Mutex::new(IncentiveRecordStorage(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(std::path::Path::new(&safe_storage_path).join(REWARD_RECORD_FILE))?,
            ))),
            need_handover: Arc::new(Mutex::new(true)),
            rpc_url,
            contract_addr,
            runtime_info_storage_path: std::path::Path::new(&safe_storage_path)
                .join(RUNTIME_INFO_FILE),
        })
    }
    pub async fn new_with_runtime_info_file(
        dev_mode: bool,
        pccs_url: String,
        ra_timeout: u64,
        rpc_url: String,
        safe_storage_path: String,
        contract_addr: String,
    ) -> Result<Self> {
        let wallet = generate_new_wallet()?;
        let mut state = CD2NState {
            handover_handler: Arc::new(Mutex::new(HandoverHandler::new(
                dev_mode, pccs_url, ra_timeout,
            ))),
            contract: Arc::new(Mutex::new(
                Eth::get_contract_conn(&rpc_url, contract_addr.clone(), wallet.mnemonic.clone())
                    .await?,
            )),
            wallet: Arc::new(Mutex::new(wallet)),
            bloom: Arc::new(Mutex::new(Bloom::create_bloom_filter(0.01, 100_000_000))),
            incentive_record_storage: Arc::new(Mutex::new(IncentiveRecordStorage(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(std::path::Path::new(&safe_storage_path).join(REWARD_RECORD_FILE))?,
            ))),
            need_handover: Arc::new(Mutex::new(true)),
            rpc_url: rpc_url.clone(),
            contract_addr: contract_addr.clone(),
            runtime_info_storage_path: std::path::Path::new(&safe_storage_path)
                .join(RUNTIME_INFO_FILE),
        };

        //recovery from runtime info file
        let data: secret::Secret = match state.runtime_info_storage_path.unseal_data() {
            Ok(data) => data,
            Err(e) => {
                if e.to_string().contains("No such file or directory") {
                    info!("[😅]runtime_info file not found,waiting for initialization!");
                    return Ok(state);
                } else {
                    return Err(e);
                }
            }
        };
        *state.wallet.lock().await = data.wallet.clone();
        *state.contract.lock().await =
            Eth::get_contract_conn(&rpc_url, contract_addr.clone(), data.wallet.mnemonic).await?;
        *state.need_handover.lock().await = data.need_handover;
        info!("[😀]State recovery from runtime info file successfully!");

        Ok(state)
    }
}

impl Sealing for PathBuf {
    fn seal_data<Sealable: ?Sized + serde::Serialize>(
        &mut self,
        data: &Sealable,
    ) -> std::result::Result<(), anyhow::Error> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(self)?;
        file.write_all(&serde_json::to_vec(data)?)?;

        Ok(())
    }

    fn unseal_data<T: serde::de::DeserializeOwned>(&mut self) -> Result<T> {
        let mut file = File::open(self)?;
        let mut local_buffer = Vec::new();

        file.read_to_end(&mut local_buffer)?;

        Ok(serde_json::from_slice(&local_buffer)?)
    }
}

pub struct IncentiveRecordStorage(File);
impl Sealing for IncentiveRecordStorage {
    fn seal_data<Sealable: ?Sized + serde::Serialize>(
        &mut self,
        seal_structure: &Sealable,
    ) -> Result<()> {
        self.0.set_len(0)?;
        self.0.seek(SeekFrom::Start(0))?;

        self.0.write_all(&serde_json::to_vec(seal_structure)?)?;

        Ok(())
    }

    fn unseal_data<T: serde::de::DeserializeOwned>(&mut self) -> Result<T> {
        self.0.flush()?;
        self.0.seek(std::io::SeekFrom::Start(0))?;

        let mut local_buffer = Vec::new();
        self.0.read_to_end(&mut local_buffer)?;
        if local_buffer.is_empty() {
            local_buffer = serde_json::to_vec(&service::RewardDatabase {
                users_supplier_map: HashMap::new(),
            })?;
        }

        Ok(serde_json::from_slice(&local_buffer)?)
    }
}

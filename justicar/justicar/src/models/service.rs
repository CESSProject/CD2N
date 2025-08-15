use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Serialize, Deserialize)]
pub struct SupplierDataAuditRequest {
    pub cid: String,
    pub user_acc: String,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub supplier_acc: String,
    pub data: Vec<u8>,
    pub request_id: String,
    pub user_sign: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SupplierDataAuditResponse {
    pub msg: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QueryInformationResponse {
    pub eth_address: String,
    pub secp256k1_public_key: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QueryDownloadTraffic {
    pub user_eth_address: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QueryDownloadTrafficResponse {
    pub user_eth_address: String,
    pub left_user_download_traffic: i64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TestEcho {
    pub key: String,
    pub value: String,
    pub reward: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TestEchoResponse {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SupplierReward {
    pub total_reward: i64,
    pub last_updated_block_number: u64,
}

//"user_acc":{"supplier_acc":{"total_reward":100,"last_updated":"15463"}...}
//when key "supplier_acc" is 0x0000000000000000000000000000000000000000,get value record the number of the user used traffic.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RewardDatabase {
    pub users_supplier_map: HashMap<String, HashMap<String, SupplierReward>>,
}

impl Default for RewardDatabase {
    fn default() -> Self {
        RewardDatabase {
            users_supplier_map: HashMap::new(),
        }
    }
}
pub const TOTAL_USER_USED_TRAFFIC: &str = "0x0000000000000000000000000000000000000000";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HandoverStatus {
    pub handover_over: bool,
}

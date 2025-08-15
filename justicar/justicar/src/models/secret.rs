use super::{service::RewardDatabase, CD2NState};
use crate::utils::{seal::Sealing, wallet::Wallet};
use anyhow::Result;
use eth::client::Eth;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Secret {
    pub wallet: Wallet,
    pub need_handover: bool,
    pub reward_database: RewardDatabase,
}

pub async fn secret_from_cdn_state(cdn: CD2NState) -> Result<Secret> {
    let reward_database: RewardDatabase =
        cdn.incentive_record_storage.lock().await.unseal_data()?;

    let wallet = cdn.wallet.lock().await.clone();
    let need_handover = cdn.need_handover.lock().await.clone();
    Ok(Secret {
        wallet,
        need_handover,
        reward_database,
    })
}

pub async fn secret_to_cdn_state(secret: Secret, cdn: &mut CD2NState) -> Result<()> {
    //update wallet and contract info into cdn state
    {
        let mut wallet_guard = cdn.wallet.lock().await;
        *wallet_guard = secret.wallet.clone();
    }
    {
        let mut contract_guard = cdn.contract.lock().await;
        *contract_guard = Eth::get_contract_conn(
            &cdn.rpc_url,
            cdn.contract_addr.clone(),
            secret.wallet.mnemonic.clone(),
        )
        .await?;
    }
    {
        let mut need_handover_guard = cdn.need_handover.lock().await;
        *need_handover_guard = secret.need_handover;
    }
    Ok(())
}

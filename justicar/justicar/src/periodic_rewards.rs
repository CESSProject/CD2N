/// This module is responsible for periodically distributing rewards to traffic suppliers.
use crate::models::{
    service::{RewardDatabase, TOTAL_USER_USED_TRAFFIC},
    IncentiveRecordStorage,
};
use crate::utils::seal::Sealing;
use anyhow::{Context, Result};
use eth::{client::Eth, interact_contract::ContractInteract};
use log::{debug, info};
use std::sync::Arc;
use tokio::sync::Mutex;

pub async fn periodic_rewards(
    block_interval: u64,
    incentive_storage: Arc<Mutex<IncentiveRecordStorage>>,
    contract: Arc<Mutex<Eth>>,
    need_handover: Arc<Mutex<bool>>,
) -> Result<()> {
    let incentive_storage_clone = incentive_storage.clone();

    while need_handover.lock().await.clone() {
        debug!("[⏳]The program has not yet completed the secret handover, waiting...");
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }

    let contract = contract.lock().await.clone();
    loop {
        contract
            .subscribe_block_numbers_amount(block_interval as usize)
            .await?;
        info!("[🎬]Traffic reward releasing...");

        let mut guard = incentive_storage_clone.lock().await;
        let reward_record: RewardDatabase = guard
            .unseal_data()
            .context("Unsealing the incentive record failed when going to distribute rewards!")?;

        for (user_acc, supplier_records) in reward_record.users_supplier_map.iter() {
            for (supplier_acc, supplier_info) in supplier_records.iter() {
                if !supplier_acc.eq(TOTAL_USER_USED_TRAFFIC) {
                    contract
                        .incentive_release(user_acc, supplier_acc, supplier_info.total_reward)
                        .await?;
                    info!("The traffic supllier {:?} reward from the user {:?} has been released successfully!",supplier_acc,user_acc);
                }

                //every time successfully rewarded, remove the supplier record and update into incentive record storage.
                let mut supplier_owned_clone = supplier_records.to_owned().clone();
                if let Some(removed_reward_record) = supplier_owned_clone.remove(supplier_acc) {
                    info!(
                        "The traffic supplier {:?} has been rewarded with {} traffic, and the reward record has been removed.",
                        supplier_acc, removed_reward_record.total_reward
                    );
                };

                let mut reward_record_clone = reward_record.clone();
                reward_record_clone
                    .users_supplier_map
                    .insert(user_acc.to_string(), supplier_owned_clone);

                guard
                    .seal_data(&reward_record_clone)
                    .context("Sealing the incentive record failed after the traffic supplier reward was distributed!")?;
            }
        }
        //reset the reward record file after all the rewards have been distributed.
        let reset_all_record = RewardDatabase::default();
        guard.seal_data(&reset_all_record).context("Reset the incentive record failed after the all traffic supplier reward was distributed!")?;

        info!("[🎊]Traffic reward released successfully!");
    }
}

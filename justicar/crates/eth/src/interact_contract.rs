#[cfg(feature = "contract-interact")]
use crate::client::Eth;
use crate::error::ContractResult as Result;
use alloy::{
    hex,
    primitives::{Address, U256},
    providers::Provider,
};
use anyhow::{anyhow, Context};
use async_trait::async_trait;

#[cfg(feature = "contract-interact")]
#[async_trait]
pub trait ContractInteract {
    //For internal operate
    async fn get_current_block_number(&self) -> Result<u64>;
    async fn get_mrenclave_list(&self) -> Result<Vec<String>>;
    async fn get_mrsigner_list(&self) -> Result<Vec<String>>;
    async fn get_update_block_number(&self) -> Result<Vec<u128>>;

    //For business
    async fn get_user_total_traffic(
        &self,
        cdn_wallet_address: &str,
        user_wallet_address: &str,
    ) -> Result<i64>;
    async fn incentive_release(
        &self,
        user_wallet_address: &str,
        supplier_wallet_address: &str,
        traffic: i64,
    ) -> Result<String>;

    async fn add_mrenclave(&self, mrenclave: &str) -> Result<String>;
}

#[cfg(feature = "contract-interact")]
#[async_trait]
impl ContractInteract for Eth {
    async fn get_current_block_number(&self) -> Result<u64> {
        Ok(self
            .cdn_contract
            .clone()
            .ok_or_else(|| {
                anyhow!("get_current_block_number failed: Please init cdn_contract first!")
            })?
            .provider()
            .get_block_number()
            .await
            .context("Get block chain current block number failed")?)
    }
    async fn get_mrenclave_list(&self) -> Result<Vec<String>> {
        Ok(self
            .cdn_contract
            .clone()
            .ok_or_else(|| anyhow!("get_mrenclave_list failed: Please init cdn_contract first!"))?
            .getAllMREnclaveList()
            .call()
            .await
            .context("Get MrEnclaveList from contract failed")?
            ._0)
    }
    async fn get_mrsigner_list(&self) -> Result<Vec<String>> {
        Ok(self
            .cdn_contract
            .clone()
            .ok_or_else(|| anyhow!("get_mrsigner_list failed: Please init cdn_contract first!"))?
            .getAllMRSignerList()
            .call()
            .await
            .context("Get MRSignerList from contract failed")?
            ._0)
    }
    async fn get_update_block_number(&self) -> Result<Vec<u128>> {
        let update_block_number = self
            .cdn_contract
            .clone()
            .ok_or_else(|| {
                anyhow!("get_update_block_number failed: Please init cdn_contract first!")
            })?
            .getAllUpdateBlockNumber()
            .call()
            .await
            .context("Get UpdateBlockNumber vec from contract failed")?
            ._0;

        let mut update_block_number_list = Vec::new();
        for i in 0..update_block_number.len() {
            update_block_number_list.push(update_block_number[i].to::<u128>());
        }

        Ok(update_block_number_list)
    }

    //Get user traffic by user eth wallet address
    async fn get_user_total_traffic(
        &self,
        cdn_wallet_address: &str,
        user_wallet_address: &str,
    ) -> Result<i64> {
        //todo
        let cdn_wallet_address =
            Address::parse_checksummed(cdn_wallet_address, None).context("valid checksum")?;

        let user_wallet_address: &str = if !user_wallet_address.starts_with("0x") {
            &format!("0x{}", user_wallet_address)
        } else {
            user_wallet_address
        };

        let user_wallet_address =
            Address::parse_checksummed(user_wallet_address, None).context("valid checksum wh")?;

        let user_traffic = self
            .cdn_contract
            .clone()
            .ok_or_else(|| {
                anyhow!("get_update_block_number failed: Please init cdn_contract first!")
            })?
            .UserTrafficMap(user_wallet_address, cdn_wallet_address)
            .call()
            .await
            .context("Get UpdateBlockNumber vec from contract failed")?
            ._0
            .to::<i64>();

        Ok(user_traffic)
    }

    async fn incentive_release(
        &self,
        user_wallet_address: &str,
        supplier_wallet_address: &str,
        traffic: i64,
    ) -> Result<String> {
        let user_wallet_address: &str = if !user_wallet_address.starts_with("0x") {
            &format!("0x{}", user_wallet_address)
        } else {
            user_wallet_address
        };
        let supplier_wallet_address: &str = if !supplier_wallet_address.starts_with("0x") {
            &format!("0x{}", supplier_wallet_address)
        } else {
            supplier_wallet_address
        };
        let user_wallet_address =
            Address::parse_checksummed(user_wallet_address, None).context("valid checksum")?;
        let supplier_wallet_address =
            Address::parse_checksummed(supplier_wallet_address, None).context("valid checksum")?;

        let tx_hash = self
            .cdn_contract
            .clone()
            .ok_or_else(|| {
                anyhow!("get_update_block_number failed: Please init cdn_contract first!")
            })?
            .trafficForwarding(
                user_wallet_address,
                supplier_wallet_address,
                U256::from(traffic),
            )
            .send()
            .await
            .map_err(|e| anyhow!("incentive_release failed: {}", e))?
            .tx_hash()
            .0;

        Ok(hex::encode(tx_hash))
    }

    async fn add_mrenclave(&self, mrenclave: &str) -> Result<String> {
        let tx_hash = self
            .cdn_contract
            .clone()
            .ok_or_else(|| {
                anyhow!("send add_mrenclave tx failed: Please init cdn_contract first!")
            })?
            .addMREnclave(mrenclave.to_string())
            .send()
            .await
            .context("add mrenclave failed")?
            .tx_hash()
            .0;
        Ok(hex::encode(tx_hash))
    }
}

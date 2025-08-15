use crate::error::ContractResult as Result;
use alloy::{
    hex::FromHex,
    network::EthereumWallet,
    primitives::Address,
    providers::{Provider, ProviderBuilder, WsConnect},
    signers::local::{coins_bip39::English, MnemonicBuilder},
    sol,
};
use anyhow::{anyhow, Context};
use log::info;
use CDN::CDNInstance;
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CDN,
    "abi/Cd2n.json"
);
use futures_util::StreamExt;

pub(crate) type CDNContract = CDNInstance<
    alloy::pubsub::PubSubFrontend,
    alloy::providers::fillers::FillProvider<
        alloy::providers::fillers::JoinFill<
            alloy::providers::fillers::JoinFill<
                alloy::providers::Identity,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::GasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::BlobGasFiller,
                        alloy::providers::fillers::JoinFill<
                            alloy::providers::fillers::NonceFiller,
                            alloy::providers::fillers::ChainIdFiller,
                        >,
                    >,
                >,
            >,
            alloy::providers::fillers::WalletFiller<EthereumWallet>,
        >,
        alloy::providers::RootProvider<alloy::pubsub::PubSubFrontend>,
        alloy::pubsub::PubSubFrontend,
        alloy::network::Ethereum,
    >,
>;
#[derive(Clone)]
pub struct Eth {
    pub(crate) cdn_contract: Option<CDNContract>,
}

impl Eth {
    pub async fn get_contract_conn(
        rpc_url: &str,
        contract_addr: String,
        mnemonic: String,
    ) -> Result<Self> {
        let ws = WsConnect::new(rpc_url);
        let signer = MnemonicBuilder::<English>::default()
            .phrase(mnemonic.clone())
            .index(0)
            .context("local signer creation failed")?
            .password("")
            .build()
            .context("build wallet from mnemonic failed")?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet)
            .on_ws(ws)
            .await?;

        let cdn_contract = Some(CDN::new(
            Address::from_hex(contract_addr)
                .context("Invalid contract address parameter passing")?,
            provider,
        ));
        Ok(Self { cdn_contract })
    }

    pub async fn subscribe_block_numbers_amount(&self, amount: usize) -> Result<()> {
        let mut stream = self
            .cdn_contract
            .clone()
            .ok_or_else(|| {
                anyhow!("subscribe_block_numbers failed: Please init cdn_contract first!")
            })?
            .provider()
            .subscribe_blocks()
            .await?
            .into_stream()
            .take(amount);

        while let Some(block) = stream.next().await {
            info!("[⛓️ ] Received block number: {}", block.header.number);
        }

        Ok(())
    }
}

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Args {
    #[arg(
        default_value = "https://dcap-sgp-dev.cess.cloud/sgx/certification/v4/",
        long = "pccs-url",
        help = "PCCS service URL required for Intel DCAP attestation."
    )]
    pub pccs_url: String,

    #[arg(
        default_value = "300",
        long = "ra-timeout",
        help = "The timeout for request Intel DCAP attestation service in seconds."
    )]
    pub ra_timeout: u64,

    #[arg(
        default_value = "ws://127.0.0.1:9944",
        long = "chain-rpc",
        help = "RPC node for connect chain."
    )]
    pub chain_rpc: String,

    #[arg(default_value = "1309", long = "port", help = "CD2N Tee node port.")]
    pub port: u64,

    #[arg(
        default_value = "/data/seal_data",
        long = "safe_storage_path",
        help = "Paths where some file contents that need to be protected by TEE storage path.To change the default settings, you must first check the template file."
    )]
    pub safe_storage_path: String,

    #[arg(
        default_value = "30",
        long = "reward_block_interval",
        help = "After how many blocks, rewards will be sent to traffic providers."
    )]
    pub reward_block_interval: u64,

    #[arg(
        default_value = "false",
        long = "dev-mode",
        help = "development mode for testing."
    )]
    pub dev_mode: bool,
}

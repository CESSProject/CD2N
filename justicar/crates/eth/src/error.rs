pub type ContractResult<T> = std::result::Result<T, EthError>;

#[derive(Debug, thiserror::Error)]
pub enum EthError {
    #[error("Connect with rpc failed: {0}")]
    RpcError(#[from] alloy::transports::TransportError),

    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Internal Error: {0}")]
    InternalError(#[from] anyhow::Error),
}

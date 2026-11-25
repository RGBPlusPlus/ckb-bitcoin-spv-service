use std::fmt;

use jsonrpc_core::{Error as RpcError, ErrorCode as RpcErrorCode};

#[repr(i64)]
pub enum ApiErrorCode {
    // Bitcoin: 21xxx
    BitcoinTxOutProofInvalid = 21101,
    // Storage: 23xxx
    StorageTxTooNew = 23101,
    StorageTxUnconfirmed,
    StorageHeaderMissing = 23301,
    StorageHeaderUnmatched,
    // Onchain: 25xxx
    OnchainTxUnconfirmed = 25101,
    OnchainClientSpent,
    OnchainReorgRequired = 25901,
}

impl ApiErrorCode {
    pub fn with_desc<D: fmt::Display>(self, desc: D) -> RpcError {
        RpcError {
            code: RpcErrorCode::ServerError(self as i64),
            message: desc.to_string(),
            data: None,
        }
    }
}

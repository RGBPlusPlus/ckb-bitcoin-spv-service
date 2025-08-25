//! A bitcoin client to communicate with a Bitcoin chain.

use bitcoin::{consensus::deserialize, MerkleBlock, Txid};
use faster_hex::hex_decode;
use jsonrpc_core::{Error as RpcError, ErrorCode as RpcErrorCode};
use reqwest::blocking::Client;
use url::Url;

use crate::result::{BtcRpcError, BtcRpcResult};

pub struct ElectrsClient {
    client: Client,
    endpoint: Url,
}

impl Clone for ElectrsClient {
    fn clone(&self) -> Self {
        Self::new(self.endpoint.clone())
    }
}

/// Implement simple JSON-RPC methods.
impl ElectrsClient {
    pub fn new(endpoint: Url) -> Self {
        let client = Client::new();
        Self { client, endpoint }
    }

    pub fn get_raw_tx_out_proof(&self, txid: Txid) -> BtcRpcResult<Vec<u8>> {
        let resp = self.client
            .get(self.endpoint.join(&format!("tx/{txid}/merkleblock-proof")).unwrap())
            .send()?;
        let hex = resp.text()?;


        let mut bin = vec![0; hex.len() / 2];
        hex_decode(hex.as_bytes(), &mut bin).map_err(|err| {
            let error = RpcError {
                code: RpcErrorCode::ParseError,
                message: format!("failed to decode the hex string \"{hex}\" since {err}"),
                data: None,
            };
            <RpcError as Into<BtcRpcError>>::into(error)
        })?;
        Ok(bin)
    }

    pub fn get_tx_out_proof(&self, txid: Txid) -> BtcRpcResult<(MerkleBlock, Vec<u8>)> {
        self.get_raw_tx_out_proof(txid).and_then(|bin| {
            deserialize(&bin)
                .map_err(|err| {
                    let error = RpcError {
                        code: RpcErrorCode::ParseError,
                        message: format!(
                            "failed to deserialize tx out proof from hex string since {err}"
                        ),
                        data: None,
                    };
                    error.into()
                })
                .map(|mb| (mb, bin))
        })
    }
}

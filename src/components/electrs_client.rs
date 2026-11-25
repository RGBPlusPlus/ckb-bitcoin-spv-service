//! A bitcoin client to communicate with a Bitcoin chain.

use bitcoin::{consensus::deserialize, MerkleBlock, Txid};
use faster_hex::hex_decode;
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
        let resp = self
            .client
            .get(
                self.endpoint
                    .join(&format!("tx/{txid}/merkleblock-proof"))
                    .unwrap(),
            )
            .send()?;
        let hex = resp.error_for_status()?.text()?;

        let mut bin = vec![0; hex.len() / 2];
        hex_decode(hex.as_bytes(), &mut bin).map_err(|err| {
            BtcRpcError::TxOutProof(format!(
                "failed to decode the hex string \"{hex}\" since {err}"
            ))
        })?;
        Ok(bin)
    }

    pub fn get_tx_out_proof(&self, txid: Txid) -> BtcRpcResult<(MerkleBlock, Vec<u8>)> {
        self.get_raw_tx_out_proof(txid).and_then(|bin| {
            deserialize(&bin)
                .map_err(|err| {
                    BtcRpcError::TxOutProof(format!("failed to deserialize since {err}"))
                })
                .map(|mb| (mb, bin))
        })
    }
}

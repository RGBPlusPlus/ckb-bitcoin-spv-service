//! JSON-RPC APIs service.

use std::{net::SocketAddr, sync::RwLock, time::SystemTime};

use bitcoin::{MerkleBlock, Txid};
use ckb_bitcoin_spv_verifier::{
    error::VerifyTxError,
    types::{
        core::{Bytes, Hash, HeaderDigest, SpvClient},
        packed,
        prelude::*,
    },
};
use ckb_jsonrpc_types::{JsonBytes, OutPoint};
use jsonrpc_core::{Error as RpcError, ErrorCode as RpcErrorCode, IoHandler, Result as RpcResult};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::{Server, ServerBuilder};
use jsonrpc_server_utils::{cors::AccessControlAllowOrigin, hosts::DomainsValidation};
use serde::Serialize;

use crate::{
    components::{SpvClientCell, SpvInstance, SpvService},
    prelude::*,
    result::{BtcRpcError, Error, Result},
};

use super::sync_status::SyncStatus;

mod error;

pub use error::ApiErrorCode;

// Bitcoin target block time is 10 minutes.
const SPV_INSTANCE_CACHED_SECS: u64 = 60 * 10;

pub struct ApiServiceConfig {
    listen_address: SocketAddr,
}

#[derive(Serialize, Clone)]
pub struct BitcoinTxProof {
    pub(crate) spv_client: OutPoint,
    pub(crate) proof: JsonBytes,
}

#[rpc(server)]
pub trait SpvRpc {
    #[rpc(name = "getSyncStatus")]
    fn get_sync_status(&self) -> RpcResult<SyncStatus>;

    #[rpc(name = "getTxProof")]
    fn get_tx_proof(
        &self,
        tx_hash: Txid,
        tx_index: u32,
        confirmations: u32,
    ) -> RpcResult<BitcoinTxProof>;
}

pub struct SpvRpcImpl {
    spv_service: SpvService,
    cached_spv_instance: RwLock<Option<CachedSpvInstance>>,
}

#[derive(Clone)]
struct CachedSpvInstance {
    instance: SpvInstance,
    expired_timestamp: u64,
}

impl ApiServiceConfig {
    pub fn new(listen_address: SocketAddr) -> Self {
        Self { listen_address }
    }

    pub fn start(&self, spv_service: SpvService) -> Result<Server> {
        log::info!("Starting the JSON-RPC service ...");
        let mut io_handler = IoHandler::new();
        let spv_rpc_impl = SpvRpcImpl::new(spv_service);
        io_handler.extend_with(spv_rpc_impl.to_delegate());

        ServerBuilder::new(io_handler)
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Null,
                AccessControlAllowOrigin::Any,
            ]))
            .health_api(("/ping", "ping"))
            .start_http(&self.listen_address)
            .map_err(Error::other)
    }
}

/// Whether local storage holds the headers an SPV client commits to.
///
/// Storage keeps headers of a rolled-back branch above its tip, so comparing
/// MMR roots alone can match a stale client whose headers proofs then fail.
fn storage_contains(spv: &SpvService, root: &HeaderDigest) -> RpcResult<bool> {
    spv.storage_contains(root).map_err(|err| {
        let message = format!(
            "failed to check headers MMR root for height {}",
            root.max_height
        );
        log::error!("{message} since {err}");
        RpcError {
            code: RpcErrorCode::InternalError,
            message,
            data: None,
        }
    })
}

fn invalid_tx_out_proof(txid: Txid, reason: impl std::fmt::Display) -> RpcError {
    let desc = format!(
        "the tx out proof for {txid:#x} from the Bitcoin node or Electrs is invalid: {reason}"
    );
    log::error!("{desc}");
    ApiErrorCode::BitcoinTxOutProofInvalid.with_desc(desc)
}

/// Checks that a tx out proof from remote is valid and proves the transaction,
/// and returns the index of the transaction in the block.
fn proven_tx_index(merkle_block: &MerkleBlock, txid: Txid) -> RpcResult<u32> {
    let mut matches = Vec::new();
    let mut indexes = Vec::new();
    merkle_block
        .extract_matches(&mut matches, &mut indexes)
        .map_err(|err| invalid_tx_out_proof(txid, err))?;
    matches
        .into_iter()
        .zip(indexes)
        .find_map(|(id, index)| (id == txid).then_some(index))
        .ok_or_else(|| invalid_tx_out_proof(txid, "it doesn't contain the transaction"))
}

/// Checks the index from the caller against the proven one.
///
/// Only meaningful once the block is known to be on the local chain: the index
/// may differ in a block of a stale branch.
fn check_tx_index(txid: Txid, tx_index: u32, proven_index: u32) -> RpcResult<()> {
    if tx_index == proven_index {
        return Ok(());
    }
    let message = format!("{txid:#x} is not the transaction at index {tx_index} in its block");
    log::warn!("{message}");
    Err(RpcError {
        code: RpcErrorCode::InvalidParams,
        message,
        data: None,
    })
}

/// Verifies a generated proof against the SPV client as the contract would.
///
/// Storage may roll back to another branch between choosing the client and
/// generating the headers proof; such a proof must not be returned.
fn check_tx_proof(
    client: &SpvClient,
    txid: Txid,
    tx_proof: &packed::TransactionProof,
    confirmations: u32,
) -> RpcResult<()> {
    let spv_client: packed::SpvClient = client.pack();
    let Err(err) =
        spv_client.verify_transaction(txid.as_ref(), tx_proof.as_reader(), confirmations)
    else {
        return Ok(());
    };
    let code = err as i8;
    let error = if code == VerifyTxError::HeaderMmrProof as i8 {
        let desc = "local storage changed while generating the proof, please retry";
        ApiErrorCode::StorageHeaderUnmatched.with_desc(desc)
    } else {
        RpcError {
            code: RpcErrorCode::InternalError,
            message: format!(
                "the generated proof for {txid:#x} fails verification \
                (verifier error code {code:#04x})"
            ),
            data: None,
        }
    };
    log::warn!("{}", error.message);
    Err(error)
}

impl SpvRpcImpl {
    pub fn new(spv_service: SpvService) -> Self {
        Self {
            spv_service,
            cached_spv_instance: RwLock::new(None),
        }
    }

    fn load_spv_instance(
        &self,
        stg_tip_height: u32,
        target_confirmed_height: u32,
    ) -> Result<Option<SpvInstance>> {
        let spv_instance = match self.load_cache_spv_instance() {
            Some(instance) => instance,
            None => return Ok(None),
        };

        let spv_client_cell =
            spv_instance.find_best_spv_client_not_greater_than_height(stg_tip_height)?;

        let spv_header_root = &spv_client_cell.client.headers_mmr_root;
        let spv_best_height = spv_header_root.max_height;

        if spv_best_height < target_confirmed_height {
            return Ok(None);
        }

        Ok(Some(spv_instance))
    }

    /// Chooses an SPV client whose cell is still live: the cache or the CKB
    /// Indexer may lag behind a rotation of the clients, and a spent cell cannot
    /// be used as a cell dep.
    fn select_live_client(
        &self,
        spv_instance: &SpvInstance,
        stg_tip_height: u32,
        target_height: u32,
        confirmations: u32,
    ) -> RpcResult<SpvClientCell> {
        let cell =
            self.select_spv_client(spv_instance, stg_tip_height, target_height, confirmations)?;
        let out_point = cell.cell.out_point.clone();
        let status = tokio::task::block_in_place(|| {
            self.spv_service
                .ckb_cli
                .get_live_cell(out_point.into(), false)
        })
        .map_err(|err| {
            let message = "failed to check whether the SPV client cell is live".to_owned();
            log::error!("{message} since {err}");
            RpcError {
                code: RpcErrorCode::InternalError,
                message,
                data: None,
            }
        })?
        .status;
        if status != "live" {
            let desc = format!("the SPV client cell is {status}, please retry");
            log::warn!("{desc}");
            return Err(ApiErrorCode::OnchainClientSpent.with_desc(desc));
        }
        Ok(cell)
    }

    fn fetch_spv_instance(
        &self,
        spv_type_script: ckb_types::packed::Script,
        stg_tip_height: u32,
    ) -> RpcResult<SpvInstance> {
        let spv = &self.spv_service;
        let spv_instance = tokio::task::block_in_place(|| -> RpcResult<SpvInstance> {
            spv.ckb_cli.find_spv_cells(spv_type_script).map_err(|err| {
                let message =
                    format!("failed to get SPV cell base on height {stg_tip_height} from chain");
                log::error!("{message} since {err}");
                RpcError {
                    code: RpcErrorCode::InternalError,
                    message,
                    data: None,
                }
            })
        })?;
        log::debug!(">>> the fetched SPV instance is {spv_instance}");
        self.update_spv_instance(spv_instance.clone());
        Ok(spv_instance)
    }

    /// Chooses the SPV client to prove a transaction in header#`target_height`
    /// with `confirmations` against.
    fn select_spv_client(
        &self,
        spv_instance: &SpvInstance,
        stg_tip_height: u32,
        target_height: u32,
        confirmations: u32,
    ) -> RpcResult<SpvClientCell> {
        let spv = &self.spv_service;
        // First Strategy: find the best SPV client not greater than the storage tip height.
        // The spv client found has the longest lifetime and
        // is most likely to cover the height of the block where the bitcoin tx is located.
        // The downside is that it can be affected by reorg.
        let mut spv_client_cell = spv_instance
            .find_best_spv_client_not_greater_than_height(stg_tip_height)
            .map_err(|err| {
                let message = format!(
                    "failed to get SPV cell base on height {stg_tip_height} from fetched data"
                );
                log::error!("{message} since {err}");
                RpcError {
                    code: RpcErrorCode::InternalError,
                    message,
                    data: None,
                }
            })?;

        log::debug!(">>> the best SPV client is {}", spv_client_cell.client);

        let spv_header_root = &spv_client_cell.client.headers_mmr_root;

        let spv_best_height = spv_header_root.max_height;
        if spv_best_height < target_height + confirmations {
            let desc = format!(
                "target transaction is in header#{target_height} \
                and it requires {confirmations} confirmations, \
                but the best SPV header is header#{spv_best_height}",
            );
            return Err(ApiErrorCode::OnchainTxUnconfirmed.with_desc(desc));
        }

        if !storage_contains(spv, spv_header_root)? {
            log::warn!("[onchain] header#{spv_best_height}; mmr-root {spv_header_root}");
            let desc = "Strategy 1 failed to find a valid SPV client due to reorg, switching to strategy 2 for further lookup";
            log::warn!("{desc}");

            // Second Strategy: walk from the tip towards older clients and take
            // the newest one storage still holds. During a reorg that is the
            // checkpoint shared with the storage branch; older clients cover
            // even fewer headers, so if it is too low, every older one is too.
            let contained = spv.newest_contained_client(spv_instance).map_err(|err| {
                let message = "failed to find an SPV client storage holds".to_owned();
                log::error!("{message} since {err}");
                RpcError {
                    code: RpcErrorCode::InternalError,
                    message,
                    data: None,
                }
            })?;
            let Some(cell) = contained else {
                let desc = "the SPV instance on chain is unknown, reorg is required";
                log::warn!("{desc}");
                return Err(ApiErrorCode::OnchainReorgRequired.with_desc(desc));
            };
            spv_client_cell = cell;
            log::debug!(
                ">>> the best SPV client storage holds is {}",
                spv_client_cell.client
            );

            let spv_best_height = spv_client_cell.client.headers_mmr_root.max_height;
            if spv_best_height < target_height + confirmations {
                let desc = format!(
                    "target transaction is in header#{target_height} \
                    and it requires {confirmations} confirmations, \
                    but the best SPV header storage holds is header#{spv_best_height}",
                );
                return Err(ApiErrorCode::OnchainTxUnconfirmed.with_desc(desc));
            }
        }

        Ok(spv_client_cell)
    }

    fn load_cache_spv_instance(&self) -> Option<SpvInstance> {
        if let Some(cached) = self
            .cached_spv_instance
            .read()
            .ok()
            .and_then(|locked| locked.as_ref().cloned())
        {
            if let Ok(dur) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                let current_timestamp = dur.as_secs();
                if current_timestamp > cached.expired_timestamp {
                    log::trace!(
                        "cached SPV instance is expired, expired at {}, now is {current_timestamp}",
                        cached.expired_timestamp
                    );
                    None
                } else {
                    log::trace!(
                        "cached SPV instance is loaded, will be expired at {}, now is {current_timestamp}",
                        cached.expired_timestamp
                    );
                    Some(cached.instance)
                }
            } else {
                log::warn!("failed to read current timestamp for load the cached SPV instance");
                None
            }
        } else {
            log::debug!("failed to load cached SPV instance: not existed or lock error");
            None
        }
    }

    fn update_spv_instance(&self, instance: SpvInstance) {
        match self.cached_spv_instance.write() {
            Ok(mut locked) => {
                if let Ok(dur) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                    let current_timestamp = dur.as_secs();
                    let expired_timestamp = current_timestamp + SPV_INSTANCE_CACHED_SECS;
                    let cache = CachedSpvInstance {
                        instance,
                        expired_timestamp,
                    };
                    *locked = Some(cache);
                    log::debug!(
                        "refreshed the cached SPV instance, it will be expired at {expired_timestamp}, \
                        now is {current_timestamp}",
                    );
                } else {
                    log::warn!(
                        "failed to read current timestamp for update the cached SPV instance"
                    );
                }
            }
            Err(err) => {
                log::debug!("failed to update the cached SPV instance since {err}");
            }
        }
    }
}

impl SpvRpc for SpvRpcImpl {
    fn get_sync_status(&self) -> RpcResult<SyncStatus> {
        Ok(self.spv_service.sync_status.snapshot())
    }

    fn get_tx_proof(
        &self,
        txid: Txid,
        tx_index: u32,
        confirmations: u32,
    ) -> RpcResult<BitcoinTxProof> {
        log::debug!("Call getTxProof with params [{txid:#x}, {confirmations}]");
        let spv = &self.spv_service;

        let (target_height, target_hash, proven_index, raw_tx_out_proof) =
            tokio::task::block_in_place(|| -> RpcResult<(u32, Hash, u32, Vec<u8>)> {
                let req = if let Some(electrs) = &spv.electrs_cli {
                    electrs.get_tx_out_proof(txid)
                } else {
                    spv.btc_cli.get_tx_out_proof(txid)
                };

                let (merkle_block, raw_tx_out_proof) = req.map_err(|err| {
                    if let BtcRpcError::TxOutProof(reason) = &err {
                        return invalid_tx_out_proof(txid, reason);
                    }
                    let message = format!("failed to get tx out proof for {txid:#x} from remote");
                    log::error!("{message} since {err}");
                    RpcError {
                        code: RpcErrorCode::InternalError,
                        message,
                        data: None,
                    }
                })?;
                let proven_index = proven_tx_index(&merkle_block, txid)?;
                let block_hash = merkle_block.header.block_hash();
                log::trace!(">>> the input tx in header {block_hash:#x}");
                let block_height = spv.btc_cli.get_block_height(block_hash).map_err(|err| {
                    let message =
                        format!("failed to get block height for {block_hash:#x} from remote");
                    log::error!("{message} since {err}");
                    RpcError {
                        code: RpcErrorCode::InternalError,
                        message,
                        data: None,
                    }
                })?;
                log::trace!(">>> the input tx in header {block_height}");
                Ok((
                    block_height,
                    block_hash.into(),
                    proven_index,
                    raw_tx_out_proof,
                ))
            })?;

        let (stg_tip_height, _) = spv.storage.tip_state().map_err(|err| {
            let message = "failed to read tip bitcoin height from local storage".to_owned();
            log::error!("{message} since {err}");
            RpcError {
                code: RpcErrorCode::InternalError,
                message,
                data: None,
            }
        })?;
        log::debug!(">>> tip height in local storage is {stg_tip_height}");

        if stg_tip_height < target_height {
            let desc = format!(
                "target transaction is in header#{target_height}, \
                but the tip header in local storage is header#{stg_tip_height}"
            );
            return Err(ApiErrorCode::StorageTxTooNew.with_desc(desc));
        }
        if stg_tip_height < target_height + confirmations {
            let desc = format!(
                "target transaction is in header#{target_height} \
                and it requires {confirmations} confirmations, \
                but the tip header in local storage is header#{stg_tip_height}"
            );
            return Err(ApiErrorCode::StorageTxUnconfirmed.with_desc(desc));
        }
        let stg_target_hash = spv
            .storage
            .bitcoin_header_hash(target_height)
            .map_err(|err| {
                let desc = format!("local storage doesn't have header#{target_height}");
                log::error!("{desc} since {err}");
                ApiErrorCode::StorageHeaderMissing.with_desc(desc)
            })?;
        if target_hash != stg_target_hash {
            let desc = format!(
                "target transaction is in header#{target_height}, \
                the header hash from remote is {target_hash:#x}, \
                its hash in local storage is {stg_target_hash:#x}"
            );
            return Err(ApiErrorCode::StorageHeaderUnmatched.with_desc(desc));
        }
        check_tx_index(txid, tx_index, proven_index)?;

        let spv_type_script = spv.storage.spv_contract_type_script().map_err(|err| {
            let message = "failed to get SPV contract type script from storage".to_owned();
            log::error!("{message} since {err}");
            RpcError {
                code: RpcErrorCode::InternalError,
                message,
                data: None,
            }
        })?;

        log::debug!(">>> try the cached SPV instance at first");

        let required_height = target_height + confirmations;
        let cached = self
            .load_spv_instance(stg_tip_height, required_height)
            .ok()
            .flatten();
        let from_cache = cached.and_then(|spv_instance| {
            log::debug!(">>> the cached SPV instance is {spv_instance}");
            self.select_live_client(&spv_instance, stg_tip_height, target_height, confirmations)
                .map_err(|err| {
                    log::debug!(">>> the cached SPV instance is unusable: {}", err.message);
                })
                .ok()
        });
        let spv_client_cell = match from_cache {
            Some(cell) => cell,
            None => {
                log::debug!(">>> fetch SPV instance from remote");
                let spv_instance = self.fetch_spv_instance(spv_type_script, stg_tip_height)?;
                self.select_live_client(
                    &spv_instance,
                    stg_tip_height,
                    target_height,
                    confirmations,
                )?
            }
        };

        let header_proof = spv
            .storage
            .generate_headers_proof(
                spv_client_cell.client.headers_mmr_root.max_height,
                vec![target_height],
            )
            .map_err(|err| {
                let message = "failed to generate headers MMR proof".to_owned();
                log::error!("{message} since {err}");
                RpcError {
                    code: RpcErrorCode::InternalError,
                    message,
                    data: None,
                }
            })?;

        let tx_proof = packed::TransactionProof::new_builder()
            .tx_index(tx_index.pack())
            .height(target_height.pack())
            .transaction_proof(Bytes::from(raw_tx_out_proof).pack())
            .header_proof(header_proof.pack())
            .build();

        // Storage may roll back to another branch between choosing the client
        // and generating the headers proof, so verify the proof against the
        // client as the contract would before returning it.
        check_tx_proof(&spv_client_cell.client, txid, &tx_proof, confirmations)?;

        let btc_tx_proof = BitcoinTxProof {
            spv_client: spv_client_cell.cell.out_point.into(),
            proof: JsonBytes::from_bytes(tx_proof.as_bytes()),
        };
        Ok(btc_tx_proof)
    }
}

#[cfg(test)]
mod tests {
    use ckb_sdk::rpc::CkbRpcClient;
    use serde_json::{json, Value};

    use super::*;
    use crate::components::{BitcoinClient, ElectrsClient, Storage};

    #[test]
    fn rejects_stale_proof() {
        use bitcoin::{blockdata::constants::genesis_block, consensus::serialize, Network};

        // Genesis plus 4 linked headers; `nonce` tells branches apart.
        let block = genesis_block(Network::Bitcoin);
        let txid = block.txdata[0].txid();
        let branch = |nonce: u32| {
            let mut headers = Vec::new();
            let mut prev = block.header;
            for _ in 0..4 {
                let mut header = prev;
                header.prev_blockhash = prev.block_hash();
                header.nonce = nonce;
                headers.push(header);
                prev = header;
            }
            headers
        };
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new(directory.path()).unwrap();
        let mut client = storage.initialize_with(0, block.header).unwrap();
        let old = branch(1);
        storage.append_headers(old.clone()).unwrap();
        client.headers_mmr_root = storage.generate_headers_root(4).unwrap().unpack();
        client.tip_block_hash = old[3].block_hash().into();

        let merkle_block = MerkleBlock::from_block_with_predicate(&block, |id| *id == txid);
        let proof = |storage: &Storage| {
            packed::TransactionProof::new_builder()
                .tx_index(0u32.pack())
                .height(0u32.pack())
                .transaction_proof(Bytes::from(serialize(&merkle_block)).pack())
                .header_proof(storage.generate_headers_proof(4, vec![0]).unwrap().pack())
                .build()
        };
        assert!(check_tx_proof(&client, txid, &proof(&storage), 1).is_ok());

        // The client was chosen on the old branch; storage then switched.
        storage.rollback_to(Some(0)).unwrap();
        storage.append_headers(branch(2)).unwrap();
        let error = check_tx_proof(&client, txid, &proof(&storage), 1).unwrap_err();
        assert_eq!(
            error.code,
            RpcErrorCode::ServerError(ApiErrorCode::StorageHeaderUnmatched as i64)
        );
    }

    /// Serves every HTTP request with the same response.
    fn serve_text(status: &'static str, body: String) -> url::Url {
        use std::{
            io::{BufRead, BufReader, Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                let mut line = String::new();
                let mut content_length = 0;
                while reader.read_line(&mut line).unwrap_or(0) > 2 {
                    let header = line.trim_end().to_ascii_lowercase();
                    if let Some(length) = header.strip_prefix("content-length:") {
                        content_length = length.trim().parse().unwrap();
                    }
                    line.clear();
                }
                let _ = reader.read_exact(&mut vec![0; content_length]);
                let _ = write!(
                    writer,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        format!("http://{address}/").parse().unwrap()
    }

    #[test]
    fn tx_out_proof_errors() {
        use bitcoin::{
            blockdata::constants::genesis_block, consensus::encode::serialize_hex, Network,
        };

        let block = genesis_block(Network::Bitcoin);
        let txid = block.txdata[0].txid();
        // Two headers after genesis; the proofs are for a block at height 1.
        let mut header = block.header;
        header.prev_blockhash = block.block_hash();
        let mut next = header;
        next.prev_blockhash = header.block_hash();
        let call = |status: &'static str, body: String, tx_index: u32| {
            let directory = tempfile::tempdir().unwrap();
            let storage = Storage::new(directory.path()).unwrap();
            storage.initialize_with(0, block.header).unwrap();
            storage.append_headers(vec![header, next]).unwrap();
            let height = json!({ "result": { "height": 1 }, "error": null, "id": 0 });
            let bitcoind = serve_text("200 OK", height.to_string());
            let rpc = SpvRpcImpl::new(SpvService {
                ckb_cli: CkbRpcClient::new("http://127.0.0.1:1"),
                btc_cli: BitcoinClient::new(bitcoind, None, None),
                electrs_cli: Some(ElectrsClient::new(serve_text(status, body))),
                storage,
                sync_status: Default::default(),
            });
            rpc.get_tx_proof(txid, tx_index, 1).err().unwrap().code
        };
        let invalid = RpcErrorCode::ServerError(ApiErrorCode::BitcoinTxOutProofInvalid as i64);
        let mut good = MerkleBlock::from_block_with_predicate(&block, |id| *id == txid);
        good.header = header;
        let mut stale = good.clone();
        stale.header.nonce += 1;
        let without_tx = MerkleBlock::from_block_with_predicate(&block, |_| false);
        let mut wrong_root = good.clone();
        wrong_root.header.merkle_root = bitcoin::hashes::Hash::all_zeros();

        assert_eq!(call("200 OK", "not hex".to_owned(), 0), invalid);
        assert_eq!(call("200 OK", "000000".to_owned(), 0), invalid);
        assert_eq!(call("200 OK", serialize_hex(&wrong_root), 0), invalid);
        // The proof is to blame, whatever index the caller gave.
        assert_eq!(call("200 OK", serialize_hex(&without_tx), 0), invalid);
        assert_eq!(call("200 OK", serialize_hex(&without_tx), 1), invalid);
        assert_eq!(
            call("200 OK", serialize_hex(&good), 1),
            RpcErrorCode::InvalidParams
        );
        // The index may differ on a stale branch, so don't blame the caller.
        assert_eq!(
            call("200 OK", serialize_hex(&stale), 1),
            RpcErrorCode::ServerError(ApiErrorCode::StorageHeaderUnmatched as i64)
        );
        // An unknown transaction is not an invalid proof.
        assert_eq!(
            call("404 Not Found", "Transaction not found".to_owned(), 0),
            RpcErrorCode::InternalError
        );
        assert_eq!(proven_tx_index(&good, txid).unwrap(), 0);
    }

    /// Serves CKB's `get_live_cell`, reporting every cell with `status`.
    fn serve_cell_status(status: &'static str) -> String {
        use std::{
            io::{BufRead, BufReader, Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut writer = stream;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let mut content_length = 0;
                        loop {
                            line.clear();
                            reader.read_line(&mut line).unwrap();
                            let line = line.trim_end().to_ascii_lowercase();
                            if line.is_empty() {
                                break;
                            }
                            if let Some(length) = line.strip_prefix("content-length:") {
                                content_length = length.trim().parse().unwrap();
                            }
                        }
                        let mut body = vec![0; content_length];
                        reader.read_exact(&mut body).unwrap();
                        let request: Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(request["method"], "get_live_cell");
                        let response = json!({
                            "jsonrpc": "2.0",
                            "id": request["id"],
                            "result": { "cell": null, "status": status },
                        })
                        .to_string();
                        write!(
                            writer,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                            Content-Length: {}\r\n\r\n{response}",
                            response.len()
                        )
                        .unwrap();
                    }
                });
            }
        });
        format!("http://{address}/")
    }

    #[test]
    fn rejects_spent_client() {
        use std::collections::HashMap;

        use bitcoin::{blockdata::constants::genesis_block, Network};
        use ckb_bitcoin_spv_verifier::types::core;
        use ckb_sdk::traits::LiveCell;
        use ckb_types::packed::{CellOutput, OutPoint as PackedOutPoint};

        use crate::components::{SpvClientCell, SpvInfoCell};

        let rpc = |status: &'static str| {
            let directory = tempfile::tempdir().unwrap();
            let storage = Storage::new(directory.path()).unwrap();
            let genesis = genesis_block(Network::Testnet).header;
            let mut header = genesis;
            let mut headers = Vec::new();
            for _ in 0..10 {
                let prev = header;
                header.prev_blockhash = prev.block_hash();
                header.time += 600;
                headers.push(header);
            }
            storage.initialize_with(0, genesis).unwrap();
            storage.append_headers(headers.clone()).unwrap();
            let service = SpvService {
                ckb_cli: CkbRpcClient::new(&serve_cell_status(status)),
                btc_cli: BitcoinClient::new("http://127.0.0.1:1".parse().unwrap(), None, None),
                electrs_cli: None,
                storage,
                sync_status: Default::default(),
            };
            (directory, SpvRpcImpl::new(service), headers)
        };
        let live_cell = || LiveCell {
            output: CellOutput::default(),
            output_data: Default::default(),
            out_point: PackedOutPoint::default(),
            block_number: 0,
            tx_index: 0,
        };
        let instance = |rpc: &SpvRpcImpl, headers: &[bitcoin::block::Header]| {
            let client = core::SpvClient {
                id: 0,
                tip_block_hash: headers[9].block_hash().into(),
                headers_mmr_root: rpc
                    .spv_service
                    .storage
                    .generate_headers_root(10)
                    .unwrap()
                    .unpack(),
                target_adjust_info: packed::TargetAdjustInfo::default(),
            };
            SpvInstance {
                info: SpvInfoCell {
                    info: core::SpvInfo { tip_client_id: 0 },
                    cell: live_cell(),
                    clients_count: 1,
                },
                clients: HashMap::from([(
                    0,
                    SpvClientCell {
                        client,
                        cell: live_cell(),
                    },
                )]),
            }
        };

        let (_directory, live, headers) = rpc("live");
        let cached = instance(&live, &headers);
        assert!(live.select_live_client(&cached, 10, 0, 1).is_ok());

        let (_directory, spent, headers) = rpc("dead");
        let cached = instance(&spent, &headers);
        let error = spent.select_live_client(&cached, 10, 0, 1).err().unwrap();
        assert_eq!(
            error.code,
            RpcErrorCode::ServerError(ApiErrorCode::OnchainClientSpent as i64)
        );
        // A live cell which doesn't cover the target is not selected either.
        assert!(live.select_live_client(&cached, 10, 10, 1).is_err());
    }

    #[test]
    fn sync_status_reads_only_the_shared_observations() {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = "http://127.0.0.1:1";
        let service = SpvService {
            ckb_cli: CkbRpcClient::new(endpoint),
            btc_cli: BitcoinClient::new(endpoint.parse().unwrap(), None, None),
            electrs_cli: None,
            storage: Storage::new(directory.path()).unwrap(),
            sync_status: Default::default(),
        };
        let observations = service.sync_status.clone();
        let mut rpc = IoHandler::new();
        rpc.extend_with(SpvRpcImpl::new(service).to_delegate());

        let status = || -> Value {
            let response = rpc
                .handle_request_sync(
                    r#"{"jsonrpc":"2.0","id":1,"method":"getSyncStatus","params":[]}"#,
                )
                .unwrap();
            let response: Value = serde_json::from_str(&response).unwrap();
            assert_eq!(response["id"], 1);
            response["result"].clone()
        };

        // No initialized storage or connected upstreams are needed, including
        // while the synchronization loop has only observed some of its inputs.
        assert_eq!(
            status(),
            json!({"bitcoinTip": null, "localHeaderTip": null, "confirmedClient": null}),
        );
        observations.observe_bitcoin_tip(105);
        observations.observe_local_tip(101);
        let partial = status();
        assert_eq!(partial["bitcoinTip"]["height"], 105);
        assert!(partial["bitcoinTip"]["observedAt"].as_u64().is_some());
        assert_eq!(partial["localHeaderTip"]["height"], 101);
        assert!(partial["localHeaderTip"]["observedAt"].as_u64().is_some());
        assert!(partial["confirmedClient"].is_null());

        observations.observe_confirmed_client(50, 98);
        observations.observe_local_tip(97);
        let after_rollback = status();
        assert_eq!(after_rollback["localHeaderTip"]["height"], 97);
        assert_eq!(after_rollback["confirmedClient"]["startHeight"], 50);
        assert_eq!(after_rollback["confirmedClient"]["endHeight"], 98);
        assert!(after_rollback["confirmedClient"]["observedAt"]
            .as_u64()
            .is_some());
        assert_eq!(after_rollback["bitcoinTip"], partial["bitcoinTip"]);
        assert_eq!(status(), after_rollback);
    }
}

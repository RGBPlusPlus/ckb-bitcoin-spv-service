//! The `serve` sub-command.

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    net::SocketAddr,
    num::NonZeroU32,
    path::PathBuf,
    thread, time,
};

use ckb_bitcoin_spv_verifier::types::{
    core::{BitcoinChainType, Hash, SpvClient, U256},
    packed,
    prelude::{Pack as VPack, Unpack as VUnpack},
};
use ckb_jsonrpc_types::{Status, TransactionView, TxStatus};
use ckb_sdk::{
    core::TransactionBuilder,
    rpc::RpcError,
    transaction::{
        builder::{ChangeBuilder, DefaultChangeBuilder},
        handler::HandlerContexts,
        input::{InputIterator, TransactionInput},
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    types::{
        Address as CkbAddress, AddressPayload as CkbAddressPayload, NetworkInfo, NetworkType,
        ScriptGroup, TransactionWithScriptGroups,
    },
    SECP256K1,
};
use ckb_types::{
    core::{Capacity, DepType},
    packed::{
        Byte32, Bytes as PackedBytes, BytesOpt, CellDep, CellInput, CellOutput, OutPoint,
        WitnessArgs,
    },
    prelude::*,
    H256,
};
use clap::Parser;
use secp256k1::SecretKey;

use crate::{
    components::{
        ApiServiceConfig, SpvOperation, SpvReorgInput, SpvService, SpvUpdateInput, Storage,
        StorageSync,
    },
    constants,
    prelude::*,
    result::{Error, Result},
    utilities::{try_raise_fd_limit, value_parsers},
};

const SPV_RESET_TIP_OFFSET: u32 = 1200;

// CKB RPC's PoolRejectedDuplicatedTransaction code. Other RPC rejections are
// definitive and must not be treated as successful submissions.
const DUPLICATED_TRANSACTION: i64 = -1107;
// CKB RPC's PoolRejectedTransactionBySizeLimit and TransactionFailedToVerify
// codes; a transaction over the cycles limit fails verification.
const TX_SIZE_LIMIT: i64 = -1110;
const TX_VERIFY_FAILED: i64 = -302;
const MAX_UNCERTAIN_POLLS: u8 = 3;

/// Whether a CKB rejection message says the transaction exceeds CKB's size or
/// cycles limits, in the RPC error or in `get_transaction`'s rejection reason.
fn mentions_ckb_limits(text: &str) -> bool {
    [
        // `Reject::ExceededTransactionSizeLimit`, by name and by its message.
        "ExceededTransactionSizeLimit",
        "exceeded maximum limit",
        "PoolRejectedTransactionBySizeLimit",
        // `ScriptError::ExceededMaximumCycles`, inside a verification failure.
        "ExceededMaximumCycles",
    ]
    .iter()
    .any(|pattern| text.contains(pattern))
}

/// Whether CKB rejected a transaction for exceeding its size or cycles limits.
///
/// Unlike transient rejections, resending the same batch cannot succeed.
fn exceeds_ckb_limits(error: &Error) -> bool {
    let Error::CkbRpc(RpcError::Rpc(error)) = error else {
        return false;
    };
    match error.code.code() {
        TX_SIZE_LIMIT => true,
        TX_VERIFY_FAILED => {
            mentions_ckb_limits(&error.message)
                || error
                    .data
                    .as_ref()
                    .is_some_and(|data| mentions_ckb_limits(&data.to_string()))
        }
        _ => false,
    }
}

/// Where a batch of headers starts: the SPV info cell it consumes, the
/// operation, and the height the headers are appended after.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BatchKey {
    info: OutPoint,
    operation: &'static str,
    base_height: u32,
}

/// A batch of headers carried by one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Batch {
    key: BatchKey,
    headers: u32,
    /// The hash of the last header, which commits to the whole Bitcoin branch
    /// the batch carries.
    end_hash: Hash,
}

impl Batch {
    fn new(storage: &Storage, key: BatchKey, headers: u32) -> Result<Self> {
        let end_hash = storage.bitcoin_header_hash(key.base_height + headers)?;
        Ok(Self {
            key,
            headers,
            end_hash,
        })
    }

    /// Whether storage still holds the Bitcoin branch this batch carried.
    fn is_on_storage_branch(&self, storage: &Storage) -> Result<bool> {
        let end_height = self.key.base_height + self.headers;
        let (tip_height, _) = storage.tip_state()?;
        Ok(end_height <= tip_height && storage.bitcoin_header_hash(end_height)? == self.end_hash)
    }
}

/// Remembers the smallest batch CKB rejected for exceeding its size or cycles
/// limits, so the next batch from the same start carries fewer headers.
///
/// It only applies to batches with the same start on the same Bitcoin branch.
/// Once the info cell, the operation or the base height changes (e.g. the
/// on-chain tip moves, or Bitcoin switches back to the on-chain branch so a
/// reorg becomes an update), or storage replaces the headers the rejected
/// batch carried, batches use the configured limits again.
#[derive(Default)]
struct BatchCap {
    rejected: Option<Batch>,
}

impl BatchCap {
    fn reject(&mut self, batch: Batch) {
        log::warn!(
            "CKB rejected {} {} headers after header#{} for size or cycles limits; \
            carry fewer headers from there",
            batch.key.operation,
            batch.headers,
            batch.key.base_height
        );
        match &self.rejected {
            Some(rejected) if rejected.key == batch.key && rejected.headers <= batch.headers => {}
            _ => self.rejected = Some(batch),
        }
    }

    /// The smallest rejected batch starting at `key` on the storage branch.
    fn rejected(&mut self, key: &BatchKey, storage: &Storage) -> Result<Option<u32>> {
        let Some(rejected) = &self.rejected else {
            return Ok(None);
        };
        if rejected.key != *key {
            log::info!("Batch start changed; lift the batch cap");
        } else if !rejected.is_on_storage_branch(storage)? {
            log::info!(
                "Bitcoin branch after header#{} changed; lift the batch cap",
                key.base_height
            );
        } else {
            return Ok(Some(rejected.headers));
        }
        self.rejected = None;
        Ok(None)
    }

    /// The limit of a batch which may carry any number of headers: halve below
    /// the smallest rejected batch. `None` pauses: even one header was rejected.
    fn any_size(
        &mut self,
        key: &BatchKey,
        storage: &Storage,
        limit: NonZeroU32,
    ) -> Result<Option<NonZeroU32>> {
        Ok(match self.rejected(key, storage)? {
            None => Some(limit),
            Some(rejected) => NonZeroU32::new(rejected / 2).map(|cap| cap.min(limit)),
        })
    }

    /// The preferred limit and the hard max of a batch which must outweigh the
    /// stale tip. Prefer half the smallest rejected batch, but allow anything
    /// below it, so the fewest headers that outweigh the stale tip are still
    /// tried once. `None` pauses: even one header was rejected.
    fn work_bound(
        &mut self,
        key: &BatchKey,
        storage: &Storage,
        limit: NonZeroU32,
        max: NonZeroU32,
    ) -> Result<Option<(NonZeroU32, NonZeroU32)>> {
        Ok(match self.rejected(key, storage)? {
            None => Some((limit, max)),
            Some(rejected) => NonZeroU32::new(rejected.saturating_sub(1)).map(|max_below| {
                let limit = NonZeroU32::new((rejected / 2).max(1))
                    .unwrap_or(NonZeroU32::MIN)
                    .min(limit);
                (limit, max_below.min(max))
            }),
        })
    }
}

/// How many headers a Testnet4 reorg update carries after the fork point.
#[derive(Debug, PartialEq, Eq)]
enum ReorgBatch {
    /// Carry this many headers; the new tip outweighs the stale tip.
    Ready(NonZeroU32),
    /// Even the whole storage chain has no more work than the stale tip yet.
    NotEnoughWork,
    /// Outweighing the stale tip needs this many headers, more than the local
    /// cap allows in one transaction.
    TooManyHeaders(u32),
}

/// Chooses the reorg batch for chains where the SPV contract requires the new
/// tip to have more chain work than the stale tip (every chain except Testnet3).
///
/// A reorg cannot be split into several transactions, so prefer `limit`
/// headers, carry more only when needed to outweigh the stale tip, and never
/// exceed `max`, the local cap on headers in one reorg transaction.
fn reorg_batch(
    storage: &Storage,
    prev_height: u32,
    limit: NonZeroU32,
    max: NonZeroU32,
    stale_work: U256,
) -> Result<ReorgBatch> {
    let (tip_height, _) = storage.tip_state()?;
    let Some(available) = tip_height
        .checked_sub(prev_height)
        .and_then(NonZeroU32::new)
    else {
        return Ok(ReorgBatch::NotEnoughWork);
    };
    let work_with = |count: u32| -> Result<U256> {
        let root = storage.generate_headers_root(prev_height + count)?;
        Ok(root.unpack().partial_chain_work)
    };

    let preferred = limit.min(max).min(available);
    if work_with(preferred.get())? > stale_work {
        return Ok(ReorgBatch::Ready(preferred));
    }
    if work_with(available.get())? <= stale_work {
        return Ok(ReorgBatch::NotEnoughWork);
    }

    // Chain work grows with height: `low` is too light, `high` is heavy enough.
    let (mut low, mut high) = (preferred.get(), available.get());
    while high - low > 1 {
        let mid = low + (high - low) / 2;
        if work_with(mid)? > stale_work {
            high = mid;
        } else {
            low = mid;
        }
    }
    if high > max.get() {
        return Ok(ReorgBatch::TooManyHeaders(high));
    }
    log::warn!("Reorg needs {high} headers to outweigh the stale tip, more than the limit {limit}");
    Ok(NonZeroU32::new(high).map_or(ReorgBatch::NotEnoughWork, ReorgBatch::Ready))
}

struct InFlight {
    hash: H256,
    consumed_info: OutPoint,
    /// The Bitcoin headers the transaction carries.
    batch: Batch,
    uncertain_polls: u8,
}

enum PreviousTx<T> {
    Wait,
    Retry,
    /// CKB rejected the transaction after accepting it, with this reason.
    Rejected(Option<String>),
    Indexed(T),
}

impl InFlight {
    fn from_send(
        hash: H256,
        consumed_info: OutPoint,
        batch: Batch,
        result: std::result::Result<H256, RpcError>,
    ) -> Result<Self> {
        let hash = match result {
            Ok(hash) => {
                log::info!("Transaction hash: {hash:#x}");
                println!("Send transaction: {hash:#x}");
                hash
            }
            Err(RpcError::Rpc(error)) if error.code.code() == DUPLICATED_TRANSACTION => hash,
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            hash,
            consumed_info,
            batch,
            uncertain_polls: 0,
        })
    }

    fn poll<T>(
        &mut self,
        status: TxStatus,
        load_indexed: impl FnOnce() -> Result<(OutPoint, u64, T)>,
    ) -> Result<PreviousTx<T>> {
        if status.status == Status::Unknown {
            self.uncertain_polls += 1;
            return Ok(if self.uncertain_polls < MAX_UNCERTAIN_POLLS {
                PreviousTx::Wait
            } else {
                PreviousTx::Retry
            });
        }
        self.uncertain_polls = 0;
        match status.status {
            Status::Pending | Status::Proposed => Ok(PreviousTx::Wait),
            Status::Committed => {
                let (indexed_info, indexed_height, instance) = load_indexed()?;
                if self.consumed_info == indexed_info
                    || status
                        .block_number
                        .is_some_and(|height| indexed_height < u64::from(height))
                {
                    Ok(PreviousTx::Wait)
                } else {
                    // Build from this snapshot, not a second indexer read.
                    Ok(PreviousTx::Indexed(instance))
                }
            }
            Status::Rejected => Ok(PreviousTx::Rejected(status.reason)),
            Status::Unknown => unreachable!("handled above"),
        }
    }
}

#[derive(Parser)]
pub struct Args {
    #[clap(flatten)]
    pub(crate) common: super::CommonArgs,

    /// The directory, which stores all cached data.
    #[arg(long)]
    pub(crate) data_dir: PathBuf,

    #[clap(flatten)]
    pub(crate) ckb: super::CkbArgs,

    #[clap(flatten)]
    pub(crate) bitcoin: super::BitcoinArgs,

    /// The JSON-RPC server's listen address.
    #[arg(long)]
    pub(crate) listen_address: SocketAddr,

    /// A interval in seconds.
    ///
    /// - When no better bitcoin blocks, waiting for several seconds.
    /// - After a CKB transaction is sent, waiting for several seconds.
    #[arg(long, default_value = "30")]
    pub(crate) interval: u64,

    /// Don't update all headers in one CKB transaction,
    /// to avoid size limit or cycles limit.
    #[arg(long, default_value = "10")]
    pub(crate) spv_headers_update_limit: NonZeroU32,

    /// The local cap on headers in one Testnet4 reorg transaction.
    ///
    /// A Testnet4 reorg must outweigh the stale tip in one transaction, so it
    /// may carry more headers than `--spv-headers-update-limit`, but not more
    /// than this. This only counts headers: whether the transaction fits CKB's
    /// size and cycles limits also depends on the replaced cells, the proof and
    /// the signature. A reorg that needs more headers is skipped and reported
    /// while the service keeps running.
    ///
    /// A reorg replaces at least two SPV clients of up to
    /// `--spv-headers-update-limit` headers each, so with equal difficulty even
    /// a one-block Bitcoin reorg can need `2 * limit + 1` headers.
    #[arg(long, default_value = "100")]
    pub(crate) spv_reorg_headers_max: NonZeroU32,

    /// The out point of the Bitcoin SPV contract.
    ///
    /// This parameter will override the value in the storage.
    /// If this parameter is not provided, the value in the storage will be used.
    #[arg(long, value_parser = value_parsers::OutPointValueParser)]
    pub(crate) spv_contract_out_point: Option<OutPoint>,

    /// The batch size that how many Bitcoin headers will be downloaded at once.
    #[arg(long, default_value = "30")]
    pub(crate) bitcoin_headers_download_batch_size: u32,

    #[clap(flatten)]
    pub(crate) spv_owner_opt: super::SpvOwnerOpt,

    /// Perform all steps without sending.
    #[arg(long, hide = true)]
    pub(crate) dry_run: bool,
}

impl Args {
    pub fn execute(&self) -> Result<()> {
        log::info!("Starting the Bitcoin SPV service");

        self.spv_owner_opt.check_network(self.ckb.network)?;

        try_raise_fd_limit();

        let storage = Storage::new(&self.data_dir)?;
        if !storage.is_initialized()? {
            let msg = format!(
                "user-provided data directory \"{}\" is empty, please initialize it",
                self.data_dir.display()
            );
            return Err(Error::other(msg));
        }

        if let Some(ref spv_contract_out_point) = self.spv_contract_out_point {
            let spv_contract_cell_dep = CellDep::new_builder()
                .out_point(spv_contract_out_point.clone())
                .dep_type(DepType::Code.into())
                .build();
            let spv_type_script = storage.spv_contract_type_script()?;
            storage.save_cells_state(spv_type_script, spv_contract_cell_dep)?;
        }

        let ckb_cli = self.ckb.client();
        let btc_cli = self.bitcoin.client();
        let electrs_cli = self.bitcoin.electrs_client();

        let spv_service = SpvService {
            ckb_cli: ckb_cli.clone(),
            btc_cli: btc_cli.clone(),
            electrs_cli: electrs_cli.clone(),
            storage: storage.clone(),
            sync_status: Default::default(),
        };

        let _api_service = ApiServiceConfig::new(self.listen_address).start(spv_service.clone());

        self.warn_reorg_limits();

        let mut in_flight: Option<InFlight> = None;
        let mut batch_cap = BatchCap::default();

        loop {
            match spv_service.sync_storage(self.bitcoin_headers_download_batch_size)? {
                StorageSync::Synced => {}
                StorageSync::Interrupted => continue,
                StorageSync::NodeBehind => {
                    // Storage cannot be checked against the node's best chain.
                    self.take_a_break();
                    continue;
                }
            }

            let instance = match in_flight.as_mut() {
                None => spv_service.load_instance()?,
                Some(tx) => {
                    let status = ckb_cli.get_transaction_status(tx.hash.clone())?.tx_status;
                    let next = tx.poll(status, || {
                        let instance = spv_service.load_instance()?;
                        Ok((
                            instance.info.cell.out_point.clone(),
                            instance.info.cell.block_number,
                            instance,
                        ))
                    })?;
                    match next {
                        PreviousTx::Wait => {
                            log::debug!("Waiting for transaction or indexer: {:#x}", tx.hash);
                            self.take_a_break();
                            continue;
                        }
                        PreviousTx::Retry => {
                            log::warn!(
                                "Transaction {:#x} not confirmed; reloading SPV state",
                                tx.hash
                            );
                            in_flight = None;
                            self.take_a_break();
                            spv_service.load_instance()?
                        }
                        PreviousTx::Rejected(reason) => {
                            let reason = reason.unwrap_or_else(|| "no reason given".to_owned());
                            if mentions_ckb_limits(&reason) {
                                log::error!(
                                    "Transaction {:#x} exceeds CKB size or cycles limits: {reason}",
                                    tx.hash
                                );
                                batch_cap.reject(tx.batch.clone());
                            } else {
                                log::warn!(
                                    "Transaction {:#x} rejected: {reason}; reloading SPV state",
                                    tx.hash
                                );
                            }
                            in_flight = None;
                            self.take_a_break();
                            spv_service.load_instance()?
                        }
                        PreviousTx::Indexed(instance) => {
                            in_flight = None;
                            instance
                        }
                    }
                }
            };

            let (stg_tip_height, stg_tip_header) = spv_service.storage.tip_state()?;
            let stg_tip_hash = stg_tip_header.block_hash();
            log::info!("[storage] header#{stg_tip_height:07}, {stg_tip_hash:#x}; tip");

            let (batch, result) = match spv_service.select_operation(instance)? {
                SpvOperation::Update(input) => {
                    let spv_tip_height = input.curr.client.headers_mmr_root.max_height;

                    match stg_tip_height.cmp(&spv_tip_height) {
                        Ordering::Less | Ordering::Equal => {
                            log::info!("No updates, sleep for a while");
                            self.take_a_break();
                            continue;
                        }
                        Ordering::Greater => {}
                    }

                    log::info!("Try to update SPV instance");

                    let key = BatchKey {
                        info: input.info.cell.out_point.clone(),
                        operation: "update",
                        base_height: spv_tip_height,
                    };
                    let Some(limit) =
                        batch_cap.any_size(&key, &storage, self.spv_headers_update_limit)?
                    else {
                        self.pause_for_ckb_limits(&key);
                        continue;
                    };
                    let (spv_client, spv_update) = storage.generate_spv_client_and_spv_update(
                        spv_tip_height,
                        limit,
                        input.info.get_flags()?,
                    )?;

                    let headers = spv_update.headers().len() as u32;
                    let batch = Batch::new(&storage, key, headers)?;
                    let result = self.update_spv_cells(
                        &spv_service,
                        input,
                        spv_client,
                        spv_update,
                        batch.clone(),
                    );
                    (batch, result)
                }
                SpvOperation::Reorg(input) => {
                    log::info!("Try to reorg SPV instance");

                    let spv_tip_height = input.curr.client.headers_mmr_root.max_height;

                    let flags = input.info.get_flags()?;
                    let key = BatchKey {
                        info: input.info.cell.out_point.clone(),
                        operation: "reorg",
                        base_height: spv_tip_height,
                    };
                    let limit = if BitcoinChainType::Testnet == flags.into() {
                        // The contract skips the chain work check on Testnet3,
                        // so a long reorg can recover in several batches.
                        let Some(limit) =
                            batch_cap.any_size(&key, &storage, self.spv_headers_update_limit)?
                        else {
                            self.pause_for_ckb_limits(&key);
                            continue;
                        };
                        limit
                    } else {
                        // Elsewhere the new tip must outweigh the stale tip in
                        // one transaction. Testnet4 prefers the update limit;
                        // other chains carry every header storage has, as before.
                        let (limit, max) = if BitcoinChainType::Testnet4 == flags.into() {
                            (self.spv_headers_update_limit, self.spv_reorg_headers_max)
                        } else {
                            (NonZeroU32::MAX, NonZeroU32::MAX)
                        };
                        let Some((limit, max)) =
                            batch_cap.work_bound(&key, &storage, limit, max)?
                        else {
                            self.pause_for_ckb_limits(&key);
                            continue;
                        };
                        let stale_work = input
                            .stale
                            .first()
                            .map(|cell| cell.client.headers_mmr_root.partial_chain_work)
                            .unwrap_or_default();
                        match reorg_batch(
                            &spv_service.storage,
                            spv_tip_height,
                            limit,
                            max,
                            stale_work,
                        )? {
                            ReorgBatch::Ready(limit) => limit,
                            ReorgBatch::NotEnoughWork => {
                                log::warn!(
                                    "Storage chain has no more work than the stale SPV tip; \
                                    wait for more headers before reorg"
                                );
                                self.take_a_break();
                                continue;
                            }
                            ReorgBatch::TooManyHeaders(needed) => {
                                if batch_cap.rejected(&key, &storage)?.is_some() {
                                    log::error!(
                                        "Cannot reorg SPV instance in one transaction: \
                                        outweighing the stale tip needs {needed} headers after \
                                        header#{spv_tip_height}, but CKB rejected a batch of \
                                        {} headers; pause until the batch start changes",
                                        max.get() + 1
                                    );
                                } else {
                                    log::error!(
                                        "Cannot reorg SPV instance in one transaction: \
                                        outweighing the stale tip needs {needed} headers after \
                                        header#{spv_tip_height}, but --spv-reorg-headers-max is \
                                        {max}; raise it if CKB size and cycles limits allow"
                                    );
                                }
                                self.take_a_break();
                                continue;
                            }
                        }
                    };
                    let (spv_client, spv_update) =
                        storage.generate_spv_client_and_spv_update(spv_tip_height, limit, flags)?;

                    let headers = spv_update.headers().len() as u32;
                    let batch = Batch::new(&storage, key, headers)?;
                    let result = self.reorg_spv_cells(
                        &spv_service,
                        input,
                        spv_client,
                        spv_update,
                        batch.clone(),
                    );
                    (batch, result)
                }
                SpvOperation::Reset(input) => {
                    let flags = input.info.get_flags()?;
                    // The contract only allows resetting all clients on Testnet3.
                    if BitcoinChainType::Testnet != flags.into() {
                        let msg = "failed to reorg since no common parent between SPV instance and storage";
                        return Err(Error::other(msg));
                    }

                    log::info!(
                        "stale length: {:?}, clients count: {:?}",
                        input.stale.len(),
                        input.info.clients_count
                    );
                    log::info!("Try to reset SPV instance");

                    let spv_tip_height =
                        input.curr.client.headers_mmr_root.max_height - SPV_RESET_TIP_OFFSET;

                    let key = BatchKey {
                        info: input.info.cell.out_point.clone(),
                        operation: "reset",
                        base_height: spv_tip_height,
                    };
                    let Some(limit) =
                        batch_cap.any_size(&key, &storage, self.spv_headers_update_limit)?
                    else {
                        self.pause_for_ckb_limits(&key);
                        continue;
                    };
                    let (spv_client, spv_update) =
                        storage.generate_spv_client_and_spv_update(spv_tip_height, limit, flags)?;

                    let headers = spv_update.headers().len() as u32;
                    let batch = Batch::new(&storage, key, headers)?;
                    let result = self.reorg_spv_cells(
                        &spv_service,
                        input,
                        spv_client,
                        spv_update,
                        batch.clone(),
                    );
                    (batch, result)
                }
            };
            match result {
                Ok(Some(tx)) => in_flight = Some(tx),
                Ok(None) => self.take_a_break(), // Dry run never enters transaction tracking.
                Err(error) if exceeds_ckb_limits(&error) => {
                    log::error!(
                        "Failed to {} SPV instance: the transaction exceeds CKB size \
                        or cycles limits: {error}",
                        batch.key.operation
                    );
                    batch_cap.reject(batch);
                    self.take_a_break();
                }
                Err(error) => {
                    log::warn!("Failed to {} SPV instance: {error}", batch.key.operation);
                    self.take_a_break();
                }
            }
        }

        // TODO Handle Ctrl-C and clean resources before exit.
    }

    fn update_spv_cells(
        &self,
        spv: &SpvService,
        update_input: SpvUpdateInput,
        mut spv_client: SpvClient,
        spv_update: packed::SpvUpdate,
        batch: Batch,
    ) -> Result<Option<InFlight>> {
        let network_info =
            NetworkInfo::new(self.ckb.network, self.ckb.ckb_endpoint.as_str().to_owned());
        let configuration = {
            let mut tmp = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;
            tmp.fee_rate = self.ckb.fee_rate()?;
            tmp
        };

        let (deployer, deployer_key) = SecretKey::from_slice(&self.ckb.private_key.as_ref()[..])
            .map(|sk| {
                let pk = sk.public_key(&SECP256K1);
                let payload = CkbAddressPayload::from_pubkey(&pk);
                let address = CkbAddress::new(self.ckb.network, payload, true);
                (address, sk)
            })?;
        log::debug!("The SPV cells will be updated by {deployer}");

        let iterator = InputIterator::new_with_address(&[deployer.clone()], &network_info);
        let mut tx_builder = TransactionBuilder::default();

        let spv_inputs = {
            let spv_info_input = CellInput::new_builder()
                .previous_output(update_input.info.cell.out_point.clone())
                .build();
            let spv_client_input = CellInput::new_builder()
                .previous_output(update_input.next.cell.out_point.clone())
                .build();
            vec![spv_info_input, spv_client_input]
        };
        tx_builder.inputs(spv_inputs);

        let spv_contract_cell_dep = spv.storage.spv_contract_cell_dep()?;
        tx_builder.cell_dep(spv_contract_cell_dep);
        let spv_client_curr_cell_dep = CellDep::new_builder()
            .out_point(update_input.curr.cell.out_point)
            .dep_type(DepType::Code.into())
            .build();
        tx_builder.cell_dep(spv_client_curr_cell_dep);

        // Try to insert cell deps for the lock scripts.
        match self.ckb.network {
            NetworkType::Mainnet | NetworkType::Testnet => {
                let known_cell_dep = if self.ckb.network == NetworkType::Mainnet {
                    constants::mainnet::known_cell_dep
                } else {
                    constants::testnet::known_cell_dep
                };
                #[allow(clippy::mutable_key_type)]
                let mut handled_code_hashes = HashSet::new();
                for cell in [&update_input.info.cell, &update_input.next.cell] {
                    let code_hash = cell.output.lock().code_hash();
                    if handled_code_hashes.insert(code_hash.clone()) {
                        if let Some(cell_dep) = known_cell_dep(&code_hash) {
                            tx_builder.cell_dep(cell_dep);
                        }
                    }
                }
            }
            _ => {
                log::warn!("Unsupport CKB network \"{}\"", self.ckb.network);
            }
        }

        let spv_outputs_data = {
            spv_client.id = update_input.next.client.id;
            let mut spv_info = update_input.info.info;
            spv_info.tip_client_id = spv_client.id;
            let packed_spv_info: packed::SpvInfo = spv_info.pack();
            let packed_spv_client: packed::SpvClient = spv_client.pack();
            vec![packed_spv_info.as_bytes(), packed_spv_client.as_bytes()]
        };
        let spv_outputs: Vec<CellOutput> = if let Some(lock_script) =
            self.spv_owner_opt.lock_script()
        {
            let spv_info_capacity = Capacity::bytes(spv_outputs_data[0].len()).map_err(|err| {
                let msg = format!(
                    "failed to calculate the capacity for Bitcoin SPV info cell since {err}"
                );
                Error::other(msg)
            })?;
            let spv_client_capacity =
                Capacity::bytes(spv_outputs_data[1].len()).map_err(|err| {
                    let msg = format!(
                        "failed to calculate the capacity for Bitcoin SPV client cell since {err}"
                    );
                    Error::other(msg)
                })?;
            let info_output = update_input
                .info
                .cell
                .output
                .clone()
                .as_builder()
                .lock(lock_script.clone())
                .build_exact_capacity(spv_info_capacity)
                .map_err(|err| {
                    let msg = format!(
                        "failed to sum the total capacity for Bitcoin SPV info cell since {err}"
                    );
                    Error::other(msg)
                })?;
            let client_output = update_input
                .next
                .cell
                .output
                .clone()
                .as_builder()
                .lock(lock_script)
                .build_exact_capacity(spv_client_capacity)
                .map_err(|err| {
                    let msg = format!(
                        "failed to sum the total capacity for Bitcoin SPV client cell since {err}"
                    );
                    Error::other(msg)
                })?;
            vec![info_output, client_output]
        } else {
            vec![
                update_input.info.cell.output.clone(),
                update_input.next.cell.output.clone(),
            ]
        };
        tx_builder.outputs(spv_outputs);
        tx_builder.outputs_data(spv_outputs_data.iter().map(Pack::pack));

        #[allow(clippy::mutable_key_type)]
        let mut lock_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
        #[allow(clippy::mutable_key_type)]
        let mut type_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();

        {
            let lock_script = update_input.info.cell.output.lock();
            lock_groups
                .entry(lock_script.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_lock_script(&lock_script))
                .input_indices
                .push(0);
            let lock_script = update_input.next.cell.output.lock();
            lock_groups
                .entry(lock_script.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_lock_script(&lock_script))
                .input_indices
                .push(1);
        }

        for (output_idx, output) in tx_builder.get_outputs().clone().iter().enumerate() {
            if let Some(type_script) = &output.type_().to_opt() {
                type_groups
                    .entry(type_script.calc_script_hash())
                    .or_insert_with(|| ScriptGroup::from_type_script(type_script))
                    .output_indices
                    .push(output_idx);
            }
        }

        let witness = {
            let type_args = BytesOpt::new_builder()
                .set(Some(Pack::pack(spv_update.as_slice())))
                .build();
            let witness_args = WitnessArgs::new_builder().output_type(type_args).build();
            Pack::pack(&witness_args.as_bytes())
        };
        tx_builder.witness(witness);
        tx_builder.witness(PackedBytes::default());

        let mut change_builder =
            DefaultChangeBuilder::new(&configuration, (&deployer).into(), Vec::new());
        change_builder.init(&mut tx_builder);
        {
            let spv_info_input = TransactionInput {
                live_cell: update_input.info.cell.clone(),
                since: 0,
            };
            let spv_client_input = TransactionInput {
                live_cell: update_input.next.cell.clone(),
                since: 0,
            };
            let _ = change_builder.check_balance(spv_info_input, &mut tx_builder);
            let _ = change_builder.check_balance(spv_client_input, &mut tx_builder);
        };
        let contexts = HandlerContexts::default();

        let mut tx_with_groups = {
            let mut check_result = None;
            for (mut input_index, input) in iterator.enumerate() {
                input_index += 2; // The first 2 inputs are SPV cells.
                log::debug!("Try to find the {input_index}-th live cell for {deployer}");
                let input = input.map_err(|err| {
                    let msg = format!(
                        "failed to find {input_index}-th live cell for {deployer} since {err}"
                    );
                    Error::other(msg)
                })?;
                tx_builder.input(input.cell_input());
                tx_builder.witness(PackedBytes::default());

                let previous_output = input.previous_output();
                let lock_script = previous_output.lock();
                lock_groups
                    .entry(lock_script.calc_script_hash())
                    .or_insert_with(|| ScriptGroup::from_lock_script(&lock_script))
                    .input_indices
                    .push(input_index);

                if change_builder.check_balance(input, &mut tx_builder) {
                    let mut script_groups: Vec<ScriptGroup> = lock_groups
                        .into_values()
                        .chain(type_groups.into_values())
                        .collect();
                    for script_group in script_groups.iter_mut() {
                        for handler in configuration.get_script_handlers() {
                            for context in &contexts.contexts {
                                if handler.build_transaction(
                                    &mut tx_builder,
                                    script_group,
                                    context.as_ref(),
                                )? {
                                    break;
                                }
                            }
                        }
                    }
                    let tx_view = change_builder.finalize(tx_builder);

                    check_result = Some(TransactionWithScriptGroups::new(tx_view, script_groups));
                    break;
                }
            }
            check_result
        }
        .ok_or_else(|| {
            let msg = format!("{deployer}'s live cells are not enough");
            Error::other(msg)
        })?;

        TransactionSigner::new(&network_info).sign_transaction(
            &mut tx_with_groups,
            &SignContexts::new_sighash(vec![deployer_key]),
        )?;

        let tx_json = TransactionView::from(tx_with_groups.get_tx_view().clone());
        self.submit_spv_transaction(spv, tx_json, update_input.info.cell.out_point, batch)
    }

    fn reorg_spv_cells(
        &self,
        spv: &SpvService,
        reorg_input: SpvReorgInput,
        mut spv_client: SpvClient,
        spv_update: packed::SpvUpdate,
        batch: Batch,
    ) -> Result<Option<InFlight>> {
        let network_info =
            NetworkInfo::new(self.ckb.network, self.ckb.ckb_endpoint.as_str().to_owned());
        let configuration = {
            let mut tmp = TransactionBuilderConfiguration::new_with_network(network_info.clone())?;
            tmp.fee_rate = self.ckb.fee_rate()?;
            tmp
        };

        let (deployer, deployer_key) = SecretKey::from_slice(&self.ckb.private_key.as_ref()[..])
            .map(|sk| {
                let pk = sk.public_key(&SECP256K1);
                let payload = CkbAddressPayload::from_pubkey(&pk);
                let address = CkbAddress::new(self.ckb.network, payload, true);
                (address, sk)
            })?;
        log::debug!("The SPV cells will be updated by {deployer}");

        let iterator = InputIterator::new_with_address(&[deployer.clone()], &network_info);
        let mut tx_builder = TransactionBuilder::default();

        let spv_inputs = {
            let spv_info_input = CellInput::new_builder()
                .previous_output(reorg_input.info.cell.out_point.clone())
                .build();
            let mut inputs = vec![spv_info_input];
            for client in &reorg_input.stale {
                let spv_client_input = CellInput::new_builder()
                    .previous_output(client.cell.out_point.clone())
                    .build();
                inputs.push(spv_client_input);
            }
            inputs
        };
        tx_builder.inputs(spv_inputs);

        let spv_contract_cell_dep = spv.storage.spv_contract_cell_dep()?;
        tx_builder.cell_dep(spv_contract_cell_dep);
        let spv_client_curr_cell_dep = CellDep::new_builder()
            .out_point(reorg_input.curr.cell.out_point)
            .dep_type(DepType::Code.into())
            .build();
        tx_builder.cell_dep(spv_client_curr_cell_dep);

        // Try to insert cell deps for the lock scripts.
        match self.ckb.network {
            NetworkType::Mainnet | NetworkType::Testnet => {
                let known_cell_dep = if self.ckb.network == NetworkType::Mainnet {
                    constants::mainnet::known_cell_dep
                } else {
                    constants::testnet::known_cell_dep
                };
                #[allow(clippy::mutable_key_type)]
                let mut handled_code_hashes = HashSet::new();
                let code_hash = reorg_input.info.cell.output.lock().code_hash();
                if handled_code_hashes.insert(code_hash.clone()) {
                    if let Some(cell_dep) = known_cell_dep(&code_hash) {
                        tx_builder.cell_dep(cell_dep);
                    }
                }
                for client in &reorg_input.stale {
                    let code_hash = client.cell.output.lock().code_hash();
                    if handled_code_hashes.insert(code_hash.clone()) {
                        if let Some(cell_dep) = known_cell_dep(&code_hash) {
                            tx_builder.cell_dep(cell_dep);
                        }
                    }
                }
            }
            _ => {
                log::warn!("Unsupport CKB network \"{}\"", self.ckb.network);
            }
        }

        let spv_outputs_data = {
            let mut spv_info = reorg_input.info.info.clone();
            spv_info.tip_client_id = reorg_input.info.next_tip_client_id();
            let packed_spv_info: packed::SpvInfo = spv_info.pack();
            let mut outputs_data = vec![packed_spv_info.as_bytes()];
            for client in &reorg_input.stale {
                spv_client.id = client.client.id;
                let packed_spv_client: packed::SpvClient = spv_client.pack();
                outputs_data.push(packed_spv_client.as_bytes());
            }
            outputs_data
        };
        let spv_outputs = if let Some(lock_script) = self.spv_owner_opt.lock_script() {
            let spv_info_capacity = Capacity::bytes(spv_outputs_data[0].len()).map_err(|err| {
                let msg = format!(
                    "failed to calculate the capacity for Bitcoin SPV info cell since {err}"
                );
                Error::other(msg)
            })?;
            let spv_client_capacity =
                Capacity::bytes(spv_outputs_data[1].len()).map_err(|err| {
                    let msg = format!(
                        "failed to calculate the capacity for Bitcoin SPV client cell since {err}"
                    );
                    Error::other(msg)
                })?;
            let info_output = reorg_input
                .info
                .cell
                .output
                .clone()
                .as_builder()
                .lock(lock_script.clone())
                .build_exact_capacity(spv_info_capacity)
                .map_err(|err| {
                    let msg = format!(
                        "failed to sum the total capacity for Bitcoin SPV info cell since {err}"
                    );
                    Error::other(msg)
                })?;
            let mut outputs = vec![info_output];
            for client in &reorg_input.stale {
                let client_output = client
                    .cell
                    .output
                    .clone()
                    .as_builder()
                    .lock(lock_script.clone())
                    .build_exact_capacity(spv_client_capacity)
                    .map_err(|err| {
                        let msg = format!(
                            "failed to sum the total capacity for Bitcoin SPV client cell since {err}"
                        );
                        Error::other(msg)
                    })?;
                outputs.push(client_output);
            }
            outputs
        } else {
            let mut outputs = vec![reorg_input.info.cell.output.clone()];
            for client in &reorg_input.stale {
                outputs.push(client.cell.output.clone());
            }
            outputs
        };
        tx_builder.outputs(spv_outputs);
        tx_builder.outputs_data(spv_outputs_data.iter().map(Pack::pack));

        #[allow(clippy::mutable_key_type)]
        let mut lock_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();
        #[allow(clippy::mutable_key_type)]
        let mut type_groups: HashMap<Byte32, ScriptGroup> = HashMap::default();

        {
            let lock_script = reorg_input.info.cell.output.lock();
            lock_groups
                .entry(lock_script.calc_script_hash())
                .or_insert_with(|| ScriptGroup::from_lock_script(&lock_script))
                .input_indices
                .push(0);
            for (index, client) in reorg_input.stale.iter().enumerate() {
                let lock_script = client.cell.output.lock();
                lock_groups
                    .entry(lock_script.calc_script_hash())
                    .or_insert_with(|| ScriptGroup::from_lock_script(&lock_script))
                    .input_indices
                    .push(index + 1);
            }
        }

        for (output_idx, output) in tx_builder.get_outputs().clone().iter().enumerate() {
            if let Some(type_script) = &output.type_().to_opt() {
                type_groups
                    .entry(type_script.calc_script_hash())
                    .or_insert_with(|| ScriptGroup::from_type_script(type_script))
                    .output_indices
                    .push(output_idx);
            }
        }

        let witness = {
            let type_args = BytesOpt::new_builder()
                .set(Some(Pack::pack(spv_update.as_slice())))
                .build();
            let witness_args = WitnessArgs::new_builder().output_type(type_args).build();
            Pack::pack(&witness_args.as_bytes())
        };
        tx_builder.witness(witness);
        tx_builder.witnesses(vec![PackedBytes::default(); reorg_input.stale.len()]);

        let mut change_builder =
            DefaultChangeBuilder::new(&configuration, (&deployer).into(), Vec::new());
        change_builder.init(&mut tx_builder);
        {
            let spv_info_input = TransactionInput {
                live_cell: reorg_input.info.cell.clone(),
                since: 0,
            };
            let _ = change_builder.check_balance(spv_info_input, &mut tx_builder);
            for client in &reorg_input.stale {
                let spv_client_input = TransactionInput {
                    live_cell: client.cell.clone(),
                    since: 0,
                };
                let _ = change_builder.check_balance(spv_client_input, &mut tx_builder);
            }
        };
        let contexts = HandlerContexts::default();

        let mut tx_with_groups = {
            let mut check_result = None;
            for (mut input_index, input) in iterator.enumerate() {
                input_index += 1 + reorg_input.stale.len(); // info + stale clients
                log::debug!("Try to find the {input_index}-th live cell for {deployer}");
                let input = input.map_err(|err| {
                    let msg = format!(
                        "failed to find {input_index}-th live cell for {deployer} since {err}"
                    );
                    Error::other(msg)
                })?;
                tx_builder.input(input.cell_input());
                tx_builder.witness(PackedBytes::default());

                let previous_output = input.previous_output();
                let lock_script = previous_output.lock();
                lock_groups
                    .entry(lock_script.calc_script_hash())
                    .or_insert_with(|| ScriptGroup::from_lock_script(&lock_script))
                    .input_indices
                    .push(input_index);

                if change_builder.check_balance(input, &mut tx_builder) {
                    let mut script_groups: Vec<ScriptGroup> = lock_groups
                        .into_values()
                        .chain(type_groups.into_values())
                        .collect();
                    for script_group in script_groups.iter_mut() {
                        for handler in configuration.get_script_handlers() {
                            for context in &contexts.contexts {
                                if handler.build_transaction(
                                    &mut tx_builder,
                                    script_group,
                                    context.as_ref(),
                                )? {
                                    break;
                                }
                            }
                        }
                    }
                    let tx_view = change_builder.finalize(tx_builder);

                    check_result = Some(TransactionWithScriptGroups::new(tx_view, script_groups));
                    break;
                }
            }
            check_result
        }
        .ok_or_else(|| {
            let msg = format!("{deployer}'s live cells are not enough");
            Error::other(msg)
        })?;

        TransactionSigner::new(&network_info).sign_transaction(
            &mut tx_with_groups,
            &SignContexts::new_sighash(vec![deployer_key]),
        )?;

        let tx_json = TransactionView::from(tx_with_groups.get_tx_view().clone());
        self.submit_spv_transaction(spv, tx_json, reorg_input.info.cell.out_point, batch)
    }

    fn submit_spv_transaction(
        &self,
        spv: &SpvService,
        tx_json: TransactionView,
        consumed_info: OutPoint,
        batch: Batch,
    ) -> Result<Option<InFlight>> {
        // Estimation, if enabled, happens before sending. An estimation error is
        // not evidence of a submission, even if it was a transport failure.
        let hash = spv.ckb_cli.prepare_transaction(&tx_json)?;
        if self.dry_run {
            return Ok(None);
        }
        InFlight::from_send(
            hash,
            consumed_info,
            batch,
            spv.ckb_cli.send_transaction(tx_json.inner, None),
        )
        .map(Some)
    }

    fn warn_reorg_limits(&self) {
        let limit = self.spv_headers_update_limit.get();
        let max = self.spv_reorg_headers_max.get();
        let shallow_reorg = limit.saturating_mul(2).saturating_add(1);
        if max < shallow_reorg {
            log::warn!(
                "--spv-reorg-headers-max {max} is below {shallow_reorg} \
                (2 * --spv-headers-update-limit + 1): on Testnet4, even a one-block \
                Bitcoin reorg replaces two SPV clients and may need more headers than \
                one reorg transaction may carry, so such reorgs will be skipped"
            );
        }
    }

    fn pause_for_ckb_limits(&self, key: &BatchKey) {
        log::warn!(
            "CKB rejected even one header to {} after header#{}; \
            pause submitting until the batch start changes",
            key.operation,
            key.base_height
        );
        self.take_a_break();
    }

    fn take_a_break(&self) {
        thread::sleep(time::Duration::from_secs(self.interval.max(1)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outpoint(byte: u8) -> OutPoint {
        let hash = H256([byte; 32]);
        OutPoint::new_builder().tx_hash(hash.pack()).build()
    }

    fn status(state: Status) -> TxStatus {
        TxStatus {
            block_number: (state == Status::Committed).then_some(100u64.into()),
            status: state,
            block_hash: None,
            reason: None,
        }
    }

    fn rpc_error(code: i64) -> RpcError {
        RpcError::Rpc(jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::ServerError(code),
            message: "test RPC response".into(),
            data: None,
        })
    }

    #[test]
    fn ckb_limit_errors() {
        let rejected = |code: i64, message: &str| {
            Error::from(RpcError::Rpc(jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::ServerError(code),
                message: message.into(),
                data: None,
            }))
        };
        assert!(exceeds_ckb_limits(&rejected(
            TX_SIZE_LIMIT,
            "PoolRejectedTransactionBySizeLimit: Transaction size 600000 exceeded maximum limit 512000",
        )));
        assert!(exceeds_ckb_limits(&rejected(
            TX_VERIFY_FAILED,
            "TransactionFailedToVerify: Verification failed Script(TransactionScriptError { \
            source: Outputs[0].Type, cause: ExceededMaximumCycles: expect cycles <= 70000000 })",
        )));
        // Other verification failures and transient rejections may be retried.
        assert!(!exceeds_ckb_limits(&rejected(
            TX_VERIFY_FAILED,
            "TransactionFailedToVerify: Verification failed Script(ValidationFailure(49))",
        )));
        assert!(!exceeds_ckb_limits(&rejected(-1106, "PoolIsFull")));
        assert!(!exceeds_ckb_limits(&Error::other("transport error")));
    }

    #[test]
    fn rejection_keeps_reason() {
        let mut tx = tracked();
        let reason = "Transaction size 600000 exceeded maximum limit 512000";
        let rejected = TxStatus {
            reason: Some(reason.to_owned()),
            ..status(Status::Rejected)
        };
        match tx.poll(rejected, no_indexer) {
            Ok(PreviousTx::Rejected(Some(text))) => assert!(mentions_ckb_limits(&text)),
            _ => panic!("a rejection must carry its reason"),
        }
        assert!(mentions_ckb_limits(
            "Verification failed Script(TransactionScriptError { source: Outputs[0].Type, \
            cause: ExceededMaximumCycles: expect cycles <= 70000000 })"
        ));
        assert!(!mentions_ckb_limits(
            "Resolve failed Dead(OutPoint(0x0000000000000000000000000000000000000000000000000000000000000000ffffffff))"
        ));
    }

    fn key(info: u8, operation: &'static str, base_height: u32) -> BatchKey {
        BatchKey {
            info: outpoint(info),
            operation,
            base_height,
        }
    }

    /// Linked headers after a base; `nonce` tells branches apart.
    fn branch(
        from: bitcoin::block::Header,
        count: usize,
        nonce: u32,
    ) -> Vec<bitcoin::block::Header> {
        let mut headers = Vec::with_capacity(count);
        let mut prev = from;
        for _ in 0..count {
            let mut header = prev;
            header.prev_blockhash = prev.block_hash();
            header.time += 600;
            header.nonce = nonce;
            headers.push(header);
            prev = header;
        }
        headers
    }

    fn chain_storage(count: usize) -> (tempfile::TempDir, Storage) {
        use bitcoin::{blockdata::constants::genesis_block, Network};

        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new(directory.path()).unwrap();
        let base = genesis_block(Network::Testnet).header;
        storage.initialize_with(0, base).unwrap();
        storage.append_headers(branch(base, count, 0)).unwrap();
        (directory, storage)
    }

    #[test]
    fn cap_halves_any_size() {
        let (_directory, storage) = chain_storage(150);
        let limit = NonZeroU32::new(10).unwrap();
        let update = key(1, "update", 100);
        let reject = |cap: &mut BatchCap, headers: u32| {
            cap.reject(Batch::new(&storage, update.clone(), headers).unwrap())
        };
        let next = |cap: &mut BatchCap| {
            cap.any_size(&update, &storage, limit)
                .unwrap()
                .map(NonZeroU32::get)
        };
        let mut cap = BatchCap::default();
        assert_eq!(next(&mut cap), Some(10));

        // Halve below the smallest rejected batch; never above the limit.
        reject(&mut cap, 10);
        assert_eq!(next(&mut cap), Some(5));
        reject(&mut cap, 40);
        assert_eq!(next(&mut cap), Some(5));
        reject(&mut cap, 5);
        assert_eq!(next(&mut cap), Some(2));
        // Even one header is too large: pause.
        reject(&mut cap, 1);
        assert_eq!(next(&mut cap), None);
    }

    #[test]
    fn cap_allows_min_work() {
        let (_directory, storage) = chain_storage(150);
        let limit = NonZeroU32::new(10).unwrap();
        let max = NonZeroU32::new(100).unwrap();
        let reorg = key(1, "reorg", 100);
        let reject = |cap: &mut BatchCap, headers: u32| {
            cap.reject(Batch::new(&storage, reorg.clone(), headers).unwrap())
        };
        let next = |cap: &mut BatchCap| {
            cap.work_bound(&reorg, &storage, limit, max)
                .unwrap()
                .map(|(limit, max)| (limit.get(), max.get()))
        };
        let mut cap = BatchCap::default();
        assert_eq!(next(&mut cap), Some((10, 100)));

        // After 10 headers are rejected, prefer 5 but still allow up to 9, so
        // a reorg which needs 8 headers to outweigh the stale tip is tried.
        reject(&mut cap, 10);
        assert_eq!(next(&mut cap), Some((5, 9)));
        // Once those 8 headers are rejected too, nothing below 8 is heavy
        // enough, so `reorg_batch` reports too many headers and the reorg pauses.
        reject(&mut cap, 8);
        assert_eq!(next(&mut cap), Some((4, 7)));
        reject(&mut cap, 2);
        assert_eq!(next(&mut cap), Some((1, 1)));
        reject(&mut cap, 1);
        assert_eq!(next(&mut cap), None);
    }

    #[test]
    fn cap_lifts_on_new_start() {
        let (_directory, storage) = chain_storage(150);
        let limit = NonZeroU32::new(10).unwrap();
        let reorg = key(1, "reorg", 100);
        let reject =
            |cap: &mut BatchCap| cap.reject(Batch::new(&storage, reorg.clone(), 1).unwrap());
        let next = |cap: &mut BatchCap, key: &BatchKey| cap.any_size(key, &storage, limit).unwrap();
        let mut cap = BatchCap::default();
        reject(&mut cap);
        assert_eq!(next(&mut cap, &reorg), None);

        // Bitcoin switched back to the on-chain branch: the same info cell now
        // takes an update, which must not inherit the failed reorg's cap.
        assert_eq!(next(&mut cap, &key(1, "update", 120)), Some(limit));
        // A different fork point or info cell is a different batch, too.
        reject(&mut cap);
        assert_eq!(next(&mut cap, &key(1, "reorg", 90)), Some(limit));
        reject(&mut cap);
        assert_eq!(next(&mut cap, &key(2, "reorg", 100)), Some(limit));
    }

    #[test]
    fn cap_lifts_on_new_branch() {
        let (_directory, storage) = chain_storage(150);
        let limit = NonZeroU32::new(10).unwrap();
        let reorg = key(1, "reorg", 100);
        let mut cap = BatchCap::default();
        cap.reject(Batch::new(&storage, reorg.clone(), 10).unwrap());
        assert_eq!(
            cap.any_size(&reorg, &storage, limit).unwrap(),
            NonZeroU32::new(5)
        );

        // Replace the headers after the start with another branch.
        storage.rollback_to(Some(100)).unwrap();
        let (_, base) = storage.tip_state().unwrap();
        storage.append_headers(branch(base, 50, 1)).unwrap();
        assert_eq!(cap.any_size(&reorg, &storage, limit).unwrap(), Some(limit));

        // A shorter branch which ends below the rejected batch also lifts it.
        cap.reject(Batch::new(&storage, reorg.clone(), 10).unwrap());
        storage.rollback_to(Some(105)).unwrap();
        assert_eq!(cap.any_size(&reorg, &storage, limit).unwrap(), Some(limit));
    }

    fn tracked() -> InFlight {
        let hash = H256([42; 32]);
        InFlight::from_send(hash.clone(), outpoint(1), test_batch(), Ok(hash)).unwrap()
    }

    fn test_batch() -> Batch {
        Batch {
            key: key(1, "update", 100),
            headers: 10,
            end_hash: <Hash as bitcoin::hashes::Hash>::all_zeros(),
        }
    }

    fn no_indexer() -> Result<(OutPoint, u64, ())> {
        panic!("indexer must not be queried while the transaction is uncommitted")
    }

    #[test]
    fn duplicate_tracks_the_locally_computed_hash() {
        let hash = H256([42; 32]);
        let batch = test_batch();
        let tx = InFlight::from_send(
            hash.clone(),
            outpoint(1),
            batch.clone(),
            Err(rpc_error(-1107)),
        )
        .unwrap();
        assert_eq!(tx.hash, hash);
        assert!(InFlight::from_send(hash, outpoint(1), batch, Err(rpc_error(-1104))).is_err());
    }

    #[test]
    fn committed_waits_for_the_indexer_then_returns_the_same_snapshot() {
        let mut tx = tracked();
        for state in [Status::Pending, Status::Proposed] {
            assert!(matches!(
                tx.poll(status(state), no_indexer),
                Ok(PreviousTx::Wait)
            ));
        }
        for (cell, height) in [(outpoint(1), 100), (outpoint(3), 98)] {
            assert!(matches!(
                tx.poll(status(Status::Committed), || Ok((cell, height, ()))),
                Ok(PreviousTx::Wait),
            ));
        }
        assert!(matches!(
            tx.poll(status(Status::Committed), || Ok((
                outpoint(2),
                101,
                "fresh snapshot"
            ))),
            Ok(PreviousTx::Indexed("fresh snapshot")),
        ));
    }

    #[test]
    fn consecutive_unknown_polls_are_bounded() {
        let mut tx = tracked();
        for state in [
            Status::Unknown,
            Status::Pending,
            Status::Unknown,
            Status::Unknown,
        ] {
            assert!(matches!(
                tx.poll(status(state), no_indexer),
                Ok(PreviousTx::Wait)
            ));
        }
        assert!(matches!(
            tx.poll(status(Status::Unknown), no_indexer),
            Ok(PreviousTx::Retry)
        ));
    }

    #[test]
    fn reorg_batch_min_work() {
        use bitcoin::{blockdata::constants::genesis_block, Network};

        // 20 linked headers after the base; every header carries the same work.
        let mut headers = vec![genesis_block(Network::Testnet).header];
        for _ in 0..20 {
            let mut header = *headers.last().unwrap();
            header.prev_blockhash = header.block_hash();
            header.time += 600;
            headers.push(header);
        }
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new(directory.path()).unwrap();
        storage.initialize_with(0, headers[0]).unwrap();
        storage.append_headers(headers[1..].to_vec()).unwrap();

        let work_at = |height: u32| -> U256 {
            storage
                .generate_headers_root(height)
                .unwrap()
                .unpack()
                .partial_chain_work
        };
        let count = |count: u32| NonZeroU32::new(count).unwrap();
        let choose = |prev: u32, limit: u32, max: u32, stale_work: U256| {
            reorg_batch(&storage, prev, count(limit), count(max), stale_work).unwrap()
        };
        let ready = |n: u32| ReorgBatch::Ready(count(n));

        // The configured limit already outweighs the stale tip.
        assert_eq!(choose(0, 15, 100, work_at(5)), ready(15));
        // The batch is capped by the headers storage has, and by `max`.
        assert_eq!(choose(0, 50, 100, work_at(5)), ready(20));
        assert_eq!(choose(0, 50, 8, work_at(5)), ready(8));
        // The limit is too light: carry the fewest headers that outweigh it.
        assert_eq!(choose(0, 3, 100, work_at(10)), ready(11));
        assert_eq!(choose(4, 3, 100, work_at(10)), ready(7));
        assert_eq!(choose(0, 3, 11, work_at(10)), ready(11));
        // After CKB rejected 10 headers, `BatchCap::work_bound` prefers 5 and
        // allows up to 9: a reorg needing 8 headers is still tried.
        let mut cap = BatchCap::default();
        let reorg = key(1, "reorg", 0);
        cap.reject(Batch::new(&storage, reorg.clone(), 10).unwrap());
        let (limit, max) = cap
            .work_bound(&reorg, &storage, count(10), count(100))
            .unwrap()
            .unwrap();
        assert_eq!(
            reorg_batch(&storage, 0, limit, max, work_at(7)).unwrap(),
            ready(8)
        );
        // Outweighing it needs more headers than one transaction may carry.
        assert_eq!(
            choose(0, 3, 10, work_at(10)),
            ReorgBatch::TooManyHeaders(11)
        );
        // Equal work is not better; the whole storage chain is not enough.
        assert_eq!(choose(0, 3, 100, work_at(20)), ReorgBatch::NotEnoughWork);
        // Nothing to carry after the storage tip.
        assert_eq!(choose(20, 3, 100, U256::zero()), ReorgBatch::NotEnoughWork);
    }
}

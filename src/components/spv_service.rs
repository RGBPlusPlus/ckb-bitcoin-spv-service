//! Internal SPV service.

use bitcoin::BlockHash;
use ckb_bitcoin_spv_verifier::types::{
    core::{Hash, Header, HeaderDigest},
    prelude::{Pack as VPack, Unpack as VUnpack},
};
use ckb_sdk::rpc::CkbRpcClient;
use ckb_types::prelude::*;

use crate::{
    components::{BitcoinClient, ElectrsClient, SpvClientCell, SpvInfoCell, SpvInstance, Storage},
    prelude::*,
    result::{Error, Result},
};

use super::sync_status::SyncStatusCache;

/// The state `SpvService::sync_storage` leaves storage in.
#[derive(Debug, PartialEq, Eq)]
pub enum StorageSync {
    /// Storage follows the Bitcoin node's best chain.
    Synced,
    /// The Bitcoin chain changed during the download; sync again right away.
    Interrupted,
    /// The Bitcoin node has not reached the storage base yet, so storage cannot
    /// be checked against its best chain; wait instead of submitting headers.
    NodeBehind,
}

impl StorageSync {
    fn from_download(headers: Option<Vec<Header>>) -> Self {
        if headers.is_some() {
            Self::Synced
        } else {
            Self::Interrupted
        }
    }
}

#[derive(Clone)]
pub struct SpvService {
    pub(crate) ckb_cli: CkbRpcClient,
    pub(crate) btc_cli: BitcoinClient,
    pub(crate) electrs_cli: Option<ElectrsClient>,
    pub(crate) storage: Storage,
    pub(crate) sync_status: SyncStatusCache,
}

pub struct SpvUpdateInput {
    pub(crate) info: SpvInfoCell,
    pub(crate) curr: SpvClientCell,
    pub(crate) next: SpvClientCell,
}

pub struct SpvReorgInput {
    pub(crate) info: SpvInfoCell,
    pub(crate) curr: SpvClientCell,
    pub(crate) stale: Vec<SpvClientCell>,
}

pub enum SpvOperation {
    Update(SpvUpdateInput),
    Reorg(SpvReorgInput),
    Reset(SpvReorgInput),
}

impl SpvService {
    pub(crate) fn load_instance(&self) -> Result<SpvInstance> {
        let spv_type_script = self.storage.spv_contract_type_script()?;
        let instance = self.ckb_cli.find_spv_cells(spv_type_script)?;
        if let Some(cell) = instance.clients.get(&instance.info.info.tip_client_id) {
            let range = &cell.client.headers_mmr_root;
            self.sync_status
                .observe_confirmed_client(range.min_height, range.max_height);
        }
        Ok(instance)
    }

    pub(crate) fn select_operation(&self, ins: SpvInstance) -> Result<SpvOperation> {
        let spv_client_curr = ins
            .clients
            .get(&ins.info.info.tip_client_id)
            .ok_or_else(|| {
                let msg = format!(
                    "the current tip SPV client (id={}) is not found",
                    ins.info.info.tip_client_id
                );
                Error::other(msg)
            })?
            .to_owned();
        log::info!("[onchain] tip SPV client {}", spv_client_curr.client);

        let spv_header_root_curr = &spv_client_curr.client.headers_mmr_root;
        let spv_height_curr = spv_header_root_curr.max_height;

        if !self.storage_contains(spv_header_root_curr)? {
            log::warn!("[onchain] header#{spv_height_curr}; mmr-root {spv_header_root_curr}");
            let input = self.prepare_reorg_input(ins)?;
            if input.info.clients_count as usize == input.stale.len() {
                log::warn!("[onchain] all SPV clients are stale, resetting");
                return Ok(SpvOperation::Reset(input));
            } else {
                return Ok(SpvOperation::Reorg(input));
            }
        }

        let next_tip_client_id = ins.info.next_tip_client_id();
        let spv_client_next = ins
            .clients
            .get(&next_tip_client_id)
            .ok_or_else(|| {
                let msg = format!("the next tip SPV client (id={next_tip_client_id}) is not found");
                Error::other(msg)
            })?
            .to_owned();
        log::trace!(
            "[onchain] old SPV client {} (will be next)",
            spv_client_next.client
        );
        let input = SpvUpdateInput {
            info: ins.info,
            curr: spv_client_curr,
            next: spv_client_next,
        };
        Ok(SpvOperation::Update(input))
    }

    /// Whether the storage chain contains the headers an SPV client commits to.
    ///
    /// Rolling back storage only moves its tip, so headers above the tip may be
    /// left over from a replaced branch. A client above the storage tip is never
    /// contained, e.g. after Bitcoin switched to a shorter but heavier branch.
    pub(crate) fn storage_contains(&self, root: &HeaderDigest) -> Result<bool> {
        let (stg_tip_height, _) = self.storage.tip_state()?;
        if root.max_height > stg_tip_height {
            log::warn!(
                "[onchain] header#{} is above the storage tip header#{stg_tip_height}",
                root.max_height
            );
            return Ok(false);
        }
        let stg_root = self.storage.generate_headers_root(root.max_height)?;
        if stg_root.as_slice() == root.pack().as_slice() {
            return Ok(true);
        }
        log::warn!(
            "[storage] header#{}; mmr-root {}",
            root.max_height,
            stg_root.unpack()
        );
        Ok(false)
    }

    /// The newest SPV client whose headers storage holds, from the tip client
    /// towards older ones. During a reorg it is the checkpoint shared with the
    /// storage branch, and older clients only cover fewer headers.
    pub(crate) fn newest_contained_client(
        &self,
        instance: &SpvInstance,
    ) -> Result<Option<SpvClientCell>> {
        for cell in instance.clients_from_tip() {
            if self.storage_contains(&cell.client.headers_mmr_root)? {
                return Ok(Some(cell));
            }
        }
        Ok(None)
    }

    pub(crate) fn prepare_reorg_input(&self, ins: SpvInstance) -> Result<SpvReorgInput> {
        let SpvInstance { mut info, clients } = ins;
        let mut stale = Vec::new();
        for _ in 0..clients.len() {
            let cell = clients.get(&info.info.tip_client_id).ok_or_else(|| {
                let msg = format!(
                    "the SPV client (id={}) is not found",
                    info.info.tip_client_id
                );
                Error::other(msg)
            })?;

            let spv_header_root = &cell.client.headers_mmr_root;

            if self.storage_contains(spv_header_root)? {
                if stale.len() > 1 {
                    let input = SpvReorgInput {
                        info,
                        curr: cell.clone(),
                        stale,
                    };
                    return Ok(input);
                } else {
                    log::warn!(
                        "[TODO::KnownIssue] this is a dirty patch to fix an issue in the contract: \
                        update and reorg only 1 block are indistinguishable, \
                        let's just reorg 1 more client"
                    );
                }
            }

            log::trace!(
                "[onchain] header#{}; mmr-root {spv_header_root}",
                spv_header_root.max_height
            );

            stale.push(cell.clone());
            info.info.tip_client_id = info.prev_tip_client_id();
        }
        log::warn!("failed to reorg since no common parent between SPV instance and storage");
        let input = SpvReorgInput {
            info: info.clone(),
            curr: clients.get(&info.info.tip_client_id).unwrap().clone(),
            stale,
        };
        Ok(input)
    }

    pub(crate) fn sync_storage(&self, batch_size: u32) -> Result<StorageSync> {
        let spv = &self;
        let (stg_tip_height, stg_tip_header) = spv.storage.tip_state()?;
        self.sync_status.observe_local_tip(stg_tip_height);
        let stg_tip_hash = stg_tip_header.block_hash();
        log::info!("[storage] header#{stg_tip_height:07}, {stg_tip_hash:#x}; tip");

        let (btc_tip_height, btc_tip_header) = spv.btc_cli.get_tip_state()?;
        self.sync_status.observe_bitcoin_tip(btc_tip_height);
        log::info!(
            "[bitcoin] header#{btc_tip_height:07}, {:#x}; tip; prev {:#x}",
            btc_tip_header.block_hash(),
            btc_tip_header.prev_blockhash
        );

        let (stg_base_height, _) = spv.storage.base_state()?;
        if btc_tip_height < stg_base_height {
            // Storage starts at a checkpoint the node has not reached yet, e.g.
            // the node is still syncing; nothing to compare until it catches up.
            log::warn!(
                "[bitcoin] tip header#{btc_tip_height:07} is below the storage base \
                header#{stg_base_height:07}; wait for the node to catch up"
            );
            return Ok(StorageSync::NodeBehind);
        }

        // Compare at the lower tip, not only when Bitcoin is higher: on Testnet4
        // (BIP 94) a shorter branch can outweigh a longer one built from
        // minimum-difficulty blocks, so the best chain may end below storage.
        let check_height = stg_tip_height.min(btc_tip_height);
        let btc_hash = if check_height == btc_tip_height {
            btc_tip_header.block_hash()
        } else {
            spv.btc_cli
                .get_block_header_by_height(check_height)?
                .block_hash()
        };
        let stg_hash = spv.storage.bitcoin_header_hash(check_height)?;
        if stg_hash == btc_hash.into() {
            if stg_tip_height >= btc_tip_height {
                // Storage is on the best chain; any extra headers extend it,
                // e.g. the Bitcoin node has not caught up yet.
                return Ok(StorageSync::Synced);
            }
            let headers_opt = self.sync_storage_internal(
                batch_size,
                stg_tip_height + 1,
                btc_tip_height,
                stg_tip_hash,
            )?;
            return Ok(StorageSync::from_download(headers_opt));
        }

        log::info!("Try to find the height when fork happened");
        let mut fork_point = None;

        for height in (stg_base_height..check_height).rev() {
            let stg_hash = spv.storage.bitcoin_header_hash(height)?;
            log::debug!("[storage] header#{height:07}, {stg_hash:#x}");
            let btc_header = spv.btc_cli.get_block_header_by_height(height)?;
            let btc_hash: Hash = btc_header.block_hash().into();
            log::debug!("[bitcoin] header#{height:07}, {btc_hash:#x}");

            if stg_hash == btc_hash {
                log::info!("Fork happened at height {height}");
                fork_point = Some((height, btc_hash));
                break;
            }
        }

        if fork_point.is_none() {
            let msg = format!(
                "reorg failed since the fork point is ahead than \
                local start height {stg_base_height}"
            );
            return Err(Error::other(msg));
        }
        let (fork_height, fork_hash) = fork_point.unwrap();

        log::warn!("The chain in storage rollback to header#{fork_height:07}, {fork_hash:#x}");
        spv.storage.rollback_to(Some(fork_height))?;
        self.sync_status.observe_local_tip(fork_height);

        let headers_opt = self.sync_storage_internal(
            batch_size,
            fork_height + 1,
            btc_tip_height,
            fork_hash.into(),
        )?;
        Ok(StorageSync::from_download(headers_opt))
    }

    fn sync_storage_internal(
        &self,
        batch_size: u32,
        mut start_height: u32,
        end_height: u32,
        mut start_hash: BlockHash,
    ) -> Result<Option<Vec<Header>>> {
        let spv = self;
        let mut headers = Vec::new();
        while start_height <= end_height {
            let mut next_height = start_height + batch_size;
            if next_height > end_height {
                next_height = end_height;
            }

            let tmp_headers = if let Some(headers) =
                spv.btc_cli
                    .get_headers(start_height, next_height, start_hash)?
            {
                headers
            } else {
                return Ok(None);
            };

            start_height = next_height + 1;
            if let Some(header) = tmp_headers.last() {
                start_hash = header.block_hash();
            } else {
                return Ok(None);
            }
            headers.extend_from_slice(&tmp_headers);
            let (height, _) = spv.storage.append_headers(tmp_headers)?;
            self.sync_status.observe_local_tip(height);
        }
        Ok(Some(headers))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        thread,
    };

    use bitcoin::{blockdata::constants::genesis_block, consensus::encode::serialize_hex, Network};
    use serde_json::{json, Value};

    use super::*;

    /// Linked headers after `from`; `nonce` tells branches apart.
    fn branch(from: Header, count: usize, nonce: u32) -> Vec<Header> {
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

    /// Serves `chain` (indexed by height) as a Bitcoin node's best chain, with
    /// the JSON-RPC methods `BitcoinClient` uses to sync headers.
    fn serve_best_chain(chain: Vec<Header>) -> url::Url {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let chain = chain.clone();
                thread::spawn(move || serve_connection(stream, &chain));
            }
        });
        format!("http://{address}/").parse().unwrap()
    }

    fn serve_connection(stream: TcpStream, chain: &[Header]) {
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
            let params = &request["params"];
            let height_of = |hash: &Value| {
                chain
                    .iter()
                    .position(|header| header.block_hash().to_string() == hash.as_str().unwrap())
                    .unwrap()
            };
            let result = match request["method"].as_str().unwrap() {
                "getbestblockhash" => json!(chain.last().unwrap().block_hash().to_string()),
                "getblockstats" => json!({ "height": height_of(&params[0]) }),
                "getblockheader" => json!(serialize_hex(&chain[height_of(&params[0])])),
                "getblockhash" => {
                    json!(chain[params[0].as_u64().unwrap() as usize]
                        .block_hash()
                        .to_string())
                }
                method => panic!("unexpected Bitcoin RPC method {method}"),
            };
            let response = json!({ "result": result, "error": null, "id": request["id"] });
            let response = response.to_string();
            write!(
                writer,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                Content-Length: {}\r\n\r\n{response}",
                response.len()
            )
            .unwrap();
        }
    }

    /// Storage holds genesis plus `stored`; the Bitcoin node's best chain is
    /// genesis plus `best`.
    fn service(stored: &[Header], best: &[Header]) -> (tempfile::TempDir, SpvService) {
        let genesis = genesis_block(Network::Testnet).header;
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new(directory.path()).unwrap();
        storage.initialize_with(0, genesis).unwrap();
        storage.append_headers(stored.to_vec()).unwrap();
        let chain = [&[genesis][..], best].concat();
        let service = SpvService {
            ckb_cli: CkbRpcClient::new("http://127.0.0.1:1"),
            btc_cli: BitcoinClient::new(serve_best_chain(chain), None, None),
            electrs_cli: None,
            storage,
            sync_status: Default::default(),
        };
        (directory, service)
    }

    #[test]
    fn sync_shorter_best_chain() {
        // BIP 94: a normal-difficulty block can outweigh several minimum-
        // difficulty blocks, so the best chain may end below the storage tip.
        let genesis = genesis_block(Network::Testnet).header;
        let long = branch(genesis, 20, 0);
        let short = [&long[..10], &branch(long[9], 5, 1)[..]].concat();
        let (_directory, spv) = service(&long, &short);
        let stale_root = spv.storage.generate_headers_root(20).unwrap().unpack();
        let common_root = spv.storage.generate_headers_root(8).unwrap().unpack();

        assert_eq!(spv.sync_storage(30).unwrap(), StorageSync::Synced);
        let (tip_height, tip_header) = spv.storage.tip_state().unwrap();
        assert_eq!(tip_height, 15);
        assert_eq!(tip_header.block_hash(), short[14].block_hash());

        // Storage rolled back, so an SPV client on the stale branch above the
        // new tip must not match leftover headers.
        assert!(!spv.storage_contains(&stale_root).unwrap());
        assert!(spv.storage_contains(&common_root).unwrap());
    }

    #[test]
    fn skips_stale_clients() {
        use std::collections::HashMap;

        use ckb_bitcoin_spv_verifier::types::{core, packed};
        use ckb_sdk::traits::LiveCell;
        use ckb_types::packed::{CellOutput, OutPoint};

        // On-chain clients at 20, 30 and 40 (the tip) on a long branch; storage
        // then switches to a branch which forks after 25 and ends at 31.
        let genesis = genesis_block(Network::Testnet).header;
        let long = branch(genesis, 40, 0);
        let short = [&long[..25], &branch(long[24], 6, 1)[..]].concat();
        let (_directory, spv) = service(&long, &long);
        let live_cell = || LiveCell {
            output: CellOutput::default(),
            output_data: Default::default(),
            out_point: OutPoint::default(),
            block_number: 0,
            tx_index: 0,
        };
        let clients = [20, 30, 40]
            .into_iter()
            .enumerate()
            .map(|(id, height)| {
                let client = core::SpvClient {
                    id: id as u8,
                    tip_block_hash: long[height - 1].block_hash().into(),
                    headers_mmr_root: spv
                        .storage
                        .generate_headers_root(height as u32)
                        .unwrap()
                        .unpack(),
                    target_adjust_info: packed::TargetAdjustInfo::default(),
                };
                let cell = SpvClientCell {
                    client,
                    cell: live_cell(),
                };
                (id as u8, cell)
            })
            .collect::<HashMap<_, _>>();
        let instance = SpvInstance {
            info: SpvInfoCell {
                info: core::SpvInfo { tip_client_id: 2 },
                cell: live_cell(),
                clients_count: 3,
            },
            clients,
        };
        let newest = |spv: &SpvService| {
            spv.newest_contained_client(&instance)
                .unwrap()
                .map(|cell| cell.client.headers_mmr_root.max_height)
        };
        assert_eq!(newest(&spv), Some(40));

        spv.storage.rollback_to(Some(25)).unwrap();
        spv.storage.append_headers(short[25..].to_vec()).unwrap();
        // 40 is above the storage tip, 30 is on the stale branch: take 20.
        assert_eq!(newest(&spv), Some(20));
    }

    #[test]
    fn sync_node_below_base() {
        let genesis = genesis_block(Network::Testnet).header;
        let chain = branch(genesis, 20, 0);
        // Storage starts at checkpoint header#10; the node only reached #5.
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new(directory.path()).unwrap();
        storage.initialize_with(10, chain[9]).unwrap();
        storage.append_headers(chain[10..].to_vec()).unwrap();
        let best = [&[genesis][..], &chain[..5]].concat();
        let spv = SpvService {
            ckb_cli: CkbRpcClient::new("http://127.0.0.1:1"),
            btc_cli: BitcoinClient::new(serve_best_chain(best), None, None),
            electrs_cli: None,
            storage,
            sync_status: Default::default(),
        };

        assert_eq!(spv.sync_storage(30).unwrap(), StorageSync::NodeBehind);
        assert_eq!(spv.storage.tip_state().unwrap().0, 20);
    }

    #[test]
    fn sync_lagging_node() {
        let genesis = genesis_block(Network::Testnet).header;
        let chain = branch(genesis, 20, 0);
        let (_directory, spv) = service(&chain, &chain[..15]);

        assert_eq!(spv.sync_storage(30).unwrap(), StorageSync::Synced);
        assert_eq!(spv.storage.tip_state().unwrap().0, 20);
    }
}

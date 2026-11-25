use bitcoin::{
    blockdata::constants::genesis_block, consensus::serialize, merkle_tree::MerkleBlock, Network,
};
use ckb_bitcoin_spv_verifier::{
    error::VerifyTxError,
    types::{core, packed, prelude::*},
};

use super::{prelude::BitcoinSpvStorage, Storage};

#[test]
fn generated_transaction_proof_rejects_a_tampered_header_mmr() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path()).unwrap();
    let block = genesis_block(Network::Bitcoin);
    let txid = block.txdata[0].txid();
    let mut client = storage.initialize_with(0, block.header).unwrap();

    // Add a linked header so the generated proof contains a sibling to tamper with.
    // This exercises storage/proof compatibility, not Bitcoin consensus validation.
    let mut next_header = block.header;
    next_header.prev_blockhash = block.block_hash();
    next_header.nonce = next_header.nonce.wrapping_add(1);
    storage.append_headers(vec![next_header]).unwrap();
    client.headers_mmr_root = storage.generate_headers_root(1).unwrap().unpack();
    client.tip_block_hash = next_header.block_hash().into();
    let client: packed::SpvClient = client.pack();
    let header_proof = storage.generate_headers_proof(1, vec![0]).unwrap();
    assert_eq!(header_proof.len(), 1);
    let merkle_block = MerkleBlock::from_block_with_predicate(&block, |id| *id == txid);
    let proof = packed::TransactionProof::new_builder()
        .tx_index(0u32.pack())
        .height(0u32.pack())
        .transaction_proof(core::Bytes::from(serialize(&merkle_block)).pack())
        .header_proof(header_proof.pack())
        .build();
    assert!(client
        .verify_transaction(txid.as_ref(), proof.as_reader(), 1)
        .is_ok());

    let mut forged_items = header_proof;
    forged_items[0].children_hash = core::Hash::hash(b"tampered sibling");
    let forged = proof.as_builder().header_proof(forged_items.pack()).build();
    assert_eq!(
        client
            .verify_transaction(txid.as_ref(), forged.as_reader(), 1)
            .map(|_| ())
            .map_err(|error| error as i8),
        Err(VerifyTxError::HeaderMmrProof as i8),
    );
}

// These fixtures deliberately do not mine headers. Storage checks linkage and
// builds MMRs; PoW/Bitcoin consensus belongs to the verifier's separate tests.
// All-leaf checks request zero confirmations so they include the current tip.
fn linked_blocks(count: usize, nonce_offset: u32) -> Vec<bitcoin::Block> {
    let mut blocks = vec![genesis_block(Network::Bitcoin)];
    for index in 1..count {
        let mut block = blocks[index - 1].clone();
        block.header.prev_blockhash = blocks[index - 1].block_hash();
        block.header.time += 600;
        block.header.nonce = block.header.nonce.wrapping_add(nonce_offset + index as u32);
        blocks.push(block);
    }
    blocks
}

fn transaction_proof(
    storage: &Storage,
    block: &bitcoin::Block,
    height: u32,
    tip: u32,
) -> packed::TransactionProof {
    let txid = block.txdata[0].txid();
    let merkle_block = MerkleBlock::from_block_with_predicate(block, |id| *id == txid);
    packed::TransactionProof::new_builder()
        .tx_index(0u32.pack())
        .height(height.pack())
        .transaction_proof(core::Bytes::from(serialize(&merkle_block)).pack())
        .header_proof(
            storage
                .generate_headers_proof(tip, vec![height])
                .unwrap()
                .pack(),
        )
        .build()
}

fn client_at_tip(storage: &Storage, mut checkpoint: core::SpvClient) -> packed::SpvClient {
    let (height, header) = storage.tip_state().unwrap();
    checkpoint.headers_mmr_root = storage.generate_headers_root(height).unwrap().unpack();
    checkpoint.tip_block_hash = header.block_hash().into();
    checkpoint.pack()
}

#[test]
fn batching_headers_preserves_roots_and_transaction_proofs() {
    // Exercise a nonzero base and several peak/carry boundaries, not just a
    // two-leaf tree. Every append strategy must produce the same public state.
    const BASE: u32 = 42;
    let blocks = linked_blocks(10, 1);
    let one_directory = tempfile::tempdir().unwrap();
    let one = Storage::new(one_directory.path()).unwrap();
    let checkpoint = one.initialize_with(BASE, blocks[0].header).unwrap();
    one.append_headers(blocks[1..].iter().map(|block| block.header).collect())
        .unwrap();
    let expected_client = client_at_tip(&one, checkpoint);
    let tip = BASE + blocks.len() as u32 - 1;

    for batch_size in [1, 2, 3, 4, 8] {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new(directory.path()).unwrap();
        let checkpoint = storage.initialize_with(BASE, blocks[0].header).unwrap();
        for batch in blocks[1..].chunks(batch_size) {
            storage
                .append_headers(batch.iter().map(|block| block.header).collect())
                .unwrap();
        }
        assert_eq!(storage.base_state().unwrap(), one.base_state().unwrap());
        assert_eq!(storage.tip_state().unwrap(), one.tip_state().unwrap());
        let client = client_at_tip(&storage, checkpoint);
        assert_eq!(client.as_slice(), expected_client.as_slice());
        for (index, block) in blocks.iter().enumerate() {
            let height = BASE + index as u32;
            let proof = transaction_proof(&storage, block, height, tip);
            assert_eq!(
                proof.as_slice(),
                transaction_proof(&one, block, height, tip).as_slice()
            );
            assert!(client
                .verify_transaction(block.txdata[0].txid().as_ref(), proof.as_reader(), 0)
                .is_ok());
        }
    }
}

#[test]
fn reopening_storage_preserves_state_and_can_continue_appending() {
    const BASE: u32 = 42;
    let blocks = linked_blocks(10, 1);
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path()).unwrap();
    let checkpoint = storage.initialize_with(BASE, blocks[0].header).unwrap();
    storage
        .append_headers(blocks[1..7].iter().map(|block| block.header).collect())
        .unwrap();
    let tip_before = storage.tip_state().unwrap();
    let root_before = storage.generate_headers_root(tip_before.0).unwrap();
    let proof_before = transaction_proof(&storage, &blocks[3], BASE + 3, tip_before.0);
    drop(storage);

    let reopened = Storage::new(directory.path()).unwrap();
    assert!(reopened.is_initialized().unwrap());
    assert_eq!(reopened.base_state().unwrap(), (BASE, blocks[0].header));
    assert_eq!(reopened.tip_state().unwrap(), tip_before);
    assert_eq!(
        reopened
            .generate_headers_root(tip_before.0)
            .unwrap()
            .as_slice(),
        root_before.as_slice()
    );
    assert_eq!(
        transaction_proof(&reopened, &blocks[3], BASE + 3, tip_before.0).as_slice(),
        proof_before.as_slice()
    );
    let client = client_at_tip(&reopened, checkpoint.clone());
    assert!(client
        .verify_transaction(
            blocks[3].txdata[0].txid().as_ref(),
            proof_before.as_reader(),
            1
        )
        .is_ok());

    reopened
        .append_headers(blocks[7..].iter().map(|block| block.header).collect())
        .unwrap();
    let reference_directory = tempfile::tempdir().unwrap();
    let reference = Storage::new(reference_directory.path()).unwrap();
    reference.initialize_with(BASE, blocks[0].header).unwrap();
    reference
        .append_headers(blocks[1..].iter().map(|block| block.header).collect())
        .unwrap();
    assert_eq!(
        reopened.tip_state().unwrap(),
        reference.tip_state().unwrap()
    );
    let tip = BASE + blocks.len() as u32 - 1;
    assert_eq!(
        reopened.generate_headers_root(tip).unwrap().as_slice(),
        reference.generate_headers_root(tip).unwrap().as_slice()
    );
    let client = client_at_tip(&reopened, checkpoint);
    for (index, block) in blocks.iter().enumerate() {
        let proof = transaction_proof(&reopened, block, BASE + index as u32, tip);
        assert!(client
            .verify_transaction(block.txdata[0].txid().as_ref(), proof.as_reader(), 0)
            .is_ok());
    }
}

#[test]
fn rollback_and_replace_branch_matches_fresh_storage() {
    const BASE: u32 = 42;
    let original = linked_blocks(10, 1);
    // Keep the first four blocks, then replace a suffix spanning MMR peaks.
    let mut replacement = original[..4].to_vec();
    for index in 4..original.len() {
        let mut block = original[index].clone();
        block.header.prev_blockhash = replacement[index - 1].block_hash();
        block.header.nonce = block.header.nonce.wrapping_add(100);
        replacement.push(block);
    }
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path()).unwrap();
    let checkpoint = storage.initialize_with(BASE, original[0].header).unwrap();
    storage
        .append_headers(original[1..].iter().map(|block| block.header).collect())
        .unwrap();
    let tip = BASE + original.len() as u32 - 1;
    let old_proof = transaction_proof(&storage, &original[6], BASE + 6, tip);
    let old_client = client_at_tip(&storage, checkpoint.clone());
    assert!(old_client
        .verify_transaction(
            original[6].txdata[0].txid().as_ref(),
            old_proof.as_reader(),
            1
        )
        .is_ok());

    storage.rollback_to(Some(BASE + 3)).unwrap();
    assert_eq!(storage.tip_state().unwrap(), (BASE + 3, original[3].header));
    storage
        .append_headers(replacement[4..].iter().map(|block| block.header).collect())
        .unwrap();
    let reference_directory = tempfile::tempdir().unwrap();
    let reference = Storage::new(reference_directory.path()).unwrap();
    reference
        .initialize_with(BASE, replacement[0].header)
        .unwrap();
    reference
        .append_headers(replacement[1..].iter().map(|block| block.header).collect())
        .unwrap();
    assert_eq!(storage.tip_state().unwrap(), reference.tip_state().unwrap());
    assert_eq!(
        storage.generate_headers_root(tip).unwrap().as_slice(),
        reference.generate_headers_root(tip).unwrap().as_slice()
    );
    let client = client_at_tip(&storage, checkpoint);
    assert_ne!(
        client.headers_mmr_root().as_slice(),
        old_client.headers_mmr_root().as_slice()
    );
    for (index, block) in replacement.iter().enumerate() {
        let height = BASE + index as u32;
        let proof = transaction_proof(&storage, block, height, tip);
        assert_eq!(
            proof.as_slice(),
            transaction_proof(&reference, block, height, tip).as_slice()
        );
        assert!(client
            .verify_transaction(block.txdata[0].txid().as_ref(), proof.as_reader(), 0)
            .is_ok());
    }
    assert_eq!(
        client
            .verify_transaction(
                original[6].txdata[0].txid().as_ref(),
                old_proof.as_reader(),
                1
            )
            .map(|_| ())
            .map_err(|error| error as i8),
        Err(VerifyTxError::HeaderMmrProof as i8)
    );
}

#[test]
fn testnet4_retarget() {
    use std::num::NonZeroU32;

    use bitcoin::{blockdata::constants::DIFFCHANGE_INTERVAL, CompactTarget};
    use ckb_bitcoin_spv_verifier::constants::{FLAG_CHAIN_TYPE_TESTNET, FLAG_CHAIN_TYPE_TESTNET4};

    // A whole difficulty period whose first block carries the real difficulty
    // and whose last block is a 20-minute minimum-difficulty block. The period
    // lasts exactly two weeks, so the retarget keeps the base difficulty.
    const PERIOD_BITS: u32 = 0x1905_2250;
    const MIN_DIFFICULTY_BITS: u32 = 0x1d00_ffff;
    const TWO_WEEKS: u32 = 14 * 24 * 60 * 60;

    let mut headers = linked_blocks(DIFFCHANGE_INTERVAL as usize, 0)
        .into_iter()
        .map(|block| block.header)
        .collect::<Vec<_>>();
    let start_time = headers[0].time;
    headers[0].bits = CompactTarget::from_consensus(PERIOD_BITS);
    for index in 1..headers.len() {
        headers[index].prev_blockhash = headers[index - 1].block_hash();
        if index == headers.len() - 1 {
            headers[index].bits = CompactTarget::from_consensus(MIN_DIFFICULTY_BITS);
            headers[index].time = start_time + TWO_WEEKS;
        }
    }

    let next_bits = |flags: u8| {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new(directory.path()).unwrap();
        storage.initialize_with(0, headers[0]).unwrap();
        storage.append_headers(headers[1..].to_vec()).unwrap();
        let (client, update) = storage
            .generate_spv_client_and_spv_update(0, NonZeroU32::MAX, flags)
            .unwrap();
        assert_eq!(client.headers_mmr_root.max_height, DIFFCHANGE_INTERVAL - 1);
        assert_eq!(update.headers().len(), headers.len() - 1);
        let (time, bits) = client.target_adjust_info.decode().unwrap();
        assert_eq!(time, start_time);
        bits.to_consensus()
    };

    // BIP-94: Testnet4 retargets from the first block, ignoring the
    // minimum-difficulty exception at the end of the period.
    assert_eq!(next_bits(FLAG_CHAIN_TYPE_TESTNET4), PERIOD_BITS);
    // Testnet3 retargets from the last block, so the exception leaks through.
    assert_eq!(next_bits(FLAG_CHAIN_TYPE_TESTNET), MIN_DIFFICULTY_BITS);
}

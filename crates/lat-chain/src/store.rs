//! Durable block store + transaction index, on the [`lat_store::KVStore`]
//! abstraction.
//!
//! Latebra state is a pure function of `genesis + the ordered blocks`, so the
//! durable thing we must keep is the block log. This stores every accepted block
//! and, alongside it, a **transaction index** so an explorer/RPC can find the
//! block containing a given transaction without scanning the chain.
//!
//! Layout across [`Column`]s:
//! * `Blocks` — key = 8-byte big-endian **sequence** (append order), value =
//!   encoded block. A prefix scan yields blocks in acceptance order, which is
//!   parent-before-child (a block is only appended after its parent), so
//!   replaying them on startup rebuilds the tree correctly.
//! * `TxIndex` — key = tx hash (`blake3(tx.encode())`, matching [`tx_root`]),
//!   value = `block_id(32) ‖ position(4 LE)`.
//! * `Meta` — the next sequence number and a `block id → sequence-key` map for
//!   O(1) block-by-id lookup.
//!
//! [`tx_root`]: crate::tx_root

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use lat_store::{Column, KVStore, WriteBatch};
use lat_types::Transaction;

use crate::mempool::tx_hash;

/// Meta key holding the next block sequence number (little-endian u64).
const NEXT_SEQ: &[u8] = b"chain/next-seq";
/// Meta key prefix for the `block id → sequence-key` map.
const BLK_ID: &[u8] = b"chain/blk/";

fn blk_id_key(id: &[u8; 32]) -> Vec<u8> {
    let mut k = BLK_ID.to_vec();
    k.extend_from_slice(id);
    k
}

/// A block log + transaction index over any [`KVStore`] backend (a `RedbStore`
/// for a persistent node, a `MemStore` for tests).
pub struct ChainStore {
    kv: Arc<dyn KVStore>,
    next_seq: AtomicU64,
}

impl ChainStore {
    /// Open a store over `kv`, recovering the append position from any prior run.
    pub fn new(kv: Arc<dyn KVStore>) -> Self {
        let next_seq = kv
            .get(Column::Meta, NEXT_SEQ)
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0);
        ChainStore { kv, next_seq: AtomicU64::new(next_seq) }
    }

    /// Append an accepted block (encoded as `encoded`) and index its
    /// transactions. Everything commits in one atomic batch, so the block, its
    /// tx-index entries, and the advanced sequence number are all durable
    /// together or not at all.
    pub fn append(&self, id: &[u8; 32], encoded: &[u8], txs: &[Transaction]) {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let seq_key = seq.to_be_bytes().to_vec();

        let mut batch = WriteBatch::new();
        batch.put(Column::Blocks, seq_key.clone(), encoded.to_vec());
        batch.put(Column::Meta, blk_id_key(id), seq_key);
        for (pos, tx) in txs.iter().enumerate() {
            let mut loc = id.to_vec();
            loc.extend_from_slice(&(pos as u32).to_le_bytes());
            batch.put(Column::TxIndex, tx_hash(tx).to_vec(), loc);
        }
        batch.put(Column::Meta, NEXT_SEQ.to_vec(), (seq + 1).to_le_bytes().to_vec());
        self.kv.write(batch);
    }

    /// Every stored block, in append (sequence) order — used to rebuild the
    /// block tree on startup.
    pub fn blocks_in_order(&self) -> Vec<Vec<u8>> {
        self.kv.scan_prefix(Column::Blocks, b"").into_iter().map(|(_, v)| v).collect()
    }

    /// The encoded block with the given id, if stored.
    pub fn block_by_id(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        let seq_key = self.kv.get(Column::Meta, &blk_id_key(id))?;
        self.kv.get(Column::Blocks, &seq_key)
    }

    /// Locate a transaction by its [`tx_hash`]: the id of the block that contains
    /// it and its position within that block. `None` if the tx isn't on any
    /// stored block.
    pub fn tx_location(&self, tx_hash: &[u8; 32]) -> Option<([u8; 32], u32)> {
        let v = self.kv.get(Column::TxIndex, tx_hash)?;
        if v.len() != 36 {
            return None;
        }
        let id: [u8; 32] = v[..32].try_into().ok()?;
        let pos = u32::from_le_bytes(v[32..36].try_into().ok()?);
        Some((id, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::tx_hash;
    use lat_store::MemStore;
    use lat_types::Transaction;

    fn reg(seed: u8) -> Transaction {
        Transaction::Register { pubkey: [seed; 32], pow_nonce: seed as u64 }
    }

    #[test]
    fn append_indexes_blocks_and_txs_in_order() {
        let store = ChainStore::new(Arc::new(MemStore::new()));
        let id_a = [1u8; 32];
        let id_b = [2u8; 32];
        let txs_a = vec![reg(10), reg(11)];
        let txs_b = vec![reg(20)];
        store.append(&id_a, b"block-a", &txs_a);
        store.append(&id_b, b"block-b", &txs_b);

        // Replay order matches append order.
        assert_eq!(store.blocks_in_order(), vec![b"block-a".to_vec(), b"block-b".to_vec()]);
        // Block-by-id.
        assert_eq!(store.block_by_id(&id_a), Some(b"block-a".to_vec()));
        assert_eq!(store.block_by_id(&[9u8; 32]), None);
        // Tx index resolves to (block id, position).
        assert_eq!(store.tx_location(&tx_hash(&txs_a[1])), Some((id_a, 1)));
        assert_eq!(store.tx_location(&tx_hash(&txs_b[0])), Some((id_b, 0)));
        assert_eq!(store.tx_location(&[0u8; 32]), None);
    }

    #[test]
    fn sequence_survives_reopen() {
        let kv = Arc::new(MemStore::new());
        {
            let store = ChainStore::new(kv.clone() as Arc<dyn KVStore>);
            store.append(&[1u8; 32], b"a", &[reg(1)]);
            store.append(&[2u8; 32], b"b", &[reg(2)]);
        }
        // A store re-created over the same kv keeps appending after the last seq.
        let store = ChainStore::new(kv as Arc<dyn KVStore>);
        store.append(&[3u8; 32], b"c", &[reg(3)]);
        assert_eq!(store.blocks_in_order(), vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
    }
}

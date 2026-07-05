//! Pluggable key/value storage abstraction for Latebra.
//!
//! Every persistent subsystem — the authenticated state trie, the block
//! database, the transaction index, snapshot storage — is written against the
//! [`KVStore`] trait rather than a concrete database. That lets the physical
//! backend evolve (in-memory now → RocksDB/MDBX later) without any change to
//! consensus or execution code. This is milestone M1, task T1 of the
//! performance program (see `PROJECT_CHECKPOINT.md`).
//!
//! Design constraints that shape the API:
//!
//! * **Column families.** Logical namespaces ([`Column`]) that map cleanly onto
//!   RocksDB column families / MDBX sub-databases, so different data classes
//!   (state, blocks, indices) live in separate keyspaces with independent
//!   iteration and, later, independent compaction/pruning policy.
//! * **Atomic write batches.** Mutations are grouped in a [`WriteBatch`] and
//!   applied all-or-nothing via [`KVStore::write`]. A block either commits in
//!   full or not at all — no torn state after a crash.
//! * **Ordered prefix scan.** [`KVStore::scan_prefix`] returns matches in
//!   ascending key order. The state trie and range queries depend on ordered
//!   iteration, so backends must preserve total key order (hence `BTreeMap` in
//!   the in-memory backend, and RocksDB's ordered SSTs later).
//! * **Shared-handle mutability.** Methods take `&self`; a store is a cheap,
//!   cloneable handle over internally-synchronized state (like a real DB
//!   connection). Backends are `Send + Sync` so nodes can share one handle
//!   across threads — a prerequisite for the parallel execution engine (M2).

use std::collections::BTreeMap;
use std::sync::RwLock;

pub mod smt;
pub use smt::{empty_root, verify as verify_proof, Proof, Smt, Terminal, KEY_BITS};

pub mod redb_store;
pub use redb_store::RedbStore;

pub mod overlay;
pub use overlay::OverlayStore;

/// Logical storage namespace. Maps to a RocksDB column family / MDBX DBI in the
/// persistent backend; kept small and explicit so the on-disk layout is a
/// deliberate, reviewable decision rather than an accident of key prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Column {
    /// Authenticated ledger state (accounts, balances, contracts, trie nodes).
    State,
    /// Encoded blocks, keyed by block id / height.
    Blocks,
    /// Secondary indices (tx hash → location, address → history, …).
    TxIndex,
    /// Chain metadata (tip pointer, schema version, snapshot markers, …).
    Meta,
    /// Authoritative ledger object records (accounts, tokens, contracts,
    /// nullifiers), keyed by kind-prefixed ids so each kind scans contiguously.
    /// Separate from [`Column::State`] because that keyspace is raw 32-byte
    /// trie-node hashes — a prefix scan there could collide with node hashes.
    Objects,
}

impl Column {
    /// All columns, in a stable order. Backends use this to open/create every
    /// column family up front.
    pub const ALL: [Column; 5] =
        [Column::State, Column::Blocks, Column::TxIndex, Column::Meta, Column::Objects];

    /// Stable u8 discriminant — the on-disk / cross-process identifier for the
    /// column. Never renumber these; they are part of the storage format.
    pub fn id(self) -> u8 {
        match self {
            Column::State => 0,
            Column::Blocks => 1,
            Column::TxIndex => 2,
            Column::Meta => 3,
            Column::Objects => 4,
        }
    }
}

/// A single mutation within a [`WriteBatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Put(Vec<u8>),
    Delete,
}

/// An ordered, atomic set of mutations across any columns. Build it up, then
/// hand it to [`KVStore::write`]; the backend applies every op or none.
///
/// Ops are retained in insertion order and applied in that order, so a later
/// write to a key supersedes an earlier one within the same batch (last-writer
/// -wins) — matching RocksDB `WriteBatch` semantics.
#[derive(Debug, Clone, Default)]
pub struct WriteBatch {
    ops: Vec<(Column, Vec<u8>, Op)>,
}

impl WriteBatch {
    /// An empty batch.
    pub fn new() -> Self {
        WriteBatch { ops: Vec::new() }
    }

    /// Queue a put of `value` at `key` in `col`.
    pub fn put(&mut self, col: Column, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> &mut Self {
        self.ops.push((col, key.into(), Op::Put(value.into())));
        self
    }

    /// Queue a delete of `key` in `col` (a no-op if absent).
    pub fn delete(&mut self, col: Column, key: impl Into<Vec<u8>>) -> &mut Self {
        self.ops.push((col, key.into(), Op::Delete));
        self
    }

    /// Iterate the queued mutations in order as `(column, key, value)`, where a
    /// `None` value denotes a delete. Backends consume this to apply the batch.
    pub fn ops(&self) -> impl Iterator<Item = (Column, &[u8], Option<&[u8]>)> {
        self.ops.iter().map(|(col, key, op)| {
            let value = match op {
                Op::Put(v) => Some(v.as_slice()),
                Op::Delete => None,
            };
            (*col, key.as_slice(), value)
        })
    }

    /// Number of queued mutations.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Whether the batch has no mutations.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// A key/value store with column families and atomic batch writes.
///
/// Implementors must guarantee: (1) [`write`](KVStore::write) is atomic — a
/// reader never observes a partially-applied batch; (2)
/// [`scan_prefix`](KVStore::scan_prefix) yields matches in ascending key order.
pub trait KVStore: Send + Sync {
    /// The value at `key` in `col`, or `None` if absent.
    fn get(&self, col: Column, key: &[u8]) -> Option<Vec<u8>>;

    /// Whether `key` exists in `col`. Backends may override with a cheaper
    /// existence check that avoids materializing the value.
    fn contains(&self, col: Column, key: &[u8]) -> bool {
        self.get(col, key).is_some()
    }

    /// Atomically apply every mutation in `batch`.
    fn write(&self, batch: WriteBatch);

    /// Every `(key, value)` in `col` whose key starts with `prefix`, in
    /// ascending key order. An empty `prefix` scans the whole column.
    fn scan_prefix(&self, col: Column, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)>;

    /// Convenience: atomically put a single key. Prefer [`write`](KVStore::write)
    /// for multi-key updates so they commit together. `where Self: Sized` keeps
    /// the trait object-safe (so `dyn KVStore` / `Arc<dyn KVStore>` works — the
    /// basis for a shared read-only base under a copy-on-write overlay).
    fn put(&self, col: Column, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>)
    where
        Self: Sized,
    {
        let mut b = WriteBatch::new();
        b.put(col, key, value);
        self.write(b);
    }

    /// Convenience: atomically delete a single key.
    fn delete(&self, col: Column, key: impl Into<Vec<u8>>)
    where
        Self: Sized,
    {
        let mut b = WriteBatch::new();
        b.delete(col, key);
        self.write(b);
    }
}

/// In-memory [`KVStore`] backend: one ordered map per column behind a single
/// lock, so a whole [`WriteBatch`] commits atomically. This is the reference
/// implementation and the default for tests and local dev networks; the
/// on-disk RocksDB/MDBX backend (task T4) implements the same trait.
///
/// A `BTreeMap` (not `HashMap`) is used so [`scan_prefix`](KVStore::scan_prefix)
/// gets total key order for free, matching the ordered-iteration contract.
/// One column's keyspace: an ordered map of key → value.
type ColumnMap = BTreeMap<Vec<u8>, Vec<u8>>;

#[derive(Debug, Default)]
pub struct MemStore {
    cols: RwLock<BTreeMap<Column, ColumnMap>>,
}

impl Clone for MemStore {
    /// Deep-copies the whole keyspace. Used when a caller (e.g. a ledger doing
    /// speculative block execution) clones its state to try transactions on a
    /// throwaway copy. A disk backend will replace this with cheap overlays.
    fn clone(&self) -> Self {
        MemStore { cols: RwLock::new(self.cols.read().unwrap().clone()) }
    }
}

impl MemStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        MemStore { cols: RwLock::new(BTreeMap::new()) }
    }

    /// Total number of keys across all columns (diagnostics/tests).
    pub fn len(&self) -> usize {
        self.cols.read().unwrap().values().map(|m| m.len()).sum()
    }

    /// Drop every key in every column. Used by the copy-on-write overlay to
    /// empty its write layer after folding it into the base.
    pub fn clear(&self) {
        self.cols.write().unwrap().clear();
    }

    /// Whether the store holds no keys at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl KVStore for MemStore {
    fn get(&self, col: Column, key: &[u8]) -> Option<Vec<u8>> {
        self.cols.read().unwrap().get(&col).and_then(|m| m.get(key).cloned())
    }

    fn contains(&self, col: Column, key: &[u8]) -> bool {
        self.cols.read().unwrap().get(&col).is_some_and(|m| m.contains_key(key))
    }

    fn write(&self, batch: WriteBatch) {
        // One lock for the whole batch ⇒ readers see all-or-nothing.
        let mut cols = self.cols.write().unwrap();
        for (col, key, op) in batch.ops {
            let map = cols.entry(col).or_default();
            match op {
                Op::Put(v) => {
                    map.insert(key, v);
                }
                Op::Delete => {
                    map.remove(&key);
                }
            }
        }
    }

    fn scan_prefix(&self, col: Column, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let cols = self.cols.read().unwrap();
        let Some(map) = cols.get(&col) else { return Vec::new() };
        // BTreeMap range from `prefix` up to the first key that no longer shares
        // it; ascending order is inherent to the map.
        map.range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_contains_delete() {
        let s = MemStore::new();
        assert!(s.get(Column::State, b"a").is_none());
        assert!(!s.contains(Column::State, b"a"));

        s.put(Column::State, b"a".to_vec(), b"1".to_vec());
        assert_eq!(s.get(Column::State, b"a"), Some(b"1".to_vec()));
        assert!(s.contains(Column::State, b"a"));

        s.delete(Column::State, b"a".to_vec());
        assert!(s.get(Column::State, b"a").is_none());
    }

    #[test]
    fn columns_are_isolated() {
        let s = MemStore::new();
        s.put(Column::State, b"k".to_vec(), b"state".to_vec());
        s.put(Column::Blocks, b"k".to_vec(), b"block".to_vec());
        assert_eq!(s.get(Column::State, b"k"), Some(b"state".to_vec()));
        assert_eq!(s.get(Column::Blocks, b"k"), Some(b"block".to_vec()));
        assert!(s.get(Column::TxIndex, b"k").is_none());
    }

    #[test]
    fn batch_applies_all_ops_in_order() {
        let s = MemStore::new();
        s.put(Column::State, b"keep".to_vec(), b"old".to_vec());

        let mut b = WriteBatch::new();
        b.put(Column::State, b"x".to_vec(), b"1".to_vec())
            .put(Column::State, b"x".to_vec(), b"2".to_vec()) // last-writer-wins
            .put(Column::Blocks, b"y".to_vec(), b"3".to_vec())
            .delete(Column::State, b"keep".to_vec());
        assert_eq!(b.len(), 4);
        s.write(b);

        assert_eq!(s.get(Column::State, b"x"), Some(b"2".to_vec()));
        assert_eq!(s.get(Column::Blocks, b"y"), Some(b"3".to_vec()));
        assert!(s.get(Column::State, b"keep").is_none());
    }

    #[test]
    fn scan_prefix_is_ordered_and_bounded() {
        let s = MemStore::new();
        for k in ["ap", "apple", "applet", "apply", "banana", "b"] {
            s.put(Column::State, k.as_bytes().to_vec(), b"v".to_vec());
        }
        let keys: Vec<Vec<u8>> =
            s.scan_prefix(Column::State, b"app").into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            vec![b"apple".to_vec(), b"applet".to_vec(), b"apply".to_vec()],
            "only 'app'-prefixed keys, ascending"
        );

        // Empty prefix scans the whole column, still ordered.
        let all: Vec<Vec<u8>> =
            s.scan_prefix(Column::State, b"").into_iter().map(|(k, _)| k).collect();
        assert_eq!(all.first(), Some(&b"ap".to_vec()));
        assert_eq!(all.last(), Some(&b"banana".to_vec()));
    }

    #[test]
    fn empty_batch_is_a_noop() {
        let s = MemStore::new();
        s.put(Column::State, b"a".to_vec(), b"1".to_vec());
        s.write(WriteBatch::new());
        assert_eq!(s.len(), 1);
        assert_eq!(s.get(Column::State, b"a"), Some(b"1".to_vec()));
    }

    #[test]
    fn column_ids_are_stable_and_unique() {
        let ids: Vec<u8> = Column::ALL.iter().map(|c| c.id()).collect();
        assert_eq!(ids, vec![0, 1, 2, 3, 4], "on-disk column ids must not drift");
    }

    #[test]
    fn store_is_shareable_across_threads() {
        use std::sync::Arc;
        use std::thread;
        let s = Arc::new(MemStore::new());
        let mut handles = Vec::new();
        for t in 0..8u8 {
            let s = Arc::clone(&s);
            handles.push(thread::spawn(move || {
                for i in 0..100u8 {
                    let key = vec![t, i];
                    s.put(Column::State, key, vec![t]);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(s.len(), 8 * 100, "all concurrent writes landed");
    }
}

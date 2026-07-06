//! Copy-on-write [`KVStore`](crate::KVStore) overlay.
//!
//! An `OverlayStore` layers an in-memory *write top* over a shared, read-only
//! *base* (`Arc<dyn KVStore>`). Reads fall through to the base unless the top has
//! a newer value (or a tombstone hiding a base key); writes only ever touch the
//! top. This gives two things the node needs:
//!
//! * **Cheap speculative execution.** [`clone`](Clone::clone) copies only the
//!   top and shares the base by `Arc`, so cloning state to try a block's
//!   transactions on a throwaway copy (miner block-building, mempool filtering)
//!   no longer deep-copies the whole state trie. The base is never mutated by a
//!   speculative clone, so discarding it is free.
//! * **Deferred durability.** [`flush`](OverlayStore::flush) folds the top into
//!   the base in one write, so a persistent base (e.g. `RedbStore`) is committed
//!   once per block rather than per state change.
//!
//! Because the overlay is itself a [`KVStore`], everything above it — the state
//! trie, the ledger — is oblivious to whether the base is in memory or on disk.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, RwLock};

use crate::{Column, KVStore, MemStore, WriteBatch};

/// A key/value store that buffers writes over a shared read-only base.
pub struct OverlayStore {
    /// Shared, read-only committed state. Never mutated except by [`flush`].
    base: Arc<dyn KVStore>,
    /// Uncommitted writes layered on top of the base.
    top: MemStore,
    /// Keys deleted in the overlay: they must read as absent even if the base
    /// still holds them. (The state trie never deletes, so this stays empty in
    /// the ledger, but a correct general `KVStore` needs it.)
    tombstones: RwLock<HashSet<(Column, Vec<u8>)>>,
}

impl OverlayStore {
    /// A new overlay over `base`, with an empty write layer.
    pub fn new(base: Arc<dyn KVStore>) -> Self {
        OverlayStore { base, top: MemStore::new(), tombstones: RwLock::new(HashSet::new()) }
    }

    /// An overlay over a fresh, empty in-memory base — the default for a chain
    /// that isn't persisting to disk.
    pub fn in_memory() -> Self {
        OverlayStore::new(Arc::new(MemStore::new()))
    }

    /// The shared base handle (e.g. to hand a sibling overlay the same base).
    pub fn base(&self) -> Arc<dyn KVStore> {
        Arc::clone(&self.base)
    }

    /// Fold the write layer into the base in a single batch (puts for written
    /// keys, deletes for tombstoned ones), then clear the top. Semantically a
    /// no-op — a read returns the same value before and after — so flushing can
    /// never change committed state, only where it physically lives.
    pub fn flush(&self) {
        let mut batch = WriteBatch::new();
        for col in Column::ALL {
            for (key, value) in self.top.scan_prefix(col, b"") {
                batch.put(col, key, value);
            }
        }
        let mut tomb = self.tombstones.write().unwrap();
        for (col, key) in tomb.iter() {
            batch.delete(*col, key.clone());
        }
        if !batch.is_empty() {
            self.base.write(batch);
        }
        self.top.clear();
        tomb.clear();
    }
}

impl Clone for OverlayStore {
    /// Shares the base (`Arc`) and deep-copies only the (small) write layer.
    fn clone(&self) -> Self {
        OverlayStore {
            base: Arc::clone(&self.base),
            top: self.top.clone(),
            tombstones: RwLock::new(self.tombstones.read().unwrap().clone()),
        }
    }
}

impl KVStore for OverlayStore {
    fn get(&self, col: Column, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(v) = self.top.get(col, key) {
            return Some(v);
        }
        if self.tombstones.read().unwrap().contains(&(col, key.to_vec())) {
            return None;
        }
        self.base.get(col, key)
    }

    fn write(&self, batch: WriteBatch) {
        let mut tomb = self.tombstones.write().unwrap();
        let mut top_batch = WriteBatch::new();
        for (col, key, value) in batch.ops() {
            match value {
                Some(v) => {
                    top_batch.put(col, key.to_vec(), v.to_vec());
                    tomb.remove(&(col, key.to_vec()));
                }
                None => {
                    top_batch.delete(col, key.to_vec());
                    tomb.insert((col, key.to_vec()));
                }
            }
        }
        drop(tomb);
        self.top.write(top_batch);
    }

    fn scan_prefix(&self, col: Column, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        // Base first, then top overrides, then drop tombstoned keys. A BTreeMap
        // keeps the merged result in ascending key order.
        let mut merged: BTreeMap<Vec<u8>, Vec<u8>> =
            self.base.scan_prefix(col, prefix).into_iter().collect();
        for (k, v) in self.top.scan_prefix(col, prefix) {
            merged.insert(k, v);
        }
        let tomb = self.tombstones.read().unwrap();
        merged.retain(|k, _| !tomb.contains(&(col, k.clone())));
        merged.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::{verify, Smt};

    fn base_with(pairs: &[(&[u8], &[u8])]) -> Arc<MemStore> {
        let b = Arc::new(MemStore::new());
        for (k, v) in pairs {
            b.put(Column::State, k.to_vec(), v.to_vec());
        }
        b
    }

    #[test]
    fn reads_fall_through_and_top_overrides() {
        let base = base_with(&[(b"a", b"base-a"), (b"b", b"base-b")]);
        let ov = OverlayStore::new(base);
        assert_eq!(ov.get(Column::State, b"a"), Some(b"base-a".to_vec()));
        ov.put(Column::State, b"a".to_vec(), b"top-a".to_vec());
        assert_eq!(ov.get(Column::State, b"a"), Some(b"top-a".to_vec()), "top wins");
        assert_eq!(ov.get(Column::State, b"b"), Some(b"base-b".to_vec()), "still falls through");
    }

    #[test]
    fn delete_tombstones_base_key() {
        let base = base_with(&[(b"a", b"base-a")]);
        let ov = OverlayStore::new(Arc::clone(&base) as Arc<dyn KVStore>);
        ov.delete(Column::State, b"a".to_vec());
        assert!(ov.get(Column::State, b"a").is_none(), "hidden in overlay");
        assert_eq!(base.get(Column::State, b"a"), Some(b"base-a".to_vec()), "base untouched");
        // Re-putting clears the tombstone.
        ov.put(Column::State, b"a".to_vec(), b"new".to_vec());
        assert_eq!(ov.get(Column::State, b"a"), Some(b"new".to_vec()));
    }

    #[test]
    fn clone_is_independent_of_original_and_base() {
        let base = base_with(&[(b"a", b"base")]);
        let ov = OverlayStore::new(base);
        ov.put(Column::State, b"x".to_vec(), b"1".to_vec());

        let clone = ov.clone();
        clone.put(Column::State, b"x".to_vec(), b"2".to_vec());
        clone.put(Column::State, b"y".to_vec(), b"clone-only".to_vec());

        // Original unaffected by clone's writes.
        assert_eq!(ov.get(Column::State, b"x"), Some(b"1".to_vec()));
        assert!(ov.get(Column::State, b"y").is_none());
        // Clone sees its own writes plus the shared base.
        assert_eq!(clone.get(Column::State, b"x"), Some(b"2".to_vec()));
        assert_eq!(clone.get(Column::State, b"a"), Some(b"base".to_vec()));
    }

    #[test]
    fn scan_prefix_merges_overrides_and_tombstones() {
        let base = base_with(&[(b"ap", b"1"), (b"apple", b"2"), (b"apply", b"3"), (b"b", b"4")]);
        let ov = OverlayStore::new(base);
        ov.put(Column::State, b"apple".to_vec(), b"OVERRIDE".to_vec());
        ov.put(Column::State, b"apron".to_vec(), b"NEW".to_vec());
        ov.delete(Column::State, b"apply".to_vec());

        let got: Vec<(Vec<u8>, Vec<u8>)> = ov.scan_prefix(Column::State, b"ap");
        let keys: Vec<&[u8]> = got.iter().map(|(k, _)| k.as_slice()).collect();
        assert_eq!(keys, vec![b"ap".as_ref(), b"apple", b"apron"], "ordered, deleted gone");
        assert_eq!(got[1].1, b"OVERRIDE".to_vec(), "top override present");
    }

    #[test]
    fn flush_folds_top_into_base() {
        let base: Arc<dyn KVStore> = base_with(&[(b"keep", b"base")]);
        let ov = OverlayStore::new(Arc::clone(&base));
        ov.put(Column::State, b"new".to_vec(), b"top".to_vec());
        ov.flush();
        // A fresh overlay over the same base now sees the flushed write.
        let ov2 = OverlayStore::new(Arc::clone(&base));
        assert_eq!(ov2.get(Column::State, b"new"), Some(b"top".to_vec()));
        assert_eq!(ov2.get(Column::State, b"keep"), Some(b"base".to_vec()));
    }

    #[test]
    fn state_trie_works_over_overlay_and_persists_on_flush() {
        // Build a trie through the overlay, flush to base, then rebuild the trie
        // from the base alone (fresh overlay) — proof the overlay is transparent
        // to the authenticated state layer.
        let base: Arc<dyn KVStore> = Arc::new(MemStore::new());
        let mut keys = Vec::new();
        let root = {
            let store = OverlayStore::new(Arc::clone(&base));
            let mut trie = Smt::new(&store);
            for i in 0u32..50 {
                let mut k = [0u8; 32];
                k[..4].copy_from_slice(&i.to_le_bytes());
                trie.update(&k, &i.to_le_bytes());
                keys.push((k, i));
            }
            let r = trie.root();
            store.flush();
            r
        };
        // Nothing left in a new overlay's top; all nodes came from the base.
        let store2 = OverlayStore::new(base);
        let trie = Smt::from_root(&store2, root);
        for (k, i) in &keys {
            assert_eq!(trie.get(k), Some(i.to_le_bytes().to_vec()));
            assert!(verify(&root, k, Some(&i.to_le_bytes()), &trie.prove(k)));
        }
    }
}

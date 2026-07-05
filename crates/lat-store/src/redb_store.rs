//! Persistent [`KVStore`](crate::KVStore) backend on [redb](https://docs.rs/redb),
//! a pure-Rust embedded ACID key/value store.
//!
//! # Why redb (ADR-0004)
//!
//! The roadmap called for RocksDB or MDBX. Both are C/C++ libraries whose `-sys`
//! crates need a clang/LLVM toolchain for bindgen — unavailable in this build
//! environment (Windows, no clang). redb gives us what we actually need behind
//! the same [`KVStore`] trait, with none of that fragility:
//!
//! * **Pure Rust** — builds anywhere the rest of the node builds, no C toolchain.
//! * **ACID + durable** — every [`write`](KVStore::write) is an atomic, fsync'd
//!   transaction, so a node survives a crash or restart with consistent state.
//! * **Ordered B-trees** — native range scans back [`scan_prefix`].
//! * **MVCC** — read transactions see a consistent snapshot, the primitive a
//!   copy-on-write speculative-execution overlay will build on later.
//!
//! Because everything upstream is written against [`KVStore`], swapping in a
//! RocksDB/MDBX backend later (for raw throughput, if ever measured to matter)
//! is a drop-in — no ledger or consensus change.
//!
//! # Error policy
//!
//! [`KVStore`] methods are infallible by signature (the in-memory backend can't
//! fail). A failing or corrupt on-disk database is unrecoverable for a node, so
//! this backend treats I/O errors as fatal (`panic`) rather than silently
//! returning wrong data. Opening is fallible and returns a `Result`.

use std::path::Path;

use redb::{Database, DatabaseError, ReadableDatabase, TableDefinition};

use crate::{Column, KVStore, WriteBatch};

type Bytes = &'static [u8];

// One redb table per column family. Table names are the on-disk identifiers —
// never rename them.
const STATE: TableDefinition<Bytes, Bytes> = TableDefinition::new("state");
const BLOCKS: TableDefinition<Bytes, Bytes> = TableDefinition::new("blocks");
const TXINDEX: TableDefinition<Bytes, Bytes> = TableDefinition::new("txindex");
const META: TableDefinition<Bytes, Bytes> = TableDefinition::new("meta");
const OBJECTS: TableDefinition<Bytes, Bytes> = TableDefinition::new("objects");

fn table_of(col: Column) -> TableDefinition<'static, Bytes, Bytes> {
    match col {
        Column::State => STATE,
        Column::Blocks => BLOCKS,
        Column::TxIndex => TXINDEX,
        Column::Meta => META,
        Column::Objects => OBJECTS,
    }
}

/// A persistent [`KVStore`] backed by a single redb database file.
#[derive(Debug)]
pub struct RedbStore {
    db: Database,
}

impl RedbStore {
    /// Open the database at `path`, creating it (and all column tables) if it
    /// does not yet exist. Reopening an existing path recovers its committed
    /// state — this is how a node boots from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let db = Database::create(path)?;
        // Materialize every column table up front so reads never race a
        // not-yet-created table, and the on-disk layout is fixed at creation.
        let wtxn = db.begin_write().expect("begin write");
        for col in Column::ALL {
            wtxn.open_table(table_of(col)).expect("create table");
        }
        wtxn.commit().expect("commit table creation");
        Ok(RedbStore { db })
    }
}

impl KVStore for RedbStore {
    fn get(&self, col: Column, key: &[u8]) -> Option<Vec<u8>> {
        let rtxn = self.db.begin_read().expect("begin read");
        let table = rtxn.open_table(table_of(col)).expect("open table");
        table.get(key).expect("get").map(|g| g.value().to_vec())
    }

    fn contains(&self, col: Column, key: &[u8]) -> bool {
        let rtxn = self.db.begin_read().expect("begin read");
        let table = rtxn.open_table(table_of(col)).expect("open table");
        table.get(key).expect("get").is_some()
    }

    fn write(&self, batch: WriteBatch) {
        let wtxn = self.db.begin_write().expect("begin write");
        {
            // All column tables open at once (they are independent), so a single
            // atomic transaction applies the whole batch in order.
            let mut state = wtxn.open_table(STATE).expect("open state");
            let mut blocks = wtxn.open_table(BLOCKS).expect("open blocks");
            let mut txindex = wtxn.open_table(TXINDEX).expect("open txindex");
            let mut meta = wtxn.open_table(META).expect("open meta");
            let mut objects = wtxn.open_table(OBJECTS).expect("open objects");
            for (col, key, value) in batch.ops() {
                let table = match col {
                    Column::State => &mut state,
                    Column::Blocks => &mut blocks,
                    Column::TxIndex => &mut txindex,
                    Column::Meta => &mut meta,
                    Column::Objects => &mut objects,
                };
                match value {
                    Some(v) => {
                        table.insert(key, v).expect("insert");
                    }
                    None => {
                        table.remove(key).expect("remove");
                    }
                }
            }
        }
        wtxn.commit().expect("commit");
    }

    fn scan_prefix(&self, col: Column, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let rtxn = self.db.begin_read().expect("begin read");
        let table = rtxn.open_table(table_of(col)).expect("open table");
        let mut out = Vec::new();
        // redb orders `&[u8]` keys lexicographically, so a range from `prefix`
        // yields prefixed keys contiguously and ascending.
        for item in table.range(prefix..).expect("range") {
            let (k, v) = item.expect("range item");
            if !k.value().starts_with(prefix) {
                break;
            }
            out.push((k.value().to_vec(), v.value().to_vec()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smt::{verify, Smt};

    /// A unique temp path that cleans itself up on drop.
    struct TempDbPath(std::path::PathBuf);
    impl TempDbPath {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            TempDbPath(std::env::temp_dir().join(format!("lat-redb-{tag}-{pid}-{n}-{nanos}.redb")))
        }
    }
    impl Drop for TempDbPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn put_get_contains_delete() {
        let path = TempDbPath::new("basic");
        let s = RedbStore::open(&path.0).unwrap();
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
        let path = TempDbPath::new("cols");
        let s = RedbStore::open(&path.0).unwrap();
        s.put(Column::State, b"k".to_vec(), b"state".to_vec());
        s.put(Column::Blocks, b"k".to_vec(), b"block".to_vec());
        assert_eq!(s.get(Column::State, b"k"), Some(b"state".to_vec()));
        assert_eq!(s.get(Column::Blocks, b"k"), Some(b"block".to_vec()));
        assert!(s.get(Column::TxIndex, b"k").is_none());
    }

    #[test]
    fn batch_is_atomic_and_ordered() {
        let path = TempDbPath::new("batch");
        let s = RedbStore::open(&path.0).unwrap();
        s.put(Column::State, b"keep".to_vec(), b"old".to_vec());
        let mut b = WriteBatch::new();
        b.put(Column::State, b"x".to_vec(), b"1".to_vec())
            .put(Column::State, b"x".to_vec(), b"2".to_vec()) // last-writer-wins
            .put(Column::Blocks, b"y".to_vec(), b"3".to_vec())
            .delete(Column::State, b"keep".to_vec());
        s.write(b);
        assert_eq!(s.get(Column::State, b"x"), Some(b"2".to_vec()));
        assert_eq!(s.get(Column::Blocks, b"y"), Some(b"3".to_vec()));
        assert!(s.get(Column::State, b"keep").is_none());
    }

    #[test]
    fn scan_prefix_is_ordered_and_bounded() {
        let path = TempDbPath::new("scan");
        let s = RedbStore::open(&path.0).unwrap();
        for k in ["ap", "apple", "applet", "apply", "banana", "b"] {
            s.put(Column::State, k.as_bytes().to_vec(), b"v".to_vec());
        }
        let keys: Vec<Vec<u8>> =
            s.scan_prefix(Column::State, b"app").into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec![b"apple".to_vec(), b"applet".to_vec(), b"apply".to_vec()]);
        let all = s.scan_prefix(Column::State, b"");
        assert_eq!(all.first().map(|(k, _)| k.clone()), Some(b"ap".to_vec()));
        assert_eq!(all.last().map(|(k, _)| k.clone()), Some(b"banana".to_vec()));
    }

    #[test]
    fn survives_close_and_reopen() {
        let path = TempDbPath::new("persist");
        {
            let s = RedbStore::open(&path.0).unwrap();
            s.put(Column::State, b"durable".to_vec(), b"value".to_vec());
            let mut b = WriteBatch::new();
            b.put(Column::Blocks, 7u64.to_be_bytes().to_vec(), b"block7".to_vec());
            s.write(b);
        } // dropped: database closed
        // Reopen the same path — committed data must still be there.
        let s = RedbStore::open(&path.0).unwrap();
        assert_eq!(s.get(Column::State, b"durable"), Some(b"value".to_vec()));
        assert_eq!(s.get(Column::Blocks, &7u64.to_be_bytes()), Some(b"block7".to_vec()));
    }

    #[test]
    fn state_trie_persists_across_reopen() {
        // Build a Sparse Merkle Tree on disk, close, reopen from just the root,
        // and confirm reads and inclusion proofs still hold — end-to-end proof
        // that the authenticated state layer works over the persistent backend.
        let path = TempDbPath::new("trie");
        let mut keys = Vec::new();
        let root = {
            let s = RedbStore::open(&path.0).unwrap();
            let mut trie = Smt::new(&s);
            for i in 0u32..64 {
                let mut k = [0u8; 32];
                k[..4].copy_from_slice(&(i.wrapping_mul(2_654_435_761)).to_le_bytes());
                trie.update(&k, &i.to_le_bytes());
                keys.push((k, i));
            }
            trie.root()
        };
        // Reopen and reconstruct the trie from the persisted root.
        let s = RedbStore::open(&path.0).unwrap();
        let trie = Smt::from_root(&s, root);
        for (k, i) in &keys {
            assert_eq!(trie.get(k), Some(i.to_le_bytes().to_vec()));
            assert!(verify(&root, k, Some(&i.to_le_bytes()), &trie.prove(k)));
        }
    }
}

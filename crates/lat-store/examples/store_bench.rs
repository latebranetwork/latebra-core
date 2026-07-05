//! Compares the in-memory and persistent (redb) `KVStore` backends on the
//! operations a node actually performs: committing a batch (one block = one
//! atomic, durable commit), random point reads, prefix scans, and open/restart
//! time. Persistent writes pay for durability (fsync); reads should be close.
//!
//! Run: cargo run --release --example store_bench -p lat-store

use std::time::Instant;

use lat_store::{Column, KVStore, MemStore, RedbStore, WriteBatch};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn key(&mut self) -> [u8; 32] {
        let mut k = [0u8; 32];
        for c in k.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes()[..c.len()]);
        }
        k
    }
}

fn temp_path() -> std::path::PathBuf {
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("lat-store-bench-{}-{nanos}.redb", std::process::id()))
}

/// Fill `store` with `n` random keys (committed in batches of `batch`) and
/// return the keys, timing the total commit work.
fn fill(store: &dyn KVStore, n: usize, batch: usize, seed: u64) -> (Vec<[u8; 32]>, f64) {
    let mut rng = Rng(seed);
    let mut keys = Vec::with_capacity(n);
    let t = Instant::now();
    let mut wb = WriteBatch::new();
    for i in 0..n {
        let k = rng.key();
        wb.put(Column::State, k.to_vec(), (i as u64).to_le_bytes().to_vec());
        keys.push(k);
        if wb.len() >= batch {
            store.write(std::mem::take(&mut wb));
        }
    }
    if !wb.is_empty() {
        store.write(wb);
    }
    (keys, t.elapsed().as_secs_f64())
}

fn time_reads(store: &dyn KVStore, keys: &[[u8; 32]]) -> f64 {
    let t = Instant::now();
    let mut hits = 0u64;
    for k in keys {
        if store.get(Column::State, k).is_some() {
            hits += 1;
        }
    }
    std::hint::black_box(hits);
    t.elapsed().as_secs_f64()
}

fn main() {
    const N: usize = 100_000;
    const BATCH: usize = 1_000; // ~ a block's worth of state writes per commit

    println!("KVStore backend benchmark — {N} keys, batch {BATCH}, release\n");
    println!("| {:<34} | {:>12} | {:>14} |", "operation", "total", "per op");
    println!("|{:-<36}|{:-<14}|{:-<16}|", "", "", "");

    // In-memory baseline.
    let mem = MemStore::new();
    let (mem_keys, mem_fill) = fill(&mem, N, BATCH, 1);
    let mem_read = time_reads(&mem, &mem_keys);

    // Persistent redb.
    let path = temp_path();
    let (redb_fill, redb_read, redb_reopen, redb_scan) = {
        let store = RedbStore::open(&path).unwrap();
        let (keys, fill_s) = fill(&store, N, BATCH, 2);
        let read_s = time_reads(&store, &keys);
        drop(store);
        // Restart: reopen the populated database and read once more.
        let t = Instant::now();
        let store = RedbStore::open(&path).unwrap();
        let reopen_s = t.elapsed().as_secs_f64();
        let ts = Instant::now();
        let scanned = store.scan_prefix(Column::State, b"").len();
        let scan_s = ts.elapsed().as_secs_f64();
        std::hint::black_box(scanned);
        (fill_s, read_s, reopen_s, scan_s)
    };
    let _ = std::fs::remove_file(&path);

    let row = |name: &str, total: f64, per_op_ns: f64| {
        println!("| {name:<34} | {:>9.1} ms | {:>11.0} ns |", total * 1e3, per_op_ns);
    };
    row("MemStore: commit", mem_fill, mem_fill * 1e9 / N as f64);
    row("RedbStore: commit (durable)", redb_fill, redb_fill * 1e9 / N as f64);
    row("MemStore: random read", mem_read, mem_read * 1e9 / N as f64);
    row("RedbStore: random read", redb_read, redb_read * 1e9 / N as f64);
    println!("| {:<34} | {:>9.1} ms | {:>14} |", "RedbStore: open 100k-key DB", redb_reopen * 1e3, "-");
    println!("| {:<34} | {:>9.1} ms | {:>14} |", "RedbStore: full scan (100k)", redb_scan * 1e3, "-");

    println!("\nPersistent writes pay fsync for durability; a node commits once per");
    println!("block, so the per-block cost is BATCH × the per-op figure above.");
}

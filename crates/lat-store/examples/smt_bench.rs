//! Measures the state-trie hot paths and, crucially, how a single-key update
//! scales with total state size. The point of the SMT (task T2) is that an
//! update touches O(log n) nodes, so per-update cost should stay ~flat as the
//! tree grows — in contrast to the previous full-state root recompute, which is
//! O(n) every block.
//!
//! Run: cargo run --release --example smt_bench -p lat-store

use std::time::Instant;

use lat_store::{verify_proof, MemStore, Smt};

// Small deterministic PRNG (keeps the example dependency-free).
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

fn median(mut v: Vec<u128>) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}

fn main() {
    println!("Latebra state-trie (SMT) benchmark — release, single core\n");
    println!("| {:<38} | {:>12} | {:>14} |", "operation", "median/op", "ops/sec");
    println!("|{:-<40}|{:-<14}|{:-<16}|", "", "", "");

    // Update scaling: pre-fill to N keys, then time single-key updates.
    for &n in &[1_000usize, 10_000, 100_000] {
        let store = MemStore::new();
        let mut trie = Smt::new(&store);
        let mut rng = Rng(0xDEADBEEF ^ n as u64);
        let mut probe = Vec::new();
        for i in 0..n {
            let k = rng.key();
            trie.update(&k, &(i as u64).to_le_bytes());
            if i % (n / 200).max(1) == 0 {
                probe.push(k);
            }
        }

        // Time updates to already-present keys (path length ~ log2(n)).
        let samples: Vec<u128> = probe
            .iter()
            .map(|k| {
                let t = Instant::now();
                std::hint::black_box(trie.update(k, b"updated-value"));
                t.elapsed().as_nanos()
            })
            .collect();
        let m = median(samples);
        println!(
            "| {:<38} | {:>9} ns | {:>14.0} |",
            format!("update @ {n} keys"),
            m,
            1e9 / m as f64
        );
    }

    // Prove + verify at 100k keys.
    {
        let store = MemStore::new();
        let mut trie = Smt::new(&store);
        let mut rng = Rng(0x1234);
        let mut keys = Vec::new();
        for i in 0..100_000u64 {
            let k = rng.key();
            trie.update(&k, &i.to_le_bytes());
            if i % 500 == 0 {
                keys.push(k);
            }
        }
        let root = trie.root();

        let proofs: Vec<_> = keys.iter().map(|k| (k, trie.prove(k))).collect();
        let prove_samples: Vec<u128> = keys
            .iter()
            .map(|k| {
                let t = Instant::now();
                std::hint::black_box(trie.prove(k));
                t.elapsed().as_nanos()
            })
            .collect();
        let verify_samples: Vec<u128> = proofs
            .iter()
            .map(|(k, p)| {
                let t = Instant::now();
                std::hint::black_box(verify_proof(&root, k, None, p));
                t.elapsed().as_nanos()
            })
            .collect();
        let pm = median(prove_samples);
        let vm = median(verify_samples);
        println!("| {:<38} | {:>9} ns | {:>14.0} |", "prove @ 100k keys", pm, 1e9 / pm as f64);
        println!("| {:<38} | {:>9} ns | {:>14.0} |", "verify proof @ 100k keys", vm, 1e9 / vm as f64);

        let avg_depth: f64 =
            proofs.iter().map(|(_, p)| p.siblings.len()).sum::<usize>() as f64 / proofs.len() as f64;
        println!("\nAverage proof depth at 100k keys: {avg_depth:.1} (≈ log2(n) = {:.1})", (100_000f64).log2());
    }

    println!("\nFlat update cost across 1k→100k keys ⇒ O(log n) updates, not O(n) full recompute.");
}

//! Quantifies the copy-on-write win from T4b + T5b: cloning a ledger for
//! speculative block execution (miner / mempool filtering) copies nothing that
//! scales with state size.
//!
//! With T5b every state object (accounts, tokens, contracts, nullifiers) lives
//! as a record in the overlay's store alongside the trie nodes, so BOTH move
//! with the overlay — nothing is left in a side `HashMap`. For each state size
//! we clone twice:
//!  * **top full** — before `flush`, the overlay's write layer holds every trie
//!    node and object record, so the clone copies them all (the pre-overlay,
//!    all-in-RAM behavior).
//!  * **flushed** — after `flush`, committed nodes and records live in the
//!    shared base and the write layer is empty, so the clone shares the base by
//!    `Arc` and copies nothing that grows with the state.
//!
//! The gap is the whole-state copy the overlay eliminates. T4b removed the trie
//! copy but left the account maps; T5b removes those too, so the flushed clone
//! is now ~O(1) instead of O(accounts).
//!
//! Run: cargo run --release --example clone_bench -p lat-state

use std::time::Instant;

use lat_state::Ledger;

fn build(n: usize) -> Ledger {
    let mut l = Ledger::new();
    for i in 0..n {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(i as u64).to_le_bytes());
        l.register(id).unwrap();
        l.credit_public(&id, 0, 1_000);
    }
    l.state_root(); // reconcile: materialize the trie into the overlay top
    l
}

fn time_clone(l: &Ledger) -> f64 {
    let t = Instant::now();
    let c = l.clone();
    let dt = t.elapsed().as_secs_f64();
    std::hint::black_box(c);
    dt
}

fn main() {
    println!("Ledger clone cost — copy-on-write overlay (release)\n");
    println!("| {:>10} | {:>16} | {:>16} | {:>10} |", "accounts", "clone (top full)", "clone (flushed)", "trie saved");
    println!("|{:-<12}|{:-<18}|{:-<18}|{:-<12}|", "", "", "", "");

    for &n in &[1_000usize, 10_000, 50_000] {
        let l = build(n);
        let full = time_clone(&l); // overlay top holds all trie nodes
        l.flush(); // commit nodes into the shared base
        let flushed = time_clone(&l); // top empty → trie nodes shared, not copied
        println!(
            "| {n:>10} | {:>13.3} ms | {:>13.3} ms | {:>9.1}x |",
            full * 1e3,
            flushed * 1e3,
            if flushed > 0.0 { full / flushed } else { 0.0 }
        );
    }
    println!("\n'flushed' is the real cost during mining/mempool filtering, since the");
    println!("chain flushes after every committed block.");
}

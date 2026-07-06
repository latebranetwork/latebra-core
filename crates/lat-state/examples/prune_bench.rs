//! Quantifies the T6 pruning win: under churn, the content-addressed
//! commitment trie strands every overwritten path forever — the store grows
//! with *history*, not with state. `Ledger::prune_history` garbage-collects
//! nodes unreachable from the current root (plus a retained window of recent
//! roots), bounding growth to roughly live-state size.
//!
//! Workload: N accounts, then R rounds of touching every account's balance
//! (each round ≈ one committed block: state_root + flush, as lat-chain does).
//! We report trie node count and byte size before and after the sweep, and the
//! sweep's wall time.
//!
//! Run: cargo run --release --example prune_bench -p lat-state

use std::time::Instant;

use lat_state::Ledger;

fn build(n: usize) -> (Ledger, Vec<[u8; 32]>) {
    let mut l = Ledger::new();
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&(i as u64).to_le_bytes());
        l.register(id).unwrap();
        l.credit_public(&id, 0, 1_000);
        ids.push(id);
    }
    l.state_root();
    l.flush();
    (l, ids)
}

fn main() {
    println!("State-trie pruning under churn (release)\n");
    println!(
        "| {:>8} | {:>6} | {:>13} | {:>12} | {:>8} | {:>9} |",
        "accounts", "rounds", "nodes before", "nodes after", "shrink", "sweep"
    );
    println!("|{:-<10}|{:-<8}|{:-<15}|{:-<14}|{:-<10}|{:-<11}|", "", "", "", "", "", "");

    for &(n, rounds) in &[(1_000usize, 10u64), (10_000, 10), (10_000, 50), (50_000, 10)] {
        let (mut l, ids) = build(n);
        // Keep the last 4 roots like a chain with a small prune window would.
        let mut recent = std::collections::VecDeque::new();
        for round in 1..=rounds {
            for id in &ids {
                l.credit_public(id, 0, round);
            }
            recent.push_back(l.state_root());
            if recent.len() > 4 {
                recent.pop_front();
            }
            l.flush();
        }
        let before = l.state_node_count();
        let retain: Vec<[u8; 32]> = recent.iter().copied().collect();
        let t = Instant::now();
        let stats = l.prune_history(&retain);
        let sweep = t.elapsed().as_secs_f64();
        let after = l.state_node_count();
        assert_eq!(after, stats.kept);
        println!(
            "| {n:>8} | {rounds:>6} | {before:>13} | {after:>12} | {:>7.1}x | {:>6.0} ms |",
            before as f64 / after as f64,
            sweep * 1e3,
        );
    }
    println!("\n'nodes before' grows with rounds (history); 'nodes after' tracks live");
    println!("state + the retained 4-root window. Archive nodes simply never sweep.");
}

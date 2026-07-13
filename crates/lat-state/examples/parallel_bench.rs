//! Quantifies the T8 win: a block's transparent lane executed across all
//! cores versus the sequential apply loop, with a result verified identical.
//!
//! Two workloads, same size:
//! * **disjoint** — every transfer touches its own {sender, receiver} pair:
//!   one wave, embarrassingly parallel (the realistic exchange/payout shape).
//! * **hot receiver** — every transfer pays the same account: every
//!   transaction conflicts, the scheduler degenerates to sequential waves —
//!   the honest worst case (expect ~1x, measuring scheduling overhead).
//!
//! Run: cargo run --release --example parallel_bench -p lat-state

use std::time::Instant;

use lat_crypto::SecretKey;
use lat_state::{apply_block_parallel, Ledger, LAT_TOKEN};
use lat_types::Transaction;
use rand::rngs::OsRng;

fn signed(mut tx: Transaction, sk: &SecretKey) -> Transaction {
    let sig = sk.sign(&tx.signing_bytes()).to_bytes();
    if let Transaction::PublicTransfer { sig: s, .. } = &mut tx {
        *s = sig;
    }
    tx
}

fn main() {
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let n_tx = 2_000usize;
    println!("Transparent-lane parallel execution — {n_tx} public transfers, {cores} cores (release)\n");

    let mut rng = OsRng;
    let sks: Vec<SecretKey> = (0..2 * n_tx).map(|_| SecretKey::random(&mut rng)).collect();
    let ids: Vec<[u8; 32]> = sks.iter().map(|s| s.public_key().to_bytes()).collect();
    let mut base = Ledger::new();
    for id in &ids {
        base.register(*id).unwrap();
        base.credit_public(id, LAT_TOKEN, 1_000_000);
    }
    base.state_root();
    base.flush();

    let make = |to_of: &dyn Fn(usize) -> usize| -> Vec<Transaction> {
        (0..n_tx)
            .map(|i| {
                signed(
                    Transaction::PublicTransfer {
                        token: LAT_TOKEN,
                        from: ids[i],
                        to: ids[to_of(i)],
                        amount: 7,
                        fee: 1,
                        nonce: 0,
                        sig: [0u8; 64],
                    },
                    &sks[i],
                )
            })
            .collect()
    };

    println!("| {:>13} | {:>12} | {:>12} | {:>8} | {:>9} |", "workload", "sequential", "parallel", "speedup", "par tx/s");
    println!("|{:-<15}|{:-<14}|{:-<14}|{:-<10}|{:-<11}|", "", "", "", "", "");

    for (name, txs) in [
        ("disjoint", make(&|i| n_tx + i)),
        ("hot receiver", make(&|_| 2 * n_tx - 1)),
    ] {
        let mut seq = base.clone();
        let t = Instant::now();
        for tx in &txs {
            seq.apply_at(tx, 1).unwrap();
        }
        let t_seq = t.elapsed().as_secs_f64();

        let mut par = base.clone();
        let t = Instant::now();
        apply_block_parallel(&mut par, &txs, 1).unwrap();
        let t_par = t.elapsed().as_secs_f64();

        assert_eq!(seq.state_root(), par.state_root(), "parallel result must be identical");
        println!(
            "| {name:>13} | {:>9.1} ms | {:>9.1} ms | {:>7.2}x | {:>9.0} |",
            t_seq * 1e3,
            t_par * 1e3,
            t_seq / t_par,
            n_tx as f64 / t_par,
        );
    }
    // T12: a confidential block — the ~ms zero-knowledge proof per transfer is
    // the dominant cost; the pre-pass verifies them all across cores.
    let n_conf = 32usize;
    let mut cbase = Ledger::new();
    let csks: Vec<SecretKey> = (0..2 * n_conf).map(|_| SecretKey::random(&mut rng)).collect();
    let cids: Vec<[u8; 32]> = csks.iter().map(|s| s.public_key().to_bytes()).collect();
    for id in &cids {
        cbase.register(*id).unwrap();
        cbase.credit_genesis(id, 1_000_000).unwrap();
    }
    cbase.state_root();
    cbase.flush();
    let ctxs: Vec<Transaction> = (0..n_conf)
        .map(|i| Transaction::SolventTransfer {
            token: LAT_TOKEN,
            xfer: lat_crypto::SolventTransfer::create(
                &csks[i],
                &csks[n_conf + i].public_key(),
                LAT_TOKEN,
                1_000,
                10,
                1_000_000,
                &cbase.balance(&cids[i], LAT_TOKEN).unwrap(),
                0,
                &mut rng,
            )
            .unwrap(),
        })
        .collect();

    let mut seq = cbase.clone();
    let t = Instant::now();
    for tx in &ctxs {
        seq.apply_at(tx, 1).unwrap();
    }
    let t_seq = t.elapsed().as_secs_f64();
    let mut par = cbase.clone();
    let t = Instant::now();
    apply_block_parallel(&mut par, &ctxs, 1).unwrap();
    let t_par = t.elapsed().as_secs_f64();
    assert_eq!(seq.state_root(), par.state_root());
    println!(
        "| {:>13} | {:>9.1} ms | {:>9.1} ms | {:>7.2}x | {:>9.0} |",
        format!("solvent x{n_conf}"),
        t_seq * 1e3,
        t_par * 1e3,
        t_seq / t_par,
        n_conf as f64 / t_par,
    );

    println!("\nRoots verified identical for all workloads (bit-identical to sequential).");
}

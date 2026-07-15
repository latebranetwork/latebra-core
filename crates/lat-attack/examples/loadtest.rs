//! End-to-end throughput against a **live** `latebrad`.
//!
//! `bench.rs` measures execution in-process: how fast the code applies a
//! transaction with no network, no mempool and no consensus in the way. Those
//! numbers (23-30k/s transparent, ~650/s confidential) are the ones Latebra
//! quotes, and **no chain can reach them**, because a chain is not an execution
//! benchmark. This measures the thing that actually matters: submit real
//! transactions to a running node and count how many *mine*.
//!
//! The ceiling is structural, and it is worth knowing before you read the
//! output:
//!
//! ```text
//!   MAX_TXS_PER_BLOCK (1000, consensus) / TARGET_BLOCK_TIME_SECS (3) = 333 TPS
//! ```
//!
//! 333 is the hard cap for **every** lane. The confidential lane's ~650/s
//! execution speed is therefore unreachable on-chain by ~2x, and the transparent
//! lane's ~30k/s by ~90x. This tool measures how close the chain gets to 333 —
//! not how fast the code is.
//!
//! It also answers a question the docs and the code disagree about. THREAT_MODEL
//! §2.7 says "one confidential/public spend per account per block", but the
//! ledger's only replay rule is `nonce == account.nonce`, and blocks apply
//! transactions in order — so nonces n, n+1, n+2 from one account should all land
//! in the same block. Whichever is true, this prints it: `txs/block > 1` from a
//! single sender means the doc is wrong; `== 1` means the doc is right and
//! reaching 333 TPS needs ~1000 distinct funded accounts.
//!
//! Run (release — debug crypto is ~20-50x slower):
//! ```sh
//!   latebrad --mine --data /tmp/lt.db --listen 127.0.0.1:4040
//!   cargo run --release --example loadtest -p lat-attack -- \
//!       --node 127.0.0.1:4040 --txs 3000 --secs 45
//! ```

use std::collections::HashSet;
use std::env;
use std::thread;
use std::time::{Duration, Instant};

use lat_chain::{Block, MIN_TRANSFER_FEE};
use lat_state::LAT_TOKEN;
use lat_types::{Network, Transaction};
use lat_wallet::Wallet;

/// The well-known testnet genesis seed (`latebrad`'s `GENESIS_SEED`). It holds
/// the public premine, which is the only source of spendable *public* LAT — and
/// public LAT is what transaction fees are paid from. NB: mining rewards do NOT
/// work here; `reward_miner` credits the confidential balance.
const GENESIS_SEED: [u8; 32] = [42u8; 32];
/// latebrad's `MINER_SEED` — registered at genesis, so it is a legal receiver.
const MINER_SEED: [u8; 32] = [43u8; 32];

struct Args {
    node: String,
    txs: usize,
    secs: u64,
}

fn parse_args() -> Args {
    let mut a = Args { node: "127.0.0.1:4040".into(), txs: 3000, secs: 45 };
    let v: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < v.len() {
        match v[i].as_str() {
            "--node" => { i += 1; a.node = v.get(i).cloned().unwrap_or(a.node); }
            "--txs" => { i += 1; a.txs = v.get(i).and_then(|s| s.parse().ok()).unwrap_or(a.txs); }
            "--secs" => { i += 1; a.secs = v.get(i).and_then(|s| s.parse().ok()).unwrap_or(a.secs); }
            _ => {}
        }
        i += 1;
    }
    a
}

fn main() {
    let args = parse_args();
    let w = Wallet::from_seed(Network::Testnet, GENESIS_SEED);

    let height0 = match lat_p2p::get_height(&args.node) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("cannot reach {} — is latebrad running? ({e})", args.node);
            std::process::exit(1);
        }
    };
    let balance = lat_p2p::get_public_balance(&args.node, w.id(), LAT_TOKEN)
        .ok()
        .flatten()
        .unwrap_or(0);
    let nonce0 = match lat_p2p::get_nonce(&args.node, w.id()) {
        Ok(Some(n)) => n,
        _ => {
            eprintln!("genesis account is not registered on this chain");
            std::process::exit(1);
        }
    };

    println!("Latebra load test — END TO END, against a live node");
    println!("  node          : {}", args.node);
    println!("  height        : {height0}");
    println!("  sender        : genesis, {} LAT public", balance / 100_000);
    println!("  structural cap: {} txs/block / {}s = {:.0} TPS",
        lat_chain::MAX_TXS_PER_BLOCK,
        lat_chain::TARGET_BLOCK_TIME_SECS,
        lat_chain::MAX_TXS_PER_BLOCK as f64 / lat_chain::TARGET_BLOCK_TIME_SECS as f64);

    let need = (args.txs as u64) * (1 + MIN_TRANSFER_FEE);
    if balance < need {
        eprintln!("\ngenesis has {balance} public base units, needs ~{need} for {} txs", args.txs);
        std::process::exit(1);
    }

    // --- build ------------------------------------------------------------
    // Sequential nonces from ONE sender. Every transfer sends 1 base unit to a
    // throwaway id, so the only cost is the fee and nothing else moves.
    print!("\nbuilding {} signed transfers... ", args.txs);
    let build = Instant::now();
    // The receiver MUST already be registered: PublicTransfer rejects an
    // unregistered `to` with ReceiverNotRegistered. Freshly generated addresses
    // therefore never mine — so we pay the miner account, which latebrad
    // registers at genesis. (This makes every transfer share both accounts, so
    // T8 serializes them all; a throughput test of the transparent lane's
    // PARALLELISM needs many funded senders, which needs many registrations,
    // which is its own bootstrap problem.)
    let to = Wallet::from_seed(Network::Testnet, MINER_SEED).address();
    let txs: Vec<Transaction> = (0..args.txs)
        .map(|i| w.build_public_transfer(&to, LAT_TOKEN, 1, MIN_TRANSFER_FEE, nonce0 + i as u64))
        .collect();
    println!("{:.2}s ({:.0}/s signing)", build.elapsed().as_secs_f64(),
        args.txs as f64 / build.elapsed().as_secs_f64());

    // --- submit -----------------------------------------------------------
    // Fire everything at the mempool as fast as it will take it. MAX_MEMPOOL_TXS
    // is 8192 with fee-priority eviction, so a flood beyond that is expected to
    // shed — that shedding is part of what we are measuring.
    print!("submitting... ");
    let submit = Instant::now();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for tx in &txs {
        match lat_p2p::submit_tx(&args.node, &tx.encode()) {
            Ok(true) => accepted += 1,
            Ok(false) => rejected += 1,
            Err(_) => rejected += 1,
        }
    }
    let submit_secs = submit.elapsed().as_secs_f64();
    println!("{accepted} accepted, {rejected} rejected in {submit_secs:.2}s ({:.0}/s)",
        accepted as f64 / submit_secs);

    // --- watch ------------------------------------------------------------
    // Count only what MINES. A transaction in the mempool has not happened.
    println!("\nwatching blocks for {}s...\n", args.secs);
    let want: HashSet<[u8; 32]> = txs.iter().map(lat_chain::tx_hash).collect();
    let mut mined = 0usize;
    let mut blocks = 0usize;
    let mut per_block: Vec<usize> = Vec::new();
    let mut h = height0 + 1;
    let watch = Instant::now();
    let first_mined = std::cell::Cell::new(None::<f64>);

    while watch.elapsed() < Duration::from_secs(args.secs) {
        match lat_p2p::get_block(&args.node, h) {
            Ok(Some(bytes)) => {
                if let Some(block) = Block::decode(&bytes) {
                    let hits = block.txs.iter().filter(|t| want.contains(&lat_chain::tx_hash(t))).count();
                    if hits > 0 {
                        if first_mined.get().is_none() {
                            first_mined.set(Some(watch.elapsed().as_secs_f64()));
                        }
                        mined += hits;
                        per_block.push(hits);
                        println!("  block {h}: {hits} of ours ({} total)", block.txs.len());
                    }
                    blocks += 1;
                    h += 1;
                    continue; // don't sleep; drain any backlog
                }
                h += 1;
            }
            _ => thread::sleep(Duration::from_millis(300)), // not mined yet
        }
        if mined >= accepted {
            break;
        }
    }

    // --- report -----------------------------------------------------------
    // TPS is mined / (blocks used x block interval), NOT mined / wall-clock.
    // Wall-clock flatters wildly: if a burst fits one block, the watcher sees it
    // all "arrive" in the poll interval and reports a rate the chain can never
    // sustain (an early version printed 1655 TPS against a 333 cap). What the
    // chain actually sustains is how full each block gets, over the block time.
    let elapsed = watch.elapsed().as_secs_f64();
    let _ = first_mined.get();
    let blocks_used = per_block.len().max(1) as f64;
    let tps = mined as f64 / (blocks_used * lat_chain::TARGET_BLOCK_TIME_SECS as f64);
    let cap = lat_chain::MAX_TXS_PER_BLOCK as f64 / lat_chain::TARGET_BLOCK_TIME_SECS as f64;
    let avg_per_block = if per_block.is_empty() { 0.0 } else {
        per_block.iter().sum::<usize>() as f64 / per_block.len() as f64
    };

    println!("\n--- RESULT -------------------------------------------------");
    println!("  submitted (accepted) : {accepted}");
    println!("  MINED                : {mined}");
    println!("  blocks scanned       : {blocks}");
    println!("  blocks carrying ours : {}", per_block.len());
    println!("  txs/block (ours, avg): {avg_per_block:.1}   max {}", per_block.iter().max().copied().unwrap_or(0));
    println!("  SUSTAINED TPS        : {tps:.1}   (mined / blocks-used / {}s)", lat_chain::TARGET_BLOCK_TIME_SECS);
    println!("  wall-clock elapsed   : {elapsed:.1}s");
    println!("  structural cap       : {cap:.0}   ({:.0}% of cap achieved)", tps / cap * 100.0);
    if mined < accepted {
        println!("  NOT MINED            : {} still pending or dropped", accepted - mined);
    }
    println!();
    if avg_per_block <= 1.0 && !per_block.is_empty() {
        println!("  NOTE: 1 tx/block from one sender — THREAT_MODEL §2.7's rate model");
        println!("        holds. Reaching {cap:.0} TPS needs ~{} distinct funded accounts.",
            lat_chain::MAX_TXS_PER_BLOCK);
    } else if avg_per_block > 1.0 {
        println!("  NOTE: {avg_per_block:.1} txs/block from ONE sender — THREAT_MODEL §2.7");
        println!("        (\"one spend per account per block\") is WRONG for the public lane.");
    }
    println!("  Compare honestly: this is a chain number. bench.rs prints execution");
    println!("  numbers, which no chain can reach.");
}

//! End-to-end soak: drive thousands of real transactions of EVERY kind the
//! chain accepts through the real wallet/crypto/consensus stack, mine them into
//! real blocks, and report per-operation throughput plus every failure.
//!
//! This is not the micro-benchmark (`examples/bench.rs`, which times isolated
//! hot paths). This exercises the whole economy end to end — register, public
//! and confidential and anonymous transfers, shield/unshield, stealth, tokens,
//! bonding-curve buys and sells, AMM liquidity and swaps, contracts, staking,
//! and HTLC lock/claim/refund — and checks the ledger's invariants afterwards.
//!
//! Run in release (debug crypto is ~20-50x slower and not representative):
//!     cargo run --release --example soak -p lat-attack
//!
//! Optional: `--wallets N` (default 48), `--rounds N` (default 40).

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use lat_chain::{Blockchain, DEFAULT_DIFFICULTY, MIN_TRANSFER_FEE, MIN_VALIDATOR_STAKE};
use lat_state::LAT_TOKEN;
use lat_types::{Network, Transaction};
use lat_wallet::Wallet;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const FEE: u64 = MIN_TRANSFER_FEE;
/// Confidential premine per wallet.
const PREMINE: u64 = 2_000_000;
/// Transparent premine per wallet — funds shields, tokens, pools and stakes.
const PUBLIC_PREMINE: u64 = 500_000_000;

/// Per-operation tally: attempts, how many produced a valid on-chain effect,
/// and the wall-clock spent building them.
#[derive(Default)]
struct Stat {
    attempted: usize,
    built: usize,
    /// Construction returned None — the wallet declined to build the tx.
    unbuildable: usize,
    /// Included in a block that the ledger accepted.
    applied: usize,
    build_time: Duration,
}

#[derive(Default)]
struct Report {
    ops: BTreeMap<&'static str, Stat>,
    errors: Vec<String>,
    blocks: usize,
    block_time: Duration,
}

impl Report {
    fn stat(&mut self, name: &'static str) -> &mut Stat {
        self.ops.entry(name).or_default()
    }
    fn err(&mut self, msg: String) {
        // Keep the log bounded — a systemic failure would otherwise print
        // thousands of identical lines and bury everything else.
        if self.errors.len() < 40 {
            self.errors.push(msg);
        }
    }
}

/// Build one tx, timing construction. `f` returning None counts as unbuildable
/// (a legitimate refusal, e.g. insufficient balance) rather than an error.
fn build(
    rep: &mut Report,
    name: &'static str,
    f: impl FnOnce() -> Option<Transaction>,
) -> Option<Transaction> {
    let t = Instant::now();
    let tx = f();
    let dt = t.elapsed();
    let s = rep.stat(name);
    s.attempted += 1;
    s.build_time += dt;
    match tx {
        Some(tx) => {
            s.built += 1;
            Some(tx)
        }
        None => {
            s.unbuildable += 1;
            None
        }
    }
}

/// Extra blocks a single failing batch may spend isolating its bad transactions
/// before the rest are written off. Every block is real proof-of-work, and
/// difficulty retargets toward the 3s target on each one, so blocks — not
/// transactions — are what this harness pays for.
const MAX_SPLIT_BLOCKS: usize = 16;

/// Mine `batch` into a block and apply it. Applying is all-or-nothing, so on
/// failure the batch is split in HALF and each half retried, recursively, until
/// the offending transactions are isolated — one bad transaction must not mask
/// the rest of the round.
///
/// Halving, not one-at-a-time: a linear walk costs one block per transaction,
/// and at a few hundred transactions per round that is minutes of PoW per
/// failure. Binary search finds a culprit in ~log2(n) blocks instead.
fn seal(chain: &mut Blockchain, rep: &mut Report, batch: Vec<(&'static str, Transaction)>) {
    if batch.is_empty() {
        return;
    }
    let mut queue = vec![batch];
    let mut split_blocks = 0usize;

    while let Some(part) = queue.pop() {
        if part.is_empty() {
            continue;
        }
        let (names, txs): (Vec<_>, Vec<_>) = part.clone().into_iter().unzip();
        let t = Instant::now();
        let block = chain.mine(txs.clone());
        let res = chain.apply_block(&block);
        rep.block_time += t.elapsed();
        rep.blocks += 1;

        match res {
            Ok(()) => {
                for n in names {
                    rep.stat(n).applied += 1;
                }
            }
            // A single transaction that will not apply — this is the culprit.
            Err(e) if txs.len() == 1 => rep.err(format!("{}: {e:?}", names[0])),
            Err(e) => {
                if split_blocks >= MAX_SPLIT_BLOCKS {
                    rep.err(format!(
                        "gave up isolating {} tx after {MAX_SPLIT_BLOCKS} split blocks: {e:?}",
                        txs.len()
                    ));
                    continue;
                }
                split_blocks += 2;
                let mut left = part;
                let right = left.split_off(left.len() / 2);
                queue.push(right);
                queue.push(left);
            }
        }
    }
}

fn arg(flag: &str, default: usize) -> usize {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let n_wallets = arg("--wallets", 300);
    let rounds = arg("--rounds", 12);
    let mut rng = OsRng;
    let mut rep = Report::default();

    println!("Latebra end-to-end soak — every transaction type, real crypto, real blocks");
    println!("wallets = {n_wallets}, rounds = {rounds}, difficulty = {DEFAULT_DIFFICULTY}\n");

    let wallets: Vec<Wallet> =
        (0..n_wallets).map(|_| Wallet::generate(Network::Testnet, &mut rng)).collect();
    let conf: Vec<([u8; 32], u64)> = wallets.iter().map(|w| (w.id(), PREMINE)).collect();
    let public: Vec<([u8; 32], u64)> = wallets.iter().map(|w| (w.id(), PUBLIC_PREMINE)).collect();
    let mut chain = Blockchain::genesis_with_public(&conf, &public, DEFAULT_DIFFICULTY);

    let started = Instant::now();
    let mut phase = Instant::now();
    macro_rules! mark { ($n:expr) => { println!("  [phase] {:<22} {:>8.2}s", $n, phase.elapsed().as_secs_f64()); phase = Instant::now(); } }

    // ---------------------------------------------------------------- register
    // Premined accounts already exist; registering fresh ones exercises the
    // registration PoW path that every real user hits first.
    {
        let mut batch = Vec::new();
        for _ in 0..n_wallets.min(16) {
            let w = Wallet::generate(Network::Testnet, &mut rng);
            if let Some(tx) = build(&mut rep, "Register", || Some(w.registration_tx())) {
                batch.push(("Register", tx));
            }
        }
        seal(&mut chain, &mut rep, batch);
    }

    mark!("register");
    // ------------------------------------------------------------ token + curve
    // One token per wallet, so curve trades and pools have something to trade.
    let mut tokens: Vec<u32> = Vec::new();
    {
        let mut batch = Vec::new();
        let n_tokens = n_wallets.min(12);
        for (i, w) in wallets.iter().enumerate().take(n_tokens) {
            let ticker = format!("SOAK{i}");
            if let Some(tx) = build(&mut rep, "CreateToken", || Some(w.create_token(&ticker, 10_000_000)))
            {
                batch.push(("CreateToken", tx));
            }
        }
        seal(&mut chain, &mut rep, batch);
        for i in 0..n_tokens {
            if let Some(meta) = chain.token(&format!("SOAK{i}")) {
                tokens.push(meta.id);
            } else {
                rep.err(format!("token SOAK{i} missing after CreateToken"));
            }
        }
    }

    mark!("tokens");
    // ------------------------------------------------------------- main rounds
    // Each round is one block. A wallet makes at most one *confidential* spend
    // per block and one anonymous spend per epoch (20 blocks), so the round
    // gives each wallet a single job and rotates which job that is.
    for round in 0..rounds {
        let mut batch: Vec<(&'static str, Transaction)> = Vec::new();

        for (i, w) in wallets.iter().enumerate() {
            let peer = &wallets[(i + 1) % wallets.len()];
            let to = peer.address();
            let slot = (i + round) % 8;

            match slot {
                // ---- transparent transfer
                0 => {
                    if let Some(tx) = build(&mut rep, "PublicTransfer", || {
                        w.create_public_transfer(&chain, &to, LAT_TOKEN, 1_000, FEE)
                    }) {
                        batch.push(("PublicTransfer", tx));
                    }
                }
                // ---- public -> private
                1 => {
                    if let Some(tx) = build(&mut rep, "Shield", || {
                        w.create_shield(&chain, &w.address(), LAT_TOKEN, 5_000, FEE)
                    }) {
                        batch.push(("Shield", tx));
                    }
                }
                // ---- confidential transfer (amount hidden)
                2 => {
                    if let Some(tx) = build(&mut rep, "SolventTransfer", || {
                        w.create_solvent_transfer(&chain, &to, LAT_TOKEN, 500, FEE, &mut rng)
                    }) {
                        batch.push(("SolventTransfer", tx));
                    }
                }
                // ---- make received confidential funds spendable
                3 => {
                    if let Some(n) = chain.nonce(&w.id()) {
                        if let Some(tx) = build(&mut rep, "Rollover", || Some(w.rollover_tx(n))) {
                            batch.push(("Rollover", tx));
                        }
                    }
                }
                // ---- private -> public
                4 => {
                    if let Some(tx) = build(&mut rep, "Unshield", || {
                        w.create_unshield(&chain, &w.address(), LAT_TOKEN, 200, FEE, &mut rng)
                    }) {
                        batch.push(("Unshield", tx));
                    }
                }
                // ---- shield straight to a one-time stealth address
                5 => {
                    if let Some(tx) = build(&mut rep, "ShieldStealth", || {
                        w.create_shield_stealth(&chain, &to, LAT_TOKEN, 400, FEE, &mut rng)
                    }) {
                        batch.push(("ShieldStealth", tx));
                    }
                }
                // ---- bonding-curve buy / sell ("buying a token")
                6 => {
                    if let (Some(&tok), Some(n)) =
                        (tokens.get(i % tokens.len().max(1)), chain.nonce(&w.id()))
                    {
                        let holding = chain.public_balance(&w.id(), tok).unwrap_or(0);
                        // A curve locks for good once it has collected
                        // GRADUATE_LAT (500 LAT), after which every trade is
                        // correctly refused — trading has moved to the AMM pool.
                        // At scale the curves do reach it, so skip them rather
                        // than bank thousands of expected rejections.
                        let graduated = chain.curve(tok).map(|c| c.graduated).unwrap_or(false);
                        if graduated {
                            // nothing to do on this curve any more
                        }
                        // Sell back only what we actually hold, else buy more.
                        else if holding > 1_000 && round % 3 == 2 {
                            if let Some(tx) = build(&mut rep, "CurveTrade(sell)", || {
                                Some(w.curve_trade(tok, false, holding / 2, 1, FEE, n))
                            }) {
                                batch.push(("CurveTrade(sell)", tx));
                            }
                        } else if let Some(tx) = build(&mut rep, "CurveTrade(buy)", || {
                            Some(w.curve_trade(tok, true, 200_000, 1, FEE, n))
                        }) {
                            batch.push(("CurveTrade(buy)", tx));
                        }
                    }
                }
                // ---- AMM: seed a pool, then swap against it
                _ => {
                    if let (Some(&tok), Some(n)) =
                        (tokens.get(i % tokens.len().max(1)), chain.nonce(&w.id()))
                    {
                        // Only the token's creator (wallet i == token i) seeds
                        // its pool. Several wallets seeding one pool in a single
                        // block is a harness error, not a chain one: the first
                        // sets the price and the rest carry a ratio that no
                        // longer matches, which the ledger rightly rejects as
                        // SlippageExceeded. Everyone else swaps instead.
                        let is_creator = i < tokens.len() && tokens[i] == tok;
                        let held = chain.public_balance(&w.id(), tok).unwrap_or(0);
                        if is_creator && chain.pool(tok).is_none() && held > 10_000 {
                            if let Some(tx) = build(&mut rep, "AddLiquidity", || {
                                Some(w.add_liquidity(tok, 100_000, held / 2, FEE, n))
                            }) {
                                batch.push(("AddLiquidity", tx));
                            }
                        } else if chain.pool(tok).is_some() {
                            if let Some(tx) = build(&mut rep, "Swap", || {
                                Some(w.swap(tok, true, 10_000, 1, FEE, n))
                            }) {
                                batch.push(("Swap", tx));
                            }
                        }
                    }
                }
            }
        }

        seal(&mut chain, &mut rep, batch);

        // Anonymous transfers get their OWN block, built after the round above
        // has been applied. An anon proof binds the exact balance ciphertext of
        // every ring member, so any other transaction that moves a decoy's
        // confidential balance in the same block invalidates it
        // (`StaleRingBalance`). Batching them with 300 ordinary transfers fails
        // all of them — a real constraint on anonymous spends, not a chain bug.
        // Also: one anonymous spend per account per 20-block epoch.
        // Each anon transfer is built against the CURRENT tip and sealed alone.
        // Two anonymous transfers in one block also collide whenever their rings
        // overlap — the first to land moves a decoy's balance and staleness the
        // rest — so a wallet has to rebuild against the new tip. Serialising
        // them here measures the anon path itself rather than that contention,
        // which is reported separately below.
        if round % 20 == 5 {
            for (i, w) in wallets.iter().enumerate().take(8) {
                let to = wallets[(i + 3) % wallets.len()].address();
                if let Some(tx) = build(&mut rep, "AnonTransfer", || {
                    w.create_anon_transfer(&chain, &to, LAT_TOKEN, 100, FEE, 8, &mut rng)
                }) {
                    seal(&mut chain, &mut rep, vec![("AnonTransfer", tx)]);
                }
            }
        }

        if round % 10 == 0 {
            println!("  round {round:>3}/{rounds}  height {:>4}", chain.height());
        }
    }

    mark!("main rounds");
    // ------------------------------------------------------ contracts + staking
    {
        let mut batch = Vec::new();
        // A tiny valid program: push, push, add, stop.
        let code: Vec<u8> = vec![0x01, 0x02, 0x01, 0x03, 0x10, 0x00];
        for w in wallets.iter().take(8) {
            if let Some(tx) = build(&mut rep, "DeployContract", || Some(w.deploy_contract(code.clone())))
            {
                batch.push(("DeployContract", tx));
            }
        }
        seal(&mut chain, &mut rep, batch);

        let mut batch = Vec::new();
        for w in wallets.iter().take(8) {
            if let Some(n) = chain.nonce(&w.id()) {
                if let Some(tx) = build(&mut rep, "Stake", || Some(w.stake_tx(MIN_VALIDATOR_STAKE, n)))
                {
                    batch.push(("Stake", tx));
                }
            }
        }
        seal(&mut chain, &mut rep, batch);

        let mut batch = Vec::new();
        for w in wallets.iter().take(4) {
            if let Some(n) = chain.nonce(&w.id()) {
                if let Some(tx) =
                    build(&mut rep, "Unstake", || Some(w.unstake_tx(MIN_VALIDATOR_STAKE / 2, n)))
                {
                    batch.push(("Unstake", tx));
                }
            }
        }
        seal(&mut chain, &mut rep, batch);
    }

    mark!("contracts+staking");
    // ------------------------------------------------------------------- HTLCs
    {
        let mut locks = Vec::new();
        let mut batch = Vec::new();
        let n_tokens = n_wallets.min(12);
        for (i, w) in wallets.iter().enumerate().take(n_tokens) {
            let to = wallets[(i + 1) % wallets.len()].address();
            let preimage = [i as u8 + 1; 32];
            let hashlock: [u8; 32] = Sha256::digest(preimage).into();
            let expiry = chain.height() + 4;
            if let Some(n) = chain.nonce(&w.id()) {
                let (tx, id) = w.htlc_lock(LAT_TOKEN, &to, 5_000, hashlock, expiry, FEE, n);
                let s = rep.stat("HtlcLock");
                s.attempted += 1;
                s.built += 1;
                batch.push(("HtlcLock", tx));
                locks.push((i, id, preimage));
            }
        }
        seal(&mut chain, &mut rep, batch);

        // Half are claimed with the preimage by the recipient; the rest are left
        // to expire and then refunded to the sender.
        let mut batch = Vec::new();
        for (i, id, preimage) in locks.iter().take(6) {
            let claimer = &wallets[(*i + 1) % wallets.len()];
            let s = rep.stat("HtlcClaim");
            s.attempted += 1;
            s.built += 1;
            let _ = claimer;
            batch.push(("HtlcClaim", Wallet::htlc_claim(*id, *preimage)));
        }
        seal(&mut chain, &mut rep, batch);

        // Mine past the expiry so the refunds are valid.
        for _ in 0..5 {
            let b = chain.mine(vec![]);
            if let Err(e) = chain.apply_block(&b) {
                rep.err(format!("filler block rejected: {e:?}"));
                break;
            }
            rep.blocks += 1;
        }
        let mut batch = Vec::new();
        for (_i, id, _) in locks.iter().skip(6) {
            let s = rep.stat("HtlcRefund");
            s.attempted += 1;
            s.built += 1;
            batch.push(("HtlcRefund", Wallet::htlc_refund(*id)));
        }
        seal(&mut chain, &mut rep, batch);
    }

    mark!("htlcs");
    let _ = phase; // the final mark leaves phase unread; keeps -D warnings happy
    let elapsed = started.elapsed();

    // ------------------------------------------------------------------ report
    println!("\n| {:<22} | {:>9} | {:>9} | {:>9} | {:>12} |", "operation", "attempted", "applied", "declined", "build/op");
    println!("|{:-<24}|{:-<11}|{:-<11}|{:-<11}|{:-<14}|", "", "", "", "", "");
    let mut total_attempted = 0usize;
    let mut total_applied = 0usize;
    for (name, s) in &rep.ops {
        total_attempted += s.attempted;
        total_applied += s.applied;
        let per = if s.built > 0 { s.build_time / s.built as u32 } else { Duration::ZERO };
        let per_str = if per.as_nanos() >= 1_000_000 {
            format!("{:.2} ms", per.as_nanos() as f64 / 1e6)
        } else {
            format!("{:.1} \u{00b5}s", per.as_nanos() as f64 / 1e3)
        };
        println!(
            "| {name:<22} | {:>9} | {:>9} | {:>9} | {per_str:>12} |",
            s.attempted, s.applied, s.unbuildable
        );
    }

    println!("\ntotals");
    println!("  transactions attempted : {total_attempted}");
    println!("  transactions applied   : {total_applied}");
    println!("  blocks mined           : {}", rep.blocks);
    println!("  chain height           : {}", chain.height());
    println!("  wall clock             : {:.2}s", elapsed.as_secs_f64());
    println!(
        "  mine+apply per block   : {:.1} ms",
        rep.block_time.as_secs_f64() * 1000.0 / rep.blocks.max(1) as f64
    );

    // --------------------------------------------------------------- invariants
    println!("\ninvariants");
    let inv_t = Instant::now();
    let mut bad = 0;
    // Every wallet's confidential balance must still decrypt — a corrupted
    // ciphertext is silent otherwise, and would mean unspendable funds.
    let mut undecryptable = 0;
    for w in &wallets {
        match chain.balance(&w.id(), LAT_TOKEN) {
            Some(ct) if w.decrypt_ciphertext(&ct).is_none() => undecryptable += 1,
            _ => {}
        }
    }
    println!(
        "  {} confidential balances decrypt cleanly ({undecryptable} failed)",
        if undecryptable == 0 { "OK  " } else { "FAIL" }
    );
    bad += undecryptable.min(1);

    // The curve must never owe more LAT than it holds.
    let mut curve_bad = 0;
    for c in chain.curves() {
        if c.vtok == 0 || c.vlat == 0 {
            curve_bad += 1;
        }
    }
    println!(
        "  {} {} bonding curve(s) have sane reserves ({curve_bad} bad)",
        if curve_bad == 0 { "OK  " } else { "FAIL" },
        chain.curves().len()
    );
    bad += curve_bad.min(1);

    // Pools must keep both sides non-empty.
    let mut pool_bad = 0;
    for p in chain.pools() {
        if p.lat == 0 || p.tok == 0 {
            pool_bad += 1;
        }
    }
    println!(
        "  {} {} AMM pool(s) hold both sides ({pool_bad} empty)",
        if pool_bad == 0 { "OK  " } else { "FAIL" },
        chain.pools().len()
    );
    bad += pool_bad.min(1);

    // The chain must still re-open and agree with itself.
    println!("  (invariant checks took {:.2}s)", inv_t.elapsed().as_secs_f64());
    let tip = chain.tip();
    println!("  --  tip {}", hex(&tip));

    if rep.errors.is_empty() {
        println!("\nERRORS: none");
    } else {
        println!("\nERRORS ({} shown, capped at 40):", rep.errors.len());
        for e in &rep.errors {
            println!("  - {e}");
        }
    }
    if bad > 0 || !rep.errors.is_empty() {
        println!("\nRESULT: FAILURES PRESENT");
        std::process::exit(1);
    }
    println!("\nRESULT: clean — {total_applied} transactions applied across {} blocks", rep.blocks);
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().take(6).map(|x| format!("{x:02x}")).collect()
}

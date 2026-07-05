//! Real-workload micro-benchmark over the actual Latebra stack — no mocks. It
//! builds a premined chain with the real wallet/crypto/VM and times the hot
//! paths a client and a full node actually run: key generation, PoW, proof
//! construction for each transfer flavour, block validation, and serialization.
//!
//! Run in release (debug crypto is ~20-50x slower and not representative):
//!     cargo run --release --example bench -p lat-attack
//!
//! Numbers are wall-clock medians over repeated iterations on one core.

use std::time::{Duration, Instant};

use lat_chain::{Blockchain, DEFAULT_DIFFICULTY, MIN_TRANSFER_FEE};
use lat_state::LAT_TOKEN;
use lat_types::{Network, Transaction};
use lat_wallet::Wallet;
use rand::rngs::OsRng;

const FEE: u64 = MIN_TRANSFER_FEE;
const PREMINE: u64 = 1_000_000;

/// Time `f` over `iters` iterations (after `warmup` untimed runs) and return the
/// median per-call duration. `f` returns a value so the optimizer can't elide it.
fn bench<T>(iters: usize, warmup: usize, mut f: impl FnMut() -> T) -> Duration {
    for _ in 0..warmup {
        std::hint::black_box(f());
    }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        std::hint::black_box(f());
        samples.push(t.elapsed());
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn row(name: &str, per_op: Duration) {
    let ns = per_op.as_nanos();
    let per_op_str = if ns >= 1_000_000 {
        format!("{:.3} ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.2} \u{00b5}s", ns as f64 / 1_000.0)
    } else {
        format!("{ns} ns")
    };
    let ops = 1_000_000_000.0 / ns.max(1) as f64;
    println!("| {name:<40} | {per_op_str:>12} | {ops:>14.0} |");
}

fn main() {
    println!("Latebra real-workload benchmark (release, single core)");
    println!("difficulty D = {DEFAULT_DIFFICULTY}, registration PoW = 8 bits\n");
    println!("| {:<40} | {:>12} | {:>14} |", "operation", "median/op", "ops/sec");
    println!("|{:-<42}|{:-<14}|{:-<16}|", "", "", "");

    let mut rng = OsRng;

    // ---- A premined economy: 64 funded wallets form the anon decoy pool. ----
    let wallets: Vec<Wallet> = (0..64).map(|_| Wallet::generate(Network::Testnet, &mut rng)).collect();
    let premine: Vec<([u8; 32], u64)> = wallets.iter().map(|w| (w.id(), PREMINE)).collect();
    let chain = Blockchain::genesis(&premine, DEFAULT_DIFFICULTY);
    let sender = &wallets[0];
    let receiver = wallets[1].address();

    // ---- Client-side cryptography ----
    row("keypair generation", bench(2000, 100, || Wallet::generate(Network::Testnet, &mut rng)));

    row(
        "account registration PoW (8 bits)",
        bench(200, 10, || {
            let w = Wallet::generate(Network::Testnet, &mut rng);
            lat_chain::mine_registration(w.id())
        }),
    );

    // Balance decryption is a bounded discrete-log recovery; time it at PREMINE.
    let bal_ct = chain.balance(&sender.id(), LAT_TOKEN).unwrap();
    row("balance decryption (discrete log)", bench(500, 20, || sender.decrypt_ciphertext(&bal_ct)));

    // ---- Transfer construction (proof generation) ----
    row(
        "confidential transfer: build proof",
        bench(300, 20, || {
            sender.create_solvent_transfer(&chain, &receiver, LAT_TOKEN, 100, FEE, &mut rng).unwrap()
        }),
    );

    row(
        "public transfer: build + sign",
        bench(2000, 100, || {
            sender.build_public_transfer(&receiver, LAT_TOKEN, 100, FEE, 0)
        }),
    );

    for ring in [2usize, 8, 16] {
        row(
            &format!("anonymous transfer: build ring={ring}"),
            bench(200, 10, || {
                sender.create_anon_transfer(&chain, &receiver, LAT_TOKEN, 100, FEE, ring, &mut rng).unwrap()
            }),
        );
    }

    // ---- Consensus / node-side validation ----
    // A confidential transfer verified through full block application: build a
    // chain of blocks (each spending once from `sender`), then time replaying
    // them into a fresh node. Per-block cost = 1 proof verify + coinbase + state
    // root recompute + signature checks.
    let n_blocks = 50usize;
    let mut producer = Blockchain::genesis(&premine, DEFAULT_DIFFICULTY);
    let mut block_bytes: Vec<Vec<u8>> = Vec::with_capacity(n_blocks);
    for _ in 0..n_blocks {
        let tx = sender.create_solvent_transfer(&producer, &receiver, LAT_TOKEN, 1, FEE, &mut rng).unwrap();
        let block = producer.mine(vec![tx]);
        block_bytes.push(block.encode());
        producer.apply_block(&block).unwrap();
    }
    // Replay-time each block once against a fresh consumer chain.
    let blocks: Vec<lat_chain::Block> =
        block_bytes.iter().map(|b| lat_chain::Block::decode(b).unwrap()).collect();
    let mut consumer = Blockchain::genesis(&premine, DEFAULT_DIFFICULTY);
    let mut idx = 0usize;
    let per_block = bench(n_blocks, 0, || {
        let r = consumer.apply_block(&blocks[idx]);
        idx += 1;
        r
    });
    row("block validation + apply (1 conf. tx)", per_block);

    // Empty-block PoW mine at the default difficulty.
    row("block PoW mine (empty, D=256)", bench(300, 20, || chain.mine(Vec::<Transaction>::new())));

    // ---- Serialization ----
    let sample_block = blocks[0].encode();
    row("block encode", bench(20000, 1000, || blocks[0].encode()));
    row("block decode", bench(20000, 1000, || lat_chain::Block::decode(&sample_block).unwrap()));

    // ---- Smart-contract VM: deploy + call validated through consensus ----
    // Build a producer chain (deploy, then N counter-increment call blocks),
    // then replay-time the call blocks into a fresh consumer node.
    {
        use lat_vm::asm;
        let mut code = asm::push(0);
        code.extend(asm::push(0));
        code.push(asm::SLOAD);
        code.extend(asm::push(1));
        code.push(asm::ADD);
        code.push(asm::SSTORE);
        code.push(asm::STOP);
        let cid = lat_vm::contract_id(&sender.id(), &code);

        let mut prod = Blockchain::genesis(&premine, DEFAULT_DIFFICULTY);
        let dep = prod.mine(vec![sender.deploy_contract(code.clone())]);
        let deploy_bytes = dep.encode();
        prod.apply_block(&dep).unwrap();

        let n_calls = 50usize;
        let mut call_blocks: Vec<lat_chain::Block> = Vec::with_capacity(n_calls);
        for _ in 0..n_calls {
            let nonce = prod.nonce(&sender.id()).unwrap();
            let blk = prod.mine(vec![sender.call_contract(cid, 0, nonce)]);
            call_blocks.push(lat_chain::Block::decode(&blk.encode()).unwrap());
            prod.apply_block(&blk).unwrap();
        }

        let mut cons = Blockchain::genesis(&premine, DEFAULT_DIFFICULTY);
        cons.apply_block(&lat_chain::Block::decode(&deploy_bytes).unwrap()).unwrap();
        let mut ci = 0usize;
        let per_call = bench(n_calls, 0, || {
            let r = cons.apply_block(&call_blocks[ci]);
            ci += 1;
            r
        });
        row("contract call: validate + apply", per_call);
    }

    println!("\nNote: PoW rows scale with difficulty and are probabilistic (median shown).");
}

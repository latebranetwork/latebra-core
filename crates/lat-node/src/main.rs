//! Latebra demo node — a narrated end-to-end run of the chain.
//!
//! Run with:  `cargo run -p lat-node`
//!
//! It spins up an in-memory testnet, creates two wallets, mines a couple of
//! blocks, sends a confidential transfer, and prints what happens — so you can
//! see the privacy chain working without writing any code.

use lat_chain::{Blockchain, DEFAULT_DIFFICULTY, MIN_TRANSFER_FEE};
use lat_state::LAT_TOKEN;
use lat_types::Network;
use lat_wallet::Wallet;
use rand::rngs::OsRng;

/// One LAT = 100,000 base units (5 decimals), matching Latebra convention.
const UNITS_PER_LAT: u64 = 100_000;

fn lat(units: u64) -> String {
    format!("{}.{:05} LAT", units / UNITS_PER_LAT, units % UNITS_PER_LAT)
}

fn rule() {
    println!("------------------------------------------------------------");
}

fn main() {
    let mut rng = OsRng;

    println!();
    println!("  Latebra — a private blockchain (demo node)");
    rule();

    // --- Wallets -----------------------------------------------------------
    // The genesis wallet uses a fixed seed so the demo is reproducible; a real
    // wallet would be random and you'd guard the seed.
    let genesis = Wallet::from_seed(Network::Testnet, [7u8; 32]);
    let alice = Wallet::generate(Network::Testnet, &mut rng);
    let bob = Wallet::generate(Network::Testnet, &mut rng);

    println!("Genesis wallet : {}", genesis.address_string());
    println!("Alice  wallet  : {}", alice.address_string());
    println!("Bob    wallet  : {}", bob.address_string());
    println!("(Alice seed backup: {})", alice.seed_hex());
    rule();

    // --- Genesis -----------------------------------------------------------
    let premine = 1_000_000_000; // 10,000 LAT, public by design
    let mut chain = Blockchain::genesis(&[(genesis.id(), premine)], DEFAULT_DIFFICULTY);
    println!("Genesis block mined. Height = {}  difficulty = {}", chain.height(), chain.difficulty());
    println!("Genesis premine: {} to the genesis wallet", lat(premine));
    rule();

    // --- Register Alice & Bob ---------------------------------------------
    println!("Mining block 1: registering Alice and Bob (anti-spam PoW)...");
    let block1 = chain.mine(vec![alice.registration_tx(), bob.registration_tx()]);
    chain.apply_block(&block1).expect("block 1 valid");
    println!(
        "  -> block 1 accepted. height={}  nonce={}  next difficulty={}  id={}",
        chain.height(),
        block1.header.nonce,
        chain.difficulty(),
        hex8(&block1.header.id())
    );
    rule();

    // --- Solvent transfer: genesis -> Alice (lands in Alice's pending) -----
    let send_1 = 250_000_000; // 2,500 LAT
    println!("Mining block 2: genesis sends {} to Alice (solvent + confidential)...", lat(send_1));
    let tx = genesis
        .create_solvent_transfer(&chain, &alice.address(), LAT_TOKEN, send_1, MIN_TRANSFER_FEE, &mut rng)
        .expect("genesis is solvent");
    let block2 = chain.mine(vec![tx]);
    chain.apply_block(&block2).expect("block 2 valid");
    println!(
        "  -> accepted. Alice spendable={}  pending={}  (received funds wait in pending)",
        lat(alice.balance(&chain, LAT_TOKEN).unwrap()),
        lat(alice.pending(&chain, LAT_TOKEN).unwrap()),
    );
    rule();

    // --- Alice rolls her pending funds into her spendable balance ---------
    println!("Mining block 3: Alice rolls over (pending -> spendable)...");
    let block3 = chain.mine(vec![alice.rollover_tx(chain.nonce(&alice.id()).expect("alice registered"))]);
    chain.apply_block(&block3).expect("block 3 valid");
    println!(
        "  -> accepted. Alice spendable={}  pending={}",
        lat(alice.balance(&chain, LAT_TOKEN).unwrap()),
        lat(alice.pending(&chain, LAT_TOKEN).unwrap()),
    );
    rule();

    // --- Solvent transfer: Alice -> Bob (Alice's spend nonce advances) ----
    let send_2 = 99_000_000; // 990 LAT
    println!("Mining block 4: Alice sends {} to Bob (solvent, spend nonce {})...", lat(send_2), chain.nonce(&alice.id()).unwrap());
    let tx = alice
        .create_solvent_transfer(&chain, &bob.address(), LAT_TOKEN, send_2, MIN_TRANSFER_FEE, &mut rng)
        .expect("alice is solvent");
    let block4 = chain.mine(vec![tx]);
    chain.apply_block(&block4).expect("block 4 valid");
    println!("  -> accepted. Alice's nonce is now {}.", chain.nonce(&alice.id()).unwrap());
    rule();

    // --- Bob rolls over, then tries to overspend --------------------------
    let b = chain.mine(vec![bob.rollover_tx(chain.nonce(&bob.id()).expect("bob registered"))]);
    chain.apply_block(&b).expect("bob rollover");
    let overspend = 500_000_000; // 5,000 LAT
    println!("Bob now holds 990 LAT (spendable). He tries to send {} to Alice...", lat(overspend));
    match bob.create_solvent_transfer(&chain, &alice.address(), LAT_TOKEN, overspend, MIN_TRANSFER_FEE, &mut rng) {
        Some(_) => println!("  -> UNEXPECTED: a proof was produced!"),
        None => println!("  -> REFUSED. The wallet cannot prove solvency for funds it doesn't have."),
    }
    rule();

    // --- The memecoin feature: a globally-unique ticker -------------------
    println!("Alice launches a memecoin, $DOGE (supply 1,000,000)...");
    let b = chain.mine(vec![alice.create_token("$DOGE", 1_000_000)]);
    chain.apply_block(&b).expect("create DOGE");
    let doge = chain.token("DOGE").expect("DOGE registered").id;
    println!("  -> $DOGE created (token id={doge}). Whole supply credited to Alice.");

    println!("Bob tries to also register $doge (same ticker, different case)...");
    let b = chain.mine(vec![bob.create_token("$doge", 5)]);
    match chain.apply_block(&b) {
        Ok(_) => println!("  -> UNEXPECTED: duplicate accepted!"),
        Err(e) => println!("  -> REJECTED ({e:?}). A ticker is global and unique — only one $DOGE, ever."),
    }
    rule();

    // Alice sends $DOGE to Bob (Alice's nonce advances again), Bob rolls it in.
    println!("Alice sends 250,000 $DOGE to Bob (solvent, spend nonce {})...", chain.nonce(&alice.id()).unwrap());
    let tx = alice
        .create_solvent_transfer(&chain, &bob.address(), doge, 250_000, MIN_TRANSFER_FEE, &mut rng)
        .expect("alice holds enough DOGE");
    let b = chain.mine(vec![tx]);
    chain.apply_block(&b).expect("DOGE transfer");
    let b = chain.mine(vec![bob.rollover_tx(chain.nonce(&bob.id()).expect("bob registered"))]);
    chain.apply_block(&b).expect("bob rollover DOGE");
    println!("  -> done. Final height = {}.", chain.height());
    rule();

    // --- Balances ----------------------------------------------------------
    println!("Final spendable balances (decrypted locally by each wallet's key):");
    println!("  Genesis : {}", lat(genesis.balance(&chain, LAT_TOKEN).unwrap()));
    println!("  Alice   : {}  +  {} $DOGE", lat(alice.balance(&chain, LAT_TOKEN).unwrap()), alice.balance(&chain, doge).unwrap());
    println!("  Bob     : {}  +  {} $DOGE", lat(bob.balance(&chain, LAT_TOKEN).unwrap()), bob.balance(&chain, doge).unwrap());
    rule();
    println!("On-chain, every balance and transfer amount above is encrypted.");
    println!("An observer sees blocks were mined and that $DOGE exists — not who");
    println!("holds what, or how much moved. That is the whole point.");
    println!();
}

/// Short hex preview of a 32-byte hash.
fn hex8(bytes: &[u8; 32]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect::<String>() + "..."
}

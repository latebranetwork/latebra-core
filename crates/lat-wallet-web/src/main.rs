//! Latebra Wallet — a local web wallet.
//!
//! A small HTTP server that serves a browser wallet UI and does the wallet
//! cryptography **natively** (no WASM), talking to a `latebrad` node over RPC.
//! The browser is only the interface; keys are held by the browser (localStorage)
//! and passed to this local server for signing. This is ideal for testnet /
//! local testing. (A mainnet wallet where keys never leave the browser needs the
//! WASM crypto build, which is blocked on a Bulletproofs-WASM issue.)
//!
//! Run:  `lat-wallet-web --listen 127.0.0.1:8090`  then open http://127.0.0.1:8090

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;

use lat_chain::{emission, Block};
use lat_crypto::{Ciphertext, PublicKey};
use lat_types::{Address, Network, Transaction};
use lat_wallet::Wallet;
use rand::rngs::OsRng;

const LAT_TOKEN: u32 = 0;
const UNITS: u64 = 100_000;

/// The well-known TESTNET genesis wallet (same seed `latebrad` premines to) —
/// it doubles as the faucet. Play money; a real network has no such seed.
const FAUCET_SEED: [u8; 32] = [42u8; 32];
/// Public LAT handed out per faucet request (base units).
const FAUCET_LAT: u64 = 100 * UNITS;

fn main() {
    let mut listen = "127.0.0.1:8090".to_string();
    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--listen" {
            i += 1;
            listen = args.get(i).cloned().unwrap_or(listen);
        }
        i += 1;
    }
    let listener = TcpListener::bind(&listen).expect("bind wallet listen address");
    println!("Latebra Wallet  →  http://{listen}");
    println!("  (talks to a node's RPC; default 127.0.0.1:4040)");
    for stream in listener.incoming().flatten() {
        thread::spawn(move || {
            let _ = handle(stream);
        });
    }
}

fn handle(stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let target = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    let (path, p) = parse_target(&target);

    let (ctype, body) = match path.as_str() {
        "/" => ("text/html; charset=utf-8", UI.to_string()),
        "/api/new" => ("application/json", api_new(&p)),
        "/api/address" => ("application/json", api_address(&p)),
        "/api/balance" => ("application/json", api_balance(&p)),
        "/api/register" => ("application/json", api_action(&p, Action::Register)),
        "/api/rollover" => ("application/json", api_action(&p, Action::Rollover)),
        "/api/send" => ("application/json", api_send(&p)),
        "/api/public-send" => ("application/json", api_public_send(&p)),
        "/api/shield" => ("application/json", api_shield(&p)),
        "/api/unshield" => ("application/json", api_unshield(&p)),
        "/api/faucet" => ("application/json", api_faucet(&p)),
        "/api/market" => ("application/json", api_market(&p)),
        "/api/activity" => ("application/json", api_activity(&p)),
        "/api/swap" => ("application/json", api_swap(&p)),
        "/api/dex/pool" => ("application/json", api_dex_pool(&p)),
        "/api/dex/add" => ("application/json", api_dex_add(&p)),
        "/api/dex/remove" => ("application/json", api_dex_remove(&p)),
        "/api/dex/swap" => ("application/json", api_dex_swap(&p)),
        "/api/bridge/quote" => ("application/json", api_bridge_quote(&p)),
        "/api/bridge/lock" => ("application/json", api_bridge_lock(&p)),
        "/api/bridge/claim" => ("application/json", api_bridge_claim(&p)),
        "/api/bridge/refund" => ("application/json", api_bridge_refund(&p)),
        "/api/bridge/list" => ("application/json", api_bridge_list(&p)),
        _ => ("application/json", err("not found")),
    };

    let mut stream = stream;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

// --- API -------------------------------------------------------------------

fn network(p: &Params) -> Network {
    if g(p, "net").as_deref() == Some("mainnet") { Network::Mainnet } else { Network::Testnet }
}
fn node(p: &Params) -> String {
    g(p, "node").unwrap_or_else(|| "127.0.0.1:4040".to_string())
}

fn api_new(p: &Params) -> String {
    let w = Wallet::generate(network(p), &mut OsRng);
    format!("{{\"seed\":\"{}\",\"address\":\"{}\"}}", w.seed_hex(), w.address_string())
}

fn api_address(p: &Params) -> String {
    match g(p, "seed").and_then(|s| Wallet::from_seed_hex(network(p), &s).ok()) {
        Some(w) => format!("{{\"address\":\"{}\"}}", w.address_string()),
        None => err("invalid seed"),
    }
}

fn api_balance(p: &Params) -> String {
    let w = match g(p, "seed").and_then(|s| Wallet::from_seed_hex(network(p), &s).ok()) {
        Some(w) => w,
        None => return err("invalid seed"),
    };
    let node = node(p);
    match lat_p2p::get_balance(&node, w.id(), LAT_TOKEN) {
        Ok(Some(bytes)) => {
            let spendable = Ciphertext::from_bytes(&bytes).and_then(|c| w.decrypt_ciphertext(&c)).unwrap_or(0);
            let pending = lat_p2p::get_pending(&node, w.id(), LAT_TOKEN)
                .ok()
                .flatten()
                .and_then(|b| Ciphertext::from_bytes(&b))
                .and_then(|c| w.decrypt_ciphertext(&c))
                .unwrap_or(0);
            // The transparent (public) balance of the dual-state model.
            let public = lat_p2p::get_public_balance(&node, w.id(), LAT_TOKEN)
                .ok()
                .flatten()
                .unwrap_or(0);
            // USDC (public token) balance, if the swap-desk market exists yet.
            let usdc = usdc_token(&node)
                .and_then(|id| lat_p2p::get_public_balance(&node, w.id(), id).ok().flatten())
                .unwrap_or(0);
            format!(
                "{{\"registered\":true,\"address\":\"{}\",\"spendable\":\"{}\",\"pending\":\"{}\",\"public\":\"{}\",\"total\":\"{}\",\"usdc\":\"{}\"}}",
                w.address_string(), lat(spendable), lat(pending), lat(public),
                lat(spendable.saturating_add(public)), lat(usdc)
            )
        }
        Ok(None) => format!("{{\"registered\":false,\"address\":\"{}\"}}", w.address_string()),
        Err(_) => err(&format!("cannot reach node at {node}")),
    }
}

enum Action { Register, Rollover }

fn api_action(p: &Params, action: Action) -> String {
    let w = match g(p, "seed").and_then(|s| Wallet::from_seed_hex(network(p), &s).ok()) {
        Some(w) => w,
        None => return err("invalid seed"),
    };
    let node = node(p);
    let tx = match action {
        Action::Register => w.registration_tx(),
        Action::Rollover => {
            // A rollover is signed at the account's current spend nonce.
            let nonce = match lat_p2p::get_nonce(&node, w.id()) {
                Ok(Some(n)) => n,
                Ok(None) => return err("your account isn't registered yet"),
                Err(_) => return err(&format!("cannot reach node at {node}")),
            };
            w.rollover_tx(nonce)
        }
    };
    match lat_p2p::submit_tx(&node, &tx.encode()) {
        Ok(true) => ok("submitted — confirms when a block is mined"),
        Ok(false) => err("rejected (duplicate or invalid)"),
        Err(_) => err(&format!("cannot reach node at {node}")),
    }
}

fn api_send(p: &Params) -> String {
    let w = match g(p, "seed").and_then(|s| Wallet::from_seed_hex(network(p), &s).ok()) {
        Some(w) => w,
        None => return err("invalid seed"),
    };
    let to = match g(p, "to").and_then(|t| Address::parse(t.trim()).ok()) {
        Some(a) => a,
        None => return err("invalid recipient address"),
    };
    let amount = match g(p, "amount").and_then(|a| parse_lat(&a)) {
        Some(a) => a,
        None => return err("invalid amount"),
    };
    let node = node(p);
    let bal = match lat_p2p::get_balance(&node, w.id(), LAT_TOKEN) {
        Ok(Some(b)) => b,
        Ok(None) => return err("your account isn't registered yet"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let ct = match Ciphertext::from_bytes(&bal) {
        Some(c) => c,
        None => return err("bad balance data"),
    };
    let nonce = match lat_p2p::get_nonce(&node, w.id()) {
        Ok(Some(n)) => n,
        _ => return err("account not registered"),
    };
    // Pay the network minimum fee (the web wallet doesn't expose fee bidding yet).
    let fee = lat_wallet::MIN_TRANSFER_FEE;
    match w.build_transfer(&to, LAT_TOKEN, amount, fee, &ct, nonce, &mut OsRng) {
        Some(tx) => match lat_p2p::submit_tx(&node, &tx.encode()) {
            Ok(true) => ok(&format!(
                "sent {} LAT (fee {}) — confirms when a block is mined",
                lat(amount),
                lat(fee)
            )),
            Ok(false) => err("transfer rejected"),
            Err(_) => err("cannot reach node"),
        },
        None => err("insufficient balance (amount + fee) or unreadable"),
    }
}

/// Transparent public→public transfer: sender, receiver, and amount on-chain
/// in the clear (the "Ethereum-style" half of the dual-state model).
fn api_public_send(p: &Params) -> String {
    let (w, amount, node) = match wallet_amount(p) {
        Ok(v) => v,
        Err(e) => return err(&e),
    };
    let to = match g(p, "to").and_then(|t| Address::parse(t.trim()).ok()) {
        Some(a) => a,
        None => return err("invalid recipient address"),
    };
    let nonce = match lat_p2p::get_nonce(&node, w.id()) {
        Ok(Some(n)) => n,
        Ok(None) => return err("your account isn't registered yet"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let fee = lat_wallet::MIN_TRANSFER_FEE;
    let tx = w.build_public_transfer(&to, LAT_TOKEN, amount, fee, nonce);
    submit(&node, &tx, &format!("sent {} LAT publicly (fee {})", lat(amount), lat(fee)))
}

/// Shield: move the wallet's own PUBLIC balance into its PRIVATE side (or, with
/// `to`, someone else's). The shielded amount is visible once at the boundary;
/// the funds land in the private *pending* pool — roll over to spend.
fn api_shield(p: &Params) -> String {
    let (w, amount, node) = match wallet_amount(p) {
        Ok(v) => v,
        Err(e) => return err(&e),
    };
    let to = match g(p, "to") {
        Some(t) if !t.trim().is_empty() => match Address::parse(t.trim()) {
            Ok(a) => a,
            Err(_) => return err("invalid recipient address"),
        },
        _ => w.address(), // default: make my own LAT private
    };
    let nonce = match lat_p2p::get_nonce(&node, w.id()) {
        Ok(Some(n)) => n,
        Ok(None) => return err("your account isn't registered yet"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let fee = lat_wallet::MIN_TRANSFER_FEE;
    let tx = w.build_shield(&to, LAT_TOKEN, amount, fee, nonce);
    submit(
        &node,
        &tx,
        &format!("shielded {} LAT (public → private, fee {}) — roll over once confirmed", lat(amount), lat(fee)),
    )
}

/// Unshield: spend the wallet's PRIVATE balance (with a solvency proof) into a
/// PUBLIC balance — its own by default, or `to`'s. The amount is revealed.
fn api_unshield(p: &Params) -> String {
    let (w, amount, node) = match wallet_amount(p) {
        Ok(v) => v,
        Err(e) => return err(&e),
    };
    let to = match g(p, "to") {
        Some(t) if !t.trim().is_empty() => match Address::parse(t.trim()) {
            Ok(a) => a,
            Err(_) => return err("invalid recipient address"),
        },
        _ => w.address(), // default: back to my own public balance
    };
    let bal = match lat_p2p::get_balance(&node, w.id(), LAT_TOKEN) {
        Ok(Some(b)) => b,
        Ok(None) => return err("your account isn't registered yet"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let ct = match Ciphertext::from_bytes(&bal) {
        Some(c) => c,
        None => return err("bad balance data"),
    };
    let nonce = match lat_p2p::get_nonce(&node, w.id()) {
        Ok(Some(n)) => n,
        _ => return err("account not registered"),
    };
    let fee = lat_wallet::MIN_TRANSFER_FEE;
    match w.build_unshield(&to, LAT_TOKEN, amount, fee, &ct, nonce, &mut OsRng) {
        Some(tx) => submit(
            &node,
            &tx,
            &format!("unshielded {} LAT (private → public, fee {})", lat(amount), lat(fee)),
        ),
        None => err("insufficient private balance (amount + fee) or unreadable"),
    }
}

/// Testnet faucet: the well-known genesis wallet sends the caller public LAT.
/// From there the user can shield, send, and unshield it — the whole loop.
fn api_faucet(p: &Params) -> String {
    if network(p) != Network::Testnet {
        return err("the faucet is testnet-only");
    }
    let to = match g(p, "to").and_then(|t| Address::parse(t.trim()).ok()) {
        Some(a) => a,
        None => return err("invalid address"),
    };
    let node = node(p);
    // The recipient must be registered — a transfer to an unknown account would
    // be dropped silently at block selection, so fail loudly here instead.
    match lat_p2p::get_nonce(&node, to.id()) {
        Ok(Some(_)) => {}
        Ok(None) => return err("activate (register) your account first, then use the faucet"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    }
    let faucet = Wallet::from_seed(Network::Testnet, FAUCET_SEED);
    let nonce = match lat_p2p::get_nonce(&node, faucet.id()) {
        Ok(Some(n)) => n,
        Ok(None) => return err("faucet account not found on this chain"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let fee = lat_wallet::MIN_TRANSFER_FEE;
    let tx = faucet.build_public_transfer(&to, LAT_TOKEN, FAUCET_LAT, fee, nonce);
    submit(&node, &tx, &format!("faucet sent {} public LAT", lat(FAUCET_LAT)))
}

// --- market: testnet price oracle -------------------------------------------
//
// A deterministic mock oracle: every node sees the same LAT/USD price for a
// given height, so the web wallet and the extension always agree. Replace with
// a real feed when the DEX lands.

/// Desk inventory minted when the USDC market first opens (base units).
/// Must stay decryptable/provable, i.e. below 2^BALANCE_BITS (2^40) base units.
const USDC_SUPPLY: u64 = 10_000_000 * UNITS;
/// Blocks treated as "24 h" for the change badge.
const DAY_BLOCKS: u64 = 1_440;

fn lat_price_at(height: u64) -> f64 {
    let h = height as f64;
    2.40 * (1.0 + 0.06 * (h / 240.0).sin() + 0.025 * (h / 37.0).sin())
}

fn api_market(p: &Params) -> String {
    let node = node(p);
    let h = match lat_p2p::get_height(&node) {
        Ok(h) => h,
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let price = lat_price_at(h);
    let prev = lat_price_at(h.saturating_sub(DAY_BLOCKS));
    let chg = if prev > 0.0 { (price - prev) / prev * 100.0 } else { 0.0 };
    // Open the USDC market once (mint the desk's inventory) so swap "just works".
    let usdc_live = usdc_token(&node).is_some() || open_usdc_market(&node);
    format!(
        "{{\"ok\":true,\"height\":{h},\"lat\":{price:.4},\"usdc\":1.0,\"chg\":{chg:.2},\"usdc_live\":{usdc_live}}}"
    )
}

/// Mint the USDC token from the desk (faucet) wallet. Returns whether the
/// token is usable *now* (it isn't — it confirms next block), guarding with a
/// flag so we don't spam duplicate mints while it confirms.
fn open_usdc_market(node: &str) -> bool {
    static OPENING: AtomicBool = AtomicBool::new(false);
    if OPENING.swap(true, Ordering::SeqCst) {
        return false;
    }
    let desk = Wallet::from_seed(Network::Testnet, FAUCET_SEED);
    let tx = desk.create_token("USDC", USDC_SUPPLY);
    let _ = lat_p2p::submit_tx(node, &tx.encode());
    false
}

// --- chain index: tokens + per-account activity ------------------------------
//
// The node has no history RPC, so the wallet server keeps a tiny in-memory
// index built by scanning blocks (incremental — only new blocks each call).
// Testnet-scale by design; a real deployment would use the explorer's indexer.

const K_REG: u8 = 0;
const K_TOKEN: u8 = 1;
const K_PRIV: u8 = 2;
const K_ROLL: u8 = 3;
const K_PUB: u8 = 4;
const K_SHIELD: u8 = 5;
const K_UNSHIELD: u8 = 6;
const K_STEALTH: u8 = 7;
const K_MINED: u8 = 8;

#[derive(Clone)]
struct Ent {
    height: u64,
    ts: u64,
    kind: u8,
    token: u32,
    a: [u8; 32], // sender / actor ([0;32] = none)
    b: [u8; 32], // receiver ([0;32] = none)
    amount: u64, // 0 for hidden-amount kinds (K_PRIV)
    fee: u64,    // tracked where the desk needs exact outflows (K_UNSHIELD)
}

#[derive(Default)]
struct Ix {
    next: u64,
    tokens: Vec<(String, u32)>, // (ticker, token id) in creation order
    entries: Vec<Ent>,
}

fn index() -> &'static Mutex<std::collections::HashMap<String, Ix>> {
    static IX: OnceLock<Mutex<std::collections::HashMap<String, Ix>>> = OnceLock::new();
    IX.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// Pull any new blocks on `node` into the index. Cheap after the first call.
fn sync_index(node: &str) -> Result<(), String> {
    let tip = lat_p2p::get_height(node).map_err(|_| format!("cannot reach node at {node}"))?;
    let mut map = index().lock().unwrap();
    let ix = map.entry(node.to_string()).or_default();
    while ix.next <= tip {
        let h = ix.next;
        let block = match lat_p2p::get_block(node, h).ok().flatten().and_then(|b| Block::decode(&b)) {
            Some(b) => b,
            None => break, // not served yet — retry next call
        };
        let ts = block.header.timestamp;
        if block.header.miner != [0u8; 32] {
            ix.entries.push(Ent { height: h, ts, kind: K_MINED, token: 0, a: [0; 32], b: block.header.miner, amount: emission(h), fee: 0 });
        }
        for tx in &block.txs {
            match tx {
                Transaction::Register { pubkey, .. } => {
                    ix.entries.push(Ent { height: h, ts, kind: K_REG, token: 0, a: *pubkey, b: [0; 32], amount: 0, fee: 0 });
                }
                Transaction::CreateToken { ticker, creator, supply, .. } => {
                    // Ids are assigned sequentially from 1 in creation order.
                    let id = ix.tokens.len() as u32 + 1;
                    let norm = lat_types::normalize_ticker(ticker).unwrap_or_else(|| ticker.clone());
                    ix.tokens.push((norm, id));
                    ix.entries.push(Ent { height: h, ts, kind: K_TOKEN, token: id, a: *creator, b: [0; 32], amount: *supply, fee: 0 });
                }
                Transaction::SolventTransfer { token, xfer } => {
                    ix.entries.push(Ent { height: h, ts, kind: K_PRIV, token: *token, a: xfer.sender.to_bytes(), b: xfer.receiver.to_bytes(), amount: 0, fee: 0 });
                }
                Transaction::Rollover { account, .. } => {
                    ix.entries.push(Ent { height: h, ts, kind: K_ROLL, token: 0, a: *account, b: [0; 32], amount: 0, fee: 0 });
                }
                Transaction::PublicTransfer { token, from, to, amount, .. } => {
                    ix.entries.push(Ent { height: h, ts, kind: K_PUB, token: *token, a: *from, b: *to, amount: *amount, fee: 0 });
                }
                Transaction::Shield { token, from, to, amount, .. } => {
                    ix.entries.push(Ent { height: h, ts, kind: K_SHIELD, token: *token, a: *from, b: *to, amount: *amount, fee: 0 });
                }
                Transaction::Unshield { token, to, amount, xfer, .. } => {
                    ix.entries.push(Ent { height: h, ts, kind: K_UNSHIELD, token: *token, a: xfer.sender.to_bytes(), b: *to, amount: *amount, fee: xfer.fee });
                }
                Transaction::ShieldStealth { token, from, amount, .. } => {
                    ix.entries.push(Ent { height: h, ts, kind: K_STEALTH, token: *token, a: *from, b: [0; 32], amount: *amount, fee: 0 });
                }
                // Anonymous transfers hide sender and receiver — nothing to index.
                _ => {}
            }
        }
        ix.next += 1;
    }
    Ok(())
}

/// The USDC token id on this chain, if the market has been opened.
fn usdc_token(node: &str) -> Option<u32> {
    sync_index(node).ok()?;
    let map = index().lock().unwrap();
    map.get(node)?.tokens.iter().find(|(t, _)| t == "USDC").map(|(_, id)| *id)
}

/// The desk's PRIVATE USDC inventory, derived from the index instead of
/// decrypting the balance ciphertext (a discrete-log walk that costs minutes
/// at inventory scale): mint supply minus every confirmed unshield outflow
/// (amount + fee). If it ever drifted, the on-chain proof would just fail.
fn desk_usdc_inventory(node: &str, usdc: u32, desk: &[u8; 32]) -> u64 {
    let map = index().lock().unwrap();
    let Some(ix) = map.get(node) else { return 0 };
    let mut bal: u64 = 0;
    for e in &ix.entries {
        if e.token != usdc || e.a != *desk {
            continue;
        }
        match e.kind {
            K_TOKEN => bal = bal.saturating_add(e.amount),
            K_UNSHIELD => bal = bal.saturating_sub(e.amount + e.fee),
            _ => {}
        }
    }
    bal
}

fn ticker_of(ix: &Ix, token: u32) -> String {
    if token == LAT_TOKEN {
        return "LAT".to_string();
    }
    ix.tokens.iter().find(|(_, id)| *id == token).map(|(t, _)| t.clone()).unwrap_or_else(|| format!("TK{token}"))
}

fn addr_of(net: Network, id: &[u8; 32]) -> String {
    match PublicKey::from_bytes(id) {
        Some(k) => Address::new(net, k).encode(),
        None => String::new(),
    }
}

fn api_activity(p: &Params) -> String {
    let w = match g(p, "seed").and_then(|s| Wallet::from_seed_hex(network(p), &s).ok()) {
        Some(w) => w,
        None => return err("invalid seed"),
    };
    let node = node(p);
    if let Err(e) = sync_index(&node) {
        return err(&e);
    }
    let net = network(p);
    let id = w.id();
    let map = index().lock().unwrap();
    let ix = match map.get(&node) {
        Some(ix) => ix,
        None => return "{\"ok\":true,\"txs\":[]}".to_string(),
    };
    let mut rows = Vec::new();
    for e in ix.entries.iter().rev() {
        if e.a != id && e.b != id {
            continue;
        }
        let me_sender = e.a == id;
        let (label, dir, amount, other) = match e.kind {
            K_REG => ("Account activated", "self", None, String::new()),
            K_TOKEN => ("Token created", "in", Some(e.amount), String::new()),
            K_ROLL => ("Rolled over", "self", None, String::new()),
            K_MINED => ("Mined", "in", Some(e.amount), String::new()),
            K_PRIV => {
                if me_sender && e.b == id {
                    ("Private self-transfer", "self", None, String::new())
                } else if me_sender {
                    ("Private send", "out", None, addr_of(net, &e.b))
                } else {
                    ("Private receive", "in", None, addr_of(net, &e.a))
                }
            }
            K_PUB => {
                if me_sender {
                    ("Sent", "out", Some(e.amount), addr_of(net, &e.b))
                } else {
                    ("Received", "in", Some(e.amount), addr_of(net, &e.a))
                }
            }
            K_SHIELD => {
                if me_sender && e.b == id {
                    ("Shielded", "self", Some(e.amount), String::new())
                } else if me_sender {
                    ("Shield sent", "out", Some(e.amount), addr_of(net, &e.b))
                } else {
                    ("Shield received", "in", Some(e.amount), addr_of(net, &e.a))
                }
            }
            K_UNSHIELD => {
                if me_sender && e.b == id {
                    ("Unshielded", "self", Some(e.amount), String::new())
                } else if me_sender {
                    ("Unshield sent", "out", Some(e.amount), addr_of(net, &e.b))
                } else {
                    ("Unshield received", "in", Some(e.amount), addr_of(net, &e.a))
                }
            }
            K_STEALTH => ("Stealth shield", "out", Some(e.amount), String::new()),
            _ => continue,
        };
        let amt = match amount {
            Some(a) => format!("\"{}\"", lat(a)),
            None => "null".to_string(),
        };
        rows.push(format!(
            "{{\"label\":\"{}\",\"dir\":\"{}\",\"amount\":{},\"token\":\"{}\",\"other\":\"{}\",\"h\":{},\"ts\":{}}}",
            label, dir, amt, ticker_of(ix, e.token), esc(&other), e.height, e.ts
        ));
        if rows.len() >= 50 {
            break;
        }
    }
    format!("{{\"ok\":true,\"txs\":[{}]}}", rows.join(","))
}

// --- swap: LAT ⇄ USDC against the desk ---------------------------------------
//
// Until the on-chain DEX lands, the faucet wallet doubles as a market-making
// desk: the user pays the desk one token by public transfer and the desk pays
// back the other side at the oracle price. Both legs confirm in the next block.

fn api_swap(p: &Params) -> String {
    if network(p) != Network::Testnet {
        return err("swap is testnet-only for now");
    }
    let (w, amount, node) = match wallet_amount(p) {
        Ok(v) => v,
        Err(e) => return err(&e),
    };
    let from = g(p, "from").unwrap_or_default().to_uppercase();
    if from != "LAT" && from != "USDC" {
        return err("swap pair must be LAT ⇄ USDC");
    }
    let usdc = match usdc_token(&node) {
        Some(id) => id,
        None => {
            open_usdc_market(&node);
            return err("the USDC market is opening — try again in a few seconds");
        }
    };
    let h = match lat_p2p::get_height(&node) {
        Ok(h) => h,
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let price = lat_price_at(h);
    let (pay_token, recv_token, recv_amount, to_ticker) = if from == "LAT" {
        (LAT_TOKEN, usdc, (amount as f64 * price).round() as u64, "USDC")
    } else {
        (usdc, LAT_TOKEN, (amount as f64 / price).round() as u64, "LAT")
    };
    if recv_amount == 0 {
        return err("amount too small to swap");
    }
    let fee = lat_wallet::MIN_TRANSFER_FEE;
    let desk = Wallet::from_seed(Network::Testnet, FAUCET_SEED);
    // Both sides must be solvent before either leg goes out.
    match lat_p2p::get_public_balance(&node, w.id(), pay_token) {
        Ok(Some(b)) if b >= amount + fee => {}
        Ok(_) => return err(&format!("insufficient public {from} balance (amount + fee) — swaps use your PUBLIC balance")),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    }
    let un = match lat_p2p::get_nonce(&node, w.id()) {
        Ok(Some(n)) => n,
        Ok(None) => return err("your account isn't registered yet"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let dn = match lat_p2p::get_nonce(&node, desk.id()) {
        Ok(Some(n)) => n,
        _ => return err("swap desk account not found on this chain"),
    };
    let leg1 = w.build_public_transfer(&desk.address(), pay_token, amount, fee, un);
    // The desk's leg. Minted USDC sits in the desk's PRIVATE balance
    // (CreateToken credits the encrypted side), so USDC is paid out by
    // unshielding straight into the buyer's public balance. LAT is paid from
    // the desk's public premine with a plain transfer.
    let leg2 = if recv_token == usdc {
        let ct = match lat_p2p::get_balance(&node, desk.id(), usdc) {
            Ok(Some(b)) => match Ciphertext::from_bytes(&b) {
                Some(c) => c,
                None => return err("bad desk balance data"),
            },
            Ok(None) => return err("swap desk account not found on this chain"),
            Err(_) => return err(&format!("cannot reach node at {node}")),
        };
        let inv = desk_usdc_inventory(&node, usdc, &desk.id());
        if inv < recv_amount + fee {
            return err("the swap desk is out of USDC inventory");
        }
        match desk.build_unshield_with_balance(&w.address(), usdc, recv_amount, fee, inv, &ct, dn, &mut OsRng) {
            Some(tx) => tx,
            None => return err("desk could not build the USDC payout"),
        }
    } else {
        match lat_p2p::get_public_balance(&node, desk.id(), LAT_TOKEN) {
            Ok(Some(b)) if b >= recv_amount + fee => {}
            Ok(_) => return err("the swap desk is out of LAT inventory"),
            Err(_) => return err(&format!("cannot reach node at {node}")),
        }
        desk.build_public_transfer(&w.address(), LAT_TOKEN, recv_amount, fee, dn)
    };
    match lat_p2p::submit_tx(&node, &leg1.encode()) {
        Ok(true) => {}
        Ok(false) => return err("swap rejected (duplicate or invalid)"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    }
    match lat_p2p::submit_tx(&node, &leg2.encode()) {
        Ok(true) => ok(&format!(
            "swapped {} {} → {} {} @ ${:.4} — confirms next block",
            lat(amount), from, lat(recv_amount), to_ticker, price
        )),
        _ => err("desk leg failed — your payment may still confirm; ask the faucet"),
    }
}

// --- on-chain DEX (native AMM) -----------------------------------------------
//
// Unlike the desk swap above (a market-maker convenience), these endpoints
// drive the chain's OWN constant-product pools: consensus computes the price
// from the reserves, LPs earn the 0.3% swap fee, and no counterparty exists.

/// Resolve a ticker to its token id via the index (`LAT` = 0).
fn token_by_ticker(node: &str, ticker: &str) -> Option<u32> {
    let t = lat_types::normalize_ticker(ticker)?;
    if t == "LAT" {
        return Some(LAT_TOKEN);
    }
    sync_index(node).ok()?;
    let map = index().lock().unwrap();
    map.get(node)?.tokens.iter().find(|(tk, _)| *tk == t).map(|(_, id)| *id)
}

fn api_dex_pool(p: &Params) -> String {
    let node = node(p);
    let ticker = g(p, "ticker").unwrap_or_else(|| "USDC".to_string());
    let token = match token_by_ticker(&node, &ticker) {
        Some(t) if t != LAT_TOKEN => t,
        _ => return err(&format!("no such token ${}", ticker.to_uppercase())),
    };
    let pool = match lat_p2p::get_pool(&node, token) {
        Ok(p) => p,
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    // The caller's LP shares, if a seed was supplied.
    let shares = g(p, "seed")
        .and_then(|s| Wallet::from_seed_hex(network(p), &s).ok())
        .and_then(|w| lat_p2p::get_lp_shares(&node, token, w.id()).ok())
        .unwrap_or(0);
    match pool {
        Some((lat_r, tok_r, lp)) => {
            let price = if tok_r > 0 { lat_r as f64 / tok_r as f64 } else { 0.0 };
            format!(
                "{{\"ok\":true,\"exists\":true,\"token\":{token},\"lat\":\"{}\",\"tok\":\"{}\",\"lp\":{lp},\"myLp\":{shares},\"price\":{price:.6}}}",
                lat(lat_r), lat(tok_r)
            )
        }
        None => format!("{{\"ok\":true,\"exists\":false,\"token\":{token},\"myLp\":0}}"),
    }
}

fn api_dex_add(p: &Params) -> String {
    let (w, lat_amount, node) = match wallet_amount(p) {
        Ok(v) => v,
        Err(e) => return err(&e),
    };
    let ticker = g(p, "ticker").unwrap_or_default();
    let token = match token_by_ticker(&node, &ticker) {
        Some(t) if t != LAT_TOKEN => t,
        _ => return err("pick a token to pair with LAT"),
    };
    let tok_amount = match g(p, "tok").and_then(|a| parse_lat(&a)) {
        Some(a) if a > 0 => a,
        _ => return err("invalid token amount"),
    };
    let nonce = match lat_p2p::get_nonce(&node, w.id()) {
        Ok(Some(n)) => n,
        Ok(None) => return err("your account isn't registered yet"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let tx = w.add_liquidity(token, lat_amount, tok_amount, lat_wallet::MIN_TRANSFER_FEE, nonce);
    submit(&node, &tx, "liquidity added")
}

fn api_dex_remove(p: &Params) -> String {
    let w = match g(p, "seed").and_then(|s| Wallet::from_seed_hex(network(p), &s).ok()) {
        Some(w) => w,
        None => return err("invalid seed"),
    };
    let node = node(p);
    let ticker = g(p, "ticker").unwrap_or_default();
    let token = match token_by_ticker(&node, &ticker) {
        Some(t) if t != LAT_TOKEN => t,
        _ => return err("no such token"),
    };
    // LP shares are raw units (no decimals).
    let lp: u64 = match g(p, "lp").and_then(|a| a.trim().parse().ok()) {
        Some(a) if a > 0 => a,
        _ => return err("invalid LP amount"),
    };
    let nonce = match lat_p2p::get_nonce(&node, w.id()) {
        Ok(Some(n)) => n,
        Ok(None) => return err("your account isn't registered yet"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let tx = w.remove_liquidity(token, lp, lat_wallet::MIN_TRANSFER_FEE, nonce);
    submit(&node, &tx, "liquidity removed")
}

fn api_dex_swap(p: &Params) -> String {
    let (w, amount_in, node) = match wallet_amount(p) {
        Ok(v) => v,
        Err(e) => return err(&e),
    };
    let ticker = g(p, "ticker").unwrap_or_default();
    let token = match token_by_ticker(&node, &ticker) {
        Some(t) if t != LAT_TOKEN => t,
        _ => return err("no such token"),
    };
    let lat_in = g(p, "from").map(|f| f.to_uppercase()) != Some(ticker.to_uppercase());
    let (lat_r, tok_r, _) = match lat_p2p::get_pool(&node, token) {
        Ok(Some(pl)) => pl,
        Ok(None) => return err("no pool for this token yet — add liquidity first"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    // Quote the constant-product output (0.3% fee) and bound slippage at 1%
    // unless the caller supplied an explicit minimum.
    let (r_in, r_out) = if lat_in { (lat_r, tok_r) } else { (tok_r, lat_r) };
    let in_after_fee = amount_in as u128 * 9_970;
    let quote = (in_after_fee * r_out as u128 / (r_in as u128 * 10_000 + in_after_fee)) as u64;
    if quote == 0 {
        return err("amount too small to swap");
    }
    let min_out = g(p, "minout").and_then(|a| parse_lat(&a)).unwrap_or(quote - quote / 100);
    let nonce = match lat_p2p::get_nonce(&node, w.id()) {
        Ok(Some(n)) => n,
        Ok(None) => return err("your account isn't registered yet"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let tx = w.swap(token, lat_in, amount_in, min_out, lat_wallet::MIN_TRANSFER_FEE, nonce);
    let (from_t, to_t) = if lat_in { ("LAT".to_string(), ticker.to_uppercase()) } else { (ticker.to_uppercase(), "LAT".to_string()) };
    match lat_p2p::submit_tx(&node, &tx.encode()) {
        Ok(true) => ok(&format!(
            "swapping {} {from_t} → ~{} {to_t} against the pool — confirms next block",
            lat(amount_in), lat(quote)
        )),
        Ok(false) => err("swap rejected (duplicate or insufficient balance)"),
        Err(_) => err(&format!("cannot reach node at {node}")),
    }
}

// --- bridge: HTLC atomic-swap escrows -----------------------------------------
//
// The cross-chain primitive: lock funds under a SHA-256 hashlock; the
// counterparty claims with the preimage (revealing it, which lets you claim
// their matching lock on the other chain), or the lock refunds after expiry.

// Cross-chain quote: build the *counterparty* HTLC leg on Bitcoin, an EVM
// chain, or Solana — the real deposit address/script/calldata a user takes to
// that chain's wallet. Keyed on the same SHA-256 hashlock as the Latebra leg,
// so one secret settles both sides of the atomic swap.
fn api_bridge_quote(p: &Params) -> String {
    use lat_bridge::{
        BtcAdapter, ChainAdapter, EvmAdapter, HtlcParams, Network as BNet, Secret, SolAdapter,
    };

    let bnet = if network(p) == Network::Mainnet { BNet::Mainnet } else { BNet::Testnet };
    let chain = g(p, "chain").unwrap_or_default().to_lowercase();
    let amount: u128 = match g(p, "amount").and_then(|a| a.trim().parse().ok()) {
        Some(a) if a > 0 => a,
        _ => return err("amount (in the chain's smallest unit) required"),
    };

    // Either the caller pins the counterparty's hashlock (they hold the secret),
    // or we mint a fresh secret for a swap this wallet initiates.
    let (hashlock, preimage): (lat_bridge::Hash, Option<[u8; 32]>) =
        match g(p, "hashlock").and_then(|s| hex::decode(s.trim()).ok()) {
            Some(hl) => match <[u8; 32]>::try_from(hl) {
                Ok(hl) => (hl, None),
                Err(_) => return err("hashlock must be 32 bytes of hex"),
            },
            None => {
                let s = Secret::random();
                (s.hashlock(), Some(s.reveal()))
            }
        };

    // A chain-native key field: exact-length hex if supplied, else a shaped
    // placeholder so the deterministic artifact is still demonstrable.
    fn key_field(p: &Params, k: &str, n: usize, fill: u8) -> Option<Vec<u8>> {
        match g(p, k) {
            Some(s) if !s.trim().is_empty() => {
                let v = hex::decode(s.trim()).ok()?;
                (v.len() == n).then_some(v)
            }
            _ => Some(vec![fill; n]),
        }
    }

    let (rlen, default_tl): (usize, u64) = match chain.as_str() {
        "btc" => (33, 800_000),
        "eth" | "evm" => (20, 1_900_000_000),
        "sol" => (32, 1_900_000_000),
        _ => return err("chain must be btc, eth, or sol"),
    };
    let recipient = match key_field(p, "recipient", rlen, 0x02) {
        Some(v) => v,
        None => return err("recipient must be the chain's native key length (hex)"),
    };
    let refund = match key_field(p, "refund", rlen, 0x03) {
        Some(v) => v,
        None => return err("refund must be the chain's native key length (hex)"),
    };
    let timelock: u64 =
        g(p, "timelock").and_then(|s| s.trim().parse().ok()).unwrap_or(default_tl);

    let params = HtlcParams { hashlock, recipient, refund, amount, timelock };

    let adapter: Box<dyn ChainAdapter> = match chain.as_str() {
        "btc" => Box::new(BtcAdapter::new(bnet)),
        "eth" | "evm" => {
            let contract = key_field(p, "contract", 20, 0x11).unwrap_or(vec![0x11; 20]);
            let chainid: u64 = g(p, "chainid")
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(if bnet == BNet::Mainnet { 1 } else { 11155111 });
            let mut c = [0u8; 20];
            c.copy_from_slice(&contract);
            Box::new(EvmAdapter::new(c, chainid, bnet))
        }
        "sol" => {
            let prog = key_field(p, "program", 32, 0x05).unwrap_or(vec![0x05; 32]);
            let mut pid = [0u8; 32];
            pid.copy_from_slice(&prog);
            Box::new(SolAdapter::new(pid, bnet))
        }
        _ => return err("chain must be btc, eth, or sol"),
    };

    let art = match adapter.lock_artifact(&params) {
        Ok(a) => a,
        Err(e) => return err(&e.to_string()),
    };
    let claim_desc = match preimage {
        Some(pre) => adapter.claim(&params, &pre).map(|t| t.describe).unwrap_or_default(),
        None => "You hold the secret — reveal your preimage on this chain to claim.".to_string(),
    };
    let refund_desc = adapter.refund(&params).map(|t| t.describe).unwrap_or_default();

    format!(
        "{{\"ok\":true,\"chain\":\"{}\",\"hashlock\":\"{}\",\"preimage\":\"{}\",\
         \"deposit\":\"{}\",\"scriptHex\":\"{}\",\"instructions\":\"{}\",\
         \"claim\":\"{}\",\"refund\":\"{}\",\"timelock\":{}}}",
        adapter.chain().ticker(),
        hex::encode(hashlock),
        preimage.map(hex::encode).unwrap_or_default(),
        esc(&art.deposit_address),
        art.script_hex,
        esc(&art.instructions),
        esc(&claim_desc),
        esc(&refund_desc),
        timelock,
    )
}

fn api_bridge_lock(p: &Params) -> String {
    let (w, amount, node) = match wallet_amount(p) {
        Ok(v) => v,
        Err(e) => return err(&e),
    };
    let net = network(p);
    let to = match g(p, "to").and_then(|a| Address::parse(&a).ok()) {
        Some(a) if a.network == net => a,
        _ => return err("invalid recipient address"),
    };
    let token = match g(p, "ticker") {
        Some(t) => match token_by_ticker(&node, &t) {
            Some(id) => id,
            None => return err("no such token"),
        },
        None => LAT_TOKEN,
    };
    let h = match lat_p2p::get_height(&node) {
        Ok(h) => h,
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let blocks: u64 = g(p, "blocks").and_then(|b| b.trim().parse().ok()).unwrap_or(240);
    let expiry = h + blocks.clamp(10, 100_000);
    // Either the caller supplies the counterparty's hashlock (the second leg
    // of an atomic swap), or we generate a fresh secret and hand it back.
    use sha2::{Digest, Sha256};
    let (hashlock, preimage_hex) = match g(p, "hashlock").and_then(|s| hex::decode(s).ok()) {
        Some(hl) => match <[u8; 32]>::try_from(hl) {
            Ok(hl) => (hl, String::new()),
            Err(_) => return err("hashlock must be 32 bytes of hex"),
        },
        None => {
            let mut secret = [0u8; 32];
            rand::RngCore::fill_bytes(&mut OsRng, &mut secret);
            (Sha256::digest(secret).into(), hex::encode(secret))
        }
    };
    let nonce = match lat_p2p::get_nonce(&node, w.id()) {
        Ok(Some(n)) => n,
        Ok(None) => return err("your account isn't registered yet"),
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let (tx, id) = w.htlc_lock(token, &to, amount, hashlock, expiry, lat_wallet::MIN_TRANSFER_FEE, nonce);
    match lat_p2p::submit_tx(&node, &tx.encode()) {
        Ok(true) => format!(
            "{{\"ok\":true,\"msg\":\"locked — claimable before block {expiry}\",\"htlcId\":\"{}\",\"hashlock\":\"{}\",\"preimage\":\"{}\",\"expiry\":{expiry}}}",
            hex::encode(id), hex::encode(hashlock), preimage_hex
        ),
        Ok(false) => err("lock rejected (duplicate or insufficient balance)"),
        Err(_) => err(&format!("cannot reach node at {node}")),
    }
}

fn api_bridge_claim(p: &Params) -> String {
    let node = node(p);
    let id = match g(p, "id").and_then(|s| hex::decode(s).ok()).and_then(|v| <[u8; 32]>::try_from(v).ok()) {
        Some(id) => id,
        None => return err("invalid HTLC id"),
    };
    let preimage = match g(p, "preimage").and_then(|s| hex::decode(s).ok()).and_then(|v| <[u8; 32]>::try_from(v).ok()) {
        Some(s) => s,
        None => return err("invalid preimage (32 bytes of hex)"),
    };
    submit(&node, &Wallet::htlc_claim(id, preimage), "claimed — escrow releases")
}

fn api_bridge_refund(p: &Params) -> String {
    let node = node(p);
    let id = match g(p, "id").and_then(|s| hex::decode(s).ok()).and_then(|v| <[u8; 32]>::try_from(v).ok()) {
        Some(id) => id,
        None => return err("invalid HTLC id"),
    };
    submit(&node, &Wallet::htlc_refund(id), "refund submitted — escrow returns to sender")
}

fn api_bridge_list(p: &Params) -> String {
    let w = match g(p, "seed").and_then(|s| Wallet::from_seed_hex(network(p), &s).ok()) {
        Some(w) => w,
        None => return err("invalid seed"),
    };
    let node = node(p);
    let net = network(p);
    let height = lat_p2p::get_height(&node).unwrap_or(0);
    let locks = match lat_p2p::get_htlcs(&node) {
        Ok(l) => l,
        Err(_) => return err(&format!("cannot reach node at {node}")),
    };
    let me = w.id();
    let mut rows = Vec::new();
    for (id, token, from, to, amount, _hashlock, expiry) in locks {
        if from != me && to != me {
            continue;
        }
        let role = if from == me { "outgoing" } else { "incoming" };
        rows.push(format!(
            "{{\"id\":\"{}\",\"role\":\"{role}\",\"token\":{token},\"from\":\"{}\",\"to\":\"{}\",\"amount\":\"{}\",\"expiry\":{expiry},\"expired\":{}}}",
            hex::encode(id), addr_of(net, &from), addr_of(net, &to), lat(amount), height >= expiry
        ));
    }
    format!("{{\"ok\":true,\"height\":{height},\"locks\":[{}]}}", rows.join(","))
}

// --- helpers ---------------------------------------------------------------

/// Shared parse step for the value-moving endpoints: seed wallet + LAT amount.
fn wallet_amount(p: &Params) -> Result<(Wallet, u64, String), String> {
    let w = g(p, "seed")
        .and_then(|s| Wallet::from_seed_hex(network(p), &s).ok())
        .ok_or("invalid seed")?;
    let amount = g(p, "amount").and_then(|a| parse_lat(&a)).ok_or("invalid amount")?;
    Ok((w, amount, node(p)))
}

/// Submit a built transaction to the node, mapping the outcome to a JSON reply.
fn submit(node: &str, tx: &lat_types::Transaction, done: &str) -> String {
    match lat_p2p::submit_tx(node, &tx.encode()) {
        Ok(true) => ok(&format!("{done} — confirms when a block is mined")),
        Ok(false) => err("rejected (duplicate, unregistered recipient, or insufficient balance)"),
        Err(_) => err(&format!("cannot reach node at {node}")),
    }
}

fn ok(msg: &str) -> String {
    format!("{{\"ok\":true,\"msg\":\"{}\"}}", esc(msg))
}
fn err(msg: &str) -> String {
    format!("{{\"ok\":false,\"error\":\"{}\"}}", esc(msg))
}
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
fn lat(units: u64) -> String {
    format!("{}.{:05}", units / UNITS, units % UNITS)
}
fn parse_lat(s: &str) -> Option<u64> {
    let (int, frac) = s.trim().split_once('.').unwrap_or((s.trim(), ""));
    let int: u64 = int.parse().ok()?;
    let mut frac = frac.to_string();
    frac.truncate(5);
    while frac.len() < 5 {
        frac.push('0');
    }
    let frac: u64 = if frac.is_empty() { 0 } else { frac.parse().ok()? };
    Some(int * UNITS + frac)
}

type Params = std::collections::HashMap<String, String>;

fn parse_target(target: &str) -> (String, Params) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut params = Params::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            params.insert(k.to_string(), url_decode(v));
        }
    }
    (path.to_string(), params)
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(bytes[i]);
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn g(p: &Params, k: &str) -> Option<String> {
    p.get(k).cloned()
}

const UI: &str = include_str!("wallet.html");

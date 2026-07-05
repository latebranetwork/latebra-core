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
use std::thread;

use lat_crypto::Ciphertext;
use lat_types::{Address, Network};
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
            format!(
                "{{\"registered\":true,\"address\":\"{}\",\"spendable\":\"{}\",\"pending\":\"{}\",\"public\":\"{}\",\"total\":\"{}\"}}",
                w.address_string(), lat(spendable), lat(pending), lat(public),
                lat(spendable.saturating_add(public))
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

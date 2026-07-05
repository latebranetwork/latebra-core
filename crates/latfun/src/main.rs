//! latfun — backend for the pump.fun-style launchpad on Latebra.
//!
//! Serves the static frontend AND a JSON API on one origin (no CORS). It:
//!   * connects to a live `latebrad` node over RPC,
//!   * INDEXES real on-chain `CreateToken` transactions into the token list
//!     (tickers are unique on-chain — the chain enforces it, we just surface it),
//!   * reads real on-chain balances for connected wallets,
//!   * signs + submits real `CreateToken` / transfer transactions,
//!   * keeps an off-chain store (JSON on disk) for the things that aren't on-chain:
//!     token image/description, the bonding-curve pricing (BETA — off-chain until
//!     the DVM curve contract lands), community chat, and governance proposals/votes.
//!
//! Run:
//!   latfun --node 127.0.0.1:4040 --listen 127.0.0.1:5180 --frontend latebra-launchpad/frontend

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lat_chain::Block;
use lat_types::{Address, Network, Transaction};
use lat_wallet::Wallet;
use serde::{Deserialize, Serialize};

const LAT_TOKEN: u32 = 0;
const NET: Network = Network::Testnet;

// Bonding-curve defaults (BETA, off-chain), mirroring contracts/bonding_curve.bas.
const VLAT0: f64 = 30.0;
const VTOK0: f64 = 1_000_000_000.0;
const GRADUATE_LAT: f64 = 500.0;
const FEE_BPS: f64 = 100.0; // 1% trading fee
// The 1% fee splits: 20% auto to the dev (creator) wallet, 80% to the community
// treasury, which holders govern by vote.
const DEV_SHARE: f64 = 0.20;
const COMMUNITY_SHARE: f64 = 0.80;
// A governance proposal executes once it has more YES than NO votes and at least
// this many total votes (the community quorum).
const QUORUM: usize = 3;

// ---------------------------------------------------------------------------
// Off-chain store
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
struct Curve {
    vlat: f64,
    vtok: f64,
    real_lat: f64,
    graduated: bool,
}
impl Default for Curve {
    fn default() -> Self {
        Curve { vlat: VLAT0, vtok: VTOK0, real_lat: 0.0, graduated: false }
    }
}
impl Curve {
    fn price(&self) -> f64 { self.vlat / self.vtok }
    fn market_cap(&self) -> f64 { self.price() * VTOK0 }
}

#[derive(Serialize, Deserialize, Clone)]
struct Trade { kind: String, user: String, lat: f64, tok: f64, time: u64 }

#[derive(Serialize, Deserialize, Clone)]
struct ChatMsg { user: String, text: String, time: u64 }

#[derive(Serialize, Deserialize, Clone)]
struct Proposal {
    id: u64,
    /// What to change: "name" | "ticker" | "image" | "banner" | "description" |
    /// "twitter" | "telegram" | "website" | "treasury" (spend LAT).
    kind: String,
    /// Proposed new value, or the purpose/recipient for a treasury spend.
    text: String,
    /// For a "treasury" proposal: LAT to release from the community treasury.
    #[serde(default)]
    amount: f64,
    proposer: String,
    time: u64,
    yes: Vec<String>,  // voter addresses
    no: Vec<String>,
    /// "open" | "executed" | "rejected".
    #[serde(default)]
    status: String,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct TokenMeta {
    ticker: String,           // on-chain ticker (immutable, the store key)
    #[serde(default)]
    display_ticker: String,   // governance can re-label the display ticker
    name: String,
    description: String,
    image: String,            // token icon URL
    #[serde(default)]
    banner: String,           // wide banner URL
    #[serde(default)]
    twitter: String,
    #[serde(default)]
    telegram: String,
    #[serde(default)]
    website: String,
    creator: String,    // address string
    creator_id: String, // hex account id
    supply: u64,
    token_id: u32,      // on-chain sequential id (assigned by replay order)
    created_at: u64,
    curve: Curve,
    /// Off-chain fee accounting (BETA): 80% of each 1% fee accrues here for the
    /// community to govern; 20% is auto-credited to the dev below.
    #[serde(default)]
    community_treasury: f64,
    #[serde(default)]
    dev_fees: f64,
    #[serde(default)]
    trades: Vec<Trade>,
    #[serde(default)]
    price_history: Vec<f64>,
    #[serde(default)]
    chat: Vec<ChatMsg>,
    #[serde(default)]
    proposals: Vec<Proposal>,
    #[serde(default)]
    holdings: HashMap<String, f64>, // address -> token balance (BETA curve accounting)
}

#[derive(Serialize, Deserialize, Default)]
struct Store {
    /// ticker (uppercase) -> metadata
    tokens: HashMap<String, TokenMeta>,
    /// highest block height indexed so far
    scanned_height: u64,
    /// next on-chain token id to assign (mirrors the ledger's counter, starts at 1)
    next_token_id: u32,
    /// next governance proposal id
    next_proposal: u64,
}

struct App {
    node: String,
    frontend: PathBuf,
    store_path: PathBuf,
    store: Mutex<Store>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl App {
    fn load(&self) {
        if let Ok(bytes) = fs::read(&self.store_path) {
            if let Ok(s) = serde_json::from_slice::<Store>(&bytes) {
                let mut guard = self.store.lock().unwrap();
                *guard = s;
                if guard.next_token_id == 0 { guard.next_token_id = 1; }
            }
        } else {
            self.store.lock().unwrap().next_token_id = 1;
        }
    }
    fn save(&self, s: &Store) {
        if let Some(parent) = self.store_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec_pretty(s) {
            let _ = fs::write(&self.store_path, bytes);
        }
    }
}

// ---------------------------------------------------------------------------
// Chain indexer — turn on-chain CreateToken txs into the token list
// ---------------------------------------------------------------------------

fn index_chain(app: &App) {
    let height = match lat_p2p::get_height(&app.node) {
        Ok(h) => h,
        Err(_) => return, // node offline; try again next tick
    };
    let mut s = app.store.lock().unwrap();
    if s.next_token_id == 0 { s.next_token_id = 1; }
    let from = s.scanned_height.saturating_add(1);
    let mut changed = false;
    for h in from..=height {
        let bytes = match lat_p2p::get_block(&app.node, h) {
            Ok(Some(b)) => b,
            _ => break, // can't fetch; stop and retry next tick (don't skip)
        };
        let Some(block) = Block::decode(&bytes) else { continue };
        for tx in &block.txs {
            if let Transaction::CreateToken { ticker, creator, supply, .. } = tx {
                // The ledger assigns ids sequentially to every accepted CreateToken;
                // a mined block only contains accepted txs, so replay order matches.
                let id = s.next_token_id;
                s.next_token_id += 1;
                let norm = match lat_types::normalize_ticker(ticker) {
                    Some(t) => t,
                    None => continue,
                };
                let creator_id_hex = hex_id(creator);
                let creator_str = lat_crypto::PublicKey::from_bytes(creator)
                    .map(|pk| Address::new(NET, pk).encode())
                    .unwrap_or_else(|| creator_id_hex.clone());
                let entry = s.tokens.entry(norm.clone()).or_insert_with(TokenMeta::default);
                // Only fill on first sight (an operator may have set image/desc via create()).
                if entry.token_id == 0 {
                    entry.ticker = norm.clone();
                    if entry.name.is_empty() { entry.name = norm.clone(); }
                    entry.creator = creator_str;
                    entry.creator_id = creator_id_hex;
                    entry.supply = *supply;
                    entry.token_id = id;
                    if entry.created_at == 0 { entry.created_at = block.header.timestamp; }
                    if entry.price_history.is_empty() {
                        entry.price_history.push(entry.curve.price());
                    }
                }
            }
        }
        s.scanned_height = h;
        changed = true;
    }
    if changed {
        let snapshot = clone_store(&s);
        drop(s);
        app.save(&snapshot);
    }
}

fn clone_store(s: &Store) -> Store {
    serde_json::from_slice(&serde_json::to_vec(s).unwrap()).unwrap()
}

fn hex_id(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

struct Req {
    method: String,
    path: String,
    query: HashMap<String, String>,
    body: Vec<u8>,
}

fn main() {
    let mut node = "127.0.0.1:4040".to_string();
    let mut listen = "127.0.0.1:5180".to_string();
    let mut frontend = PathBuf::from("latebra-launchpad/frontend");
    let mut data = PathBuf::from("latfun-data/store.json");
    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--node" => { i += 1; node = args.get(i).cloned().unwrap_or(node); }
            "--listen" => { i += 1; listen = args.get(i).cloned().unwrap_or(listen); }
            "--frontend" => { i += 1; frontend = PathBuf::from(args.get(i).cloned().unwrap_or_default()); }
            "--data" => { i += 1; data = PathBuf::from(args.get(i).cloned().unwrap_or_default()); }
            _ => {}
        }
        i += 1;
    }

    let app = Arc::new(App {
        node: node.clone(),
        frontend,
        store_path: data,
        store: Mutex::new(Store::default()),
    });
    app.load();

    // Background indexer.
    {
        let app = Arc::clone(&app);
        thread::spawn(move || loop {
            index_chain(&app);
            thread::sleep(Duration::from_secs(2));
        });
    }

    let listener = TcpListener::bind(&listen).expect("bind latfun listen address");
    println!("latfun  →  http://{listen}");
    println!("  node    : {node}");
    println!("  frontend: {}", app.frontend.display());
    for stream in listener.incoming().flatten() {
        let app = Arc::clone(&app);
        thread::spawn(move || { let _ = handle(stream, &app); });
    }
}

fn handle(mut stream: TcpStream, app: &App) -> std::io::Result<()> {
    let req = match read_request(&mut stream)? {
        Some(r) => r,
        None => return Ok(()),
    };

    let (status, ctype, body) = route(app, &req);
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Req>> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    // Read until we have the full header block.
    let header_end;
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 { return Ok(None); }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buf.len() > 1 << 20 { return Ok(None); } // header too big
    }
    let header_txt = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_txt.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();

    let mut content_len = 0usize;
    for line in lines {
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_len = v.trim().parse().unwrap_or(0);
        }
    }

    let (path, query) = parse_target(&target);
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut tmp)?;
        if n == 0 { break; }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_len);
    Ok(Some(Req { method, path, query, body }))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_target(target: &str) -> (String, HashMap<String, String>) {
    let (path, q) = target.split_once('?').unwrap_or((target, ""));
    let mut query = HashMap::new();
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            query.insert(k.to_string(), url_decode(v));
        }
    }
    (path.to_string(), query)
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
            b'+' => { out.push(b' '); i += 1; }
            c => { out.push(c); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

fn route(app: &App, req: &Req) -> (&'static str, &'static str, Vec<u8>) {
    if req.path.starts_with("/api/") {
        let (status, json) = api(app, req);
        return (status, "application/json; charset=utf-8", json.into_bytes());
    }
    serve_static(app, &req.path)
}

fn serve_static(app: &App, path: &str) -> (&'static str, &'static str, Vec<u8>) {
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    // Prevent path traversal.
    if rel.contains("..") {
        return ("400 Bad Request", "text/plain", b"bad path".to_vec());
    }
    let full = app.frontend.join(rel);
    match fs::read(&full) {
        Ok(bytes) => ("200 OK", content_type(rel), bytes),
        Err(_) => ("404 Not Found", "text/plain", b"not found".to_vec()),
    }
}

fn content_type(name: &str) -> &'static str {
    if name.ends_with(".html") { "text/html; charset=utf-8" }
    else if name.ends_with(".css") { "text/css; charset=utf-8" }
    else if name.ends_with(".js") { "text/javascript; charset=utf-8" }
    else if name.ends_with(".json") { "application/json" }
    else if name.ends_with(".svg") { "image/svg+xml" }
    else if name.ends_with(".png") { "image/png" }
    else { "application/octet-stream" }
}

// ---------------------------------------------------------------------------
// JSON API
// ---------------------------------------------------------------------------

fn api(app: &App, req: &Req) -> (&'static str, String) {
    let body: serde_json::Value = if req.body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null)
    };
    let seg: Vec<&str> = req.path.trim_start_matches("/api/").split('/').collect();
    match (req.method.as_str(), seg.as_slice()) {
        ("GET", ["status"]) => ok(status_json(app)),
        ("GET", ["tokens"]) => ok(tokens_json(app)),
        ("GET", ["token", ticker]) => token_detail(app, ticker),
        ("GET", ["balance"]) => balance_json(app, req.query.get("addr").map(String::as_str).unwrap_or("")),
        ("POST", ["connect"]) => connect(app, &body),
        ("POST", ["create"]) => create_token(app, &body),
        ("POST", ["trade"]) => trade(app, &body),
        ("POST", ["chat", ticker]) => post_chat(app, ticker, &body),
        ("POST", ["gov", ticker]) => post_proposal(app, ticker, &body),
        ("POST", ["vote", ticker]) => vote(app, ticker, &body),
        _ => ("404 Not Found", json_err("unknown endpoint")),
    }
}

fn ok(v: serde_json::Value) -> (&'static str, String) {
    ("200 OK", v.to_string())
}
fn json_err(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}
fn err(msg: &str) -> (&'static str, String) {
    ("200 OK", json_err(msg))
}

fn status_json(app: &App) -> serde_json::Value {
    let height = lat_p2p::get_height(&app.node).ok();
    let s = app.store.lock().unwrap();
    serde_json::json!({
        "ok": true,
        "node": app.node,
        "online": height.is_some(),
        "height": height,
        "indexed": s.scanned_height,
        "tokens": s.tokens.len(),
        "graduate_lat": GRADUATE_LAT,
        "fee_bps": FEE_BPS,
    })
}

fn tokens_json(app: &App) -> serde_json::Value {
    let s = app.store.lock().unwrap();
    let mut list: Vec<serde_json::Value> = s.tokens.values().map(token_summary).collect();
    // newest first
    list.sort_by(|a, b| b["created_at"].as_u64().unwrap_or(0).cmp(&a["created_at"].as_u64().unwrap_or(0)));
    serde_json::json!({ "ok": true, "tokens": list })
}

fn disp_ticker(t: &TokenMeta) -> String {
    if t.display_ticker.is_empty() { t.ticker.clone() } else { t.display_ticker.clone() }
}

fn token_summary(t: &TokenMeta) -> serde_json::Value {
    serde_json::json!({
        "ticker": disp_ticker(t),
        "onchain_ticker": t.ticker,
        "name": t.name,
        "description": t.description,
        "image": t.image,
        "banner": t.banner,
        "creator": t.creator,
        "supply": t.supply,
        "token_id": t.token_id,
        "created_at": t.created_at,
        "price": t.curve.price(),
        "market_cap": t.curve.market_cap(),
        "real_lat": t.curve.real_lat,
        "graduated": t.curve.graduated,
        "progress": (t.curve.real_lat / GRADUATE_LAT * 100.0).min(100.0),
        "trades": t.trades.len(),
        "replies": t.chat.len(),
    })
}

fn token_detail(app: &App, ticker: &str) -> (&'static str, String) {
    let norm = match lat_types::normalize_ticker(ticker) {
        Some(t) => t,
        None => return err("bad ticker"),
    };
    let s = app.store.lock().unwrap();
    let Some(t) = s.tokens.get(&norm) else { return err("no such token") };
    let detail = serde_json::json!({
        "ok": true,
        "token": {
            "ticker": disp_ticker(t), "onchain_ticker": t.ticker,
            "name": t.name, "description": t.description, "image": t.image, "banner": t.banner,
            "twitter": t.twitter, "telegram": t.telegram, "website": t.website,
            "creator": t.creator, "creator_id": t.creator_id, "supply": t.supply, "token_id": t.token_id,
            "created_at": t.created_at,
            "price": t.curve.price(), "market_cap": t.curve.market_cap(),
            "real_lat": t.curve.real_lat, "graduated": t.curve.graduated,
            "progress": (t.curve.real_lat / GRADUATE_LAT * 100.0).min(100.0),
            "vlat": t.curve.vlat, "vtok": t.curve.vtok,
            "community_treasury": t.community_treasury, "dev_fees": t.dev_fees,
            "quorum": QUORUM,
            "price_history": t.price_history,
            "trades": t.trades,
            "chat": t.chat,
            "proposals": t.proposals,
        }
    });
    ok(detail)
}

fn balance_json(app: &App, addr: &str) -> (&'static str, String) {
    let a = match Address::parse(addr.trim()) {
        Ok(a) => a,
        Err(_) => return err("bad address"),
    };
    let public = lat_p2p::get_public_balance(&app.node, a.id(), LAT_TOKEN).ok().flatten();
    let registered = matches!(lat_p2p::get_nonce(&app.node, a.id()), Ok(Some(_)));
    ok(serde_json::json!({
        "ok": true,
        "address": addr,
        "registered": registered,
        "public_lat": public,
    }))
}

/// Connect: derive an address from a seed (client keeps the seed; sends it only to
/// build/sign txs). Returns the address + real on-chain balance. Testnet only.
fn connect(app: &App, body: &serde_json::Value) -> (&'static str, String) {
    let seed = body["seed"].as_str().unwrap_or("");
    let w = match Wallet::from_seed_hex(NET, seed) {
        Ok(w) => w,
        Err(_) => return err("bad seed hex (need 64 hex chars)"),
    };
    let addr = w.address_string();
    let public = lat_p2p::get_public_balance(&app.node, w.id(), LAT_TOKEN).ok().flatten();
    let registered = matches!(lat_p2p::get_nonce(&app.node, w.id()), Ok(Some(_)));
    // Auto-register if new, so the account can create/transfer.
    let mut note = String::new();
    if !registered {
        if let Ok(true) = lat_p2p::submit_tx(&app.node, &w.registration_tx().encode()) {
            note = "Registering your account on-chain — try again in a few seconds.".into();
        }
    }
    ok(serde_json::json!({
        "ok": true, "address": addr, "registered": registered,
        "public_lat": public, "note": note,
    }))
}

fn create_token(app: &App, body: &serde_json::Value) -> (&'static str, String) {
    let seed = body["seed"].as_str().unwrap_or("");
    let name = body["name"].as_str().unwrap_or("").trim().to_string();
    let ticker_in = body["ticker"].as_str().unwrap_or("");
    let description = body["description"].as_str().unwrap_or("").trim().to_string();
    let image = body["image"].as_str().unwrap_or("").trim().to_string();
    let banner = body["banner"].as_str().unwrap_or("").trim().to_string();
    let twitter = body["twitter"].as_str().unwrap_or("").trim().to_string();
    let telegram = body["telegram"].as_str().unwrap_or("").trim().to_string();
    let website = body["website"].as_str().unwrap_or("").trim().to_string();
    let supply = body["supply"].as_u64().unwrap_or(1_000_000_000);

    let w = match Wallet::from_seed_hex(NET, seed) {
        Ok(w) => w,
        Err(_) => return err("connect a wallet first"),
    };
    let norm = match lat_types::normalize_ticker(ticker_in) {
        Some(t) => t,
        None => return err("ticker must be 1-10 letters/digits"),
    };
    if name.is_empty() {
        return err("name is required");
    }
    // Uniqueness is enforced on-chain, but reject early if we already indexed it.
    {
        let s = app.store.lock().unwrap();
        if s.tokens.get(&norm).map(|t| t.token_id != 0).unwrap_or(false) {
            return err("that ticker is already taken");
        }
    }
    // Must be registered to create.
    match lat_p2p::get_nonce(&app.node, w.id()) {
        Ok(Some(_)) => {}
        Ok(None) => {
            let _ = lat_p2p::submit_tx(&app.node, &w.registration_tx().encode());
            return err("your account isn't registered yet — registering now, retry in a few seconds");
        }
        Err(_) => return err("node offline"),
    }
    // Build + submit the real on-chain CreateToken.
    let tx = w.create_token(&norm, supply);
    match lat_p2p::submit_tx(&app.node, &tx.encode()) {
        Ok(true) => {}
        Ok(false) => return err("node rejected the token (ticker taken or duplicate in mempool)"),
        Err(_) => return err("node offline"),
    }
    // Stash the off-chain metadata now, keyed by ticker; the indexer fills token_id
    // once it's mined.
    {
        let mut s = app.store.lock().unwrap();
        let entry = s.tokens.entry(norm.clone()).or_insert_with(TokenMeta::default);
        entry.ticker = norm.clone();
        entry.name = name;
        entry.description = description;
        entry.image = image;
        entry.banner = banner;
        entry.twitter = twitter;
        entry.telegram = telegram;
        entry.website = website;
        entry.creator = w.address_string();
        entry.creator_id = hex_id(&w.id());
        entry.supply = supply;
        if entry.created_at == 0 { entry.created_at = now(); }
        if entry.price_history.is_empty() { entry.price_history.push(entry.curve.price()); }
        let snap = clone_store(&s);
        drop(s);
        app.save(&snap);
    }
    ok(serde_json::json!({ "ok": true, "ticker": norm, "note": "Token submitted on-chain — it appears once the next block mines." }))
}

/// Bonding-curve buy/sell — BETA, off-chain accounting against the virtual curve.
/// Real on-chain LAT movement lands when the DVM curve contract is deployed.
fn trade(app: &App, body: &serde_json::Value) -> (&'static str, String) {
    let ticker = body["ticker"].as_str().unwrap_or("");
    let side = body["side"].as_str().unwrap_or("buy");
    let amount = body["amount"].as_f64().unwrap_or(0.0);
    let user = body["address"].as_str().unwrap_or("anon").to_string();
    let norm = match lat_types::normalize_ticker(ticker) {
        Some(t) => t,
        None => return err("bad ticker"),
    };
    if amount <= 0.0 { return err("amount must be positive"); }

    let mut s = app.store.lock().unwrap();
    let Some(t) = s.tokens.get_mut(&norm) else { return err("no such token") };
    if t.curve.graduated { return err("token graduated — trade on the DEX (coming soon)"); }

    let (out, note);
    let fee;
    if side == "buy" {
        fee = amount * FEE_BPS / 10000.0;
        let net = amount - fee;
        let tok = (t.curve.vtok * net) / (t.curve.vlat + net);
        t.curve.vlat += net; t.curve.vtok -= tok; t.curve.real_lat += net;
        *t.holdings.entry(user.clone()).or_insert(0.0) += tok;
        out = tok;
        note = format!("bought {:.0} {}", tok, t.ticker);
    } else {
        let have = *t.holdings.get(&user).unwrap_or(&0.0);
        if amount > have + 1e-9 { return err("you don't hold that many tokens"); }
        let gross = (t.curve.vlat * amount) / (t.curve.vtok + amount);
        fee = gross * FEE_BPS / 10000.0;
        let lat = gross - fee;
        t.curve.vtok += amount; t.curve.vlat -= gross; t.curve.real_lat = (t.curve.real_lat - gross).max(0.0);
        *t.holdings.entry(user.clone()).or_insert(0.0) -= amount;
        out = lat;
        note = format!("sold {:.0} {}", amount, t.ticker);
    }
    // Split the fee: 20% auto to the dev wallet, 80% to the community treasury.
    t.dev_fees += fee * DEV_SHARE;
    t.community_treasury += fee * COMMUNITY_SHARE;
    t.trades.insert(0, Trade {
        kind: side.to_string(), user: user.clone(),
        lat: if side == "buy" { amount } else { out },
        tok: if side == "buy" { out } else { amount },
        time: now(),
    });
    if t.trades.len() > 200 { t.trades.truncate(200); }
    t.price_history.push(t.curve.price());
    if t.price_history.len() > 200 { t.price_history.remove(0); }
    if t.curve.real_lat >= GRADUATE_LAT { t.curve.graduated = true; }

    let holding = *t.holdings.get(&user).unwrap_or(&0.0);
    let resp = serde_json::json!({
        "ok": true, "out": out, "note": note,
        "price": t.curve.price(), "market_cap": t.curve.market_cap(),
        "holding": holding, "progress": (t.curve.real_lat / GRADUATE_LAT * 100.0).min(100.0),
    });
    let snap = clone_store(&s);
    drop(s);
    app.save(&snap);
    ok(resp)
}

fn post_chat(app: &App, ticker: &str, body: &serde_json::Value) -> (&'static str, String) {
    let user = body["address"].as_str().unwrap_or("").to_string();
    let text = body["text"].as_str().unwrap_or("").trim().to_string();
    if user.is_empty() { return err("connect a wallet to chat"); }
    if text.is_empty() || text.len() > 500 { return err("message must be 1-500 chars"); }
    let norm = match lat_types::normalize_ticker(ticker) { Some(t) => t, None => return err("bad ticker") };
    let mut s = app.store.lock().unwrap();
    let Some(t) = s.tokens.get_mut(&norm) else { return err("no such token") };
    t.chat.insert(0, ChatMsg { user, text, time: now() });
    if t.chat.len() > 500 { t.chat.truncate(500); }
    let chat = serde_json::to_value(&t.chat).unwrap_or(serde_json::Value::Null);
    let snap = clone_store(&s);
    drop(s);
    app.save(&snap);
    ok(serde_json::json!({ "ok": true, "chat": chat }))
}

fn post_proposal(app: &App, ticker: &str, body: &serde_json::Value) -> (&'static str, String) {
    let proposer = body["address"].as_str().unwrap_or("").to_string();
    let kind = body["kind"].as_str().unwrap_or("other").to_string();
    let text = body["text"].as_str().unwrap_or("").trim().to_string();
    let amount = body["amount"].as_f64().unwrap_or(0.0);
    if proposer.is_empty() { return err("connect a wallet to propose"); }
    if text.is_empty() || text.len() > 200 { return err("proposal must be 1-200 chars"); }
    if kind == "treasury" && amount <= 0.0 { return err("treasury spend needs a positive LAT amount"); }
    let norm = match lat_types::normalize_ticker(ticker) { Some(t) => t, None => return err("bad ticker") };
    let mut s = app.store.lock().unwrap();
    let pid = s.next_proposal; s.next_proposal += 1;
    let Some(t) = s.tokens.get_mut(&norm) else { return err("no such token") };
    t.proposals.insert(0, Proposal {
        id: pid, kind, text, amount, proposer: proposer.clone(), time: now(),
        yes: vec![proposer], no: vec![], status: "open".into(),
    });
    let props = serde_json::to_value(&t.proposals).unwrap_or(serde_json::Value::Null);
    let snap = clone_store(&s);
    drop(s);
    app.save(&snap);
    ok(serde_json::json!({ "ok": true, "proposals": props }))
}

fn vote(app: &App, ticker: &str, body: &serde_json::Value) -> (&'static str, String) {
    let voter = body["address"].as_str().unwrap_or("").to_string();
    let pid = body["proposal"].as_u64().unwrap_or(u64::MAX);
    let support = body["support"].as_bool().unwrap_or(true);
    if voter.is_empty() { return err("connect a wallet to vote"); }
    let norm = match lat_types::normalize_ticker(ticker) { Some(t) => t, None => return err("bad ticker") };
    let mut s = app.store.lock().unwrap();
    let Some(t) = s.tokens.get_mut(&norm) else { return err("no such token") };
    let Some(p) = t.proposals.iter_mut().find(|p| p.id == pid) else { return err("no such proposal") };
    if p.status != "open" && !p.status.is_empty() { return err("this proposal is closed"); }
    p.yes.retain(|v| v != &voter);
    p.no.retain(|v| v != &voter);
    if support { p.yes.push(voter); } else { p.no.push(voter); }
    // Execute once the community quorum is met with more YES than NO.
    let (yes, no) = (p.yes.len(), p.no.len());
    let mut executed = String::new();
    if yes + no >= QUORUM {
        if yes > no {
            let (kind, text, amount) = (p.kind.clone(), p.text.clone(), p.amount);
            p.status = "executed".into();
            executed = execute_proposal(t, &kind, &text, amount);
        } else {
            p.status = "rejected".into();
        }
    }
    let props = serde_json::to_value(&t.proposals).unwrap_or(serde_json::Value::Null);
    let snap = clone_store(&s);
    drop(s);
    app.save(&snap);
    ok(serde_json::json!({ "ok": true, "proposals": props, "executed": executed }))
}

/// Apply an approved proposal to the token. Field changes update the off-chain
/// display metadata (the on-chain ticker/id are immutable); a "treasury" proposal
/// releases LAT from the community treasury. Returns a human-readable note.
fn execute_proposal(t: &mut TokenMeta, kind: &str, text: &str, amount: f64) -> String {
    match kind {
        "name" => { t.name = text.to_string(); format!("renamed to {text}") }
        "ticker" => { t.display_ticker = text.to_string(); format!("display ticker → {text}") }
        "image" => { t.image = text.to_string(); "icon updated".into() }
        "banner" => { t.banner = text.to_string(); "banner updated".into() }
        "description" => { t.description = text.to_string(); "description updated".into() }
        "twitter" => { t.twitter = text.to_string(); "twitter updated".into() }
        "telegram" => { t.telegram = text.to_string(); "telegram updated".into() }
        "website" => { t.website = text.to_string(); "website updated".into() }
        "treasury" => {
            let spend = amount.min(t.community_treasury);
            t.community_treasury -= spend;
            format!("released {spend:.4} LAT from the treasury: {text}")
        }
        _ => "approved".into(),
    }
}

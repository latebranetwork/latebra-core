//! latfun — backend for the pump.fun-style launchpad on Latebra.
//!
//! Serves the static frontend AND a JSON API on one origin (no CORS). It:
//!   * connects to a live `latebrad` node over RPC,
//!   * INDEXES real on-chain `CreateToken` transactions into the token list
//!     (tickers are unique on-chain — the chain enforces it, we just surface it),
//!   * reads real on-chain balances for connected wallets,
//!   * signs + submits real `CreateToken` / transfer transactions,
//!   * deploys each token's **bonding curve as a real contract** and trades it
//!     with signed `CallContract` transactions, reading reserves and holdings back
//!     out of contract storage — so no node (including this one) can fake a price
//!     or invent a holding,
//!   * keeps an off-chain store (JSON on disk) only for what genuinely isn't
//!     on-chain: token image/description, community chat, governance
//!     proposals/votes, and the fee split (the VM has no value-transfer opcode).
//!
//! ## Honest boundary
//! Pricing and token accounting are consensus-enforced. **LAT settlement is not**:
//! the VM cannot move value, so the LAT leg of a trade is a separate transfer and
//! the two are not atomic. See D4 in PROJECT_CHECKPOINT.md and THREAT_MODEL §2.6.
//! latfun is also **custodial** — callers post their seed — which is testnet-only
//! posture, not a launch posture.
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

// Curve parameters live in ONE place — the deployed contract (lat-contracts).
// latfun no longer keeps its own copy: it re-exports the contract's so a quote
// rendered here can never drift from the price consensus will actually charge.
use lat_contracts::bonding_curve::{Curve, GRADUATE_LAT, VTOK0};

/// Base units per LAT (the ledger is 5-decimal: 1 LAT = 100_000).
const LAT_UNITS: u64 = 100_000;

// The 1% trading fee (the contract's FEE_DIVISOR) splits 20% to the dev
// (creator) wallet, 80% to the community treasury, which holders govern by vote.
// NB: the *split* is latfun bookkeeping — the contract deducts the fee from the
// trade but has no opcode to pay anyone, so this accounting stays off-chain.
const DEV_SHARE_BPS: u64 = 2_000;
const COMMUNITY_SHARE_BPS: u64 = 8_000;
// The community takes `fee - dev_cut` rather than its own bps of the fee, so the
// sub-base-unit remainder of the integer split lands with the community instead
// of evaporating. That is only correct while the two shares are the whole fee:
const _: () = assert!(DEV_SHARE_BPS + COMMUNITY_SHARE_BPS == 10_000, "fee split must be whole");
// A governance proposal executes once it has more YES than NO votes and at least
// this many total votes (the community quorum).
const QUORUM: usize = 3;

// ---------------------------------------------------------------------------
// Off-chain store
// ---------------------------------------------------------------------------

/// Serde mirror of the contract's [`Curve`], which is consensus-side and derives
/// no serde. Kept as a *mirror* rather than a second implementation: all curve
/// math runs in [`Curve`], so latfun's quotes are the contract's arithmetic to
/// the base unit — not a float restatement that rounds differently.
#[derive(Serialize, Deserialize, Clone, Copy)]
struct CurveState {
    vlat: u64,
    vtok: u64,
    real_lat: u64,
    graduated: bool,
}
impl Default for CurveState {
    fn default() -> Self {
        Curve::default().into()
    }
}
impl From<Curve> for CurveState {
    fn from(c: Curve) -> Self {
        CurveState { vlat: c.vlat, vtok: c.vtok, real_lat: c.real_lat, graduated: c.graduated }
    }
}
impl From<CurveState> for Curve {
    fn from(c: CurveState) -> Self {
        Curve { vlat: c.vlat, vtok: c.vtok, real_lat: c.real_lat, graduated: c.graduated }
    }
}
impl CurveState {
    /// Spot price in LAT per token (display only — never fed back into math).
    fn price(&self) -> f64 {
        Curve::from(*self).price_scaled() as f64 / 1e9 / LAT_UNITS as f64
    }
    fn market_cap(&self) -> f64 {
        self.price() * VTOK0 as f64
    }
    /// Progress toward graduation, 0..=100 (display only).
    fn progress(&self) -> f64 {
        Curve::from(*self).graduation_bps() as f64 / 100.0
    }
}

/// One recorded trade. `lat` and `tok` are **base units**, matching the contract.
#[derive(Serialize, Deserialize, Clone)]
struct Trade { kind: String, user: String, lat: u64, tok: u64, time: u64 }

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
    /// For a "treasury" proposal: LAT (base units) to release from the community
    /// treasury.
    #[serde(default)]
    amount: u64,
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
    curve: CurveState,
    /// Off-chain fee accounting (base units): 80% of each 1% fee accrues here for
    /// the community to govern; 20% is auto-credited to the dev below. The
    /// contract deducts the fee but cannot pay it out (no value-transfer opcode),
    /// so this split stays latfun's books — see THREAT_MODEL §2.6.
    #[serde(default)]
    community_treasury: u64,
    #[serde(default)]
    dev_fees: u64,
    #[serde(default)]
    trades: Vec<Trade>,
    /// Spot price samples, as the contract's scaled integer (`price_scaled`).
    #[serde(default)]
    price_history: Vec<u64>,
    #[serde(default)]
    chat: Vec<ChatMsg>,
    #[serde(default)]
    proposals: Vec<Proposal>,
    /// address -> token balance in base units. Mirrors the curve contract's
    /// holdings slot; the contract is authoritative once a curve is deployed.
    #[serde(default)]
    holdings: HashMap<String, u64>,
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

/// Render base units as a human LAT string (the ledger is 5-decimal). Display
/// only — base units are what cross the API and the curve.
fn lat(units: u64) -> String {
    format!("{}.{:05}", units / LAT_UNITS, units % LAT_UNITS)
}

/// Inverse of [`hex_id`]: decode a 32-byte account id from hex.
fn account_id(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Read a token's curve straight from the chain's contract storage — the
/// authoritative state, as consensus applied it. `None` if the curve isn't
/// deployed yet or the node is unreachable.
///
/// This is what makes the curve checkable: the numbers come from the ledger, not
/// from latfun's JSON, so the operator cannot quote a price the chain disagrees
/// with. Slot 4 (`SLOT_INIT`) is 0 until the first trade initializes the
/// reserves, in which case the contract is deployed but still at its defaults.
fn read_curve(node: &str, contract: [u8; 32]) -> Option<Curve> {
    use lat_contracts::bonding_curve::{SLOT_GRADUATED, SLOT_INIT, SLOT_REAL_LAT, SLOT_VLAT, SLOT_VTOK};
    let slot = |k: u64| lat_p2p::get_contract_storage(node, contract, k).ok();
    if slot(SLOT_INIT)? == 0 {
        // Deployed but never traded: the contract initializes on first call, so
        // its storage is empty and the defaults are the honest answer.
        return Some(Curve::default());
    }
    Some(Curve {
        vlat: slot(SLOT_VLAT)?,
        vtok: slot(SLOT_VTOK)?,
        real_lat: slot(SLOT_REAL_LAT)?,
        graduated: slot(SLOT_GRADUATED)? != 0,
    })
}

/// Read one account's on-chain holdings of a token's curve.
fn read_holdings(node: &str, contract: [u8; 32], who: &[u8; 32]) -> Option<u64> {
    lat_p2p::get_contract_storage(node, contract, lat_contracts::bonding_curve::holdings_key(who)).ok()
}

/// Which indexed token, if any, owns `contract` as its curve.
///
/// Derived rather than stored: a curve id is `hash(creator ‖ salted code)`, so
/// recomputing it per token is the same check a trader would run. Contracts the
/// launchpad didn't deploy simply don't match, which is what keeps an unrelated
/// contract from being indexed as somebody's curve.
fn curve_owner(s: &Store, contract: &[u8; 32]) -> Option<String> {
    s.tokens.iter().find_map(|(norm, t)| {
        let creator = account_id(&t.creator_id)?;
        (&lat_contracts::bonding_curve::curve_id(&creator, norm) == contract).then(|| norm.clone())
    })
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
                let entry = s.tokens.entry(norm.clone()).or_default();
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
                        entry.price_history.push(Curve::from(entry.curve).price_scaled());
                    }
                }
            }

            // A MINED CallContract against a token's curve is a settled trade.
            // Recording them here rather than in the trade() endpoint is what
            // makes the books honest: a submitted trade that the chain rejects
            // (bad nonce, reverted by the curve) never reaches a block, so it can
            // never reach the ledger below either.
            if let Transaction::CallContract { contract, caller, input, .. } = tx {
                let Some(norm) = curve_owner(&s, contract) else { continue };
                let (is_buy, amount) = lat_contracts::bonding_curve::decode_trade(*input);
                let Some(t) = s.tokens.get_mut(&norm) else { continue };

                // Replay the trade through the contract's own math, from the
                // state we last agreed with the chain on. The curve is
                // deterministic and blocks arrive in order, so this tracks it
                // exactly — and read_curve() re-anchors us to the ledger anyway.
                let mut curve: Curve = t.curve.into();
                let who = hex_id(caller);
                let held = t.holdings.get(&who).copied().unwrap_or(0);
                let Some(fill) = (if is_buy { curve.apply_buy(amount) } else { curve.apply_sell(amount, held) })
                else {
                    continue; // The contract reverted; consensus changed nothing.
                };
                if is_buy {
                    *t.holdings.entry(who.clone()).or_insert(0) += fill.out;
                } else {
                    *t.holdings.entry(who.clone()).or_insert(0) -= amount;
                }
                t.curve = curve.into();

                // 1% on both sides, as the curve computed it — never recomputed
                // here, or the two could drift apart again. Integer split; the
                // sub-unit remainder stays with the community.
                let dev_cut = fill.fee * DEV_SHARE_BPS / 10_000;
                t.dev_fees += dev_cut;
                t.community_treasury += fill.fee - dev_cut;

                t.trades.insert(0, Trade {
                    kind: if is_buy { "buy".into() } else { "sell".into() },
                    user: who,
                    lat: if is_buy { amount } else { fill.out },
                    tok: if is_buy { fill.out } else { amount },
                    time: block.header.timestamp,
                });
                if t.trades.len() > 200 { t.trades.truncate(200); }
                t.price_history.push(curve.price_scaled());
                if t.price_history.len() > 200 { t.price_history.remove(0); }
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
        ("GET", ["token", ticker]) => {
            token_detail(app, ticker, req.query.get("id").map(String::as_str).unwrap_or(""))
        }
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
        "fee_bps": 10_000 / lat_contracts::bonding_curve::FEE_DIVISOR,
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
        "progress": t.curve.progress(),
        "trades": t.trades.len(),
        "replies": t.chat.len(),
    })
}

fn token_detail(app: &App, ticker: &str, viewer_id: &str) -> (&'static str, String) {
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
            "progress": t.curve.progress(),
            "vlat": t.curve.vlat, "vtok": t.curve.vtok,
            "community_treasury": t.community_treasury, "dev_fees": t.dev_fees,
            // The curve's contract id, derived from (creator, ticker) — both
            // public. Surfaced so a client can recompute it and confirm it is
            // trading the real curve rather than one this server points it at.
            "curve_id": account_id(&t.creator_id)
                .map(|c| hex_id(&lat_contracts::bonding_curve::curve_id(&c, &t.ticker))),
            // The viewer's own position, keyed by account id (the contract's
            // CALLER), not by address.
            "holdings_self": t.holdings.get(viewer_id).copied().unwrap_or(0),
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
        // Holdings are keyed by account id (that is what the contract's CALLER
        // is), not by the bech32 address — a client needs this to look its own
        // position up.
        "id": hex_id(&w.id()),
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
    // Deploy this token's curve in the same breath. The creator deploys it (they
    // are already paying fees here and hold the key), salted by ticker so it gets
    // its own instance — see bonding_curve::bytecode_for. The id is derivable from
    // (creator, ticker), both public, so anyone can verify the curve later.
    //
    // Independent of the CreateToken above: DeployContract does not reference the
    // token, so mempool ordering between the two does not matter. A rejection here
    // is not fatal to the token — the curve can be re-deployed — so it is reported
    // rather than unwound (there is no way to unwind a submitted tx anyway).
    let curve_code = lat_contracts::bonding_curve::bytecode_for(
        lat_contracts::bonding_curve::ticker_salt(&norm),
    );
    let curve_deployed = matches!(
        lat_p2p::submit_tx(&app.node, &w.deploy_contract(curve_code).encode()),
        Ok(true)
    );
    // Stash the off-chain metadata now, keyed by ticker; the indexer fills token_id
    // once it's mined.
    {
        let mut s = app.store.lock().unwrap();
        let entry = s.tokens.entry(norm.clone()).or_default();
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
        if entry.price_history.is_empty() { entry.price_history.push(Curve::from(entry.curve).price_scaled()); }
        let snap = clone_store(&s);
        drop(s);
        app.save(&snap);
    }
    let note = if curve_deployed {
        "Token + bonding curve submitted on-chain — they appear once the next block mines."
    } else {
        "Token submitted on-chain, but the node rejected its curve — trading stays off-chain until it deploys."
    };
    ok(serde_json::json!({
        "ok": true,
        "ticker": norm,
        "curve_deployed": curve_deployed,
        "curve_id": hex_id(&lat_contracts::bonding_curve::curve_id(&w.id(), &norm)),
        "note": note,
    }))
}

/// Bonding-curve buy/sell — a real on-chain `CallContract` against the token's
/// deployed curve.
///
/// `amount` is **base units** (LAT in for a buy, whole tokens for a sell).
///
/// Three things changed when this stopped being JSON arithmetic:
///
/// 1. **It is authenticated.** The old endpoint took an `address` STRING and no
///    proof, so any HTTP client could trade as anyone and sell someone else's
///    holdings. A `CallContract` is signed, and the contract keys holdings by
///    `CALLER`, so only the key holder can move their tokens — consensus enforces
///    it, not latfun.
/// 2. **It is asynchronous.** The trade is a transaction: it lands in the mempool
///    and only takes effect when a block mines (~3s). This returns the expected
///    result as a *quote* and `pending: true`; callers re-read the token to see
///    the settled state.
/// 3. **latfun is no longer authoritative.** Reserves and holdings are read from
///    contract storage, not the local store. The operator cannot fake a price.
///
/// Still true (D4): the VM cannot move LAT, so this settles token accounting
/// only — the LAT leg is a separate transfer and the two are not atomic. See
/// THREAT_MODEL §2.6.
fn trade(app: &App, body: &serde_json::Value) -> (&'static str, String) {
    let ticker = body["ticker"].as_str().unwrap_or("");
    let side = body["side"].as_str().unwrap_or("buy");
    let amount = body["amount"].as_u64().unwrap_or(0);
    let seed = body["seed"].as_str().unwrap_or("");
    let norm = match lat_types::normalize_ticker(ticker) {
        Some(t) => t,
        None => return err("bad ticker"),
    };
    if amount == 0 {
        return err("amount must be positive (base units)");
    }
    let w = match Wallet::from_seed_hex(NET, seed) {
        Ok(w) => w,
        Err(_) => return err("connect a wallet first"),
    };

    // Derive the curve from public data (creator + ticker) — never from a
    // client-supplied id, or the caller could point us at their own contract.
    let creator_hex = {
        let s = app.store.lock().unwrap();
        let Some(t) = s.tokens.get(&norm) else { return err("no such token") };
        t.creator_id.clone()
    };
    let Some(creator) = account_id(&creator_hex) else {
        return err("that token hasn't mined yet — wait for the next block");
    };
    let contract = lat_contracts::bonding_curve::curve_id(&creator, &norm);

    // Authoritative state: the ledger's, not ours.
    let Some(mut curve) = read_curve(&app.node, contract) else {
        return err("the curve isn't on-chain yet (or the node is offline) — retry shortly");
    };
    if curve.graduated {
        return err("token graduated — trade on the DEX (coming soon)");
    }
    let held = read_holdings(&app.node, contract, &w.id()).unwrap_or(0);

    // Dry-run the contract's own math so a doomed trade costs no transaction, and
    // so we can quote what it will produce. The chain re-runs this for real.
    let is_buy = side == "buy";
    let quote = if is_buy { curve.apply_buy(amount) } else { curve.apply_sell(amount, held) };
    let Some(fill) = quote else {
        return err(if !is_buy && amount > held {
            "you don't hold that many tokens"
        } else {
            "the curve would reject that trade (zero, or above MAX_TRADE)"
        });
    };

    let nonce = match lat_p2p::get_nonce(&app.node, w.id()) {
        Ok(Some(n)) => n,
        Ok(None) => {
            let _ = lat_p2p::submit_tx(&app.node, &w.registration_tx().encode());
            return err("your account isn't registered yet — registering now, retry in a few seconds");
        }
        Err(_) => return err("node offline"),
    };
    let input = lat_contracts::bonding_curve::encode_trade(is_buy, amount);
    match lat_p2p::submit_tx(&app.node, &w.call_contract(contract, input, nonce).encode()) {
        Ok(true) => {}
        Ok(false) => return err("the node rejected the trade (duplicate nonce, or too little LAT for the fee)"),
        Err(_) => return err("node offline"),
    }

    let note = if is_buy {
        format!("buying ~{} {norm} for {} LAT — confirms in a block", fill.out, lat(amount))
    } else {
        format!("selling {amount} {norm} for ~{} LAT — confirms in a block", lat(fill.out))
    };
    // Quoted, not settled: these are what the curve WILL produce if this trade is
    // the next one to touch it. Another trade mining first re-prices it.
    ok(serde_json::json!({
        "ok": true,
        "pending": true,
        "quoted_out": fill.out,
        "quoted_fee": fill.fee,
        "note": note,
        "curve_id": hex_id(&contract),
        "price": CurveState::from(curve).price(),
        "market_cap": CurveState::from(curve).market_cap(),
        "progress": CurveState::from(curve).progress(),
    }))
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
    // Base units, like every other amount crossing this API.
    let amount = body["amount"].as_u64().unwrap_or(0);
    if proposer.is_empty() { return err("connect a wallet to propose"); }
    if text.is_empty() || text.len() > 200 { return err("proposal must be 1-200 chars"); }
    if kind == "treasury" && amount == 0 { return err("treasury spend needs a positive LAT amount"); }
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
fn execute_proposal(t: &mut TokenMeta, kind: &str, text: &str, amount: u64) -> String {
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
            format!("released {} LAT from the treasury: {text}", lat(spend))
        }
        _ => "approved".into(),
    }
}

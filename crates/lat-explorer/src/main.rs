//! Latscan — the Latebra block explorer, Etherscan / BscScan-style.
//!
//! A web server that queries live `latebrad` nodes over RPC and renders the chain
//! with a mainnet/testnet switcher. Amounts and balances stay encrypted — the
//! explorer shows what is public and marks confidential values.
//!
//! Run:
//!   `lat-explorer --testnet 127.0.0.1:4040 --mainnet 127.0.0.1:4041 --listen 127.0.0.1:8080`

use std::collections::HashMap;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use lat_chain::{emission, mine_registration, Block, MIN_TRANSFER_FEE};
use lat_types::{Address, Network, Transaction};
use lat_wallet::Wallet;
use rand::rngs::OsRng;

/// The Latebra logo mark as an inline SVG data-URI — used for the browser
/// favicon and the header brand mark. Violet rounded "LD" monogram whose right
/// edge dissolves into pixels (privacy: data scattering away).
const LOGO: &str = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'><defs><mask id='latm'><rect width='512' height='512' fill='%23000'/><rect x='108' y='104' width='230' height='304' rx='52' fill='%23fff'/><path fill='%23000' d='M192 180H362V292a24 24 0 0 1-24 24H216a24 24 0 0 1-24-24Z'/><rect x='192' y='104' width='34' height='80' fill='%23000'/></mask></defs><g mask='url(%23latm)'><rect width='512' height='512' fill='%238b5cf6'/></g><g fill='%238b5cf6'><rect x='410' y='150' width='30' height='30' rx='5'/><rect x='360' y='182' width='24' height='24' rx='4'/><rect x='404' y='216' width='22' height='22' rx='4'/><rect x='356' y='238' width='18' height='18' rx='3'/><rect x='392' y='262' width='30' height='30' rx='5'/><rect x='352' y='298' width='16' height='16' rx='3'/><rect x='404' y='300' width='14' height='14' rx='3'/><rect x='368' y='330' width='18' height='18' rx='3'/></g></svg>";

// Small line icons (24x24, currentColor stroke).
const IC_BLOCK: &str = "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.7' stroke-linejoin='round'><path d='M12 2 3 7v10l9 5 9-5V7z'/><path d='M3 7l9 5 9-5M12 12v10'/></svg>";
const IC_COIN: &str = "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.7'><circle cx='12' cy='12' r='9'/><path d='M12 7.5v9M14.5 9.7c0-1-1.1-1.7-2.5-1.7s-2.5.7-2.5 1.7 1.1 1.6 2.5 1.6 2.5.7 2.5 1.7-1.1 1.7-2.5 1.7-2.5-.7-2.5-1.7'/></svg>";
const IC_CLOCK: &str = "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.7' stroke-linecap='round'><circle cx='12' cy='12' r='9'/><path d='M12 7v5l3.5 2'/></svg>";
const IC_NET: &str = "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.7'><circle cx='12' cy='12' r='9'/><path d='M3 12h18M12 3c2.6 3 2.6 15 0 18M12 3c-2.6 3-2.6 15 0 18'/></svg>";
const IC_TX: &str = "<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'><path d='M17 3v12M17 15l4-4M17 15l-4-4M7 21V9M7 9 3 13M7 9l4 4'/></svg>";

struct Config {
    mainnet: String,
    testnet: String,
    listen: String,
}

impl Config {
    fn node(&self, net: &str) -> &str {
        if net == "mainnet" { &self.mainnet } else { &self.testnet }
    }
}

fn main() {
    let mut cfg = Config {
        mainnet: "127.0.0.1:4041".to_string(),
        testnet: "127.0.0.1:4040".to_string(),
        listen: "127.0.0.1:8080".to_string(),
    };
    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--mainnet" => { i += 1; cfg.mainnet = args.get(i).cloned().unwrap_or(cfg.mainnet); }
            "--testnet" => { i += 1; cfg.testnet = args.get(i).cloned().unwrap_or(cfg.testnet); }
            "--listen" => { i += 1; cfg.listen = args.get(i).cloned().unwrap_or(cfg.listen); }
            _ => {}
        }
        i += 1;
    }

    let listener = TcpListener::bind(&cfg.listen).expect("bind explorer listen address");
    println!("Latscan explorer  →  http://{}", cfg.listen);
    println!("  testnet node: {}", cfg.testnet);
    println!("  mainnet node: {}", cfg.mainnet);

    let cfg = std::sync::Arc::new(cfg);
    for stream in listener.incoming().flatten() {
        let cfg = std::sync::Arc::clone(&cfg);
        thread::spawn(move || { let _ = handle(stream, &cfg); });
    }
}

fn handle(stream: TcpStream, cfg: &Config) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let target = line.split_whitespace().nth(1).unwrap_or("/").to_string();

    let (path, params) = parse_target(&target);
    let net = match params.get("net").map(String::as_str) {
        Some("mainnet") => "mainnet",
        _ => "testnet",
    };
    let node = cfg.node(net);

    let (ctype, body): (&str, String) = if path == "/feed" {
        // Live JSON feed for the home page's client-side poller — this is what
        // makes new blocks/transactions slide in smoothly without a full reload.
        ("application/json", render_feed_json(node, net))
    } else if path == "/search" {
        // A search query is either a block height (a number) or an address.
        let q = params.get("q").map(|q| q.trim().to_string()).unwrap_or_default();
        let html = if let Ok(h) = q.parse::<u64>() {
            render_block(node, h, net)
        } else if Address::parse(&q).is_ok() {
            render_address(node, &q, net)
        } else {
            render_home(node, net)
        };
        ("text/html; charset=utf-8", html)
    } else if let Some(rest) = path.strip_prefix("/address/") {
        ("text/html; charset=utf-8", render_address(node, rest.trim_end_matches('/'), net))
    } else if let Some(rest) = path.strip_prefix("/block/") {
        let html = match rest.trim_end_matches('/').parse::<u64>() {
            Ok(h) => render_block(node, h, net),
            Err(_) => render_home(node, net),
        };
        ("text/html; charset=utf-8", html)
    } else if path == "/faucet" {
        ("text/html; charset=utf-8", render_faucet(node, net, &params))
    } else {
        ("text/html; charset=utf-8", render_home(node, net))
    };

    let mut stream = stream;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
}

fn parse_target(target: &str) -> (String, HashMap<String, String>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            params.insert(k.to_string(), v.to_string());
        }
    }
    (path.to_string(), params)
}

fn fetch_block(node: &str, height: u64) -> Option<Block> {
    let bytes = lat_p2p::get_block(node, height).ok()??;
    Block::decode(&bytes)
}

// --- home page -------------------------------------------------------------

fn render_home(node: &str, net: &str) -> String {
    let height = match lat_p2p::get_height(node) {
        Ok(h) => h,
        Err(_) => return page("Latscan", &node_offline(node, net), net, "", true),
    };

    // Fetch the latest blocks once; reuse for stats, block rows and tx rows.
    let start = height;
    let end = start.saturating_sub(11);
    let mut blocks: Vec<(u64, Block)> = Vec::new();
    for h in (end..=start).rev() {
        if let Some(b) = fetch_block(node, h) {
            blocks.push((h, b));
        }
    }

    let reward = emission(height);
    let avg = avg_block_time(&blocks);
    let net_label = if net == "mainnet" { "Mainnet" } else { "Testnet" };

    let stats = format!(
        "<div class='stats'>
           <div class='scard'><div class='sic'>{IC_BLOCK}</div><div class='sbody'><div class='lab'>Latest block</div><div class='val mono' id='st-h'>#{}</div></div></div>
           <div class='scard'><div class='sic'>{IC_CLOCK}</div><div class='sbody'><div class='lab'>Avg block time</div><div class='val mono' id='st-avg'>{}</div></div></div>
           <div class='scard'><div class='sic'>{IC_COIN}</div><div class='sbody'><div class='lab'>Block reward</div><div class='val mono' id='st-rw'>{} <small>LAT</small></div></div></div>
           <div class='scard'><div class='sic'>{IC_NET}</div><div class='sbody'><div class='lab'>Network</div><div class='val'>{} <span class='live'></span></div></div></div>
         </div>",
        commafy(height),
        avg.map(|s| format!("{s:.1}s")).unwrap_or_else(|| "—".into()),
        fmt_lat(reward),
        net_label,
    );

    // Latest blocks + transactions — the same row markup the /feed poller emits,
    // so freshly-arrived rows match the server-rendered ones exactly.
    let mut brows = String::new();
    for (h, b) in blocks.iter().take(8) {
        brows.push_str(&home_block_row(*h, b, net));
    }
    if brows.is_empty() { brows.push_str("<div class='empty'>No blocks yet.</div>"); }

    let mut trows = String::new();
    let mut count = 0;
    'outer: for (h, b) in &blocks {
        for (i, tx) in b.txs.iter().enumerate() {
            if count >= 8 { break 'outer; }
            trows.push_str(&home_tx_row(tx, *h, i, net));
            count += 1;
        }
    }
    if trows.is_empty() { trows.push_str("<div class='empty'>No transactions yet.</div>"); }

    let latest = format!("/block/{height}?net={net}");
    let script = feed_script(net);
    let body = format!(
        "<div class='hero'><div class='wrap'>
           <span class='kicker'>Latebra {net_label} &middot; live ledger</span>
           <h1>Read the chain.<br><span class='v'>Never the secrets.</span></h1>
           <form class='searchbar' action='/search' method='get'>
             <input name='q' placeholder='Search a block height or address (latt1…)' autocomplete='off'>
             <input type='hidden' name='net' value='{net}'>
             <button type='submit'>Search</button>
           </form>
         </div></div>
         <div class='wrap'>
           {stats}
           <div class='cols'>
             <div class='panel'><div class='ph'>Latest blocks<span class='live'></span></div><div class='feed' id='feed-blocks'>{brows}</div><a class='pf' href='{latest}'>View latest block →</a></div>
             <div class='panel'><div class='ph'>Latest transactions<span class='live'></span></div><div class='feed' id='feed-txs'>{trows}</div><a class='pf' href='{latest}'>View latest block →</a></div>
           </div>
         </div>
         <script>{script}</script>"
    );
    // refresh=false: the client-side poller keeps this page live now, so no crude
    // full-page meta-refresh (which would reset scroll and kill the animations).
    page("Latscan — Latebra explorer", &body, net, &format!("Height {}", commafy(height)), false)
}

// --- block page ------------------------------------------------------------

fn render_block(node: &str, height: u64, net: &str) -> String {
    let block = match fetch_block(node, height) {
        Some(b) => b,
        None => {
            let body = format!(
                "<div class='wrap' style='padding-top:24px'><div class='card'><div class='ph'>Block #{height}</div>
                 <div class='kv'><div class='k'>Status</div><div class='muted'>Not found on this node.</div></div></div>
                 <p><a href='/?net={net}'>← Back to explorer</a></p></div>"
            );
            return page("Block not found", &body, net, "", false);
        }
    };
    let h = &block.header;
    let miner = if h.miner == [0u8; 32] { "— (no reward)".to_string() } else { hex(&h.miner) };
    let details = format!(
        "<div class='card'>
           <div class='ph'>Block <span class='muted'>#{height}</span></div>
           <div class='kv'><div class='k'>Block height</div><div>{height}</div></div>
           <div class='kv'><div class='k'>Timestamp</div><div>{} ago &nbsp;<span class='muted'>({})</span></div></div>
           <div class='kv'><div class='k'>Transactions</div><div>{} in this block</div></div>
           <div class='kv'><div class='k'>Block reward</div><div>{} LAT</div></div>
           <div class='kv'><div class='k'>Mined by</div><div class='hash'>{}</div></div>
           <div class='kv'><div class='k'>Hash</div><div class='hash'>{}</div></div>
           <div class='kv'><div class='k'>Parent hash</div><div class='hash'>{}</div></div>
           <div class='kv'><div class='k'>Tx root</div><div class='hash'>{}</div></div>
           <div class='kv'><div class='k'>State root</div><div class='hash'>{}</div></div>
           <div class='kv'><div class='k'>Nonce</div><div>{}</div></div>
         </div>",
        ago(h.timestamp), h.timestamp, block.txs.len(), fmt_lat(emission(height)),
        miner, hex(&h.id()), hex(&h.prev_hash), hex(&h.tx_root), hex(&h.state_root), h.nonce,
    );

    let mut rows = String::new();
    if block.txs.is_empty() {
        rows.push_str("<tr><td colspan='3' class='muted'>No transactions in this block.</td></tr>");
    }
    for tx in &block.txs {
        rows.push_str(&tx_table_row(tx));
    }

    let prev = if height > 0 {
        format!("<a href='/block/{}?net={net}'>← Prev</a>", height - 1)
    } else {
        "<span class='muted'>← Prev</span>".into()
    };
    let next = format!("<a href='/block/{}?net={net}'>Next →</a>", height + 1);
    let nav = format!("<div class='bnav'>{prev}<span>Block #{height}</span>{next}</div>");

    let body = format!(
        "<div class='wrap' style='padding-top:24px'>
           <p><a href='/?net={net}'>← Explorer</a></p>
           {nav}
           {details}
           <div class='card'><div class='ph'>Transactions</div>
             <table><thead><tr><th>Type</th><th>Detail</th><th>Amount</th></tr></thead><tbody>{rows}</tbody></table>
           </div>
         </div>"
    );
    page(&format!("Block #{height} — Latscan"), &body, net, "", false)
}

// --- address page ------------------------------------------------------------

/// How many recent blocks the address page scans for activity. The explorer is
/// stateless (no index DB), so history is a bounded walk back from the tip —
/// balances above the list are always current regardless of this depth.
const ADDRESS_SCAN_BLOCKS: u64 = 600;

fn render_address(node: &str, raw: &str, net: &str) -> String {
    let addr = match Address::parse(raw.trim()) {
        Ok(a) => a,
        Err(_) => {
            let body = format!(
                "<div class='wrap' style='padding-top:24px'><div class='card'><div class='ph'>Address</div>
                 <div class='kv'><div class='k'>Status</div><div class='muted'>Not a valid Latebra address.</div></div></div>
                 <p><a href='/?net={net}'>← Back to explorer</a></p></div>"
            );
            return page("Address not found — Latscan", &body, net, "", false);
        }
    };
    let id = addr.id();
    let height = match lat_p2p::get_height(node) {
        Ok(h) => h,
        Err(_) => return page("Latscan", &node_offline(node, net), net, "", true),
    };

    let registered = matches!(lat_p2p::get_nonce(node, id), Ok(Some(_)));
    let public = lat_p2p::get_public_balance(node, id, 0).ok().flatten();
    let private_ct = lat_p2p::get_balance(node, id, 0).ok().flatten();
    let pending_ct = lat_p2p::get_pending(node, id, 0).ok().flatten();

    // The dual-state summary: the public balance is plaintext consensus data;
    // the private balance EXISTS on-chain only as a ciphertext — showing its
    // bytes (not its value) is the whole point of the privacy model.
    let enc = |ct: &Option<[u8; 64]>| match ct {
        Some(b) => format!(
            "<span class='tag xfer'>encrypted</span> <span class='muted hash'>{}…</span> — only the key holder can read it",
            b[..8].iter().map(|x| format!("{x:02x}")).collect::<String>()
        ),
        None => "—".to_string(),
    };
    let details = format!(
        "<div class='card'>
           <div class='ph'>Address</div>
           <div class='kv'><div class='k'>Address</div><div class='hash'>{addr_str}</div></div>
           <div class='kv'><div class='k'>Status</div><div>{status}</div></div>
           <div class='kv'><div class='k'>Public balance</div><div>{pub_bal}</div></div>
           <div class='kv'><div class='k'>Private balance</div><div>{priv_bal}</div></div>
           <div class='kv'><div class='k'>Private pending</div><div>{pend_bal}</div></div>
         </div>",
        addr_str = esc(raw.trim()),
        status = if registered { "Registered on-chain" } else { "Not registered (no on-chain account yet)" },
        pub_bal = match public {
            Some(v) => format!("<span class='pill-amt'>{} LAT</span> — visible to everyone", fmt_lat(v)),
            None => "—".to_string(),
        },
        priv_bal = enc(&private_ct),
        pend_bal = enc(&pending_ct),
    );

    // Recent activity: newest-first bounded scan, capped rows.
    let mut rows = String::new();
    let mut found = 0;
    let stop = height.saturating_sub(ADDRESS_SCAN_BLOCKS);
    for h in (stop..=height).rev() {
        if found >= 25 {
            break;
        }
        let Some(b) = fetch_block(node, h) else { continue };
        if b.header.miner == id {
            rows.push_str(&format!(
                "<div class='row'><div class='ic'>{IC_COIN}</div>
                 <div class='mid'><div class='t1'><span class='tag tok'>Coinbase</span></div>
                   <div class='t2'>mined this block · reward {} LAT</div></div>
                 <div class='rt'><a href='/block/{h}?net={net}'>#{h}</a><br><span class='muted'>{} ago</span></div></div>",
                fmt_lat(emission(h)), ago(b.header.timestamp)
            ));
            found += 1;
        }
        for tx in &b.txs {
            if found >= 25 {
                break;
            }
            if tx_involves(tx, &id) {
                rows.push_str(&tx_row(tx, h, net, &b.header.timestamp));
                found += 1;
            }
        }
    }
    if rows.is_empty() {
        rows.push_str(&format!(
            "<div class='row muted'>No activity in the last {ADDRESS_SCAN_BLOCKS} blocks. \
             (Balances above are current; the activity list scans recent history only. \
             Fully private transfers received via stealth never appear here — that's the point.)</div>"
        ));
    }

    let body = format!(
        "<div class='wrap' style='padding-top:24px'>
           <p><a href='/?net={net}'>← Explorer</a></p>
           {details}
           <div class='panel'><div class='ph'>Recent activity <span class='muted'>(last {ADDRESS_SCAN_BLOCKS} blocks)</span></div>{rows}</div>
         </div>"
    );
    page("Address — Latscan", &body, net, "", false)
}

/// Whether `id` appears in one of the transaction's PUBLIC fields. This is
/// exactly what an outside observer can link — confidential transfers still
/// name their parties today (sender/receiver hiding is the Phase-3b milestone),
/// while a stealth shield's one-time key is linkable only if you search the
/// one-time key itself.
fn tx_involves(tx: &Transaction, id: &[u8; 32]) -> bool {
    match tx {
        Transaction::Register { pubkey, .. } => pubkey == id,
        Transaction::CreateToken { creator, .. } => creator == id,
        Transaction::SolventTransfer { xfer, .. } => {
            &xfer.sender.to_bytes() == id || &xfer.receiver.to_bytes() == id
        }
        Transaction::Rollover { account, .. } => account == id,
        Transaction::DeployContract { deployer, .. } => deployer == id,
        Transaction::CallContract { contract, caller, .. } => contract == id || caller == id,
        Transaction::PublicTransfer { from, to, .. } => from == id || to == id,
        Transaction::Shield { from, to, .. } => from == id || to == id,
        Transaction::ShieldStealth { from, one_time, .. } => from == id || one_time == id,
        Transaction::Unshield { to, xfer, .. } => to == id || &xfer.sender.to_bytes() == id,
        // The whole point: no PUBLIC field names the sender or receiver. The
        // ring members are visible (as the anonymity set), but membership is
        // not involvement, so an anonymous transfer never links to an address.
        Transaction::AnonTransfer { .. } => false,
        Transaction::Stake { validator, .. }
        | Transaction::Unstake { validator, .. }
        | Transaction::SlashEvidence { validator, .. } => validator == id,
    }
}

// --- faucet ------------------------------------------------------------------

/// The public TESTNET faucet — the well-known genesis premine wallet that every
/// `latebrad` testnet instance shares. Testnet coins are worthless by design;
/// embedding this seed here is intentional and must never carry to a mainnet.
const FAUCET_SEED: [u8; 32] = [42u8; 32];
/// Paid per request: 100 LAT (5 decimals).
const FAUCET_AMOUNT: u64 = 10_000_000;
/// Per-address wait between payouts.
const ADDRESS_COOLDOWN_SECS: u64 = 60;
/// Faucet-wide spacing: the faucet can spend only once per block (its solvency
/// proof binds its exact balance + nonce), so requests are spaced out.
const GLOBAL_COOLDOWN_SECS: u64 = 10;

/// (per-address last payout, faucet-wide last payout)
fn cooldowns() -> &'static Mutex<(HashMap<String, Instant>, Option<Instant>)> {
    static CD: OnceLock<Mutex<(HashMap<String, Instant>, Option<Instant>)>> = OnceLock::new();
    CD.get_or_init(|| Mutex::new((HashMap::new(), None)))
}

fn render_faucet(node: &str, net: &str, params: &HashMap<String, String>) -> String {
    if net == "mainnet" {
        let body = "<div class='wrap' style='padding-top:24px'><div class='card'><div class='ph'>Faucet</div>
             <div class='kv'><div class='k'>Status</div><div>The faucet is <b>testnet-only</b> — mainnet LAT is never given away.</div></div>
             <div class='kv'><div class='k'>Get testnet LAT</div><div><a href='/faucet?net=testnet'>Switch to the testnet faucet →</a></div></div>
             </div></div>".to_string();
        return page("Faucet — Latscan", &body, net, "", false);
    }

    let result = match params.get("address").map(|a| a.trim()) {
        Some(a) if !a.is_empty() => {
            let (ok, msg) = faucet_send(node, a);
            let cls = if ok { "ok" } else { "err" };
            format!("<div class='fmsg {cls}'>{}</div>", esc(&msg))
        }
        _ => String::new(),
    };

    let body = format!(
        "<div class='hero'><div class='wrap'>
           <span class='kicker'>Testnet &middot; free LAT</span>
           <h1>Fill your <span class='v'>vault.</span></h1>
           <form class='searchbar' action='/faucet' method='get'>
             <input name='address' placeholder='Your testnet address (latt1…)' autocomplete='off'>
             <input type='hidden' name='net' value='{net}'>
             <button type='submit'>Send me {amount} LAT</button>
           </form>
         </div></div>
         <div class='wrap' style='padding-top:20px'>
           {result}
           <div class='card'><div class='ph'>How it works</div>
             <div class='kv'><div class='k'>1 · Paste your address</div><div>Create one in the wallet app — it starts with <code>latt1</code>.</div></div>
             <div class='kv'><div class='k'>2 · Auto-registration</div><div>If your account isn't on-chain yet, the faucet registers it first — request again a few seconds later to get paid.</div></div>
             <div class='kv'><div class='k'>3 · Roll over</div><div>Funds arrive in your <b>pending</b> balance next block. Hit “Roll over” in your wallet to make them spendable.</div></div>
             <div class='kv'><div class='k'>Limits</div><div>{amount} LAT per request · one request per address per minute.</div></div>
           </div>
         </div>",
        amount = FAUCET_AMOUNT / 100_000,
    );
    page("Faucet — Latscan", &body, net, "", false)
}

/// Try to pay `raw` (a testnet address string) from the faucet. Returns
/// `(success, user-facing message)` — never panics on bad input.
fn faucet_send(node: &str, raw: &str) -> (bool, String) {
    let addr = match Address::parse(raw) {
        Ok(a) => a,
        Err(_) => return (false, "That doesn't look like a valid address.".into()),
    };
    if addr.network != Network::Testnet {
        return (false, "The faucet only pays testnet (latt1…) addresses.".into());
    }
    {
        let cd = cooldowns().lock().unwrap_or_else(|p| p.into_inner());
        if let Some(t) = cd.1 {
            if t.elapsed().as_secs() < GLOBAL_COOLDOWN_SECS {
                return (false, "The faucet just paid someone (it can pay once per block) — try again in a few seconds.".into());
            }
        }
        if let Some(t) = cd.0.get(raw) {
            if t.elapsed().as_secs() < ADDRESS_COOLDOWN_SECS {
                return (false, "This address was just funded — try again in a minute.".into());
            }
        }
    }

    let unreachable = || (false, format!("Testnet node unreachable at {node} — is latebrad running?"));
    match lat_p2p::get_nonce(node, addr.id()) {
        Err(_) => unreachable(),
        Ok(None) => {
            // Not on-chain yet: solve the anti-spam PoW and register it for them.
            match lat_p2p::submit_tx(node, &mine_registration(addr.id()).encode()) {
                Ok(true) => (true, "Your account wasn't registered yet, so the faucet submitted a registration. It mines in a few seconds — then request again to receive LAT.".into()),
                Ok(false) => (false, "A registration for this address is already pending — wait a few seconds, then request again.".into()),
                Err(_) => unreachable(),
            }
        }
        Ok(Some(_)) => {
            let faucet = Wallet::from_seed(Network::Testnet, FAUCET_SEED);
            let bal = match lat_p2p::get_balance(node, faucet.id(), 0) {
                Ok(Some(b)) => b,
                Ok(None) => return (false, "The faucet account isn't on this chain (wrong genesis?).".into()),
                Err(_) => return unreachable(),
            };
            let ct = match lat_crypto::Ciphertext::from_bytes(&bal) {
                Some(c) => c,
                None => return (false, "The faucet balance is unreadable.".into()),
            };
            let nonce = match lat_p2p::get_nonce(node, faucet.id()) {
                Ok(Some(n)) => n,
                _ => return unreachable(),
            };
            let tx = match faucet.build_transfer(&addr, 0, FAUCET_AMOUNT, MIN_TRANSFER_FEE, &ct, nonce, &mut OsRng) {
                Some(t) => t,
                None => return (false, "The faucet can't pay right now (balance in flux or empty) — try again shortly.".into()),
            };
            match lat_p2p::submit_tx(node, &tx.encode()) {
                Ok(true) => {
                    let mut cd = cooldowns().lock().unwrap_or_else(|p| p.into_inner());
                    cd.0.insert(raw.to_string(), Instant::now());
                    cd.1 = Some(Instant::now());
                    (true, format!(
                        "Sent {} LAT to {raw}. It lands in your PENDING balance when the next block mines — hit “Roll over” in your wallet to make it spendable.",
                        FAUCET_AMOUNT / 100_000
                    ))
                }
                Ok(false) => (false, "The node rejected the transfer (possibly a duplicate) — try again shortly.".into()),
                Err(_) => unreachable(),
            }
        }
    }
}

/// Minimal HTML escaping for user-echoed strings.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

// --- transaction rendering -------------------------------------------------

fn tag(tx: &Transaction) -> (&'static str, &'static str) {
    match tx {
        Transaction::Register { .. } => ("reg", "Register"),
        Transaction::CreateToken { .. } => ("tok", "Create Token"),
        Transaction::SolventTransfer { .. } => ("xfer", "Transfer"),
        Transaction::Rollover { .. } => ("roll", "Rollover"),
        Transaction::DeployContract { .. } => ("ct", "Deploy Contract"),
        Transaction::CallContract { .. } => ("ct", "Call Contract"),
        Transaction::PublicTransfer { .. } => ("xfer", "Public Transfer"),
        Transaction::Shield { .. } => ("xfer", "Shield"),
        Transaction::ShieldStealth { .. } => ("xfer", "Stealth Shield"),
        Transaction::Unshield { .. } => ("xfer", "Unshield"),
        Transaction::AnonTransfer { .. } => ("xfer", "Anonymous Transfer"),
        Transaction::Stake { .. } => ("stake", "Stake"),
        Transaction::Unstake { .. } => ("stake", "Unstake"),
        Transaction::SlashEvidence { .. } => ("stake", "Slash"),
    }
}

fn tx_detail(tx: &Transaction) -> (String, String) {
    match tx {
        Transaction::Register { pubkey, .. } => (short(pubkey), "—".to_string()),
        Transaction::CreateToken { ticker, supply, .. } => (format!("${ticker}"), format!("supply {}", commafy(*supply))),
        Transaction::SolventTransfer { token, xfer } => (
            format!("{} → {}", short(&xfer.sender.to_bytes()), short(&xfer.receiver.to_bytes())),
            format!("<span class='pill-amt'>confidential</span> · token {token}"),
        ),
        Transaction::Rollover { account, .. } => (short(account), "—".to_string()),
        Transaction::DeployContract { deployer, code, .. } => (format!("by {}", short(deployer)), format!("{} bytes", code.len())),
        Transaction::CallContract { contract, input, .. } => (short(contract), format!("input {input}")),
        // Public transfer: sender, receiver, and amount are all shown in the
        // clear — the transparent half of the dual-state model.
        Transaction::PublicTransfer { token, from, to, amount, .. } => (
            format!("{} → {}", short(from), short(to)),
            format!("<span class='pill-amt'>{}</span> · token {token}", commafy(*amount)),
        ),
        // Shield: public → private. Amount is public (it leaves the public ledger).
        Transaction::Shield { token, from, to, amount, .. } => (
            format!("{} → {} (private)", short(from), short(to)),
            format!("<span class='pill-amt'>{}</span> shield · token {token}", commafy(*amount)),
        ),
        // Unshield: private → public. Origin is revealed; amount re-enters public.
        Transaction::Unshield { token, to, amount, xfer, .. } => (
            format!("{} (private) → {}", short(&xfer.sender.to_bytes()), short(to)),
            format!("<span class='pill-amt'>{}</span> unshield · token {token}", commafy(*amount)),
        ),
        // Stealth shield: public → private, recipient hidden (a one-time address).
        Transaction::ShieldStealth { token, from, amount, .. } => (
            format!("{} → (stealth)", short(from)),
            format!("<span class='pill-amt'>{}</span> shield · token {token}", commafy(*amount)),
        ),
        // Anonymous transfer: sender hidden in a ring, receiver behind a
        // one-time stealth key, amount hidden behind a commitment (v3).
        Transaction::AnonTransfer { token, xfer } => (
            format!("(ring of {}) → (stealth)", xfer.ring.len()),
            format!("<span class='pill-amt'>hidden</span> anonymous · token {token}"),
        ),
        // Staking (T13): bond / begin unbonding validator stake, in the clear.
        Transaction::Stake { validator, amount, .. } => (
            format!("{} bonds", short(validator)),
            format!("<span class='pill-amt'>{}</span> stake", commafy(*amount)),
        ),
        Transaction::Unstake { validator, amount, .. } => (
            format!("{} unbonds", short(validator)),
            format!("<span class='pill-amt'>{}</span> unstake", commafy(*amount)),
        ),
        Transaction::SlashEvidence { validator, height, .. } => (
            format!("{} slashed", short(validator)),
            format!("equivocation at height {height} — stake burned"),
        ),
    }
}

fn tx_row(tx: &Transaction, height: u64, net: &str, ts: &u64) -> String {
    let (cls, label) = tag(tx);
    let (detail, _amount) = tx_detail(tx);
    format!(
        "<div class='row'>
           <div class='ic'>{IC_TX}</div>
           <div class='mid'><div class='t1'><span class='tag {cls}'>{label}</span></div>
             <div class='t2 hash'>{detail}</div></div>
           <div class='rt'><a href='/block/{height}?net={net}'>#{height}</a><br><span class='muted'>{} ago</span></div>
         </div>",
        ago(*ts)
    )
}

fn tx_table_row(tx: &Transaction) -> String {
    let (cls, label) = tag(tx);
    let (detail, amount) = tx_detail(tx);
    format!("<tr><td><span class='tag {cls}'>{label}</span></td><td class='hash'>{detail}</td><td>{amount}</td></tr>")
}

fn node_offline(node: &str, net: &str) -> String {
    format!(
        "<div class='wrap' style='padding-top:32px'><div class='card'><div class='ph'>{net} node unreachable</div>
         <div class='kv'><div class='k'>Node</div><div class='hash'>{node}</div></div>
         <div class='kv'><div class='k'>Fix</div><div>Start it with <code>latebrad --mine --listen {node}</code>, or switch network above.</div></div>
         </div></div>"
    )
}

// --- page scaffold ---------------------------------------------------------

fn page(title: &str, body: &str, net: &str, status: &str, refresh: bool) -> String {
    let meta_refresh = if refresh { "<meta http-equiv='refresh' content='8'>" } else { "" };
    let pill = |n: &str, label: &str| {
        let active = if n == net { " active" } else { "" };
        format!("<a class='pill{active}' href='/?net={n}'>{label}</a>")
    };
    let net_label = if net == "mainnet" { "Mainnet" } else { "Testnet" };
    format!(
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>
         <meta name='viewport' content='width=device-width, initial-scale=1'>
         <link rel='icon' href=\"{logo}\">
         {meta_refresh}<title>{title}</title><style>{css}</style></head><body>
         <div class='strip'><div class='wrap'>
           <span>Latebra Blockchain Explorer</span>
           <span>{status}{}<b class='netbadge'>{net_label}</b></span>
         </div></div>
         <div class='hdr'><div class='wrap'>
           <a class='brand' href='/?net={net}'><img class='brandlogo' src=\"{logo}\" alt=''>Latscan <em>lat1&hellip;</em></a>
           <nav class='nav'>
             <a href='/?net={net}'>Home</a>
             <a href='/faucet?net={net}'>Faucet</a>
             {}{}
           </nav>
         </div></div>
         <div class='marq'><div>&nbsp;&nbsp;<b>LATEBRA EXPLORER</b> <i>//</i> LIVE CHAIN STATE <i>//</i> SHIELDED BY DEFAULT <i>//</i> lat1&hellip; <i>//</i> AMOUNTS ENCRYPTED <i>//</i> PROOF, NOT EXPOSURE <i>//</i> &nbsp;&nbsp;<b>LATEBRA EXPLORER</b> <i>//</i> LIVE CHAIN STATE <i>//</i> SHIELDED BY DEFAULT <i>//</i> lat1&hellip; <i>//</i> AMOUNTS ENCRYPTED <i>//</i> PROOF, NOT EXPOSURE <i>//</i> &nbsp;&nbsp;</div></div>
         {body}
         <footer><div class='wrap cols2'>
           <div><b>Latscan</b> — the Latebra block explorer.<br>Public where it can be, <i>encrypted where it counts.</i></div>
           <div class='muted'>lat1&hellip; · balances &amp; amounts stay shielded on-chain · powered by latebrad</div>
         </div></footer>
         </body></html>",
        if status.is_empty() { "" } else { " · " },
        pill("mainnet", "Mainnet"),
        pill("testnet", "Testnet"),
        css = css(),
        logo = LOGO,
    )
}

// --- live home feed (client-polled for smooth new-row motion) ---------------

/// JSON payload the home page's poller fetches every few seconds: the current
/// height/avg/reward, plus the newest block and transaction rows (same markup as
/// the server-rendered ones, each carrying a `data-k` so the client only
/// animates in rows it hasn't seen).
fn render_feed_json(node: &str, net: &str) -> String {
    let height = match lat_p2p::get_height(node) {
        Ok(h) => h,
        Err(_) => return "{\"height\":0,\"blocks\":[],\"txs\":[]}".to_string(),
    };
    let end = height.saturating_sub(11);
    let mut blocks: Vec<(u64, Block)> = Vec::new();
    for h in (end..=height).rev() {
        if let Some(b) = fetch_block(node, h) {
            blocks.push((h, b));
        }
    }
    let avg = avg_block_time(&blocks).map(|s| format!("{s:.1}s")).unwrap_or_else(|| "—".into());
    let reward = fmt_lat(emission(height));
    let mut brows: Vec<String> = Vec::new();
    for (h, b) in blocks.iter().take(8) {
        brows.push(json_string(&home_block_row(*h, b, net)));
    }
    let mut trows: Vec<String> = Vec::new();
    'outer: for (h, b) in &blocks {
        for (i, tx) in b.txs.iter().enumerate() {
            if trows.len() >= 8 {
                break 'outer;
            }
            trows.push(json_string(&home_tx_row(tx, *h, i, net)));
        }
    }
    format!(
        "{{\"height\":{height},\"avg\":\"{avg}\",\"reward\":\"{reward}\",\"blocks\":[{}],\"txs\":[{}]}}",
        brows.join(","),
        trows.join(",")
    )
}

/// One block row for the home feed. Single-line (so it embeds cleanly in JSON)
/// and keyed by height so the poller can dedupe.
fn home_block_row(h: u64, b: &Block, net: &str) -> String {
    let miner = if b.header.miner == [0u8; 32] { "—".to_string() } else { short(&b.header.miner) };
    format!(
        "<div class='brow' data-k='{h}'><span class='bic'>{IC_BLOCK}</span><div class='bmid'><div class='bh'><a href='/block/{h}?net={net}'>#{h}</a></div><div class='bt'>{} ago</div></div><div class='brt'><span class='txns'>{} txns</span><div class='bm mono'>{}</div></div></div>",
        ago(b.header.timestamp),
        b.txs.len(),
        miner
    )
}

/// One transaction row for the home feed: a method badge, the public route, and
/// an honest amount (confidential/anonymous transfers read as such — the whole
/// point of the chain). Keyed by `height-index` for dedup.
fn home_tx_row(tx: &Transaction, h: u64, idx: usize, net: &str) -> String {
    let (cls, label) = feed_badge(tx);
    let route = tx_detail(tx).0;
    let amount = feed_amount(tx);
    format!(
        "<div class='trow' data-k='{h}-{idx}'><span class='badge {cls}'>{label}</span><div class='tmid'><div class='troute mono'><a href='/block/{h}?net={net}'>{route}</a></div></div>{amount}</div>"
    )
}

/// Method badge (colour class + short label) for the home feed. Colour splits
/// the dual-state model at a glance: blue = transparent, violet = confidential.
fn feed_badge(tx: &Transaction) -> (&'static str, &'static str) {
    match tx {
        Transaction::Register { .. } => ("b-reg", "Register"),
        Transaction::Rollover { .. } => ("b-reg", "Rollover"),
        Transaction::CreateToken { .. } => ("b-tk", "Token"),
        Transaction::SolventTransfer { .. } => ("b-prv", "Private"),
        Transaction::Shield { .. } => ("b-prv", "Shield"),
        Transaction::ShieldStealth { .. } => ("b-prv", "Shield"),
        Transaction::AnonTransfer { .. } => ("b-prv", "Anon"),
        Transaction::PublicTransfer { .. } => ("b-pub", "Public"),
        Transaction::Unshield { .. } => ("b-pub", "Unshield"),
        Transaction::DeployContract { .. } => ("b-ct", "Deploy"),
        Transaction::CallContract { .. } => ("b-ct", "Call"),
        Transaction::Stake { .. } => ("b-pub", "Stake"),
        Transaction::Unstake { .. } => ("b-pub", "Unstake"),
        Transaction::SlashEvidence { .. } => ("b-reg", "Slash"),
    }
}

/// The right-hand amount cell for the home feed — visible amounts in LAT, but
/// confidential/anonymous transfers reveal nothing (that is the feature).
fn feed_amount(tx: &Transaction) -> String {
    match tx {
        Transaction::PublicTransfer { amount, .. } | Transaction::Unshield { amount, .. } => {
            format!("<span class='tamt pos'>{} LAT</span>", fmt_lat(*amount))
        }
        Transaction::Shield { amount, .. } | Transaction::ShieldStealth { amount, .. } => {
            format!("<span class='tamt'>{} LAT</span>", fmt_lat(*amount))
        }
        Transaction::SolventTransfer { .. } => "<span class='enc'>encrypted</span>".to_string(),
        Transaction::AnonTransfer { .. } => "<span class='enc'>anonymous</span>".to_string(),
        Transaction::CreateToken { supply, .. } => format!("<span class='tamt'>{}</span>", commafy(*supply)),
        Transaction::DeployContract { code, .. } => format!("<span class='tamt muted'>{} B</span>", code.len()),
        Transaction::CallContract { .. } => "<span class='tamt muted'>call</span>".to_string(),
        Transaction::Register { .. } | Transaction::Rollover { .. } => "<span class='tamt muted'>—</span>".to_string(),
        Transaction::Stake { amount, .. } | Transaction::Unstake { amount, .. } => {
            format!("<span class='tamt'>{} LAT</span>", fmt_lat(*amount))
        }
        Transaction::SlashEvidence { .. } => "<span class='tamt muted'>slashed</span>".to_string(),
    }
}

/// The home page's live poller: fetch `/feed` every few seconds, animate in the
/// block/tx rows it hasn't shown yet, and tick the stat cards. `__NET__` is
/// substituted (net is a fixed literal, so no escaping needed).
fn feed_script(net: &str) -> String {
    let js = r#"(function(){
  var net='__NET__';
  var h=document.getElementById('st-h'),av=document.getElementById('st-avg'),rw=document.getElementById('st-rw');
  var bf=document.getElementById('feed-blocks'),tf=document.getElementById('feed-txs');
  if(!bf||!tf)return;
  var reduce=window.matchMedia&&matchMedia('(prefers-reduced-motion:reduce)').matches;
  function merge(feed,rows){
    var have={};for(var i=0;i<feed.children.length;i++){have[feed.children[i].getAttribute('data-k')]=1;}
    for(var j=rows.length-1;j>=0;j--){
      var t=document.createElement('div');t.innerHTML=rows[j];
      var el=t.firstElementChild;if(!el)continue;
      var k=el.getAttribute('data-k');if(have[k])continue;
      el.className+=' fresh';feed.insertBefore(el,feed.firstChild);have[k]=1;
    }
    while(feed.children.length>8){feed.removeChild(feed.lastChild);}
  }
  function poll(){
    fetch('/feed?net='+net).then(function(r){return r.json();}).then(function(d){
      if(d.height&&h){h.textContent='#'+Number(d.height).toLocaleString();}
      if(d.avg&&av){av.textContent=d.avg;}
      if(d.reward&&rw){rw.innerHTML=d.reward+' <small>LAT</small>';}
      merge(bf,d.blocks||[]);merge(tf,d.txs||[]);
    }).catch(function(){});
  }
  if(!reduce){setInterval(poll,3000);}
})();"#;
    js.replace("__NET__", net)
}

/// Escape a string as a JSON string literal (quotes included). Used to embed
/// server-rendered row HTML in the `/feed` payload.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn css() -> &'static str {
    // "Cipher Vault" theme matched to the Latebra site: deep slate canvas,
    // Satoshi display + JetBrains Mono for all data, one violet accent,
    // blue/violet to split transparent vs confidential. Braces are literal
    // (this is a value substituted into page()'s format!, not a format string).
    r#"@import url('https://api.fontshare.com/v2/css?f[]=satoshi@400,500,700,900&display=swap');@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap');
:root{--bg:#0f172a;--el:#1e1b4b;--el2:#262157;--ln:rgba(148,163,184,.16);--ln2:rgba(139,92,246,.4);--tx:#ffffff;--mut:#94a3b8;--am:#8b5cf6;--am2:#a78bfa;--gr:#34d399;--bl:#4c9bf5;--vi:#a78bfa;--rd:#f87171}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(900px 420px at 50% -12%,rgba(139,92,246,.14) 0,#0f172a 62%),var(--bg);color:var(--tx);font:14px/1.55 'Satoshi',system-ui,-apple-system,Segoe UI,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--am);text-decoration:none}a:hover{color:var(--am2)}
.wrap{max-width:1160px;margin:0 auto;padding:0 18px}
.mono{font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace;font-variant-numeric:tabular-nums}
.muted{color:var(--mut)}
.strip{border-bottom:1px solid var(--ln);font-size:12px;color:var(--mut)}
.strip .wrap{display:flex;justify-content:space-between;align-items:center;height:34px}
.netbadge{color:var(--am);margin-left:6px}
.hdr{background:rgba(8,8,10,.72);backdrop-filter:blur(12px);border-bottom:1px solid var(--ln);position:sticky;top:0;z-index:10}
.hdr .wrap{display:flex;align-items:center;height:60px;gap:14px}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:17px;color:var(--tx);letter-spacing:-.01em}
.brand:hover{color:var(--tx)}
.brandlogo{width:26px;height:26px;border-radius:7px;display:block}
.nav{display:flex;gap:6px;margin-left:auto;align-items:center;font-weight:500}
.nav a{color:var(--mut);padding:7px 11px;border-radius:9px}
.nav a:hover{color:var(--tx);background:var(--el)}
.pill{padding:6px 13px;border-radius:9px;font-size:12.5px;font-weight:600;color:var(--mut);border:1px solid var(--ln)}
.pill:hover{color:var(--tx)}
.pill.active{background:var(--am);color:#fff;border-color:transparent}
.hero{padding:34px 0 26px;border-bottom:1px solid var(--ln)}
.hero h1{font-size:26px;margin:0 0 16px;font-weight:600;letter-spacing:-.02em}
.searchbar{display:flex;max-width:760px;background:var(--el);border:1px solid var(--ln);border-radius:13px;overflow:hidden;transition:border-color .18s}
.searchbar:focus-within{border-color:var(--ln2)}
.searchbar input{flex:1;border:0;padding:14px 16px;font-size:14px;outline:none;background:transparent;color:var(--tx);font-family:inherit}
.searchbar input::placeholder{color:var(--mut)}
.searchbar button{border:0;background:var(--am);color:#fff;padding:0 24px;font-weight:600;font-family:inherit;font-size:14px;cursor:pointer;transition:background .18s}
.searchbar button:hover{background:var(--am2)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:22px 0}
.scard{background:var(--el);border:1px solid var(--ln);border-radius:14px;padding:15px 16px;display:flex;gap:12px;align-items:center;animation:rise .5s cubic-bezier(.2,.8,.2,1) both}
.scard:nth-child(2){animation-delay:.06s}.scard:nth-child(3){animation-delay:.12s}.scard:nth-child(4){animation-delay:.18s}
.sic{width:40px;height:40px;border-radius:11px;background:rgba(139,92,246,.14);color:var(--am);display:flex;align-items:center;justify-content:center;flex:none}
.sic svg{width:20px;height:20px}
.lab{font-size:10.5px;text-transform:uppercase;letter-spacing:.12em;color:var(--mut);font-weight:500}
.val{font-size:20px;font-weight:600;margin-top:4px;letter-spacing:-.01em}
.val small{font-size:12px;color:var(--mut);font-weight:500}
.live{width:7px;height:7px;border-radius:50%;background:var(--gr);display:inline-block;vertical-align:middle;box-shadow:0 0 0 0 rgba(53,208,127,.6);animation:beat 2.2s infinite}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:30px}
.panel,.card{background:var(--el);border:1px solid var(--ln);border-radius:16px;overflow:hidden;animation:rise .5s cubic-bezier(.2,.8,.2,1) both}
.cols .panel:nth-child(2){animation-delay:.08s}
.card{margin-bottom:18px}
.panel .ph,.card .ph{display:flex;align-items:center;gap:9px;padding:15px 17px;border-bottom:1px solid var(--ln);font-weight:600;font-size:14.5px}
.panel .ph .live{margin-left:auto}
.feed{padding:5px 8px}
.brow,.trow{display:flex;align-items:center;gap:11px;padding:11px 9px;border-radius:11px}
.brow+.brow,.trow+.trow{border-top:1px solid var(--ln)}
.brow:hover,.trow:hover{background:var(--el2)}
.fresh{animation:slidein .55s cubic-bezier(.2,.8,.2,1),flash 1.6s ease}
.bic{width:34px;height:34px;border-radius:9px;flex:none;display:flex;align-items:center;justify-content:center;background:#262157;color:var(--mut)}
.bic svg{width:17px;height:17px}
.bmid{flex:1;min-width:0}
.bh{font-size:14px;font-weight:600}
.bt{font-size:11.5px;color:var(--mut);margin-top:2px}
.brt{text-align:right;font-size:12px;white-space:nowrap}
.txns{color:var(--tx);font-weight:500}
.bm{font-size:11px;color:var(--mut);margin-top:3px}
.badge{font-size:10.5px;font-weight:600;padding:5px 8px;border-radius:7px;flex:none;min-width:62px;text-align:center}
.b-pub{color:var(--bl);background:rgba(76,155,245,.13)}
.b-prv{color:var(--vi);background:rgba(185,140,246,.14)}
.b-tk{color:var(--am);background:rgba(139,92,246,.14)}
.b-reg{color:var(--mut);background:rgba(255,255,255,.06)}
.b-ct{color:#5dd6c0;background:rgba(93,214,192,.13)}
.tmid{flex:1;min-width:0}
.troute{font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.troute a{color:#cbd5e1}.troute a:hover{color:var(--am)}
.tamt{margin-left:auto;text-align:right;font-size:12.5px;font-weight:600;flex:none;font-family:'JetBrains Mono',monospace;font-variant-numeric:tabular-nums;white-space:nowrap}
.tamt.pos{color:var(--gr)}
.enc{margin-left:auto;font-size:11.5px;font-weight:500;color:var(--vi);white-space:nowrap;flex:none}
.pf{display:block;padding:13px 17px;text-align:center;font-weight:600;border-top:1px solid var(--ln);color:var(--am)}
.pf:hover{background:var(--el2)}
.empty{padding:22px 14px;color:var(--mut);text-align:center;font-size:13px}
.kv{display:grid;grid-template-columns:200px 1fr;gap:10px;padding:13px 18px;border-bottom:1px solid var(--ln);font-size:13.5px}
.kv:last-child{border-bottom:none}.kv .k{color:var(--mut)}
.bnav{display:flex;justify-content:space-between;align-items:center;background:var(--el);border:1px solid var(--ln);border-radius:12px;padding:11px 16px;margin-bottom:16px;font-weight:600}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:12px 18px;border-bottom:1px solid var(--ln);font-size:13.5px}
th{color:var(--mut);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.08em}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--el2)}
.hash{font-family:'JetBrains Mono',ui-monospace,Menlo,monospace;color:#cbd5e1;word-break:break-all}
.row{display:flex;align-items:center;gap:12px;padding:13px 17px;border-bottom:1px solid var(--ln)}
.row:last-of-type{border-bottom:none}
.row:hover{background:var(--el2)}
.row .ic{width:36px;height:36px;border-radius:10px;background:#262157;color:var(--mut);display:flex;align-items:center;justify-content:center;flex:none}
.row .ic svg{width:18px;height:18px}
.row .mid{flex:1;min-width:0;overflow:hidden}
.row .t1{font-weight:600}
.row .t2{font-size:12.5px;color:var(--mut);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.row .rt{text-align:right;font-size:12.5px;color:var(--mut);white-space:nowrap}
.tag{display:inline-block;padding:3px 9px;border-radius:7px;font-size:11.5px;font-weight:600;background:rgba(255,255,255,.05);color:var(--mut)}
.tag.xfer{background:rgba(185,140,246,.14);color:var(--vi)}
.tag.tok{background:rgba(139,92,246,.14);color:var(--am)}
.tag.reg{background:rgba(76,155,245,.13);color:var(--bl)}
.tag.roll{background:rgba(255,255,255,.06);color:var(--mut)}
.tag.ct{background:rgba(93,214,192,.13);color:#5dd6c0}
.pill-amt{background:rgba(139,92,246,.14);color:var(--am);border-radius:6px;padding:1px 8px;font-size:12px;font-weight:600}
code{background:var(--el2);padding:2px 6px;border-radius:6px;font-size:13px;color:var(--am2);font-family:'JetBrains Mono',monospace}
.fmsg{border-radius:12px;padding:13px 16px;margin-bottom:18px;font-weight:500;border:1px solid}
.fmsg.ok{background:rgba(53,208,127,.1);color:var(--gr);border-color:rgba(53,208,127,.3)}
.fmsg.err{background:rgba(255,93,108,.1);color:#ff97a1;border-color:rgba(255,93,108,.3)}
footer{border-top:1px solid var(--ln);margin-top:26px;padding:26px 0;color:var(--mut);font-size:13px}
footer .cols2{display:flex;justify-content:space-between;flex-wrap:wrap;gap:20px}footer b{color:var(--tx)}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes slidein{from{opacity:0;transform:translateY(-14px)}to{opacity:1;transform:none}}
@keyframes flash{0%{background:rgba(139,92,246,.18)}100%{background:transparent}}
@keyframes beat{0%,100%{box-shadow:0 0 0 0 rgba(53,208,127,.55)}50%{box-shadow:0 0 0 5px rgba(53,208,127,0)}}
@media(max-width:820px){.stats{grid-template-columns:repeat(2,1fr)}.cols{grid-template-columns:1fr}}
@media(prefers-reduced-motion:reduce){.scard,.panel,.fresh,.live,.marq>div{animation:none}}
/* ---- site-match overrides: bring Latscan up to the marketing site's visual language ---- */
:root{--sans:'Satoshi',ui-sans-serif,system-ui,sans-serif;--mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace;--vln:rgba(139,92,246,.22)}
body{background:radial-gradient(1100px 520px at 74% -12%,rgba(30,27,75,.85) 0,rgba(15,23,42,0) 58%),var(--bg);font-family:var(--sans)}
::selection{background:var(--am);color:#0f172a}
.kicker{font-family:var(--mono);font-size:11px;letter-spacing:.3em;color:var(--am);text-transform:uppercase;display:block;margin-bottom:18px}
.strip{font-family:var(--mono);letter-spacing:.14em;text-transform:uppercase;background:rgba(15,23,42,.55)}
.marq{overflow:hidden;border-bottom:1px solid var(--ln);background:rgba(30,27,75,.26)}
.marq>div{display:inline-block;white-space:nowrap;padding:9px 0;font-family:var(--mono);font-size:11px;letter-spacing:.26em;color:var(--mut);text-transform:uppercase;animation:marq 36s linear infinite}
.marq b{color:var(--am);font-weight:600}
.marq i{color:var(--am);font-style:normal;opacity:.55;margin:0 4px}
@keyframes marq{from{transform:translateX(0)}to{transform:translateX(-50%)}}
.hdr{background:rgba(15,23,42,.72)}.hdr .wrap{height:64px}
.brand{font-weight:900;letter-spacing:.26em;text-transform:uppercase;font-size:15px;gap:11px}
.brand em{font-style:normal;font-family:var(--mono);font-size:10px;letter-spacing:.12em;color:var(--am);text-transform:none;margin-left:3px}
.brandlogo{width:28px;height:28px}
.nav{gap:clamp(12px,2vw,26px)}
.nav a:not(.pill){position:relative;color:var(--mut);font-family:var(--mono);font-size:11px;letter-spacing:.18em;text-transform:uppercase;padding:4px 0;border-radius:0}
.nav a:not(.pill):hover{color:var(--tx);background:none}
.nav a:not(.pill)::after{content:'';position:absolute;left:0;bottom:-3px;height:1px;width:100%;background:var(--am);transform:scaleX(0);transform-origin:right;transition:transform .35s cubic-bezier(.77,0,.18,1)}
.nav a:not(.pill):hover::after{transform:scaleX(1);transform-origin:left}
.pill{border-radius:999px;font-family:var(--mono);font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;border-color:var(--vln)}
.pill.active{background:var(--am);color:#0f172a}
.hero{background:radial-gradient(120% 130% at 80% -30%,rgba(30,27,75,.8) 0,rgba(15,23,42,0) 55%);padding:clamp(38px,6vw,78px) 0 clamp(28px,4vw,40px)}
.hero h1{font-size:clamp(30px,5vw,58px);line-height:1.03;font-weight:900;letter-spacing:-.025em;max-width:15ch;margin:0 0 26px}
.hero h1 .v{color:var(--am)}
.searchbar{background:rgba(26,23,64,.7);border-color:var(--vln);border-radius:14px}
.searchbar input{font-family:var(--mono)}
.searchbar button{background:var(--am);color:#0f172a;font-weight:700;letter-spacing:.04em;font-family:var(--sans)}
.searchbar button:hover{background:var(--am2)}
.scard,.panel,.card{background:rgba(26,23,64,.5);border-radius:16px}
.sic{border-radius:12px}
.lab{font-family:var(--mono);letter-spacing:.18em}
.val{font-weight:800}
.panel .ph,.card .ph{font-family:var(--mono);font-size:12px;letter-spacing:.15em;text-transform:uppercase;color:#cbd5e1}
.panel .ph .muted{text-transform:none;letter-spacing:0;font-family:var(--sans)}
.badge{font-family:var(--mono);font-size:9.5px;letter-spacing:.08em;text-transform:uppercase}
.bh,.txns,.tamt,.troute,.hash,.bm,.row .rt{font-family:var(--mono)}
.tag{font-family:var(--mono);font-size:10px;letter-spacing:.06em;text-transform:uppercase}
.tag.stake{background:rgba(52,211,153,.13);color:var(--gr)}
.enc{font-family:var(--mono);text-transform:uppercase;letter-spacing:.06em}
.pf{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase}
.kv .k{font-family:var(--mono);font-size:12px}
.pill-amt{font-family:var(--mono);color:var(--am2)}
footer i{font-style:italic;color:var(--am2)}"#
}

// --- helpers ---------------------------------------------------------------

fn avg_block_time(blocks: &[(u64, Block)]) -> Option<f64> {
    // Exclude the genesis block: its timestamp is a fixed constant far in the past
    // and would swamp the average. Use only mined blocks (height > 0), newest-first.
    let mined: Vec<u64> = blocks.iter().filter(|(h, _)| *h > 0).map(|(_, b)| b.header.timestamp).collect();
    if mined.len() < 2 {
        return None;
    }
    let span = mined.first()?.checked_sub(*mined.last()?)? as f64;
    if span == 0.0 {
        return None;
    }
    Some(span / (mined.len() - 1) as f64)
}

fn fmt_lat(units: u64) -> String {
    format!("{}.{:05}", commafy(units / 100_000), units % 100_000)
}

fn commafy(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut out = String::new();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn short(bytes: &[u8]) -> String {
    let h = hex(bytes);
    if h.len() > 16 { format!("{}…{}", &h[..10], &h[h.len() - 8..]) } else { h }
}

fn ago(ts: u64) -> String {
    if ts == 0 {
        return "—".to_string();
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(ts);
    let secs = now.saturating_sub(ts);
    if secs < 60 { format!("{secs} secs") } else if secs < 3600 { format!("{} mins", secs / 60) } else { format!("{} hrs", secs / 3600) }
}

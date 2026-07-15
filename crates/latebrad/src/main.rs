//! `latebrad` — the Latebra node daemon.
//!
//! Ties together everything: a persistent chain, TCP networking (peer sync +
//! gossip + RPC), and a mempool. Run one node mining and point others at it to
//! form a testnet.
//!
//! ```text
//! latebrad --mine --data ./node-a/chain.db --listen 127.0.0.1:4040
//! latebrad         --data ./node-b/chain.db --listen 127.0.0.1:4041 --peer 127.0.0.1:4040
//! ```
//!
//! Flags:
//!   --data <path>        chain database file (redb; default: latebra-data/chain.db)
//!   --listen <addr>      address to serve peers + RPC on (default: 127.0.0.1:4040)
//!   --peer <addr>        a seed peer to sync from / gossip to (repeatable)
//!   --public-addr <addr> the address OTHER nodes can reach us on — advertised
//!                        via peer exchange (default: the --listen address).
//!                        For internet nodes: listen on 0.0.0.0:4040, then set
//!                        --public-addr your.host.or.ip:4040 (port-forwarded).
//!   --mine               mine blocks on an interval
//!   --mine-blocks <n>    mine exactly n blocks, then exit (for demos/tests)
//!
//! Networking: on contact, nodes **handshake** — comparing protocol version and
//! genesis id — so only same-network peers are kept (a wrong-chain node is
//! dropped, never synced). They then exchange peer addresses (one seed is enough
//! to discover the rest), re-gossip new blocks (topology needn't be fully
//! connected), and sync via block locators — two nodes that mined apart reconcile
//! onto the heavier chain. The known-peer set is **persisted** to `peers.txt`
//! beside the block log, so a restarted node rejoins without `--peer`;
//! unreachable peers are evicted after repeated failures. Multiple miners are
//! supported by fork-choice.

use std::env;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use lat_chain::{emission, Blockchain, DEFAULT_DIFFICULTY};
use lat_p2p::{lock_node, serve, sync_shared, NodeState, SharedNode};
use lat_types::Network;
use lat_wallet::Wallet;

/// Fixed testnet genesis so every `latebrad` instance derives the SAME genesis
/// block and can sync with the others. The premine goes to a well-known testnet
/// wallet (seed below). Testnet only — a real launch sets its own genesis.
const GENESIS_SEED: [u8; 32] = [42u8; 32];
// Mining rewards go to a SEPARATE account, not genesis. If the sender of a transfer
// is also earning block rewards, its balance changes every block and breaks the
// solvency proof's balance snapshot — so the faucet (genesis) must stay stable.
const MINER_SEED: [u8; 32] = [43u8; 32];
// 1,000,000 LAT (5 decimals). Within the wallet's balance-decrypt range.
const GENESIS_PREMINE: u64 = 100_000_000_000;
// A transparent PUBLIC premine to the same genesis wallet, so the network has
// spendable plaintext LAT for Public->Public transfers from genesis. Adds only
// ledger state (not a new genesis block id), so existing chain logs still replay.
const GENESIS_PUBLIC_PREMINE: u64 = 100_000_000_000;
// Was a local daemon constant — meaning every other node simply trusted us to
// honour it. It is now a consensus rule that peers enforce against us too.
use lat_chain::MAX_TXS_PER_BLOCK;
const BLOCK_INTERVAL_SECS: u64 = 3;

/// CORS headers so browser dApps / the explorer / the web wallet can call the
/// public JSON-RPC from another origin. The API is read-only (plus `lat_submitTx`,
/// which is self-authenticating), so a permissive origin is safe.
const CORS: &str = "access-control-allow-origin: *\r\n\
                    access-control-allow-methods: GET, POST, OPTIONS\r\n\
                    access-control-allow-headers: content-type\r\n\
                    access-control-max-age: 86400\r\n";

struct Config {
    data: PathBuf,
    listen: String,
    public_addr: Option<String>,
    peers: Vec<String>,
    mine: bool,
    mine_blocks: Option<u64>,
    /// T22 ops: HTTP status/metrics address, or "off". Serves GET /status
    /// (JSON) and GET /metrics (Prometheus text) for monitoring/auditing.
    metrics: String,
    /// Keep every historical state root (no trie pruning).
    archive: bool,
    /// Vote for finality with the miner wallet's key (T14). The account must
    /// be staked (`Stake` tx) or its votes are ignored by every node.
    validator: bool,
}

/// Default T6 prune window: sweep unreachable trie nodes every 64 blocks,
/// keeping the last 64 block state-roots provable. Matches the snapshot
/// cadence's order of magnitude; archive nodes opt out with --archive.
const PRUNE_WINDOW: u64 = 64;

fn parse_config() -> Config {
    let mut cfg = Config {
        data: PathBuf::from("latebra-data/chain.db"),
        listen: "127.0.0.1:4040".to_string(),
        public_addr: None,
        peers: Vec::new(),
        mine: false,
        mine_blocks: None,
        archive: false,
        validator: false,
        metrics: "127.0.0.1:4090".to_string(),
    };
    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data" => {
                i += 1;
                cfg.data = PathBuf::from(args.get(i).cloned().unwrap_or_default());
            }
            "--listen" => {
                i += 1;
                cfg.listen = args.get(i).cloned().unwrap_or_default();
            }
            "--peer" => {
                i += 1;
                if let Some(p) = args.get(i) {
                    cfg.peers.push(p.clone());
                }
            }
            "--public-addr" => {
                i += 1;
                cfg.public_addr = args.get(i).cloned();
            }
            "--metrics" => {
                i += 1;
                cfg.metrics = args.get(i).cloned().unwrap_or_else(|| "off".to_string());
            }
            "--mine" => cfg.mine = true,
            "--archive" => cfg.archive = true,
            "--validator" => cfg.validator = true,
            "--mine-blocks" => {
                i += 1;
                cfg.mine_blocks = args.get(i).and_then(|s| s.parse().ok());
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => eprintln!("warning: ignoring unknown argument '{other}'"),
        }
        i += 1;
    }
    cfg
}

fn print_usage() {
    println!("latebrad — Latebra node daemon");
    println!("  --data <path>         chain database file (redb; default latebra-data/chain.db)");
    println!("  --listen <addr>       serve peers + RPC (default 127.0.0.1:4040)");
    println!("  --peer <addr>         seed peer to sync from / gossip to (repeatable)");
    println!("  --public-addr <addr>  address other nodes can reach us on (default: --listen);");
    println!("                        for internet nodes: --listen 0.0.0.0:4040 --public-addr host:4040");
    println!("  --mine                mine blocks on an interval");
    println!("  --mine-blocks <n>     mine n blocks then exit");
    println!("  --archive             keep all historical state roots (default: prune,");
    println!("                        retaining the last {PRUNE_WINDOW} block state-roots)");
    println!("  --validator           vote for finality with the miner wallet's key");
    println!("                        (the account must be staked via a Stake tx)");
    println!("  --metrics <addr|off>  HTTP /status (JSON) + /metrics (Prometheus)");
    println!("                        + /rpc (POST, JSON-RPC 2.0; see RPC.md)");
    println!("                        (default 127.0.0.1:4090)");
}

fn main() {
    let cfg = parse_config();

    // Deterministic testnet genesis shared by all nodes.
    let genesis_wallet = Wallet::from_seed(Network::Testnet, GENESIS_SEED);
    let premine = [(genesis_wallet.id(), GENESIS_PREMINE)];
    let public_premine = [(genesis_wallet.id(), GENESIS_PUBLIC_PREMINE)];

    if let Some(parent) = cfg.data.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut chain = match Blockchain::open_with_public(&cfg.data, &premine, &public_premine, DEFAULT_DIFFICULTY) {
        Ok(chain) => chain,
        Err(e) => {
            // The common cause is pointing --data at a file that isn't a Latebra
            // chain database — most often data from an older build whose block
            // store was a flat append-only log (pre-redb). Rather than a raw
            // panic, tell the operator exactly what to do.
            eprintln!("error: could not open the chain database at {}", cfg.data.display());
            eprintln!("  cause: {e}");
            eprintln!();
            eprintln!("If this path holds data from an older Latebra build, it is no longer");
            eprintln!("compatible (the block store is now a redb database, not a flat log).");
            eprintln!("Move the old file aside or point --data at a fresh path, e.g.:");
            eprintln!("  latebrad --data ./latebra-data/chain.db --listen {}", cfg.listen);
            std::process::exit(1);
        }
    };

    if !cfg.archive {
        chain.set_prune_window(PRUNE_WINDOW);
    }

    println!("Latebra node (latebrad)");
    println!("  data        : {}", cfg.data.display());
    println!("  state       : {}", if cfg.archive { "archive (all roots kept)".to_string() } else { format!("pruned (last {PRUNE_WINDOW} roots kept)") });
    println!(
        "  boot        : {}",
        match chain.boot_mode() {
            lat_chain::BootMode::Records => "state records + tail replay",
            lat_chain::BootMode::Snapshot => "snapshot file + tail replay",
            lat_chain::BootMode::FullReplay => "full replay",
            lat_chain::BootMode::FastSync => "fast sync (peer state, root-verified)",
        }
    );
    println!("  genesis addr: {}", genesis_wallet.address_string());
    println!("  height      : {}", chain.height());
    println!("  difficulty  : {}", chain.difficulty());

    // Mined blocks pay their coinbase to a SEPARATE miner account so the genesis
    // faucet's balance stays stable (see MINER_SEED note above).
    let miner_wallet = Wallet::from_seed(Network::Testnet, MINER_SEED);
    println!("  miner  addr : {}", miner_wallet.address_string());
    let node: SharedNode = Arc::new(Mutex::new(NodeState::with_miner(chain, miner_wallet.id())));
    if cfg.validator {
        lock_node(&node).set_validator_key(miner_wallet.secret_key().clone());
        println!("  finality    : validator (voting with the miner wallet)");
    }

    // The address we advertise to other nodes (peer exchange).
    let public_addr = cfg.public_addr.clone().unwrap_or_else(|| cfg.listen.clone());

    // The genesis id is the network's fingerprint — every peer handshake checks
    // it, so a wrong-network node can never join or waste our sync effort.
    let genesis_id = lock_node(&node).chain.genesis_id();

    // Where the known-peer set is persisted, next to the block log, so the node
    // rejoins the network on restart without needing --peer again.
    let peers_path = cfg
        .data
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("peers.txt");

    {
        let mut n = lock_node(&node);
        // Never try to sync from ourselves.
        n.set_self_addr(&public_addr);
        // Seed peers from the CLI, then any peers persisted from a previous run.
        for p in &cfg.peers {
            n.add_peer(p);
        }
        let restored = n.load_peers(&peers_path);
        if restored > 0 {
            println!("  peers       : restored {restored} from {}", peers_path.display());
        }
    }

    // Serve peers + RPC.
    let listener = TcpListener::bind(&cfg.listen).expect("bind listen address");
    println!("  listening on: {}", cfg.listen);
    println!("  public addr : {public_addr}");
    serve(listener, Arc::clone(&node));

    // T22 ops: HTTP status/metrics for monitoring (loopback by default —
    // exposing it publicly is an operator decision via --metrics 0.0.0.0:...).
    if cfg.metrics != "off" {
        match TcpListener::bind(&cfg.metrics) {
            Ok(l) => {
                println!("  metrics     : http://{}/status", cfg.metrics);
                println!("  json-rpc    : http://{}/rpc (POST, JSON-RPC 2.0 — see RPC.md)", cfg.metrics);
                serve_metrics(l, Arc::clone(&node));
            }
            Err(e) => eprintln!("warning: metrics disabled ({}: {e})", cfg.metrics),
        }
    }

    // One-shot mining mode (for demos / tests): mine n blocks, then exit.
    if let Some(n) = cfg.mine_blocks {
        for _ in 0..n {
            mine_one(&node);
        }
        println!("done: mined {n} block(s). exiting.");
        return;
    }

    // Background: handshake, sync from, and exchange peers with every known
    // node. One seed is enough — the handshake makes a same-chain peer record us
    // AND confirms it's on our network; get_peers() then teaches us the rest.
    // Peers that fail the handshake (wrong genesis/version) are dropped; peers
    // that go unreachable are evicted after MAX_PEER_FAILURES.
    {
        let node = Arc::clone(&node);
        let public_addr = public_addr.clone();
        let peers_path = peers_path.clone();
        thread::spawn(move || loop {
            // Snapshot the peer list in its own statement: `for x in lock().peers()`
            // would hold the node lock across the whole loop body (a `for`
            // scrutinee's temporaries live until the loop ends) and deadlock
            // against sync_shared's own locking.
            let peers = lock_node(&node).peers();
            for peer in peers {
                // Handshake first: a same-chain peer records us; anything else is
                // dropped so we never waste sync effort on a foreign chain.
                match lat_p2p::handshake(peer.as_str(), genesis_id, &public_addr) {
                    Ok(true) => {
                        lock_node(&node).record_peer_ok(&peer);
                    }
                    Ok(false) => {
                        println!("[peers] dropping {peer} (different network / version)");
                        lock_node(&node).remove_peer(&peer);
                        continue;
                    }
                    Err(_) => {
                        if lock_node(&node).record_peer_failure(&peer) {
                            println!("[peers] evicted unreachable peer {peer}");
                        }
                        continue;
                    }
                }
                // T19: a FRESH node (height 0, e.g. first boot) bootstraps by
                // downloading the peer's state records instead of replaying
                // every historical proof; the derived state root is verified
                // against the PoW-validated header chain. Any failure falls
                // through to ordinary full-validation sync below.
                if lock_node(&node).chain.height() == 0 {
                    match lat_p2p::fast_sync_shared(&node, peer.as_str()) {
                        Ok(true) => {
                            let h = lock_node(&node).chain.height();
                            println!("[sync] fast-synced to height {h} from {peer} (state root verified)");
                            cast_and_announce_vote(&node);
                        }
                        Ok(false) => {} // not applicable; full sync handles it
                        Err(e) => println!("[sync] fast sync from {peer} failed ({e}); falling back to full sync"),
                    }
                }
                if let Ok(n) = sync_shared(&node, peer.as_str()) {
                    if n > 0 {
                        println!("[sync] adopted {n} block(s) from {peer}");
                        cast_and_announce_vote(&node);
                    }
                }
                if let Ok(theirs) = lat_p2p::get_peers(peer.as_str()) {
                    let mut me = lock_node(&node);
                    for p in theirs {
                        if p != public_addr && me.add_peer(&p) {
                            println!("[peers] discovered {p} (via {peer})");
                        }
                    }
                }
            }
            // Persist the (health-pruned) peer set so a restart rejoins directly.
            let _ = lock_node(&node).save_peers(&peers_path);
            thread::sleep(Duration::from_secs(5));
        });
    }

    // Background miner.
    if cfg.mine {
        let node = Arc::clone(&node);
        thread::spawn(move || loop {
            mine_one(&node);
            thread::sleep(Duration::from_secs(BLOCK_INTERVAL_SECS));
        });
    }

    // A validator re-votes for its booted tip right away (T16): after a
    // restart, its earlier votes are gone from every pool, and a quorum that
    // never converged needs the periodic heartbeat re-cast below too (the
    // vote pool dedups, so this never spams).
    cast_and_announce_vote(&node);

    // Heartbeat — keep the process alive and show liveness.
    loop {
        thread::sleep(Duration::from_secs(15));
        cast_and_announce_vote(&node);
        let n = lock_node(&node);
        let (h, p) = (n.chain.height(), n.peers().len());
        drop(n);
        println!("[heartbeat] height={h} peers={p}");
    }
}

/// T22 ops: serve GET `/status` (JSON) and GET `/metrics` (Prometheus text
/// exposition) so monitoring and auditors can watch node health without the
/// binary P2P protocol. Read-only; every request takes the node lock briefly.
fn serve_metrics(listener: TcpListener, node: SharedNode) {
    let started = std::time::Instant::now();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let node = Arc::clone(&node);
            thread::spawn(move || {
                let _ = handle_metrics(stream, &node, started);
            });
        }
    });
}

fn handle_metrics(
    stream: std::net::TcpStream,
    node: &SharedNode,
    started: std::time::Instant,
) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Read, Write};
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let verb = line.split_whitespace().next().unwrap_or("").to_string();
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();

    // CORS preflight: browsers send OPTIONS before a cross-origin POST /rpc.
    if verb == "OPTIONS" {
        let mut s = stream;
        return write!(s, "HTTP/1.1 204 No Content\r\n{CORS}content-length: 0\r\nconnection: close\r\n\r\n");
    }

    // T20: JSON-RPC 2.0 over POST /rpc — read headers for the body length,
    // then dispatch. Everything else falls through to the GET endpoints.
    if verb == "POST" && path == "/rpc" {
        let mut content_length = 0usize;
        loop {
            let mut h = String::new();
            reader.read_line(&mut h)?;
            let h = h.trim();
            if h.is_empty() {
                break;
            }
            if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
        // Bound the body so a hostile client can't OOM the node.
        if content_length > 1024 * 1024 {
            let mut s = stream;
            s.write_all(b"HTTP/1.1 413 Payload Too Large\r\ncontent-length: 0\r\n\r\n")?;
            return Ok(());
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)?;
        let reply = rpc_handle(node, &body).to_string();
        let mut s = stream;
        return write!(
            s,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{CORS}content-length: {}\r\nconnection: close\r\n\r\n{reply}",
            reply.len()
        );
    }

    // One snapshot of everything under a single brief lock.
    let (height, tip, difficulty, peers, mempool, finalized, boot) = {
        let n = lock_node(node);
        (
            n.chain.height(),
            n.chain.tip(),
            n.chain.difficulty(),
            n.peers().len(),
            n.mempool.len(),
            n.chain.finalized(),
            n.chain.boot_mode(),
        )
    };
    let uptime = started.elapsed().as_secs();
    let tip_hex: String = tip.iter().map(|b| format!("{b:02x}")).collect();
    let (fin_height, fin_id) = match finalized {
        Some((h, id)) => (h as i64, id.iter().map(|b| format!("{b:02x}")).collect()),
        None => (-1, String::new()),
    };
    let boot = match boot {
        lat_chain::BootMode::Records => "records",
        lat_chain::BootMode::Snapshot => "snapshot",
        lat_chain::BootMode::FullReplay => "full-replay",
        lat_chain::BootMode::FastSync => "fast-sync",
    };

    let (content_type, body) = match path.as_str() {
        "/metrics" => (
            "text/plain; version=0.0.4",
            format!(
                "# HELP latebra_height Active chain height\n\
                 # TYPE latebra_height gauge\n\
                 latebra_height {height}\n\
                 # HELP latebra_difficulty Next-block difficulty target\n\
                 # TYPE latebra_difficulty gauge\n\
                 latebra_difficulty {difficulty}\n\
                 # HELP latebra_peers Known peer count\n\
                 # TYPE latebra_peers gauge\n\
                 latebra_peers {peers}\n\
                 # HELP latebra_mempool_txs Pending transactions in the mempool\n\
                 # TYPE latebra_mempool_txs gauge\n\
                 latebra_mempool_txs {mempool}\n\
                 # HELP latebra_finalized_height BFT-finalized height (-1 = none)\n\
                 # TYPE latebra_finalized_height gauge\n\
                 latebra_finalized_height {fin_height}\n\
                 # HELP latebra_uptime_seconds Seconds since the daemon started\n\
                 # TYPE latebra_uptime_seconds counter\n\
                 latebra_uptime_seconds {uptime}\n"
            ),
        ),
        "/health" => ("text/plain", "ok".to_string()),
        "/status" | "/" => (
            "application/json",
            format!(
                "{{\"height\":{height},\"tip\":\"{tip_hex}\",\"difficulty\":{difficulty},\
                 \"peers\":{peers},\"mempool\":{mempool},\
                 \"finalized_height\":{fin_height},\"finalized_id\":\"{fin_id}\",\
                 \"boot_mode\":\"{boot}\",\"uptime_secs\":{uptime}}}"
            ),
        ),
        _ => {
            let mut s = stream;
            s.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")?;
            return Ok(());
        }
    };
    let mut s = stream;
    write!(
        s,
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\n{CORS}content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// T20: handle one JSON-RPC 2.0 request body and produce the response object.
/// Split from the HTTP plumbing so tests can call it directly.
fn rpc_handle(node: &SharedNode, body: &[u8]) -> serde_json::Value {
    use serde_json::{json, Value};
    let req: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            return json!({"jsonrpc": "2.0", "id": null,
                "error": {"code": -32700, "message": "parse error"}})
        }
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let params = req.get("params").and_then(Value::as_array).cloned().unwrap_or_default();

    // Param helpers: positional params only, hex for ids/bytes.
    let p_str = |i: usize| params.get(i).and_then(Value::as_str);
    let p_u64 = |i: usize| params.get(i).and_then(Value::as_u64);
    let p_id = |i: usize| -> Option<[u8; 32]> {
        hex::decode(p_str(i)?).ok()?.try_into().ok()
    };

    let result: Result<Value, (i64, &str)> = match method {
        // -- liveness --------------------------------------------------------
        "lat_health" => Ok(json!("ok")),
        // -- chain info ------------------------------------------------------
        "lat_status" => {
            let n = lock_node(node);
            Ok(json!({
                "height": n.chain.height(),
                "tip": hex::encode(n.chain.tip()),
                "difficulty": n.chain.difficulty(),
                "genesis": hex::encode(n.chain.genesis_id()),
                "peers": n.peers().len(),
                "mempool": n.mempool.len(),
                "finalized": n.chain.finalized().map(|(h, id)| json!({"height": h, "id": hex::encode(id)})),
            }))
        }
        // -- blocks / transactions -------------------------------------------
        "lat_blockByHeight" => match p_u64(0) {
            Some(h) => {
                let n = lock_node(node);
                match n.chain.block_bytes(h) {
                    Some(b) => Ok(json!({"height": h, "bytes": hex::encode(b)})),
                    None => Ok(Value::Null),
                }
            }
            None => Err((-32602, "params: [height]")),
        },
        "lat_txByHash" => match p_id(0) {
            Some(hash) => {
                let n = lock_node(node);
                match n.chain.tx_location(&hash) {
                    Some((block_id, index)) => Ok(json!({
                        "block": hex::encode(block_id),
                        "index": index,
                    })),
                    None => Ok(Value::Null),
                }
            }
            None => Err((-32602, "params: [tx_hash_hex]")),
        },
        // -- decoded, developer-friendly reads (Solana-style) ----------------
        "lat_getBlock" => match p_u64(0) {
            Some(h) => {
                let n = lock_node(node);
                Ok(n.chain.block_bytes(h).map(block_json).unwrap_or(Value::Null))
            }
            None => Err((-32602, "params: [height]")),
        },
        "lat_getBlockByHash" => match p_id(0) {
            Some(bid) => {
                let n = lock_node(node);
                Ok(n.chain.block_by_id(&bid).as_deref().map(block_json).unwrap_or(Value::Null))
            }
            None => Err((-32602, "params: [block_id_hex]")),
        },
        "lat_latestBlocks" => {
            let count = p_u64(0).unwrap_or(10).clamp(1, 50);
            let n = lock_node(node);
            let mut h = n.chain.height();
            let mut out = Vec::new();
            loop {
                if let Some(blk) = n.chain.block_bytes(h).and_then(lat_chain::Block::decode) {
                    let hdr = &blk.header;
                    out.push(json!({
                        "height": hdr.height,
                        "id": hex::encode(hdr.id()),
                        "timestamp": hdr.timestamp,
                        "miner": hex::encode(hdr.miner),
                        "tx_count": blk.txs.len(),
                        "reward": emission(hdr.height),
                    }));
                }
                if out.len() as u64 >= count || h == 0 {
                    break;
                }
                h -= 1;
            }
            Ok(json!(out))
        }
        "lat_getTransaction" => match p_id(0) {
            Some(hash) => {
                let n = lock_node(node);
                match n.chain.tx_location(&hash) {
                    Some((block_id, index)) => {
                        let height = n.chain.active_height_of(&block_id);
                        let tx = n
                            .chain
                            .block_by_id(&block_id)
                            .and_then(|b| lat_chain::Block::decode(&b))
                            .and_then(|blk| blk.txs.get(index as usize).cloned());
                        Ok(json!({
                            "hash": hex::encode(hash),
                            "block": hex::encode(block_id),
                            "height": height,
                            "index": index,
                            "tx": tx.as_ref().map(tx_summary),
                        }))
                    }
                    None => Ok(Value::Null),
                }
            }
            None => Err((-32602, "params: [tx_hash_hex]")),
        },
        "lat_supply" => {
            let height = lock_node(node).chain.height();
            let mined = mined_supply(height);
            let premine = GENESIS_PREMINE as u128 + GENESIS_PUBLIC_PREMINE as u128;
            Ok(json!({
                "height": height,
                "decimals": 5,
                "current_block_reward": emission(height),
                "halving_interval": lat_chain::HALVING_INTERVAL,
                "halvings_done": height / lat_chain::HALVING_INTERVAL,
                "premine_base_units": premine as u64,
                "mined_base_units": mined as u64,
                "total_base_units": (premine + mined) as u64,
            }))
        }
        "lat_validators" => {
            let n = lock_node(node);
            let height = n.chain.height();
            let set = n
                .chain
                .validator_set_at(height)
                .map(|s| {
                    s.iter()
                        .map(|(id, stake)| json!({"account": hex::encode(id), "stake": stake}))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Ok(json!(set))
        }
        "lat_token" => match p_str(0) {
            Some(ticker) => Ok(json!(lock_node(node).chain.token(ticker).map(|t| json!({
                "id": t.id,
                "ticker": t.ticker,
                "creator": hex::encode(t.creator),
                "supply": t.supply,
            })))),
            None => Err((-32602, "params: [ticker]")),
        },
        // -- account reads ---------------------------------------------------
        "lat_publicBalance" => match (p_id(0), p_u64(1)) {
            (Some(acct), Some(token)) => {
                let b = lock_node(node).chain.public_balance(&acct, token as u32);
                Ok(json!(b))
            }
            _ => Err((-32602, "params: [account_hex, token]")),
        },
        "lat_encryptedBalance" => match (p_id(0), p_u64(1)) {
            (Some(acct), Some(token)) => {
                let b = lock_node(node).chain.balance(&acct, token as u32);
                Ok(json!(b.map(|ct| hex::encode(ct.to_bytes()))))
            }
            _ => Err((-32602, "params: [account_hex, token]")),
        },
        "lat_pending" => match (p_id(0), p_u64(1)) {
            (Some(acct), Some(token)) => {
                let b = lock_node(node).chain.pending(&acct, token as u32);
                Ok(json!(b.map(|ct| hex::encode(ct.to_bytes()))))
            }
            _ => Err((-32602, "params: [account_hex, token]")),
        },
        "lat_nonce" => match p_id(0) {
            Some(acct) => Ok(json!(lock_node(node).chain.nonce(&acct))),
            None => Err((-32602, "params: [account_hex]")),
        },
        "lat_stake" => match p_id(0) {
            Some(acct) => {
                let n = lock_node(node);
                Ok(json!({
                    "staked": n.chain.staked(&acct),
                    "unbonding": n.chain.unbonding(&acct)
                        .iter().map(|(a, r)| json!({"amount": a, "release_height": r})).collect::<Vec<_>>(),
                }))
            }
            None => Err((-32602, "params: [account_hex]")),
        },
        // -- contracts / privacy helpers --------------------------------------
        "lat_contractStorage" => match (p_id(0), p_u64(1)) {
            (Some(contract), Some(key)) => {
                Ok(json!(lock_node(node).chain.contract_storage(&contract, key)))
            }
            _ => Err((-32602, "params: [contract_hex, key]")),
        },
        "lat_ringCandidates" => match p_u64(0) {
            Some(token) => {
                let all = lock_node(node).chain.ring_candidates(token as u32);
                let max = p_u64(1).unwrap_or(lat_p2p::MAX_RING_CANDIDATES as u64) as usize;
                Ok(json!(all
                    .iter()
                    .take(max.min(lat_p2p::MAX_RING_CANDIDATES))
                    .map(|(id, ct)| json!({"account": hex::encode(id), "balance": hex::encode(ct.to_bytes())}))
                    .collect::<Vec<_>>()))
            }
            None => Err((-32602, "params: [token, max?]")),
        },
        // -- writes ------------------------------------------------------------
        "lat_submitTx" => match p_str(0).and_then(|s| hex::decode(s).ok()) {
            Some(bytes) => match lat_types::Transaction::decode(&bytes) {
                Some(tx) => {
                    let accepted = lock_node(node).submit_tx(tx);
                    if accepted {
                        // Same forwarding a binary SubmitTx gets (T17): gossip
                        // so every miner's mempool sees it, not just ours.
                        let peers = lock_node(node).peers();
                        thread::spawn(move || {
                            for p in peers {
                                let _ = lat_p2p::announce_tx(p.as_str(), &bytes);
                            }
                        });
                    }
                    Ok(json!(accepted))
                }
                None => Err((-32602, "undecodable transaction")),
            },
            None => Err((-32602, "params: [tx_hex]")),
        },
        _ => Err((-32601, "method not found")),
    };

    match result {
        Ok(value) => json!({"jsonrpc": "2.0", "id": id, "result": value}),
        Err((code, message)) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
        }
    }
}

/// A public, privacy-respecting summary of one transaction for the JSON-RPC API.
/// Confidential fields (encrypted amounts, ZK proofs, anonymity-set members) are
/// never expanded — only what is public on-chain is surfaced. Amounts are in base
/// units (1 LAT = 100000). See RPC.md.
fn tx_summary(tx: &lat_types::Transaction) -> serde_json::Value {
    use lat_types::Transaction::*;
    use serde_json::json;
    let hash = hex::encode(lat_chain::tx_hash(tx));
    match tx {
        Register { pubkey, .. } => {
            json!({"hash": hash, "type": "register", "account": hex::encode(pubkey)})
        }
        CreateToken { ticker, creator, supply, .. } => json!({
            "hash": hash, "type": "create_token",
            "ticker": ticker, "creator": hex::encode(creator), "supply": supply,
        }),
        SolventTransfer { token, .. } => json!({
            "hash": hash, "type": "confidential_transfer", "token": token,
            "amount": "confidential",
        }),
        Rollover { account, .. } => {
            json!({"hash": hash, "type": "rollover", "account": hex::encode(account)})
        }
        DeployContract { deployer, code, .. } => json!({
            "hash": hash, "type": "deploy_contract",
            "deployer": hex::encode(deployer), "code_len": code.len(),
        }),
        CallContract { contract, caller, input, .. } => json!({
            "hash": hash, "type": "call_contract",
            "contract": hex::encode(contract), "caller": hex::encode(caller), "input": input,
        }),
        PublicTransfer { token, from, to, amount, fee, .. } => json!({
            "hash": hash, "type": "public_transfer", "token": token,
            "from": hex::encode(from), "to": hex::encode(to), "amount": amount, "fee": fee,
        }),
        Shield { token, from, to, amount, fee, .. } => json!({
            "hash": hash, "type": "shield", "token": token,
            "from": hex::encode(from), "to": hex::encode(to), "amount": amount, "fee": fee,
        }),
        Unshield { token, to, amount, .. } => json!({
            "hash": hash, "type": "unshield", "token": token,
            "to": hex::encode(to), "amount": amount,
        }),
        ShieldStealth { token, from, amount, fee, .. } => json!({
            "hash": hash, "type": "shield_stealth", "token": token,
            "from": hex::encode(from), "amount": amount, "fee": fee,
        }),
        AnonTransfer { token, .. } => json!({
            "hash": hash, "type": "anon_transfer", "token": token,
            "sender": "hidden", "receiver": "hidden",
        }),
        Stake { validator, amount, .. } => json!({
            "hash": hash, "type": "stake", "validator": hex::encode(validator), "amount": amount,
        }),
        Unstake { validator, amount, .. } => json!({
            "hash": hash, "type": "unstake", "validator": hex::encode(validator), "amount": amount,
        }),
        SlashEvidence { validator, beneficiary, height, .. } => json!({
            "hash": hash, "type": "slash_evidence",
            "validator": hex::encode(validator), "beneficiary": hex::encode(beneficiary),
            "height": height,
        }),
    }
}

/// Decode an encoded block into a structured JSON object (header + tx summaries).
/// Returns `null` if the bytes don't decode.
fn block_json(bytes: &[u8]) -> serde_json::Value {
    use serde_json::json;
    match lat_chain::Block::decode(bytes) {
        Some(b) => {
            let h = &b.header;
            json!({
                "height": h.height,
                "id": hex::encode(h.id()),
                "prev_hash": hex::encode(h.prev_hash),
                "timestamp": h.timestamp,
                "tx_root": hex::encode(h.tx_root),
                "state_root": hex::encode(h.state_root),
                "miner": hex::encode(h.miner),
                "nonce": h.nonce,
                "reward": emission(h.height),
                "tx_count": b.txs.len(),
                "txs": b.txs.iter().map(tx_summary).collect::<Vec<_>>(),
            })
        }
        None => serde_json::Value::Null,
    }
}

/// Total LAT emitted by mining from block 1..=height, in base units. Computed in
/// closed form over halving eras (≤64 iterations) rather than per-block, so it is
/// cheap even for a long chain. Matches `lat_chain::emission` exactly.
fn mined_supply(height: u64) -> u128 {
    let mut total: u128 = 0;
    let mut h: u64 = 1;
    while h <= height {
        let reward = emission(h) as u128;
        if reward == 0 {
            break; // emission is monotonic non-increasing; nothing more to add.
        }
        let era = h / lat_chain::HALVING_INTERVAL;
        let era_end = (era + 1) * lat_chain::HALVING_INTERVAL; // first height of the next era
        let upper = era_end.min(height + 1);
        total += reward * (upper - h) as u128;
        h = upper;
    }
    total
}

/// Mine one block from the mempool, apply it, and gossip it to every known peer
/// (they re-gossip it onward, so the whole network hears about it).
fn mine_one(node: &SharedNode) {
    let mined = lock_node(node).produce_block(MAX_TXS_PER_BLOCK);
    if let Some(bytes) = mined {
        let (height, peers) = {
            let n = lock_node(node);
            (n.chain.height(), n.peers())
        };
        let reward = emission(height);
        println!("[mine] new block -> height {height}  reward {}.{:05} LAT", reward / 100_000, reward % 100_000);
        // T17: compact announce — peers that already have the block (e.g. via
        // another peer's relay) cost one 40-byte message, not the whole block.
        if let Some(block) = lat_chain::Block::decode(&bytes) {
            let id = block.header.id();
            for peer in peers {
                let _ = lat_p2p::announce_block_compact(peer.as_str(), &id, height, &bytes);
            }
        }
        cast_and_announce_vote(node);
    }
}

/// If this node is a validator, sign a finality vote for the adopted tip and
/// gossip it (plus any certificate the vote completes) to every peer. A no-op
/// when not a validator or when this tip was already voted for.
fn cast_and_announce_vote(node: &SharedNode) {
    let Some((vote, cert)) = lock_node(node).cast_vote() else { return };
    let peers = lock_node(node).peers();
    for p in &peers {
        let _ = lat_p2p::announce_vote(p.as_str(), &vote);
    }
    if let Some(cert) = cert {
        if let Some((h, _)) = lock_node(node).chain.finalized() {
            println!("[finality] height {h} finalized (certificate formed)");
        }
        for p in &peers {
            let _ = lat_p2p::announce_cert(p.as_str(), &cert);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lat_chain::{Blockchain, DEFAULT_DIFFICULTY};
    use lat_p2p::NodeState;
    use serde_json::{json, Value};

    fn test_node() -> SharedNode {
        let genesis = Wallet::from_seed(Network::Testnet, [9u8; 32]);
        let chain = Blockchain::genesis_with_public(
            &[(genesis.id(), 1_000_000)],
            &[(genesis.id(), 500_000)],
            DEFAULT_DIFFICULTY,
        );
        Arc::new(Mutex::new(NodeState::new(chain)))
    }

    fn call(node: &SharedNode, method: &str, params: Value) -> Value {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        rpc_handle(node, body.to_string().as_bytes())
    }

    #[test]
    fn rpc_status_reads_and_errors() {
        let node = test_node();
        let genesis_id = {
            let w = Wallet::from_seed(Network::Testnet, [9u8; 32]);
            hex::encode(w.id())
        };

        // Status carries the chain fingerprint.
        let r = call(&node, "lat_status", json!([]));
        assert_eq!(r["result"]["height"], 0);
        assert!(r["result"]["genesis"].is_string());

        // Reads: public balance from the transparent premine; nonce; stake.
        let r = call(&node, "lat_publicBalance", json!([genesis_id, 0]));
        assert_eq!(r["result"], 500_000);
        let r = call(&node, "lat_encryptedBalance", json!([genesis_id, 0]));
        assert!(r["result"].is_string(), "confidential premine is a hex ciphertext");
        let r = call(&node, "lat_nonce", json!([genesis_id]));
        assert_eq!(r["result"], 0);
        let r = call(&node, "lat_stake", json!([genesis_id]));
        assert_eq!(r["result"]["staked"], 0);

        // Block 0 (genesis) is servable; beyond the tip is null.
        let r = call(&node, "lat_blockByHeight", json!([0]));
        assert!(r["result"]["bytes"].is_string());
        let r = call(&node, "lat_blockByHeight", json!([99]));
        assert!(r["result"].is_null());

        // Unknown accounts read as null, not errors.
        let r = call(&node, "lat_publicBalance", json!([hex::encode([7u8; 32]), 0]));
        assert!(r["result"].is_null());

        // Error paths: bad method, bad params, unparseable body.
        let r = call(&node, "lat_noSuchMethod", json!([]));
        assert_eq!(r["error"]["code"], -32601);
        let r = call(&node, "lat_publicBalance", json!(["nothex", 0]));
        assert_eq!(r["error"]["code"], -32602);
        let r = rpc_handle(&node, b"{not json");
        assert_eq!(r["error"]["code"], -32700);
    }

    #[test]
    fn rpc_submit_tx_accepts_a_valid_registration() {
        let node = test_node();
        let tx = lat_chain::mine_registration([5u8; 32]);
        let r = call(&node, "lat_submitTx", json!([hex::encode(tx.encode())]));
        assert_eq!(r["result"], true, "valid registration enters the mempool");
        assert_eq!(lock_node(&node).mempool.len(), 1);

        // Garbage bytes are rejected as an error, not a panic.
        let r = call(&node, "lat_submitTx", json!(["deadbeef"]));
        assert_eq!(r["error"]["code"], -32602);
    }
}

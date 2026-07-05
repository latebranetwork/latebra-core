//! `latebrad` — the Latebra node daemon.
//!
//! Ties together everything: a persistent chain, TCP networking (peer sync +
//! gossip + RPC), and a mempool. Run one node mining and point others at it to
//! form a testnet.
//!
//! ```text
//! latebrad --mine --data ./node-a/chain.log --listen 127.0.0.1:4040
//! latebrad         --data ./node-b/chain.log --listen 127.0.0.1:4041 --peer 127.0.0.1:4040
//! ```
//!
//! Flags:
//!   --data <path>        block-log file (default: latebra-data/chain.log)
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
use lat_p2p::{announce_block, lock_node, serve, sync_shared, NodeState, SharedNode};
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
const MAX_TXS_PER_BLOCK: usize = 1000;
const BLOCK_INTERVAL_SECS: u64 = 3;

struct Config {
    data: PathBuf,
    listen: String,
    public_addr: Option<String>,
    peers: Vec<String>,
    mine: bool,
    mine_blocks: Option<u64>,
}

fn parse_config() -> Config {
    let mut cfg = Config {
        data: PathBuf::from("latebra-data/chain.log"),
        listen: "127.0.0.1:4040".to_string(),
        public_addr: None,
        peers: Vec::new(),
        mine: false,
        mine_blocks: None,
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
            "--mine" => cfg.mine = true,
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
    println!("  --data <path>         block-log file (default latebra-data/chain.log)");
    println!("  --listen <addr>       serve peers + RPC (default 127.0.0.1:4040)");
    println!("  --peer <addr>         seed peer to sync from / gossip to (repeatable)");
    println!("  --public-addr <addr>  address other nodes can reach us on (default: --listen);");
    println!("                        for internet nodes: --listen 0.0.0.0:4040 --public-addr host:4040");
    println!("  --mine                mine blocks on an interval");
    println!("  --mine-blocks <n>     mine n blocks then exit");
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
    let chain = Blockchain::open_with_public(&cfg.data, &premine, &public_premine, DEFAULT_DIFFICULTY)
        .expect("open persistent chain");

    println!("Latebra node (latebrad)");
    println!("  data        : {}", cfg.data.display());
    println!(
        "  boot        : {}",
        if chain.booted_from_snapshot() { "snapshot + tail replay" } else { "full replay" }
    );
    println!("  genesis addr: {}", genesis_wallet.address_string());
    println!("  height      : {}", chain.height());
    println!("  difficulty  : {}", chain.difficulty());

    // Mined blocks pay their coinbase to a SEPARATE miner account so the genesis
    // faucet's balance stays stable (see MINER_SEED note above).
    let miner_wallet = Wallet::from_seed(Network::Testnet, MINER_SEED);
    println!("  miner  addr : {}", miner_wallet.address_string());
    let node: SharedNode = Arc::new(Mutex::new(NodeState::with_miner(chain, miner_wallet.id())));

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
                if let Ok(n) = sync_shared(&node, peer.as_str()) {
                    if n > 0 {
                        println!("[sync] adopted {n} block(s) from {peer}");
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

    // Heartbeat — keep the process alive and show liveness.
    loop {
        thread::sleep(Duration::from_secs(15));
        let n = lock_node(&node);
        let (h, p) = (n.chain.height(), n.peers().len());
        drop(n);
        println!("[heartbeat] height={h} peers={p}");
    }
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
        for peer in peers {
            let _ = announce_block(peer.as_str(), &bytes);
        }
    }
}

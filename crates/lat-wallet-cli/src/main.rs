//! `lat-wallet` — a command-line Latebra wallet that talks to a live node over RPC.
//!
//! Keys never leave the wallet; private balances are decrypted locally. The node
//! only ever sees ciphertexts. Latebra has a dual-state model — every account has
//! a transparent **public** balance and a confidential **private** balance — and
//! this wallet drives both, plus the moves between them (shield / unshield).
//!
//! ```text
//! lat-wallet new
//! lat-wallet address        --seed <hex>
//! lat-wallet balance        --seed <hex> [--node 127.0.0.1:4040]
//! lat-wallet register       --seed <hex> [--node ...]
//! lat-wallet send           --seed <hex> --to <lat1…> --amount <LAT> [--fee <LAT>]   (private)
//! lat-wallet anon-send      --seed <hex> --to <lat1…> --amount <LAT> [--fee <LAT>] [--ring <n>]  (sender+receiver hidden)
//! lat-wallet public-send    --seed <hex> --to <lat1…> --amount <LAT> [--fee <LAT>]   (transparent)
//! lat-wallet shield         --seed <hex> [--to <lat1…>] --amount <LAT> [--fee <LAT>] (public → private)
//! lat-wallet shield-stealth --seed <hex> --to <lat1…> --amount <LAT> [--fee <LAT>]   (recipient hidden)
//! lat-wallet unshield       --seed <hex> --to <lat1…> --amount <LAT> [--fee <LAT>]   (private → public)
//! lat-wallet scan-stealth   --seed <hex> [--from <height>] [--node ...]
//! lat-wallet rollover       --seed <hex> [--node ...]
//! ```

use std::collections::HashMap;
use std::env;

use lat_crypto::{Ciphertext, PublicKey};
use lat_types::{Address, Network};
use lat_wallet::Wallet;
use rand::rngs::OsRng;

const LAT_TOKEN: u32 = 0;
const UNITS: u64 = 100_000; // 5 decimals

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let flags = parse_flags(&args);
    let node = flags.get("node").cloned().unwrap_or_else(|| "127.0.0.1:4040".to_string());
    let network = match flags.get("network").map(String::as_str) {
        Some("mainnet") => Network::Mainnet,
        _ => Network::Testnet,
    };

    let result = match cmd {
        "new" => cmd_new(network),
        "address" => wallet(&flags, network).map(|w| {
            println!("{}", w.address_string());
        }),
        "balance" => cmd_balance(&flags, network, &node),
        "register" => cmd_register(&flags, network, &node),
        "send" => cmd_send(&flags, network, &node),
        "anon-send" => cmd_anon_send(&flags, network, &node),
        "public-send" => cmd_public_send(&flags, network, &node),
        "shield" => cmd_shield(&flags, network, &node),
        "shield-stealth" => cmd_shield_stealth(&flags, network, &node),
        "unshield" => cmd_unshield(&flags, network, &node),
        "scan-stealth" => cmd_scan_stealth(&flags, network, &node),
        "rollover" => cmd_rollover(&flags, network, &node),
        "stake" => cmd_stake(&flags, network, &node),
        "unstake" => cmd_unstake(&flags, network, &node),
        "staking" => cmd_staking(&flags, network, &node),
        _ => {
            usage();
            Ok(())
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn usage() {
    println!("lat-wallet — Latebra command-line wallet (dual-state: public + private)");
    println!("  new                                   generate a new wallet seed");
    println!("  address       --seed <hex>            show this wallet's address");
    println!("  balance       --seed <hex> [--node]   show public + private + pending balance");
    println!("  register      --seed <hex> [--node]   register the account on-chain");
    println!("  send          --seed <hex> --to <addr> --amount <LAT> [--fee] [--node]   confidential transfer");
    println!("  anon-send     --seed <hex> --to <addr> --amount <LAT> [--fee] [--ring <n>] [--node]  anonymous: sender hidden in a ring, receiver stealth (amount public)");
    println!("  public-send   --seed <hex> --to <addr> --amount <LAT> [--fee] [--node]   transparent transfer");
    println!("  shield        --seed <hex> [--to <addr>] --amount <LAT> [--fee] [--node] public → private");
    println!("  shield-stealth--seed <hex> --to <addr> --amount <LAT> [--fee] [--node]   public → private, recipient hidden");
    println!("  unshield      --seed <hex> --to <addr> --amount <LAT> [--fee] [--node]   private → public");
    println!("  scan-stealth  --seed <hex> [--from <height>] [--node]  find stealth funds sent to you");
    println!("  rollover      --seed <hex> [--node]   move pending funds to spendable");
    println!("  stake         --seed <hex> --amount <LAT> [--node]  bond public LAT as validator stake");
    println!("                                        (--amount 0 claims matured unbonding funds)");
    println!("  unstake       --seed <hex> --amount <LAT> [--node]  begin unbonding stake");
    println!("  staking       --seed <hex> [--node]   show bonded stake + unbonding entries");
    println!("  (add --network mainnet for mainnet addresses; default testnet)");
}

fn parse_flags(args: &[String]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(key) = args[i].strip_prefix("--") {
            if let Some(val) = args.get(i + 1) {
                m.insert(key.to_string(), val.clone());
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    m
}

fn wallet(flags: &HashMap<String, String>, network: Network) -> Result<Wallet, String> {
    let seed = flags.get("seed").ok_or("missing --seed <hex>")?;
    Wallet::from_seed_hex(network, seed).map_err(|_| "invalid seed hex (need 64 hex chars)".to_string())
}

/// The miner fee: defaults to the consensus floor; pay more to jump the queue.
/// Rejects a below-floor `--fee` up front (consensus would reject it anyway).
fn fee_from(flags: &HashMap<String, String>) -> Result<u64, String> {
    match flags.get("fee") {
        Some(s) => {
            let f = parse_lat(s)?;
            if f < lat_wallet::MIN_TRANSFER_FEE {
                return Err(format!(
                    "fee too low — the network minimum is {}",
                    lat(lat_wallet::MIN_TRANSFER_FEE)
                ));
            }
            Ok(f)
        }
        None => Ok(lat_wallet::MIN_TRANSFER_FEE),
    }
}

fn require_addr(flags: &HashMap<String, String>) -> Result<Address, String> {
    let to = flags.get("to").ok_or("missing --to <address>")?;
    Address::parse(to).map_err(|_| "invalid address".to_string())
}

fn require_amount(flags: &HashMap<String, String>) -> Result<u64, String> {
    parse_lat(flags.get("amount").ok_or("missing --amount <LAT>")?)
}

fn nonce_of(node: &str, w: &Wallet) -> Result<u64, String> {
    lat_p2p::get_nonce(node, w.id())
        .map_err(net_err(node))?
        .ok_or_else(|| "your account isn't registered yet — run `register`".to_string())
}

fn cmd_new(network: Network) -> Result<(), String> {
    let w = Wallet::generate(network, &mut OsRng);
    println!("New wallet created.");
    println!("  address : {}", w.address_string());
    println!("  seed    : {}", w.seed_hex());
    println!("\nKeep the seed secret — anyone with it controls this wallet.");
    Ok(())
}

fn cmd_balance(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    println!("Address: {}", w.address_string());

    // Public (transparent) balance — visible to everyone, no decryption needed.
    let public = lat_p2p::get_public_balance(node, w.id(), LAT_TOKEN)
        .map_err(net_err(node))?
        .unwrap_or(0);
    println!("Public   : {}", lat(public));

    // Private (confidential) balance — decrypted locally with the secret key.
    match lat_p2p::get_balance(node, w.id(), LAT_TOKEN).map_err(net_err(node))? {
        Some(bytes) => {
            let ct = Ciphertext::from_bytes(&bytes).ok_or("bad balance ciphertext")?;
            let spendable = w.decrypt_ciphertext(&ct).ok_or("could not decrypt balance")?;
            let pending = lat_p2p::get_pending(node, w.id(), LAT_TOKEN)
                .map_err(net_err(node))?
                .and_then(|b| Ciphertext::from_bytes(&b))
                .and_then(|c| w.decrypt_ciphertext(&c))
                .unwrap_or(0);
            println!("Private  : {}   (spendable)", lat(spendable));
            println!("Pending  : {}   (run `rollover` to make spendable)", lat(pending));
        }
        None => println!("(Not registered yet — run `register` to receive private funds.)"),
    }
    Ok(())
}

fn cmd_register(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let tx = w.registration_tx();
    submit(node, &tx, "registration")
}

fn cmd_rollover(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let nonce = nonce_of(node, &w)?;
    let tx = w.rollover_tx(nonce);
    submit(node, &tx, "rollover")
}

fn cmd_stake(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    // --amount 0 is meaningful (claim matured unbonding funds), so it is
    // required but may be zero.
    let amount = parse_lat(flags.get("amount").ok_or("missing --amount <LAT> (0 = claim matured unbonding funds)")?)?;
    let nonce = nonce_of(node, &w)?;
    let tx = w.stake_tx(amount, nonce);
    if amount == 0 {
        println!("Claiming matured unbonding funds (stake unchanged)");
    } else {
        println!("Bonding {} as validator stake (from your PUBLIC balance)", lat(amount));
    }
    submit(node, &tx, "stake")
}

fn cmd_unstake(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let amount = require_amount(flags)?;
    let nonce = nonce_of(node, &w)?;
    let tx = w.unstake_tx(amount, nonce);
    println!("Unbonding {} (released after the unbonding window; claim with `stake --amount 0`)", lat(amount));
    submit(node, &tx, "unstake")
}

fn cmd_staking(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let (staked, unbonding) = lat_p2p::get_stake(node, w.id()).map_err(net_err(node))?;
    println!("Bonded stake : {}", lat(staked));
    if unbonding.is_empty() {
        println!("Unbonding    : none");
    } else {
        for (amount, release) in unbonding {
            println!("Unbonding    : {} (releases at height {release})", lat(amount));
        }
    }
    Ok(())
}

fn cmd_send(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let receiver = require_addr(flags)?;
    let amount = require_amount(flags)?;
    let fee = fee_from(flags)?;

    let bal_bytes = lat_p2p::get_balance(node, w.id(), LAT_TOKEN)
        .map_err(net_err(node))?
        .ok_or("your account isn't registered yet — run `register`")?;
    let balance_ct = Ciphertext::from_bytes(&bal_bytes).ok_or("bad balance ciphertext")?;
    let nonce = nonce_of(node, &w)?;

    let tx = w
        .build_transfer(&receiver, LAT_TOKEN, amount, fee, &balance_ct, nonce, &mut OsRng)
        .ok_or("cannot build transfer — insufficient private balance (amount + fee) or unreadable")?;
    println!("Sending {} privately (fee {})", lat(amount), lat(fee));
    submit(node, &tx, "transfer")
}

fn cmd_anon_send(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let receiver = require_addr(flags)?;
    let amount = require_amount(flags)?;
    let fee = fee_from(flags)?;
    let ring_size: usize = flags
        .get("ring")
        .map(|s| s.parse().map_err(|_| "bad --ring".to_string()))
        .transpose()?
        .unwrap_or(lat_wallet::DEFAULT_RING_SIZE);

    let bal_bytes = lat_p2p::get_balance(node, w.id(), LAT_TOKEN)
        .map_err(net_err(node))?
        .ok_or("your account isn't registered yet — run `register`")?;
    let balance_ct = Ciphertext::from_bytes(&bal_bytes).ok_or("bad balance ciphertext")?;

    // The decoy pool and the epoch of the block expected to include the spend.
    let raw = lat_p2p::get_ring_candidates(node, LAT_TOKEN, 64).map_err(net_err(node))?;
    let candidates: Vec<([u8; 32], Ciphertext)> = raw
        .iter()
        .filter_map(|(id, ct)| Ciphertext::from_bytes(ct).map(|c| (*id, c)))
        .collect();
    let epoch = lat_chain::epoch_of(lat_p2p::get_height(node).map_err(net_err(node))? + 1);

    let tx = w
        .build_anon_transfer(&receiver, LAT_TOKEN, amount, fee, &balance_ct, &candidates, epoch, ring_size, &mut OsRng)
        .ok_or("cannot build anonymous transfer — insufficient private balance, or not enough other accounts on-chain to hide among")?;
    let ring = match &tx {
        lat_types::Transaction::AnonTransfer { xfer, .. } => xfer.ring.len(),
        _ => 0,
    };
    println!(
        "Sending {} anonymously — you hide among {ring} accounts; the receiver is a one-time stealth address (amount is public; fee {}).",
        lat(amount), lat(fee)
    );
    println!("Note: one anonymous spend per epoch ({} blocks); if it misses the epoch, just resend.", lat_chain::EPOCH_BLOCKS);
    submit(node, &tx, "anonymous transfer")
}

fn cmd_public_send(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let receiver = require_addr(flags)?;
    let amount = require_amount(flags)?;
    let fee = fee_from(flags)?;
    let nonce = nonce_of(node, &w)?;
    let tx = w.build_public_transfer(&receiver, LAT_TOKEN, amount, fee, nonce);
    println!("Public transfer {} (transparent, fee {})", lat(amount), lat(fee));
    submit(node, &tx, "public transfer")
}

fn cmd_shield(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    // Default: shield to yourself ("make my LAT private"); --to shields to someone.
    let receiver = match flags.get("to") {
        Some(a) => Address::parse(a).map_err(|_| "invalid recipient address".to_string())?,
        None => w.address(),
    };
    let amount = require_amount(flags)?;
    let fee = fee_from(flags)?;
    let nonce = nonce_of(node, &w)?;
    let tx = w.build_shield(&receiver, LAT_TOKEN, amount, fee, nonce);
    println!("Shielding {} (public → private, fee {})", lat(amount), lat(fee));
    submit(node, &tx, "shield")
}

fn cmd_shield_stealth(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let recipient = require_addr(flags)?;
    let amount = require_amount(flags)?;
    let fee = fee_from(flags)?;
    let nonce = nonce_of(node, &w)?;
    let tx = w.build_shield_stealth(&recipient, LAT_TOKEN, amount, fee, nonce, &mut OsRng);
    println!("Stealth-shielding {} (public → private, recipient hidden on-chain, fee {})", lat(amount), lat(fee));
    submit(node, &tx, "stealth shield")
}

fn cmd_unshield(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let dest = require_addr(flags)?;
    let amount = require_amount(flags)?;
    let fee = fee_from(flags)?;

    let bal_bytes = lat_p2p::get_balance(node, w.id(), LAT_TOKEN)
        .map_err(net_err(node))?
        .ok_or("your account isn't registered yet — run `register`")?;
    let balance_ct = Ciphertext::from_bytes(&bal_bytes).ok_or("bad balance ciphertext")?;
    let nonce = nonce_of(node, &w)?;

    let tx = w
        .build_unshield(&dest, LAT_TOKEN, amount, fee, &balance_ct, nonce, &mut OsRng)
        .ok_or("cannot build unshield — insufficient private balance (amount + fee) or unreadable")?;
    println!("Unshielding {} (private → public, fee {})", lat(amount), lat(fee));
    submit(node, &tx, "unshield")
}

fn cmd_scan_stealth(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let height = lat_p2p::get_height(node).map_err(net_err(node))?;
    let from: u64 = flags.get("from").and_then(|s| s.parse().ok()).unwrap_or(1);

    let (mut found, mut total) = (0u64, 0u64);
    for h in from..=height {
        let bytes = match lat_p2p::get_block(node, h).map_err(net_err(node))? {
            Some(b) => b,
            None => continue,
        };
        for r in w.scan_stealth_bytes(&bytes) {
            let addr = PublicKey::from_bytes(&r.one_time)
                .map(|pk| Address::new(network, pk).encode())
                .unwrap_or_else(|| "<one-time>".to_string());
            println!("  block {h}: received {} at one-time address {}", lat(r.amount), addr);
            found += 1;
            total += r.amount;
        }
    }
    if found == 0 {
        println!("No stealth funds found for this wallet in blocks {from}..={height}.");
    } else {
        println!("Found {found} stealth payment(s), total {}.", lat(total));
        println!("(These are held in one-time accounts only this wallet can derive; CLI claiming is a follow-up.)");
    }
    Ok(())
}

fn submit(node: &str, tx: &lat_types::Transaction, what: &str) -> Result<(), String> {
    let ok = lat_p2p::submit_tx(node, &tx.encode()).map_err(net_err(node))?;
    if ok {
        println!("{what} submitted to {node}. It will confirm once a block is mined.");
        Ok(())
    } else {
        Err(format!("{what} was rejected (duplicate or invalid)"))
    }
}

fn net_err(node: &str) -> impl Fn(std::io::Error) -> String + '_ {
    move |_| format!("could not reach a node at {node} (is latebrad running?)")
}

fn lat(units: u64) -> String {
    format!("{}.{:05} LAT", units / UNITS, units % UNITS)
}

fn parse_lat(s: &str) -> Result<u64, String> {
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    let int: u64 = int.parse().map_err(|_| "bad amount".to_string())?;
    let mut frac = frac.to_string();
    frac.truncate(5);
    while frac.len() < 5 {
        frac.push('0');
    }
    let frac: u64 = if frac.is_empty() { 0 } else { frac.parse().map_err(|_| "bad amount".to_string())? };
    Ok(int * UNITS + frac)
}

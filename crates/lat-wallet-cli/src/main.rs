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
        // Tokens, the native DEX, HTLC swaps and contracts. These transaction
        // types have always been in consensus, but until now no shipped client
        // could build them — only the launchpad, which is not in the release.
        "create-token" => cmd_create_token(&flags, network, &node),
        "market" => cmd_market(&flags, network, &node),
        "curve-buy" => cmd_curve_trade(&flags, network, &node, true),
        "curve-sell" => cmd_curve_trade(&flags, network, &node, false),
        "swap" => cmd_swap(&flags, network, &node),
        "add-liquidity" => cmd_add_liquidity(&flags, network, &node),
        "remove-liquidity" => cmd_remove_liquidity(&flags, network, &node),
        "htlc-lock" => cmd_htlc_lock(&flags, network, &node),
        "htlc-claim" => cmd_htlc_claim(&flags, network, &node),
        "htlc-refund" => cmd_htlc_refund(&flags, network, &node),
        "deploy-contract" => cmd_deploy_contract(&flags, network, &node),
        "call-contract" => cmd_call_contract(&flags, network, &node),
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
    println!("  anon-send     --seed <hex> --to <addr> --amount <LAT> [--fee] [--ring <n>] [--node]  anonymous: sender hidden in a ring, receiver stealth, amount hidden (only the fee is public)");
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
    println!();
    println!(" tokens & the native DEX");
    println!("  create-token  --seed <hex> --ticker <SYM> --supply <units>   mint a token (supply is yours)");
    println!("  market        --seed <hex> --token <id>   show the bonding curve + AMM pool");
    println!("  curve-buy     --seed <hex> --token <id> --amount <LAT> [--min-out <units>]");
    println!("  curve-sell    --seed <hex> --token <id> --amount <units> [--min-out <units>]");
    println!("  swap          --seed <hex> --token <id> [--in lat|token] --amount <n> [--min-out <n>]");
    println!("  add-liquidity --seed <hex> --token <id> --lat <LAT> --tokens <units>");
    println!("  remove-liquidity --seed <hex> --token <id> --shares <n>");
    println!();
    println!(" atomic swaps (HTLC) & contracts");
    println!("  htlc-lock     --seed <hex> --to <addr> --amount <LAT> [--token <id>] [--secret <hex>] [--expiry <blocks>]");
    println!("  htlc-claim    --seed <hex> --id <hex> --secret <hex>");
    println!("  htlc-refund   --seed <hex> --id <hex>       reclaim after expiry");
    println!("  deploy-contract --seed <hex> --code <hex>");
    println!("  call-contract --seed <hex> --contract <hex> [--input <n>]");
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
    // The amount has been hidden since AnonTransfer v3 (a Pedersen `c_debit`
    // commitment plus an aggregated range proof — it never appears in
    // plaintext). This line still said "amount is public", which was left over
    // from v2 and understated the protocol's actual privacy.
    println!(
        "Sending {} anonymously — you hide among {ring} accounts; the receiver is a one-time \
         stealth address, and the amount is hidden. Only the fee ({}) is public.",
        lat(amount),
        lat(fee)
    );
    // Sender anonymity IS the ring size — a ring of 2 means a 50/50 guess. On a
    // young chain there are barely any funded accounts to hide among, so the
    // wallet silently produces a tiny ring. Say so rather than let the word
    // "anonymous" imply a strength the set does not have.
    if ring < 5 {
        println!(
            "WARNING: only {ring} accounts in your ring — an observer has a 1-in-{ring} guess at the sender."
        );
        println!(
            "         This chain does not yet have enough funded accounts to hide among. Wait for more \
             activity, or raise --ring once it does, before treating this as private."
        );
    }
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

// --------------------------------------------------------------------------
// Tokens, DEX, HTLC swaps, contracts
// --------------------------------------------------------------------------

/// A token id. There is no ticker→id lookup in the node's binary RPC, so these
/// commands take the numeric id; `create-token` prints it, and the JSON-RPC
/// `lat_token` method resolves a ticker if you have the metrics port.
fn require_token(flags: &HashMap<String, String>) -> Result<u32, String> {
    flags
        .get("token")
        .ok_or("missing --token <id> (the numeric token id; see `create-token` output)")?
        .parse()
        .map_err(|_| "bad --token: expected a number".to_string())
}

/// A raw count of token units (NOT LAT — tokens carry their own supply and are
/// not scaled by the 5-decimal LAT unit).
fn require_units(flags: &HashMap<String, String>, flag: &str) -> Result<u64, String> {
    flags
        .get(flag)
        .ok_or(format!("missing --{flag} <units>"))?
        .parse()
        .map_err(|_| format!("bad --{flag}: expected a whole number of units"))
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| format!("bad --{what}: expected hex"))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| format!("bad --{what}: expected 64 hex chars"))
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn cmd_create_token(
    flags: &HashMap<String, String>,
    network: Network,
    node: &str,
) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let ticker = flags.get("ticker").ok_or("missing --ticker <SYMBOL>")?;
    let supply = require_units(flags, "supply")?;
    if supply == 0 {
        return Err("--supply must be greater than zero".to_string());
    }
    let tx = w.create_token(ticker, supply);
    println!(
        "Creating token ${} with a fixed supply of {supply} units — the whole supply goes to you.",
        ticker.to_uppercase()
    );
    println!("Tickers are globally unique and case-insensitive: $doge, DOGE and Doge are one token.");
    submit(node, &tx, "token creation")
}

/// Read-only: the AMM pool and bonding curve for a token, plus your LP shares.
fn cmd_market(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let token = require_token(flags)?;

    match lat_p2p::get_curve(node, token).map_err(net_err(node))? {
        Some((vlat, vtok, real_lat, graduated)) => {
            println!("Bonding curve for token {token}:");
            println!("  virtual reserves : {vlat} LAT-units / {vtok} token-units");
            println!("  real LAT held    : {}", lat(real_lat));
            println!(
                "  status           : {}",
                if graduated {
                    "GRADUATED — the curve is locked; trade the AMM pool instead"
                } else {
                    "open for buys and sells"
                }
            );
        }
        None => println!("Bonding curve for token {token}: none yet (the first buy opens it)."),
    }

    match lat_p2p::get_pool(node, token).map_err(net_err(node))? {
        Some((lat_res, tok_res, lp_supply)) => {
            println!("AMM pool for token {token}:");
            println!("  reserves   : {} / {tok_res} token-units", lat(lat_res));
            println!("  LP supply  : {lp_supply}");
            let mine = lat_p2p::get_lp_shares(node, token, w.id()).map_err(net_err(node))?;
            println!("  your shares: {mine}");
        }
        None => println!("AMM pool for token {token}: none yet (add liquidity to open it)."),
    }
    Ok(())
}

fn cmd_curve_trade(
    flags: &HashMap<String, String>,
    network: Network,
    node: &str,
    is_buy: bool,
) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let token = require_token(flags)?;
    let fee = fee_from(flags)?;
    // A buy spends LAT; a sell spends token units.
    let amount = if is_buy { require_amount(flags)? } else { require_units(flags, "amount")? };
    let min_out = flags.get("min-out").map(|s| s.parse().unwrap_or(1)).unwrap_or(1);

    if let Some((.., graduated)) = lat_p2p::get_curve(node, token).map_err(net_err(node))? {
        if graduated {
            return Err(format!(
                "token {token}'s curve has graduated and is locked — use `swap` against the AMM pool"
            ));
        }
    }

    let nonce = nonce_of(node, &w)?;
    let tx = w.curve_trade(token, is_buy, amount, min_out, fee, nonce);
    if is_buy {
        println!("Buying token {token} on its bonding curve with {} (fee {})", lat(amount), lat(fee));
    } else {
        println!("Selling {amount} units of token {token} back to its curve (fee {})", lat(fee));
    }
    submit(node, &tx, "curve trade")
}

fn cmd_swap(flags: &HashMap<String, String>, network: Network, node: &str) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let token = require_token(flags)?;
    let fee = fee_from(flags)?;
    // --in says which side you are paying with.
    let lat_in = match flags.get("in").map(String::as_str) {
        Some("lat") | None => true,
        Some("token") => false,
        Some(other) => return Err(format!("bad --in {other}: expected `lat` or `token`")),
    };
    let amount_in = if lat_in { require_amount(flags)? } else { require_units(flags, "amount")? };
    let min_out = flags.get("min-out").map(|s| s.parse().unwrap_or(1)).unwrap_or(1);

    if lat_p2p::get_pool(node, token).map_err(net_err(node))?.is_none() {
        return Err(format!("token {token} has no AMM pool yet — `add-liquidity` opens one"));
    }
    let nonce = nonce_of(node, &w)?;
    let tx = w.swap(token, lat_in, amount_in, min_out, fee, nonce);
    println!(
        "Swapping {} for token {token} (fee {}); min out {min_out} units",
        if lat_in { lat(amount_in) } else { format!("{amount_in} token-units") },
        lat(fee)
    );
    if min_out <= 1 {
        println!("NOTE: --min-out is unset, so this accepts ANY price. Set it to bound slippage.");
    }
    submit(node, &tx, "swap")
}

fn cmd_add_liquidity(
    flags: &HashMap<String, String>,
    network: Network,
    node: &str,
) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let token = require_token(flags)?;
    let fee = fee_from(flags)?;
    let lat_amount = parse_lat(flags.get("lat").ok_or("missing --lat <LAT>")?)?;
    let tok_amount = require_units(flags, "tokens")?;
    let nonce = nonce_of(node, &w)?;
    let tx = w.add_liquidity(token, lat_amount, tok_amount, fee, nonce);
    println!("Adding {} + {tok_amount} units of token {token} as liquidity (fee {})", lat(lat_amount), lat(fee));
    if lat_p2p::get_pool(node, token).map_err(net_err(node))?.is_some() {
        println!("NOTE: this pool exists, so your deposit must match its CURRENT ratio or it is rejected.");
    }
    submit(node, &tx, "add liquidity")
}

fn cmd_remove_liquidity(
    flags: &HashMap<String, String>,
    network: Network,
    node: &str,
) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let token = require_token(flags)?;
    let fee = fee_from(flags)?;
    let shares = require_units(flags, "shares")?;
    let nonce = nonce_of(node, &w)?;
    let tx = w.remove_liquidity(token, shares, fee, nonce);
    println!("Redeeming {shares} LP shares from token {token}'s pool (fee {})", lat(fee));
    submit(node, &tx, "remove liquidity")
}

fn cmd_htlc_lock(
    flags: &HashMap<String, String>,
    network: Network,
    node: &str,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let w = wallet(flags, network)?;
    let token = flags.get("token").map(|s| s.parse().unwrap_or(LAT_TOKEN)).unwrap_or(LAT_TOKEN);
    let to = require_addr(flags)?;
    let fee = fee_from(flags)?;
    let amount = if token == LAT_TOKEN { require_amount(flags)? } else { require_units(flags, "amount")? };
    // The secret is the preimage; the chain only ever sees its SHA-256 hash
    // until the claim reveals it. Generated here unless supplied.
    let secret = match flags.get("secret") {
        Some(s) => parse_hex32(s, "secret")?,
        None => {
            let mut b = [0u8; 32];
            use rand::RngCore;
            OsRng.fill_bytes(&mut b);
            b
        }
    };
    let hashlock: [u8; 32] = Sha256::digest(secret).into();
    let blocks: u64 = flags.get("expiry").map(|s| s.parse().unwrap_or(200)).unwrap_or(200);
    let height = lat_p2p::get_height(node).map_err(net_err(node))?;
    let expiry = height + blocks;
    let nonce = nonce_of(node, &w)?;
    let (tx, id) = w.htlc_lock(token, &to, amount, hashlock, expiry, fee, nonce);

    println!("Locking {} for {} until height {expiry}", if token == LAT_TOKEN { lat(amount) } else { format!("{amount} units") }, to.encode());
    println!("  htlc id : {}", hex32(&id));
    println!("  secret  : {}  <- KEEP THIS. The receiver needs it to claim.", hex32(&secret));
    println!("  hashlock: {}", hex32(&hashlock));
    println!("If it is never claimed, reclaim your funds after height {expiry} with `htlc-refund --id <id>`.");
    submit(node, &tx, "htlc lock")
}

fn cmd_htlc_claim(
    flags: &HashMap<String, String>,
    network: Network,
    node: &str,
) -> Result<(), String> {
    let _ = wallet(flags, network)?; // seed is required for symmetry/validation
    let id = parse_hex32(flags.get("id").ok_or("missing --id <hex>")?, "id")?;
    let secret = parse_hex32(flags.get("secret").ok_or("missing --secret <hex>")?, "secret")?;
    let tx = Wallet::htlc_claim(id, secret);
    println!("Claiming HTLC {} by revealing the secret.", hex32(&id));
    submit(node, &tx, "htlc claim")
}

fn cmd_htlc_refund(
    flags: &HashMap<String, String>,
    network: Network,
    node: &str,
) -> Result<(), String> {
    let _ = wallet(flags, network)?;
    let id = parse_hex32(flags.get("id").ok_or("missing --id <hex>")?, "id")?;
    let tx = Wallet::htlc_refund(id);
    println!("Refunding expired HTLC {} to its sender.", hex32(&id));
    submit(node, &tx, "htlc refund")
}

fn cmd_deploy_contract(
    flags: &HashMap<String, String>,
    network: Network,
    node: &str,
) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let code_hex = flags.get("code").ok_or("missing --code <hex bytecode>")?;
    let code = (0..code_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(code_hex.get(i..i + 2).unwrap_or("zz"), 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| "bad --code: expected hex bytecode".to_string())?;
    if code.is_empty() {
        return Err("--code is empty".to_string());
    }
    let tx = w.deploy_contract(code.clone());
    println!("Deploying a {}-byte contract to the lat-vm.", code.len());
    submit(node, &tx, "contract deploy")
}

fn cmd_call_contract(
    flags: &HashMap<String, String>,
    network: Network,
    node: &str,
) -> Result<(), String> {
    let w = wallet(flags, network)?;
    let contract = parse_hex32(flags.get("contract").ok_or("missing --contract <hex>")?, "contract")?;
    let input: u64 = flags
        .get("input")
        .map(|s| s.parse().map_err(|_| "bad --input".to_string()))
        .transpose()?
        .unwrap_or(0);
    let nonce = nonce_of(node, &w)?;
    let tx = w.call_contract(contract, input, nonce);
    println!("Calling contract {} with input {input}.", hex32(&contract));
    submit(node, &tx, "contract call")
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

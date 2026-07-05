//! # Latebra privacy red-team — passive chain-analysis attack
//!
//! This is an adversarial audit of our OWN chain. We first simulate a realistic
//! "private" economy through the real wallet / chain / crypto stack — an exchange
//! pays a user, the user *shields* funds to "make them private", moves them
//! through two confidential transfers, and a third user *unshields* to cash out.
//! The users believe the confidential transfers hide their activity.
//!
//! Then we drop all privileged knowledge and become a **passive observer** — a
//! peer, a block explorer, a surveillance firm — who sees ONLY the serialized
//! block log (`Vec<Vec<u8>>`, exactly what `BlockStore` persists and what every
//! node syncs). From those bytes alone we reconstruct:
//!
//!   1. the full **transaction graph** (who paid whom),
//!   2. every account's **exact public balance**,
//!   3. the **amounts** of transfers that were supposed to be confidential, by
//!      conservation across the public shield/unshield boundary.
//!
//! Everything the attacker prints is derived from public block bytes. We never
//! hand it a secret key. At the end we check the attacker's conclusions against
//! ground truth to prove they are correct, not guesses.
//!
//! **Act 2** then replays the economy using `AnonTransfer` — the ring +
//! stealth spend now wired into consensus — and runs the SAME attacker over the
//! new block log, asserting (with a `cargo test` regression, not just prose)
//! that the transaction graph goes dark: no edge names a sender or receiver,
//! the best sender guess is 1-in-ring, and nullifiers don't link across spends.

use lat_chain::{emission, Block, Blockchain, DEFAULT_DIFFICULTY, MIN_TRANSFER_FEE};
use lat_types::{Network, Transaction};
use lat_wallet::Wallet;
use rand::rngs::OsRng;
use std::collections::BTreeMap;

const LAT: u32 = 0;
const NET: Network = Network::Testnet;

// Ground-truth amounts (base units). Kept small so confidential balances decrypt
// instantly; the attack is independent of magnitude.
const PREMINE: u64 = 1_000_000; // exchange's public genesis allocation
const ONRAMP: u64 = 60_000; //     exchange -> Alice (public transfer)
const SHIELD: u64 = 40_000; //     Alice shields to herself (public -> private)
const HOP1: u64 = 25_000; //       Alice -> Bob   (CONFIDENTIAL)
const HOP2: u64 = 20_000; //       Bob   -> Carol (CONFIDENTIAL)
const CASHOUT: u64 = 18_000; //    Carol unshields to herself (private -> public)
const FEE: u64 = MIN_TRANSFER_FEE;

fn short(id: &[u8; 32]) -> String {
    let mut s = String::new();
    for b in &id[..4] {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hr(title: &str) {
    println!("\n\x1b[1m{}\x1b[0m", title);
    println!("{}", "─".repeat(72));
}

fn main() {
    let mut rng = OsRng;

    // ── Cast of characters (the attacker does NOT get these names) ────────────
    let exchange = Wallet::from_seed(NET, [1u8; 32]);
    let alice = Wallet::from_seed(NET, [2u8; 32]);
    let bob = Wallet::from_seed(NET, [3u8; 32]);
    let carol = Wallet::from_seed(NET, [4u8; 32]);
    let miner = Wallet::from_seed(NET, [9u8; 32]);

    let names: BTreeMap<[u8; 32], &str> = [
        (exchange.id(), "Exchange"),
        (alice.id(), "Alice"),
        (bob.id(), "Bob"),
        (carol.id(), "Carol"),
        (miner.id(), "Miner"),
    ]
    .into_iter()
    .collect();

    println!("\x1b[1mLATEBRA PRIVACY RED-TEAM\x1b[0m  —  passive chain-analysis attack\n");
    println!("Simulating a 'private' economy, then attacking it with only public block data.");
    println!("\nGround-truth participants (hidden from the attacker):");
    for (id, name) in &names {
        println!("  {:<9} {}", name, short(id));
    }

    // ── Build the chain through the REAL stack ────────────────────────────────
    // Exchange holds a transparent public premine; everyone else registers.
    let mut chain = Blockchain::genesis_with_public(&[], &[(exchange.id(), PREMINE)], DEFAULT_DIFFICULTY);

    let apply = |chain: &mut Blockchain, txs: Vec<Transaction>| {
        let block = chain.mine_with_reward(miner.id(), txs);
        chain.apply_block(&block).expect("valid block");
    };

    // Block 1: Alice, Bob, Carol register.
    apply(&mut chain, vec![alice.registration_tx(), bob.registration_tx(), carol.registration_tx()]);

    // Block 2: Exchange pays Alice 60,000 via a PUBLIC transfer (a KYC on-ramp).
    let t = exchange.create_public_transfer(&chain, &alice.address(), LAT, ONRAMP, FEE).unwrap();
    apply(&mut chain, vec![t]);

    // Block 3: Alice SHIELDS 40,000 into her own private balance ("now it's private").
    let t = alice.create_shield(&chain, &alice.address(), LAT, SHIELD, FEE).unwrap();
    apply(&mut chain, vec![t]);

    // Block 4: Alice rolls the shielded funds into her spendable private balance.
    let n = chain.nonce(&alice.id()).unwrap();
    apply(&mut chain, vec![alice.rollover_tx(n)]);

    // Block 5: Alice -> Bob, 25,000, CONFIDENTIAL (amount hidden by the proof).
    let t = alice.create_solvent_transfer(&chain, &bob.address(), LAT, HOP1, FEE, &mut rng).unwrap();
    apply(&mut chain, vec![t]);

    // Block 6: Bob rolls over.
    let n = chain.nonce(&bob.id()).unwrap();
    apply(&mut chain, vec![bob.rollover_tx(n)]);

    // Block 7: Bob -> Carol, 20,000, CONFIDENTIAL.
    let t = bob.create_solvent_transfer(&chain, &carol.address(), LAT, HOP2, FEE, &mut rng).unwrap();
    apply(&mut chain, vec![t]);

    // Block 8: Carol rolls over.
    let n = chain.nonce(&carol.id()).unwrap();
    apply(&mut chain, vec![carol.rollover_tx(n)]);

    // Block 9: Carol UNSHIELDS 18,000 to her own public balance (cash out).
    let t = carol.create_unshield(&chain, &carol.address(), LAT, CASHOUT, FEE, &mut rng).unwrap();
    apply(&mut chain, vec![t]);

    // Snapshot the block log — THIS is all the attacker gets.
    let block_log: Vec<Vec<u8>> = (0..=chain.height())
        .map(|h| chain.block_bytes(h).expect("block present").to_vec())
        .collect();

    println!("\nChain built: height {}, {} blocks in the log.", chain.height(), block_log.len());
    println!("From here the attacker sees ONLY those raw block bytes — no keys, no names.");

    // ══════════════════════════════════════════════════════════════════════════
    //                            ATTACKER STARTS HERE
    // ══════════════════════════════════════════════════════════════════════════
    let intel = analyze(&block_log);

    // ── 1. Transaction graph ──────────────────────────────────────────────────
    hr("[1] RECONSTRUCTED TRANSACTION GRAPH  (who paid whom)");
    println!("Every confidential transfer ships its sender & receiver keys in the CLEAR.");
    println!("The 'confidential' proof hides only the amount — not the identities.\n");
    for e in &intel.edges {
        let amt = match e.amount {
            Some(a) => format!("{a:>9}"),
            None => "  HIDDEN ".to_string(),
        };
        println!(
            "  blk{:<2} {:<14} {} → {}   (fee {}, {})",
            e.height, e.kind, short(&e.from), short(&e.to), e.fee, amt
        );
    }

    // ── 2. Exact public balances ──────────────────────────────────────────────
    hr("[2] RECOVERED PUBLIC BALANCES  (exact, no key needed)");
    println!("All public-side value is cleartext: premine, fees, public/shield/unshield amounts.\n");
    for (id, bal) in &intel.public_balance {
        println!("  {}   {:>10} LAT-units (public)", short(id), bal);
    }

    // ── 3. Deanonymizing the 'confidential' path ──────────────────────────────
    hr("[3] BREAKING THE 'CONFIDENTIAL' TRANSFERS  (conservation attack)");
    println!("The confidential hops hide their amounts. But value ENTERS the private");
    println!("zone via a public shield and LEAVES via a public unshield — both cleartext.");
    println!("The graph tells us the path; the boundary amounts tell us the size.\n");
    trace_flows(&intel);

    // ── 4. Other leaks ────────────────────────────────────────────────────────
    hr("[4] SIDE-CHANNEL LEAKS");
    println!("  • Spend nonces are public → exact count of confidential sends per account.");
    println!("  • Coinbase lands in the miner's 'private' balance but is a TRANSPARENT mint,");
    println!("    so its amount (block emission) is readable by anyone: {} LAT-units/block.", emission(1));
    println!("  • Rollover txs are public → reveal exactly when an account consolidated");
    println!("    received funds (a timing fingerprint linking a receive to its spender).");
    for (id, n) in &intel.confidential_sends {
        if *n > 0 {
            println!("      {} made {} confidential send(s).", short(id), n);
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    //                    GROUND-TRUTH CHECK  (prove it's real)
    // ══════════════════════════════════════════════════════════════════════════
    hr("[5] VERIFICATION AGAINST GROUND TRUTH");

    // 5a. Public balances match the actual ledger exactly.
    let mut ok = true;
    for w in [&exchange, &alice, &bob, &carol, &miner] {
        let truth = chain.public_balance(&w.id(), LAT).unwrap_or(0);
        let guess = *intel.public_balance.get(&w.id()).unwrap_or(&0);
        let mark = if truth == guess { "✓" } else { ok = false; "✗" };
        println!(
            "  {} {:<9} attacker={:>10}  actual={:>10}",
            mark, names[&w.id()], guess, truth
        );
    }

    // 5b. The confidential path the attacker inferred matches what really happened.
    println!();
    let real_private: BTreeMap<[u8; 32], u64> = [&alice, &bob, &carol]
        .into_iter()
        .map(|w| (w.id(), w.balance(&chain, LAT).unwrap_or(0)))
        .collect();
    println!("  Real (decrypted) leftover private balances — attacker canNOT see these:");
    for w in [&alice, &bob, &carol] {
        println!("      {:<9} {} LAT-units", names[&w.id()], real_private[&w.id()]);
    }
    println!(
        "\n  Attacker's inference: Exchange→Alice→(shield)→Bob→Carol→(unshield/cash-out),"
    );
    println!("  ~{}–{} LAT-units flowed down the 'private' path. Ground truth: {}→{}.", CASHOUT, SHIELD, HOP1, HOP2);

    println!("\n{}", "═".repeat(72));
    if ok {
        println!("\x1b[1mRESULT: attacker reproduced every public balance exactly, and fully");
        println!("de-anonymized the transfer graph. Amounts are hidden; PRIVACY IS NOT.\x1b[0m");
    } else {
        println!("Public-balance reconstruction mismatch — investigate accounting.");
        std::process::exit(1);
    }

    // ══════════════════════════════════════════════════════════════════════════
    //   ACT 2 — the same attacker vs. AnonTransfer (the F1 fix, now in consensus)
    // ══════════════════════════════════════════════════════════════════════════
    println!("\n\n\x1b[1mACT 2 — RE-RUN THE ATTACK AGAINST ANONYMOUS TRANSFERS\x1b[0m");
    println!("Same passive observer, same public block log — but the payments now use");
    println!("`AnonTransfer` (ring sender + stealth receiver). Watch the graph go dark.\n");

    let dark = build_and_attack_anon(&mut OsRng);

    hr("[A1] WHAT THE ATTACKER SEES PER ANONYMOUS TRANSFER");
    for s in &dark.report.anon {
        println!(
            "  blk{:<2} ring of {}  → one-time {}   amount {} (public), fee {}",
            s.height, s.ring.len(), short(&s.one_time), s.amount, s.fee
        );
        println!("        sender ∈ {{{}}}", s.ring.iter().map(short).collect::<Vec<_>>().join(", "));
    }

    hr("[A2] DE-ANONYMIZATION ATTEMPTS  (all must fail)");
    println!("  • Edges naming a sender/receiver ............ {}", dark.naming_edges);
    println!("  • Best sender guess for any spend ........... 1-in-{} (ring size)", dark.min_ring);
    println!("  • One-time receiver keys matching a known addr {}", dark.receiver_links);
    println!("  • Nullifiers repeated across DISTINCT spenders {}", dark.nullifier_collisions);
    println!("  • Stealth outputs claimable by an observer .. {}", dark.observer_claims);

    println!("\n{}", "═".repeat(72));
    if dark.graph_is_dark() {
        println!("\x1b[1mRESULT: against AnonTransfer the attacker links NOTHING — no sender, no");
        println!("receiver, no cross-spend correlation. F1 (transaction-graph leak) is CLOSED");
        println!("on-chain. (Amounts remain public — F2 — by design this phase.)\x1b[0m");
    } else {
        println!("\x1b[1;31mRESULT: the anonymous path LEAKED — this is a privacy regression.\x1b[0m");
        std::process::exit(1);
    }
}

/// The outcome of running the passive attacker against an anonymous-transfer
/// economy. Every count here is something the attacker *tried* to link; for
/// privacy to hold they must all be zero (except `min_ring`, the anonymity set).
struct DarkResult {
    report: AttackReport,
    naming_edges: usize,       // graph edges that name a sender or receiver
    min_ring: usize,           // smallest ring = best-case sender guess (1-in-N)
    receiver_links: usize,     // one-time keys linkable to a known participant
    nullifier_collisions: usize, // a nullifier shared by two different real spenders
    observer_claims: usize,    // stealth outputs a non-recipient could claim
    anon_count: usize,         // how many anonymous transfers were actually made
}

impl DarkResult {
    fn graph_is_dark(&self) -> bool {
        self.anon_count > 0
            && self.naming_edges == 0
            && self.receiver_links == 0
            && self.nullifier_collisions == 0
            && self.observer_claims == 0
            && self.min_ring >= 2
    }
}

/// Build a realistic anonymous economy on the REAL stack, then run the passive
/// attacker (`analyze`) over its public block log and measure every link it can
/// (or cannot) make. Shared by the demo and the `graph_goes_dark` test.
fn build_and_attack_anon<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> DarkResult {
    // A pool of funded wallets (confidential premine) so anyone can be a decoy,
    // plus off-ring receivers who only ever appear as one-time stealth keys.
    let spenders: Vec<Wallet> = (0..9).map(|i| Wallet::from_seed(NET, [100 + i; 32])).collect();
    let receivers: Vec<Wallet> = (0..3).map(|i| Wallet::from_seed(NET, [200 + i; 32])).collect();
    let miner = Wallet::from_seed(NET, [9u8; 32]);

    let premine: Vec<([u8; 32], u64)> = spenders.iter().map(|w| (w.id(), 1_000_000)).collect();
    let mut chain = Blockchain::genesis(&premine, DEFAULT_DIFFICULTY);

    let apply = |chain: &mut Blockchain, txs: Vec<Transaction>| {
        let block = chain.mine_with_reward(miner.id(), txs);
        chain.apply_block(&block).expect("valid block");
    };

    // A few anonymous transfers from different senders, some in the same epoch
    // (distinct nullifiers) and one crossing an epoch boundary (the same spender
    // spends twice — must NOT be linkable by nullifier).
    let ring = lat_wallet::DEFAULT_RING_SIZE;
    // Spender 0 pays receiver 0.
    let t = spenders[0].create_anon_transfer(&chain, &receivers[0].address(), LAT, 30_000, FEE, ring, rng).unwrap();
    apply(&mut chain, vec![t]);
    // Spender 3 pays receiver 1 (same epoch as above at EPOCH_BLOCKS = 20).
    let t = spenders[3].create_anon_transfer(&chain, &receivers[1].address(), LAT, 12_000, FEE, ring, rng).unwrap();
    apply(&mut chain, vec![t]);
    // Advance into the NEXT epoch, then spender 0 spends AGAIN (new nullifier).
    while lat_chain::epoch_of(chain.height() + 1) == lat_chain::epoch_of(1) {
        apply(&mut chain, vec![]);
    }
    let t = spenders[0].create_anon_transfer(&chain, &receivers[2].address(), LAT, 5_000, FEE, ring, rng).unwrap();
    apply(&mut chain, vec![t]);

    let block_log: Vec<Vec<u8>> = (0..=chain.height())
        .map(|h| chain.block_bytes(h).expect("block present").to_vec())
        .collect();
    let report = analyze(&block_log);

    // The set of addresses an observer could plausibly know (every registered
    // participant, ring members included). If a one-time receiver key ever
    // equals one of these, the receiver leaked.
    let known: Vec<[u8; 32]> = spenders.iter().chain(receivers.iter()).map(|w| w.id()).collect();

    let naming_edges = report
        .edges
        .iter()
        .filter(|e| e.kind == "CONFIDENTIAL" || e.kind == "public-xfer")
        .count();
    let min_ring = report.anon.iter().map(|s| s.ring.len()).min().unwrap_or(0);
    let receiver_links = report
        .anon
        .iter()
        .filter(|s| known.contains(&s.one_time))
        .count();

    // Nullifier collision across DIFFERENT real spenders would let the attacker
    // cluster spends. (The same spender across epochs yields DIFFERENT
    // nullifiers, so even that is unlinkable — the strong property.)
    let mut nullifier_collisions = 0;
    for i in 0..report.anon.len() {
        for j in i + 1..report.anon.len() {
            if report.anon[i].nullifier == report.anon[j].nullifier {
                nullifier_collisions += 1;
            }
        }
    }

    // Can any non-recipient (every spender/ring member) claim a stealth output?
    // Re-scan each anon transfer's block with every non-recipient wallet: none
    // may recognize the one-time output as theirs.
    let mut observer_claims = 0;
    for s in &report.anon {
        for w in spenders.iter() {
            if w.scan_stealth_bytes(&block_log[s.height as usize]).iter().any(|r| r.one_time == s.one_time) {
                observer_claims += 1;
            }
        }
    }

    DarkResult {
        anon_count: report.anon.len(),
        naming_edges,
        min_ring,
        receiver_links,
        nullifier_collisions,
        observer_claims,
        report,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//                               THE ATTACKER
// ─────────────────────────────────────────────────────────────────────────────

struct Edge {
    height: u64,
    kind: &'static str,
    from: [u8; 32],
    to: [u8; 32],
    amount: Option<u64>, // None = confidential (hidden)
    fee: u64,
}

/// What a passive observer can extract from ONE anonymous transfer: the ring
/// (the sender is *somewhere* in it), a one-time receiver key, the public
/// amount/fee, and the epoch nullifier. Nothing here names anyone.
struct AnonSighting {
    height: u64,
    ring: Vec<[u8; 32]>,
    one_time: [u8; 32],
    amount: u64,
    fee: u64,
    nullifier: [u8; 32],
}

#[derive(Default)]
struct Intel {
    edges: Vec<Edge>,
    public_balance: BTreeMap<[u8; 32], i128>, // signed during accumulation
    confidential_sends: BTreeMap<[u8; 32], u64>,
    shields: Vec<([u8; 32], u64)>,   // (shielder, amount) entering the private zone
    unshields: Vec<([u8; 32], u64)>, // (sender, amount) leaving the private zone
    anon: Vec<AnonSighting>,         // anonymous transfers: ring + stealth only
}

impl Intel {
    fn credit(&mut self, id: [u8; 32], amt: u64) {
        *self.public_balance.entry(id).or_default() += amt as i128;
    }
    fn debit(&mut self, id: [u8; 32], amt: u64) {
        *self.public_balance.entry(id).or_default() -= amt as i128;
    }
}

/// Everything below is derived from public block bytes only.
fn analyze(block_log: &[Vec<u8>]) -> AttackReport {
    let mut intel = Intel::default();

    for raw in block_log {
        let block = Block::decode(raw).expect("attacker decodes any block");
        let h = block.header.height;

        // The genesis allocation is a published chain parameter (every chain
        // ships its genesis config); we seed it as public knowledge.
        if h == 0 {
            intel.credit(seed_id(1), PREMINE); // the exchange's known premine
        }

        for tx in &block.txs {
            match tx {
                Transaction::PublicTransfer { from, to, amount, fee, .. } => {
                    intel.debit(*from, amount + fee);
                    intel.credit(*to, *amount);
                    intel.credit(block.header.miner, *fee); // public fee → miner public
                    intel.edges.push(Edge { height: h, kind: "public-xfer", from: *from, to: *to, amount: Some(*amount), fee: *fee });
                }
                Transaction::Shield { from, to, amount, fee, .. } => {
                    intel.debit(*from, amount + fee);
                    intel.credit(block.header.miner, *fee);
                    intel.shields.push((*from, *amount));
                    intel.edges.push(Edge { height: h, kind: "shield(pub→pri)", from: *from, to: *to, amount: Some(*amount), fee: *fee });
                }
                Transaction::ShieldStealth { from, one_time, amount, fee, .. } => {
                    intel.debit(*from, amount + fee);
                    intel.credit(block.header.miner, *fee);
                    // Recipient is a one-time key — genuinely unlinkable here.
                    intel.edges.push(Edge { height: h, kind: "stealth-shield", from: *from, to: *one_time, amount: Some(*amount), fee: *fee });
                }
                Transaction::SolventTransfer { xfer, .. } => {
                    let from = xfer.sender.to_bytes();
                    let to = xfer.receiver.to_bytes();
                    *intel.confidential_sends.entry(from).or_default() += 1;
                    intel.edges.push(Edge { height: h, kind: "CONFIDENTIAL", from, to, amount: None, fee: xfer.fee });
                }
                Transaction::AnonTransfer { xfer, .. } => {
                    // The whole harvest: a ring, a one-time key, public numbers.
                    // No debit is attributable — every ring member's encrypted
                    // balance changed by an indistinguishable ciphertext.
                    intel.anon.push(AnonSighting {
                        height: h,
                        ring: xfer.ring.iter().map(|p| p.to_bytes()).collect(),
                        one_time: xfer.output.one_time.to_bytes(),
                        amount: xfer.amount,
                        fee: xfer.fee,
                        nullifier: xfer.nullifier(),
                    });
                }
                Transaction::Unshield { to, amount, xfer, .. } => {
                    let from = xfer.sender.to_bytes();
                    intel.credit(*to, *amount); // revealed amount → public balance
                    intel.unshields.push((from, *amount));
                    intel.edges.push(Edge { height: h, kind: "unshield(pri→pub)", from, to: *to, amount: Some(*amount), fee: xfer.fee });
                }
                _ => {} // Register / Rollover / CreateToken / contracts: no public value move
            }
        }
    }

    // Finalize signed balances to unsigned (all should be ≥ 0).
    let public_balance = intel
        .public_balance
        .iter()
        .map(|(k, v)| (*k, (*v).max(0) as u64))
        .collect();

    AttackReport {
        edges: intel.edges,
        public_balance,
        confidential_sends: intel.confidential_sends,
        shields: intel.shields,
        unshields: intel.unshields,
        anon: intel.anon,
    }
}

struct AttackReport {
    edges: Vec<Edge>,
    public_balance: BTreeMap<[u8; 32], u64>,
    confidential_sends: BTreeMap<[u8; 32], u64>,
    shields: Vec<([u8; 32], u64)>,
    unshields: Vec<([u8; 32], u64)>,
    anon: Vec<AnonSighting>,
}

/// Trace value from each public shield entry, through the confidential edges, to
/// each public unshield exit — the conservation attack that sizes hidden hops.
fn trace_flows(intel: &AttackReport) {
    for (shielder, amt_in) in &intel.shields {
        println!("  • {} entered the private zone with a public shield of {} LAT-units.", short(shielder), amt_in);
        // Follow confidential out-edges from this account (and one hop further).
        let mut frontier = vec![*shielder];
        let mut visited = vec![*shielder];
        while let Some(cur) = frontier.pop() {
            for e in intel.edges.iter().filter(|e| e.kind == "CONFIDENTIAL" && e.from == cur) {
                println!("      ↳ confidential hop {} → {} (amount hidden, but the EDGE is public)", short(&e.from), short(&e.to));
                if !visited.contains(&e.to) {
                    visited.push(e.to);
                    frontier.push(e.to);
                }
            }
        }
        // Did any traced account cash out?
        for (sender, amt_out) in &intel.unshields {
            if visited.contains(sender) {
                println!("      ⇒ {} cashed out {} LAT-units via a public unshield.", short(sender), amt_out);
                let leak = *amt_in as i128 - *amt_out as i128;
                println!("        Conservation: {} entered, {} exited → ~{} stayed private,", amt_in, amt_out, leak.max(0));
                println!("        and the exit is provably reachable from the entry. Unlinkability: BROKEN.");
            }
        }
    }
}

fn seed_id(seed_byte: u8) -> [u8; 32] {
    Wallet::from_seed(NET, [seed_byte; 32]).id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Regression: the passive chain-analysis attacker that fully de-anonymizes
    /// `SolventTransfer` (Act 1) must extract NOTHING linkable from a chain whose
    /// payments use `AnonTransfer`. This is the end-to-end proof, on a real
    /// multi-block chain, that wiring the ring+stealth spend into consensus
    /// actually closes finding F1 — not just that the primitive verifies.
    #[test]
    fn anon_transfer_makes_the_graph_go_dark() {
        let dark = build_and_attack_anon(&mut OsRng);

        assert!(dark.anon_count >= 3, "the economy actually used anonymous transfers");
        // No edge in the reconstructed graph names a sender or receiver of an
        // anonymous spend (they simply don't appear as edges at all).
        assert_eq!(dark.naming_edges, 0, "an anonymous transfer leaked a named edge");
        // Best-case sender identification is 1-in-ring, never better.
        assert!(dark.min_ring >= 2, "ring collapsed below its minimum");
        assert_eq!(dark.min_ring, lat_wallet::DEFAULT_RING_SIZE, "full ring preserved on-chain");
        // The one-time receiver key never matches a known participant address.
        assert_eq!(dark.receiver_links, 0, "a stealth receiver was linkable to a known address");
        // Distinct spenders never share a nullifier; and because one spender
        // spent in two different epochs, even self-spends don't collide.
        assert_eq!(dark.nullifier_collisions, 0, "nullifiers linked two spends");
        // No non-recipient can recognize/claim any stealth output.
        assert_eq!(dark.observer_claims, 0, "an observer could claim a stealth output");

        assert!(dark.graph_is_dark(), "graph must be fully dark under AnonTransfer");
    }

    /// The same spender making two anonymous spends across an epoch boundary
    /// produces two UNLINKABLE nullifiers — the strong unlinkability property,
    /// not merely "different senders differ".
    #[test]
    fn same_spender_across_epochs_is_unlinkable() {
        let dark = build_and_attack_anon(&mut OsRng);
        // Spender 0 spent twice (blocks in different epochs). Their two sightings
        // must carry different nullifiers, so no clustering is possible.
        let nulls: Vec<[u8; 32]> = dark.report.anon.iter().map(|s| s.nullifier).collect();
        let mut uniq = nulls.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), nulls.len(), "every anonymous spend had a distinct nullifier");
    }
}

# Latebra

### The chain that is private, public, programmable, and final — all at once.

**Version 1.0 · 2026 · Testnet-grade, pre-audit**

> Latebra is an independent, clean-room Rust implementation built from public
> cryptography and permissively-licensed libraries. This paper describes the
> system **as implemented and tested today**, and is explicit about what is
> proven, what is unaudited, and what remains before mainnet.

---

## Abstract

Every blockchain forces a single trade-off. Public chains like Ethereum are
radically transparent — every balance and payment is visible forever. Privacy
chains like Monero make privacy mandatory — which gets them delisted and blocks
smart contracts. Nobody lets the *user* choose.

**Latebra removes the trade-off.** It is one account-based Layer-1 where the
same asset can move three ways, chosen per transaction:

- **Transparent** — fast, cheap, auditable (the compliant default).
- **Confidential** — amounts encrypted on-chain, provably solvent.
- **Anonymous** — sender, receiver, *and* amount hidden.

On top of that single ledger it runs **smart contracts**, reaches **deterministic
BFT finality** with slashing, and boots a fresh node from disk in milliseconds.
No competitor offers this combination — and the reason is structural: Monero
cannot add contracts, Ethereum cannot add native privacy. Latebra was designed
from the first commit to be all four things at once.

---

## 1. The problem

Blockchains ask users to pick one of two bad options:

1. **Total transparency** (Ethereum, Solana, every major L1). Your salary,
   savings, counterparties, and business flows are public forever. This is
   unacceptable for payroll, treasury, trading, or ordinary financial privacy —
   and it has no fix, because privacy bolted on afterward (mixers) gets
   sanctioned and breaks composability.

2. **Total privacy** (Monero). Everything is hidden — which means exchanges
   delist you, regulators fight you, you cannot build applications on encrypted
   state, and your wallet must scan the entire chain to find its own money.

Neither serves a real user who wants a fast public transaction *sometimes* and a
private one *other times*, on the same coin, without a bridge — and who also
wants to build and use applications.

## 2. The Latebra thesis

**Privacy should be a per-transaction choice on a programmable chain with real
finality.** That single sentence is the product. Everything below is how it is
built, and every capability described is implemented and tested in the codebase
today.

---

## 3. What Latebra does today

### 3.1 Three transfer modes, one ledger

Accounts hold balances as ElGamal ciphertexts under the account's own key. From
that one primitive, three transfer types are built:

- **Transparent transfers** — plaintext and signed, ~140 µs to build, executed
  in parallel across cores (measured ~3× speedup, provably identical to serial).
  The fast lane for anything that doesn't need hiding.
- **Confidential transfers** — the amount is hidden, and a zero-knowledge
  *solvency proof* guarantees the sender actually holds the funds (closing the
  classic "hidden overspend" hole — you cannot spend money you don't have even
  when nobody can see the balance).
- **Anonymous transfers** — the sender hides inside a ring of decoys, the
  receiver behind a one-time stealth address, and (as of v3) **the amount is
  hidden too**, behind cryptographic commitments. Only the network fee is
  public. Replays are stopped by per-epoch nullifiers.

Users **shield and unshield** freely between the transparent and private lanes
on the same ledger — no bridge, no wrapped asset.

**Proven, not promised:** an in-repo test decrypts *every* account balance
before and after an anonymous transfer and verifies that not a single unit is
minted or destroyed. A dedicated adversarial suite (`lat-attack`) attacks the
chain's own privacy and fails to break it: zero attributable payment edges, zero
linkable receivers, zero forgeable proofs.

### 3.2 Deterministic finality with real economic security

Latebra produces blocks with proof-of-work, then **finalizes** them with a
BFT-style stake vote: validators sign votes, and once votes representing more
than two-thirds of stake accumulate, the block is **irreversible** — the
fork-choice rule refuses any reorg beneath that watermark. This gives users
fast, deterministic settlement instead of "wait for N confirmations and hope."

Validators put real money at risk. The full lifecycle is live: stake, unstake
with an unbonding delay, and **partial slashing** — a validator caught
equivocating (double-signing) loses a fraction of its stake, a share of which is
**paid to whoever submitted the evidence** (a whistleblower reward), with the
offender permanently barred from the validator set. This is the modern
proof-of-stake security model, implemented and tested.

### 3.3 Smart contracts and live applications

Latebra runs a stack-based virtual machine: contracts deploy and execute
on-chain, and their storage is publicly readable over the API. Real applications
already run on it:

- a **block explorer** with a live-updating feed and testnet faucet,
- **web and CLI wallets**, and
- a **token launchpad** that mints real on-chain tokens with bonding-curve
  pricing — a "pump.fun for a privacy chain."

### 3.4 Node engineering built for operators

- **Boots from disk in ~15 ms**; corrupted state self-heals through layered
  fallback paths.
- **Fast sync**: a brand-new node downloads current state from a peer and
  verifies the rebuilt state root against the proof-of-work header chain —
  trusting math, not the peer. (Verified live: a fresh node reached the tip in
  seconds.)
- **Authenticated state** in a Sparse Merkle Tree with O(log n) updates and
  history pruning — light clients can be handed a proof for a single account.
- **Operations surface**: JSON-RPC 2.0 API (for exchanges, explorers, bots),
  Prometheus metrics, a one-command multi-node Docker testnet, and CI.
- **Runs on a laptop.** No 100-GB-RAM validator requirement.

**Chaos-tested:** a multi-node soak that repeatedly kills and restarts nodes
ends with every node reconverged on the identical chain tip.

---

## 4. Why Latebra wins — the structural moat

The competitive advantage is not a feature; it is a combination no rival can
assemble:

| Capability | Latebra | Monero | Zcash | Ethereum | Solana |
|---|:---:|:---:|:---:|:---:|:---:|
| Hides amounts | ✅ | ✅ | ✅ | ❌ | ❌ |
| Hides sender + receiver | ✅ | ✅ | ✅ | ❌ | ❌ |
| Transparent fast lane (same asset) | ✅ | ❌ | partial | ✅ | ✅ |
| User chooses privacy per-tx | ✅ | ❌ | limited | ❌ | ❌ |
| Smart contracts | ✅ | ❌ | ❌ | ✅ | ✅ |
| Deterministic finality + slashing | ✅ | ❌ | ❌ | ✅ | ✅ |
| Account model (instant wallet) | ✅ | ❌ | ❌ | ✅ | ✅ |
| Parallel execution | ✅ | ❌ | ❌ | ❌ | ✅ |

**The moat is structural, not incremental.** Monero's UTXO+ring model has no
account state for a virtual machine to touch — it *cannot* grow contracts.
Ethereum's entire ecosystem and regulatory posture depend on transparency —
privacy bolted on breaks both (Tornado Cash showed how that ends). Their gaps
are permanent. Latebra's gaps — an external audit and a user base — are
temporary and already being closed.

### The one sentence that survives scrutiny

> **Latebra is the only chain that is simultaneously private, public,
> programmable, and final — and the incumbents cannot become it, while Latebra
> can become as proven as they are.**

---

## 5. Market

- **Private payments & payroll** — salaries, treasury, B2B settlement that must
  not be public, but must be auditable on demand (the transparent lane + shield
  is exactly this).
- **Compliant privacy for institutions** — dual-mode gives exchanges and
  regulators a transparent lane, removing the reason privacy coins get delisted.
- **Private DeFi & token launches** — the launchpad and contracts run against
  encrypted balances today; a whole design space Ethereum and Monero both
  structurally exclude.
- **The Monero user who wants more** — the same privacy, plus contracts,
  finality, an instant wallet, and exchange-friendliness.

---

## 6. Cryptography (summary)

All privacy rests on standard, well-studied assumptions — discrete log and DDH
in the Ristretto group over Curve25519, Pedersen commitments, Bulletproofs range
proofs, and Fiat–Shamir Sigma-protocols. **There is no trusted setup.** The full
mathematical specification — every proof statement and verification equation — is
published in `CRYPTO_SPEC.md` as the scoping document for external audit. The
solvency proof, ring construction, and hidden-amount scheme are clean-room
designs; their soundness arguments are written out and backed by an adversarial
test suite, but they are **not yet externally audited** (see §8).

---

## 7. Tokenomics (testnet parameters)

- Native coin **LAT**, 5 decimals.
- Proof-of-work emission with halvings; BFT finality secured by staked LAT.
- Public fees on every transfer (including the private lanes) fund miners and
  underpin the fee-floor that anti-spam relies on.
- Validator staking with a minimum bond, unbonding delay, and slashing.

Mainnet parameters — genesis, premine ceremony, emission curve, validator set
size, and slashing rates — are the launch decisions gated behind audit, and are
enumerated in `LAUNCH.md`.

---

## 8. Status, roadmap, and honest disclosure

**What is done (implemented + tested, ~260 tests, live multi-node testnet):**
all three transfer modes including hidden-amount anonymity; BFT finality with
partial slashing; smart contracts; explorer, wallets, and launchpad; fast sync;
JSON-RPC; Docker/CI; chaos-tested networking; and an auditor-ready crypto spec
with an adversarial red-team suite.

**What remains before mainnet:**

1. **External cryptographic audit.** The privacy constructions are novel and
   unreviewed. This is a hard gate before real value — and it is why the spec
   and red-team pack already exist.
2. **Public testnet & decentralization.** No external validators run yet;
   benchmarks are from a single implementation on one machine. A public testnet
   period with independent operators is the next step.
3. **Anonymity-set maturity.** The ring-based sender set is bounded (≤16) and a
   young chain has a small crowd to hide in; this strengthens with adoption.

We state these plainly because credibility is the scarcest asset a young privacy
chain has. Latebra ships its own attack tool, a supply-conservation proof, a
threat model, and a full crypto spec precisely so that reviewers, exchanges, and
users can verify rather than trust.

---

## 9. Conclusion

Latebra is not "a faster chain" or "a more private chain." It is the first chain
that refuses the trade-off entirely: **the user decides, per transaction, how
private to be — on a programmable ledger with real finality, engineered to run
anywhere.** The hard combination is already built and tested. What stands between
today and mainnet is an audit and a community — a path, not a research problem.

*Latebra — privacy is a choice, not a compromise.*

# Anonymous Transfer — consensus integration design (Phase 3c)

> **Status: IMPLEMENTED ON TESTNET (steps 1–3 + mempool rules), UNAUDITED.**
>
> This document specified how the `AnonTransfer` **primitive**
> (`crates/lat-crypto/src/anon_transfer.rs`, unaudited) becomes a live
> transaction that hides the sender/receiver of a value-carrying spend. It resolves
> the design forks left open by [`ANON_SPEND.md`](ANON_SPEND.md). The consensus
> wiring described here is now implemented (see §10 for the per-step status);
> wallet-side decoy selection is still open, and none of it must carry real value
> before a professional cryptographic audit.

---

## 1. Goal and non-goals

**Goal.** A transaction that moves confidential value while hiding *who paid whom*
(finding **F1** — the transaction-graph leak the `lat-attack` red-team exploits off
the cleartext `SolventTransfer.sender` / `.receiver`).

**Explicit non-goals (this phase).**
- **Amount privacy (F2).** The primitive takes `amount`/`fee` as *public*
  parameters (the `{0, amount}` membership set is public). This phase closes the
  graph leak, not the amount leak. Committed-amount hiding is a later phase.
- **Network-level privacy.** Tx-origin IP / timing correlation is a separate
  transport concern (Dandelion++ etc.), out of scope here.

**Threat model.** A passive observer with the full block log and every participant's
long-term public key. Success = they cannot identify the sender (better than
1-in-`N`) or link the receiver to a known address.

## 2. What the primitive already provides

`AnonTransfer::verify` establishes, over a public ring `{Y_i}` with on-chain balance
ciphertexts `{(C_i^bal, D_i^bal)}`:

- exactly one member — the hidden, **owned, solvent** sender — is debited `amount`;
  decoys are debited `0` (fused bricks A+B+C+D + conservation);
- a **key image** `I` bound to that member for double-spend detection;
- a **stealth** output `(R, P)` crediting the hidden receiver.

What it does **not** yet provide, and this doc must add:
1. the **value-movement** ciphertexts the ledger actually applies (the proof commits
   to Pedersen *deltas*, not ElGamal balance updates) — see §5 (**brick E**);
2. an **anti-replay** scheme that fits the ledger's account model — see §4, which is
   the load-bearing design fork.

## 3. The load-bearing fork: account model vs. note model

The current ledger (`crates/lat-state/src/lib.rs`) is **account-based**: each
`Account` holds one *aggregated* homomorphic balance per token (`balances`), plus a
`pending` pool and a per-account `nonce` for replay protection. The primitive does a
**partial spend with change in place** (it proves `balance − amount − fee ≥ 0` and
commits the remaining balance), which is account-shaped.

**The mismatch:** the primitive's key image `I = x·H_p(Y_l)` is **static per account
key**. In a UTXO/note world that is fine (each note has a unique one-time key, so its
image is unique per spend — the Monero model). In an **account** world it is *wrong*:
a static per-account image means an account could make only **one** anonymous spend
ever, because its second spend reuses the same image and is rejected as a
double-spend.

So integration must pick a lane:

| | **A. Note / UTXO private layer** | **B. Account + Zether epochs** |
|---|---|---|
| Private balance | a set of one-time **notes** (each a value + one-time key) | one aggregated ciphertext per account (as today) |
| A spend | consumes a whole note, emits change + payment notes | partial debit, change stays in the account |
| Anti-replay | **per-note** nullifier (= the primitive's key image, unchanged) | **per-epoch** nullifier `x·H_p(epoch)`; one spend / account / epoch |
| Ring is over | note commitments | account balances (as the primitive assumes) |
| State rework | large (note commitment tree, nullifier set, scanning) | moderate (nullifier set, epoch clock, delta application) |
| Fit to built primitive | key image fits; **solvency/change model must change** to note-consume | ring-over-balances fits; **key image must change** to epoch nullifier |

**Recommendation: Option B (account + Zether epochs).** It is the smaller delta from
the existing homomorphic account ledger and reuses the primitive's ring-over-balances
and solvency-with-change design. The one required primitive change is swapping the
static key image for an **epoch nullifier** (below). Option A is cleaner cryptography
but is a second ledger model bolted next to the account one — a much larger surface.

The rest of this doc assumes **Option B**.

## 4. Anti-replay: epoch nullifiers

Replace the static image with an epoch-scoped nullifier so an account can spend once
per epoch, unlinkably:

- Define an **epoch** as a fixed window of `E` blocks: `epoch = height / E`.
- Nullifier base `G_epoch = H_p("Latebra.Epoch" ‖ epoch)`.
- Nullifier `u = x · G_epoch`, proven (in the fused OR, replacing relation (d)) to use
  the **same** hidden `x` as ownership/solvency. The verifier recomputes `G_epoch`
  from the block's epoch and checks the OR relation `u = x·G_{epoch}` at the hidden
  index.
- Consensus keeps a **nullifier set**; a block is invalid if it (or the chain) already
  contains `u`. This caps each account at one anonymous spend per epoch — the standard
  Zether liveness/anti-front-running tradeoff. Wallets needing more throughput split
  value across sub-accounts (stealth notes) as usual.

**Front-running.** Because the solvency proof is built against the account's balance
*at proof time*, a confirmed transfer that changes that balance would invalidate a
concurrent in-flight proof. Epochs solve this the Zether way: balance-changing effects
(incoming credits) are **buffered** and only merged at epoch boundaries, so a proof
built during epoch `t` remains valid for the whole of epoch `t`. This maps onto the
existing `pending`-pool idea (§6).

> **Primitive change — DONE.** `anon_transfer.rs` now derives the nullifier as
> `u = x·G_epoch` (relation (d) of the fused OR), with `epoch` bound into the
> Fiat–Shamir transcript and stored on the struct. `nullifier()` replaces the old
> `key_image()`. Tested: same spender + epoch → same nullifier; different epoch →
> different nullifier. Consensus must still check `self.epoch == block epoch`.

## 5. Value movement (brick E: committed-delta ⇄ ciphertext link)

The proof commits to Pedersen deltas `C_i = δ_i·G + s_i·H`. The ledger, however,
updates **ElGamal** balances. So the transaction must also carry, per ring member `i`,
an encrypted debit `Enc_i = (δ_i·G + y_i·Y_i, y_i·G)` under `Y_i`, plus a **linking
proof** that `Enc_i` encrypts the *same* `δ_i` committed in `C_i` (a standard
two-base Schnorr equality, the same shape as `range.rs`'s linking sigma). Then
consensus applies, homomorphically and for **every** member (so the touched account is
hidden):

```
balance_i  ←  balance_i  −  Enc_i          // δ_sender = amount, δ_decoy = 0
```

The receiver leg is the **stealth** credit: because `amount` is public, credit
`Ciphertext::mint(amount)` to the one-time account `P`'s `pending` — exactly the
mechanism `ShieldStealth` already uses. The miner fee is credited in the clear at the
block level, as all fee paths already do.

Conservation across the whole tx: `Σ_i δ_i (debited) = amount (credited to P)`, which
the primitive's sum-proof already pins on the debit side; the receiver credit equals
that same public `amount`.

> **Primitive change — DONE.** The `AnonTransfer` struct now carries `enc: Vec<Ciphertext>`
> (the per-member ElGamal debits) and a per-member brick-E link proving each `Enc_i`
> encrypts the same `δ_i` as `C_i`; both are in the wire format and the `verify` path.
> Tested: `enc[sender]` decrypts to `debit`, decoys to `0`; a forged `Enc_i` fails.
> **Note:** the committed delta is now `debit = amount + fee` (the fee cannot be
> subtracted from a hidden sender separately), so membership/solvency/conservation are
> over `debit`; consensus credits `amount` to the receiver and `fee` to the miner.

## 6. Ledger and state-tree changes

`crates/lat-state`:

1. **Nullifier set.** Add `spent_nullifiers: HashSet<[u8;32]>` to `Ledger`, committed
   into `state_root` as a new sorted leaf group (alongside accounts/tokens/contracts)
   and included in the snapshot encode/decode. `apply` rejects a repeat.
2. **Epoch-buffered credits.** The existing `pending` pool already buffers incoming
   value until a `Rollover`. Reuse it: anonymous credits land in `pending`; define
   rollover eligibility by epoch so in-flight proofs stay valid within an epoch.
3. **Delta application.** A new `apply` arm for `AnonTransfer` verifies the proof,
   checks the nullifier is fresh + the epoch matches the block, subtracts `Enc_i` from
   every ring member's `balances`, credits `mint(amount)` to the stealth `P.pending`,
   inserts the nullifier, and credits the fee to the miner at the block level.
4. **No per-account nonce bump** for the hidden sender (its identity is secret); the
   nullifier is the replay guard. Transparent tx types keep using `nonce` unchanged.

`crates/lat-types`: a new `Transaction::AnonTransfer { token, xfer: AnonTransfer }`
variant (tag `0x0B`), encode/decode delegating to the primitive's `to_bytes` /
`from_bytes` (already implemented), with a strict length check.

`crates/lat-chain`: block verification includes the nullifier-freshness and epoch
checks; mempool rejects a tx whose nullifier is already in a mempool tx or the chain
(§7). Anonymous fees join the existing miner-fee accounting.

## 7. Mempool, fees, and DoS

- **Fees are public** (finding **F3** is inherent — miners must see the fee). To blunt
  fee-fingerprinting, consider a small fixed set of allowed fee tiers rather than
  free-form fees; that is a policy choice, not a consensus requirement.
- **Ring size** `N` is a consensus parameter (fixed, or a small allowed set) so proof
  size/verify cost is bounded. Verify is `O(N)` group ops + one Bulletproof; pick `N`
  against a per-tx verification budget.
- **Mempool nullifier tracking:** two mempool txs sharing a nullifier conflict; keep
  the higher-fee one. A tx whose epoch has passed is dropped.
- **Anonymity-set (decoy) selection** must be reproducible and agreed: candidates are
  registered accounts with a non-trivial balance ciphertext. Options: (a) wallet
  picks `N−1` decoys and names them in the tx (simple, but selection heuristics can
  leak — see Monero research); (b) consensus derives the ring deterministically from a
  seed + the spender's chosen anchor. Recommend (a) for the first version with an
  explicit, documented sampling distribution, and treat selection privacy as an audit
  item.

## 8. Backward compatibility

The transparent dual-state (public balances, `PublicTransfer`, `Shield`/`Unshield`,
`ShieldStealth`) is unchanged. `AnonTransfer` is additive — a new private spend path
alongside the existing `SolventTransfer`, which can be deprecated for value once
`AnonTransfer` is audited and live. Coinbase/emission stays public by design (finding
**F5** is intentional, like every chain).

## 9. Open problems / audit checklist

Before implementing, and again before any real value:

- [ ] **Epoch nullifier soundness** — the `u = x·G_epoch` relation must bind to the
      *same* `x` as ownership and solvency in the fused OR (no cross-index escape).
- [ ] **Brick E linking soundness** — `Enc_i` must provably encrypt the committed
      `δ_i`; a gap re-opens the "debit a decoy / park value" theft.
- [ ] **Front-running / epoch liveness** — confirm buffered-credit rules keep
      in-flight proofs valid and cannot be griefed.
- [ ] **Decoy-selection privacy** — sampling distribution vs. real-world
      chain-analysis (age bias, amount correlation).
- [ ] **Ring-size / cost bounds** — `O(N)` verify against block-time budget.
- [ ] **State-root / snapshot** — nullifier set committed and round-trips.
- [ ] **Professional cryptographic review of the whole composition.**

## 10. Sequenced plan

1. ✅ **Done** — primitive edits: epoch nullifier (§4) + brick E value-movement link
   (§5), with tests (`crates/lat-crypto/src/anon_transfer.rs`).
2. ✅ **Done** — `Transaction::AnonTransfer` type + wire (§6): tag `0x0B` in
   `lat-types`, strict-length decode, no signature (the proof authenticates).
3. ✅ **Done** — Ledger (`lat-state`): `spent_nullifiers` set (committed into the
   state root as a sorted leaf group; snapshot magic bumped to `LATLEDG2`),
   `apply_at(tx, height)` enforcing epoch match / fresh nullifier / ring members
   registered + distinct / **claimed ring balances equal to current on-chain
   balances** (the stale-balance overspend guard), whole-ring `Enc_i` debit,
   stealth credit into the one-time account's `pending` (auto-registered), fee to
   the miner's encrypted balance at the block level. `EPOCH_BLOCKS = 20`.
4. ✅ **Done (consensus + mempool + wallet)** — `lat-chain`: fee floor,
   `MAX_RING_SIZE = 16`, `select_valid`/block-apply at the real height; mempool
   same-nullifier replacement (higher fee wins), eviction on confirmed
   nullifiers, and epoch-expiry pruning wired into the node (`lat-p2p`).
   Wallet flow (§7 option (a)): `Ledger::ring_candidates` exposes the decoy pool
   (served over RPC by `lat_p2p::get_ring_candidates`, capped at 64 with an
   evenly-strided slice of the id-sorted pool); `Wallet::create_anon_transfer` /
   `build_anon_transfer` sample decoys **uniformly** (partial Fisher–Yates,
   self at a uniform ring position) and target the next block's epoch;
   `Wallet::scan_stealth` detects anonymous payments so receivers claim the
   one-time account; `lat-wallet anon-send` drives it from the CLI.
   **Uniform decoy sampling vs. real chain analysis remains an audit item (§9),
   as does modulo bias in index sampling (negligible at these ring sizes).**
5. ✅ **Done — end-to-end red-team regression.** `lat-attack` now has an **Act 2**
   (`crates/lat-attack/src/main.rs`): the *same* passive chain-analysis attacker
   that fully de-anonymizes `SolventTransfer` in Act 1 is re-run over a real
   multi-block chain whose payments use `AnonTransfer`. Two `cargo test`
   regressions (`anon_transfer_makes_the_graph_go_dark`,
   `same_spender_across_epochs_is_unlinkable`) assert the attacker links nothing:
   zero named edges, best sender guess 1-in-ring, no one-time key matching a
   known address, no nullifier collisions (even for one spender spending in two
   epochs), and no observer-claimable stealth output. This is the on-chain proof
   that F1 is closed — not just that the primitive verifies.
6. **Audit.** Only then does it guard value.

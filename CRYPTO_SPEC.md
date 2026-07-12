# Latebra — Cryptographic Specification

**Status: UNAUDITED.** This document states the mathematics of Latebra's
value-privacy scheme so a cryptographic auditor can review the *design*
without reverse-engineering it from Rust. Every construction here is a
clean-room implementation and has had **no external review**. It must not
carry real value before a professional audit.

Scope: the confidential and anonymous transfer proofs, the stealth-address
and epoch-nullifier mechanisms, and the finality-vote signature. It does not
cover the VM, consensus fork-choice, or networking (see `SPEC.md`,
`PROJECT_CHECKPOINT.md`).

---

## 0. Notation and group setup

- Group: the Ristretto prime-order group over Curve25519 (`curve25519-dalek`).
  `G` is the Ristretto basepoint; scalars are integers mod the group order `ℓ`.
- `H` is a second generator with unknown discrete log w.r.t. `G` — the
  Pedersen blinding base (`PedersenGens::default().B_blinding` from the
  `bulletproofs` crate). The hardness assumption is that no party knows
  `log_G H`; all hiding/soundness of Pedersen commitments rests on it.
- `H_p(·)` is hash-to-group (`RistrettoPoint::from_uniform_bytes` over a
  SHA-512 digest). `H_s(·)` is hash-to-scalar (`from_bytes_mod_order_wide`
  over SHA-512). All Fiat–Shamir challenges are `H_s` over a domain-separated
  transcript of the **entire** public statement.
- Range proofs are Bulletproofs (`bulletproofs` crate) over `RANGE_BITS = 64`.

### Keys and balances

- A secret key is a scalar `x`; the public key is `Y = x·G`.
- Balances are ElGamal ciphertexts under the account's own key:
  `Enc_Y(v; r) = (c, d) = (v·G + r·Y, r·G)`. Homomorphic: `(c₁,d₁)+(c₂,d₂)`
  encrypts `v₁+v₂`. A fresh account's balance is `(0, 0)`.
- Decryption recovers `v·G = c − x·d`, then solves the discrete log by
  bounded search (wallet uses `BALANCE_BITS = 40`, ≈ 11M LAT). This bound is a
  wallet decode limit, **not** a consensus rule; range proofs enforce the
  cryptographic `[0, 2^64)` bound.

**Assumptions:** discrete-log and DDH in Ristretto; `log_G H` unknown; SHA-512
modelled as a random oracle for Fiat–Shamir.

---

## 1. Solvent confidential transfer (`solvent.rs`)

Hides the **amount**; sender and receiver keys are public (this is the fast
confidential path — anonymity is the separate construction in §2). Proves
knowledge of `(x, t, r, b', s_t, s_b)` for public
`(Y_s, Y_r, c_sender, c_receiver, d, V_t, C_rem, D_rem, V_b)`:

```
1. Y_s        = x·G                (sender owns the debited account)
2. c_sender   = t·G + r·Y_s        (amount t debited under sender key)
3. c_receiver = t·G + r·Y_r        (same t credited under receiver key)
4. d          = r·G                (pins the shared randomness r)
5. V_t        = t·G + s_t·H        (Pedersen commit to the amount)
6. C_rem      = b'·G + x·D_rem      (b' = remaining sender balance)
7. V_b        = b'·G + s_b·H        (Pedersen commit to remaining balance)
```

plus Bulletproofs that `V_t` and `V_b` each commit to a value in `[0, 2^64)`.

**Soundness sketch.** (4) pins `r`; with it (2) pins `t`; (5) ties the
range-proven value to that `t` (so the amount is non-negative and bounded).
(1) pins `x`; then (6), with `C_rem, D_rem` public, pins `b'`. Because
`C_rem = (b_s − t)·G + r'·Y_s` and `D_rem = r'·G`, relation (6) forces
`b' = b_s − t`; proving `b' ≥ 0` (7) proves the sender could afford the
transfer — closing the overspend/mint gap that a naive range proof bolted onto
`c_sender` alone would leave (there `r` is free, so any `t` is forgeable since
every `G`-multiple lives in `⟨G⟩`). `H ⟂ G` prevents shifting the committed
values.

The 7 relations are one merged Σ-protocol with a single Fiat–Shamir challenge
`e = H_s(statement ‖ announcements)`; responses `z_• = k_• + e·w_•`.

**Unshield** (private → public) is the same proof with `Y_r` fixed to a
published *view key* whose secret is public, so consensus recomputes the
amount and credits a named transparent account (`unshield_reveals`).

---

## 2. Anonymous transfer, hidden amount — `AnonTransfer` v3 (`anon_transfer.rs`)

Hides **sender** (one of a public ring of `N`), **receiver** (one-time stealth
address), **and amount** (v3). Only the **fee** is public (miner credit +
fee-floor enforcement). This is the flagship construction and the primary
audit target.

### 2.1 Public statement

Ring `{Y_i}`, on-chain balance ciphertexts `{(C_i^bal, D_i^bal)}`, per-member
Pedersen delta commitments `{C_i = δ_i·G + s_i·H}`, per-member ElGamal debit
ciphertexts `{Enc_i}`, debit commitment `C_debit = debit·G + s_d·H`, receiver
credit ciphertext `credit`, public `fee`, `epoch`, nullifier `u`, remaining-
balance commitment `V`, and the aggregated range proof. Here
`debit = amount + fee`, and the real sender sits at hidden index `l`.

### 2.2 What is proven

1. **Zero-or-debit bounds (brick B).** For every `i`, a CDS OR proof that
   `C_i ∈ ⟨H⟩` **or** `C_i − C_debit ∈ ⟨H⟩` — i.e. `δ_i ∈ {0, debit}` — with
   no public amount. (Two Schnorr-on-`H` clauses; one is simulated.)
2. **Conservation.** `Σ_i C_i − C_debit ∈ ⟨H⟩`, a Schnorr on base `H` for the
   blinding `σ' = Σ s_i − s_d`. With (1) and `debit ≠ 0` (guaranteed by the
   public fee floor, `debit ≥ fee > 0`), exactly one member carries `debit`
   and the rest carry `0`.
3. **Owned = debited = solvent = nullified (fused A+C+D).** One CDS
   OR-composition over the ring proves a hidden `l` at which simultaneously:
   - (a) ownership `Y_l = x·G`;
   - (b) `C_l − C_debit ∈ ⟨H⟩` (member `l` carries the debit);
   - (c) solvency `balance_l − debit ≥ 0`, via target
     `T_i = V − C_i^bal + C_debit` (at `l`, `T_l = (γ + s_d)·H − x·D_l^bal`,
     so the debit commitment's blinding folds into the range-proof blinding);
   - (d) nullifier `u = x·G_epoch`.
   All four share the branch challenge `e_l` and the witness `x`. Off-branch
   challenges are random; `Σ_i e_i = H_s(statement)` closes the OR.
4. **Value-movement link (brick E).** For every `i`, a two-base Schnorr that
   `Enc_i` encrypts the same value as `C_i` commits to — so the ciphertext the
   ledger subtracts from `balance_i` equals the proven delta.
5. **Amount well-formedness + credit link (v3).** ONE aggregated Bulletproof
   range-proves *both* the remaining balance (in `V`) and the amount (in
   `C_amt = C_debit − fee·G`) in `[0, 2^64)`. Range-proving the amount slot is
   what forbids `debit < fee` (which would wrap `amount` around `ℓ`). A
   two-base Schnorr (`credit_link`) proves `credit` encrypts, under the stealth
   one-time key, exactly the value `C_amt` commits to — so the receiver is
   credited precisely `debit − fee`.

### 2.3 Ledger effect

For each ring member: `balance_i ← balance_i − Enc_i` (decoys subtract an
encryption of 0, so which balance truly moved is hidden). The receiver's
pending pool gains `credit`. The fee is credited to the miner in the clear at
block level. The nullifier `u` is inserted into the committed nullifier set.

### 2.4 Epoch nullifier (anti-replay)

`u = x·G_epoch`, where `G_epoch = H_p("Latebra.Epoch.v1" ‖ epoch)`. It is
deterministic per account **per epoch** (a second spend by the same account in
the same epoch collides and is rejected) yet reveals nothing about which member
spent — linking `u` to any `Y_i` is a DDH problem. An account model cannot use
a static per-key image (that would permit only one spend ever); the epoch
scoping is the Zether-style tradeoff (`EPOCH_BLOCKS = 20`). Consensus checks
`xfer.epoch == epoch_of(block_height)` and that `u` is unseen.

### 2.5 Consensus-side checks (not in the proof)

Ring members must be registered, distinct accounts, and the claimed
`{(C_i^bal, D_i^bal)}` must equal their **current** on-chain balances
(otherwise a prover could cite an old, richer balance). Ring size ≤
`MAX_RING_SIZE = 16`; fee ≥ floor. These live in `lat-state`/`lat-chain`, not
the ZK proof, and are essential to soundness.

---

## 3. Stealth addresses (`stealth.rs`)

Sender draws ephemeral `e`, publishes `E = e·G`; the one-time key is
`P = H_s(e·Y_r)·G + Y_r`. The receiver, holding `x_r`, recomputes the shared
secret `H_s(x_r·E)` and the one-time secret `p = H_s(x_r·E) + x_r` (so
`P = p·G`), scanning each transfer for outputs it can claim. Unlinkable to
`Y_r` without `x_r` (DDH).

---

## 4. Finality vote signature (`lat-chain::finality`)

A validator's vote over `(block_id, height)` is a domain-separated Schnorr
signature under its staking key. A certificate is a set of such votes from
distinct staked validators whose combined stake is strictly greater than 2/3
of the stake recorded by the voted block. Equivocation (two votes at one
height) is self-authenticating slashing evidence. No pairing / BLS
aggregation — signatures are verified individually (parallelised).

---

## 5. Known limitations (for the auditor's attention)

1. **No external audit** — this is the whole point of the gate.
2. **Anonymity set = ring size** (≤ 16), far smaller than a shielded pool;
   the ring is chosen wallet-side, so decoy-selection heuristics against
   chain-analysis are an open design item.
3. **Metadata leaks**: ring size, fee, epoch, and transaction *timing* are
   public; network-level origin (IP/timing) is out of scope (no Dandelion++).
4. **Fiat–Shamir in the ROM** — soundness is heuristic under SHA-512 as a
   random oracle; the transcript binds the full statement (checked by the
   malleability sweep test) but a review should confirm no field is omitted
   from any challenge.
5. **Epoch replay tradeoff**: one anonymous spend per account per epoch. A
   busy account must wait for the next epoch or use the confidential path.

---

## 6. Where to read the code

| Construction | File | Key entry points |
|---|---|---|
| ElGamal balances, keys | `crates/lat-crypto/src/lib.rs` | `Ciphertext`, `PublicKey`, `SecretKey` |
| Solvent transfer | `crates/lat-crypto/src/solvent.rs` | `SolventTransfer::{create, verify}` |
| Anonymous transfer (v3) | `crates/lat-crypto/src/anon_transfer.rs` | `AnonTransfer::{create, verify}` |
| Range/membership bricks | `range.rs`, `membership.rs`, `ring.rs`, `hidden_solvency.rs` | — |
| Stealth | `crates/lat-crypto/src/stealth.rs` | `stealth_send`, `stealth_receive` |
| Finality | `crates/lat-chain/src/finality.rs` | `Vote`, `Certificate` |
| Consensus enforcement | `crates/lat-state/src/lib.rs` | `Ledger::apply_at` (AnonTransfer arm) |
| Red-team | `crates/lat-attack/` | graph-goes-dark, conservation, malleability |

Adversarial regression tests referenced above:
`anon_transfer_conserves_total_supply_no_inflation` (lat-state),
`malleability_sweep_every_byte_flip_is_rejected`,
`forgery_without_owning_a_ring_member_is_impossible`,
`splicing_a_range_proof_from_another_transfer_fails` (lat-crypto).

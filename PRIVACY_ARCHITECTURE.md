# LATEBRA — Privacy Architecture Specification

> Companion to [`SPEC.md`](SPEC.md). `SPEC.md` describes the crypto/consensus
> engine as **built today** (all balances encrypted). This document describes the
> **target architecture**: a single Layer-1 that natively supports *both* public
> and private state on the same chain, same token, same wallet.
>
> The mapping between this vision and the code as it stands today is in
> [§ Implementation status](#implementation-status--mapping-to-current-code) at
> the end — read it before estimating any of this work.

---

## Vision

LATEBRA is a Layer-1 blockchain that natively supports both **public** and
**private** transactions on the same network. Unlike traditional privacy chains
that force all users into one privacy model, LATEBRA lets every wallet interact
with both transparent and confidential state without requiring separate
blockchains or tokens.

The goal is to make privacy a **native protocol feature**, not an optional
secondary network.

## Core principles

- One blockchain.
- One native token.
- One wallet.
- Two transaction states: **public** and **private**.

Users are free to choose whether assets remain public or become private.

## Wallet architecture

Every wallet contains two independent balances:

```
Wallet
├── Public Balance
└── Private Balance
```

These are not different wallets — they are two **protocol-level states** of the
same wallet.

## Transaction types

### 1. Public → Public
Traditional transparent transaction.

**Visible on-chain:** sender, receiver, amount, tx hash, block height, timestamp.
Equivalent to Ethereum or Solana.

### 2. Private → Private
Completely confidential transfer.

**Visible on-chain:** proof verification, transaction commitment, block height,
tx hash.
**Hidden:** sender, receiver, amount, balance, transaction-history linkage.
Only sender and recipient can decrypt or verify the transfer details.

### 3. Public → Private (Shield)
Assets move from transparent state into confidential state.

- **Public ledger records:** sender, amount leaving the public balance.
- **Private ledger records:** encrypted ownership of the received assets.

Only sender and recipient know who ultimately controls the private assets. The
protocol must prevent public observers from linking the shielded output to a
specific private owner.

### 4. Private → Public (Unshield)
Assets move from confidential state back into transparent state.

- **Public ledger records:** public receiving address, amount received.
- **Private ledger records:** confidential spend proof.

The origin private wallet must remain undisclosed. Observers can verify the
transaction is valid without learning which private account created it.

## Privacy requirements

Private transactions must hide: wallet identity, sender, receiver, balance,
amount, and the historical transaction graph. The network verifies only
**cryptographic validity** without exposing transaction contents.

## Cryptographic goals

The protocol should use modern privacy primitives such as: zero-knowledge
proofs, note commitments, nullifiers, Merkle trees, encrypted notes, and
cryptographic commitments. Consensus validates correctness without revealing
confidential information.

> **Design note (honest):** LATEBRA today is an **account + homomorphic-ElGamal**
> chain, not a **note/UTXO** chain. Nullifiers, note commitments, and Merkle
> trees are the *Zcash-family* toolkit; the equivalent guarantees here come from
> encrypted account balances, Bulletproofs range proofs, and one-of-many ring
> proofs. See the implementation-status section — the two models reach the same
> privacy goals by different means, and mixing them is a decision, not a default.

## Consensus

All validators verify: transaction validity, proof correctness, no double
spending, and state transitions. Validators **never** learn private transaction
contents.

## Explorer behavior

- **Public transactions:** explorer displays sender, receiver, amount, block,
  timestamp.
- **Private transactions:** explorer displays only tx hash, "proof verified",
  block height, status. No confidential metadata is visible.

## Smart-contract support

Contracts may be **public**, **private**, or **hybrid**:

- **Public DEX** — transparent order book, public liquidity.
- **Private Vault** — hidden balances, deposits, withdrawals.
- **Hybrid DAO** — public governance, private treasury.

## Protocol objectives

LATEBRA should provide transparency when desired, complete financial privacy
when desired, native movement between the two states, one unfragmented
blockchain, one token economy, and developer flexibility for public, private,
or hybrid applications.

## Design philosophy

Privacy is not mandatory. Transparency is not mandatory. Every user decides how
they interact with the blockchain while staying interoperable within a single
network. LATEBRA aims to be the first privacy-first Layer-1 where transparency
and confidentiality coexist as equal, native protocol features.

---

## Implementation status & mapping to current code

This is the bridge between the vision above and `latebra-core/` as it exists on
2026-07-02. It exists so this document is a **buildable plan**, not marketing.

### What already exists (reusable foundation)

| Vision element | Status in code | Where |
|---|---|---|
| Private balance (encrypted) | **Done** — twisted-ElGamal ciphertext per account/token | `lat-crypto`, `lat-chain` (`Ciphertext`) |
| Public balance (transparent) | **Done (Phase 1)** — plaintext `u64` per account/token | `lat-state` (`Account.public`) |
| Public → Public transfer | **Done (Phase 1)** — signed, nonce-bound, fee-floored | `lat-types` `Transaction::PublicTransfer` |
| Shield (public → private) | **Done (Phase 2)** — public debit, private-pending credit | `lat-types` `Transaction::Shield` |
| Unshield (private → public) | **Done (Phase 2)** — solvent spend to a public view key, amount revealed | `lat-types` `Transaction::Unshield`, `lat-crypto::unshield_reveals` |
| Hide the *recipient* of a shield | **Done (Phase 3a)** — stealth one-time addresses (CryptoNote-style, ristretto) | `lat-crypto/stealth.rs`, `lat-types` `Transaction::ShieldStealth` |
| Hide the *sender/origin* of a spend | **In progress (unaudited primitives, not wired)** — bricks A/B/C done; brick D (hidden-index solvency) + integration remain, audit-gated | `lat-crypto/{ring,membership,index_binding}.rs`, blueprint `ANON_SPEND.md` |
| Private → Private, amount hidden | **Done** — `SolventTransfer` (range + conservation + solvency proofs) | `lat-crypto/transfer.rs`, `lat-types` `Transaction::SolventTransfer` |
| Hide amount / balance | **Done** | Bulletproofs range proofs |
| Hide sender / receiver | **In progress** — ring proof + linkable tag built & unit-tested, **not yet wired into the live transfer** | WHITEPAPER §11 |
| No-double-spend on private | **Done** — spend nonce + solvency proof | `lat-chain` |
| One token, one chain, PoW consensus, fork sync, gossip | **Done** | `lat-chain`, `lat-p2p`, `latebrad` |

### What this vision adds (net-new work)

1. **A public/transparent balance dimension.** Today *every* balance is a
   ciphertext — there is no plaintext balance field on an account. Dual-state
   requires adding a transparent `u64` balance per account/token alongside the
   encrypted one.
2. **Public → Public transfer.** A new transparent, Schnorr-signed transaction
   with a plaintext amount and public sender/receiver. Cheapest to build (no new
   crypto).
3. **Shield (Public → Private). ✅ Phase 2 + 3a.** Debits the sender's plaintext
   public balance and credits the recipient's private pending pool. Phase 2's
   `Shield` names the recipient in the clear; Phase 3a's `ShieldStealth` hides the
   recipient behind a one-time stealth address, so observers can't link the
   shielded output to a private owner — the vision's shield requirement is met.
4. **Unshield (Private → Public). ✅ Phase 2.** Spends from the private balance
   with the existing solvency proof and credits a named public address with the
   revealed amount. Keeping the *origin* private account undisclosed is the
   Phase-3 step (Phase 2 reveals the origin, as an ordinary solvent transfer does).
5. **Explorer dual rendering** — public txs fully expanded, private txs reduced
   to hash / "proof verified" / height / status. (Partly already true for
   today's private txs.)
6. **Hybrid contracts** — public/private/hybrid contract state. This is a large,
   separable track built on top of 1–4.

### Honest sequencing (proposed)

- **Phase 1 — Transparent state + Public→Public. ✅ DONE (2026-07-02).** Every
  account now carries a plaintext `public` balance (`lat-state`); a genesis
  **public premine** seeds it (`genesis_with_public` / `open_with_public`); a
  signed, nonce-bound `PublicTransfer` (`lat-types`, tag `0x07`) moves it in the
  clear, with the `MIN_TRANSFER_FEE` floor enforced and public fees paid into the
  miner's public balance. Wallet builds/reads it; the explorer renders it in
  full. No new crypto. Covered by unit tests in lat-types/state/chain/wallet.
  *Follow-up (small): a `get_public_balance` RPC so a remote wallet/explorer can
  display public balances without a local chain — deferred, not blocking.*
- **Phase 2 — Shield & Unshield without unlinkability. ✅ DONE (2026-07-02).**
  `Shield` (tag `0x08`) debits a public balance and credits the recipient's
  private *pending* pool; `Unshield` (tag `0x09`) is an ordinary `SolventTransfer`
  sent to a publicly-known **view key**, so consensus reveals the amount in O(1)
  (`c_receiver − amount·G == x_view·d`) and credits the named public destination —
  value-conserving, solvency-proven, with a Schnorr signature binding the
  destination against malleability. **No new zero-knowledge machinery** — it
  reuses the existing solvent-transfer proof. Documented limitation (this is the
  point of Phase 3): shield names the recipient and unshield reveals the origin.
- **Phase 3 — Unlinkability.** Two halves, only one soundly buildable today:
  - **3a — recipient hiding. ✅ DONE (2026-07-02).** `ShieldStealth` (tag `0x0A`)
    pays a fresh **one-time account** derived from the recipient's ordinary
    address (`lat-crypto/stealth.rs`, CryptoNote-style ECDH + hashing — no ZK).
    On-chain an observer sees only the one-time key `P` and an ephemeral `R`, and
    can't link them to the recipient; only the recipient can scan, detect, and
    derive the spend key. No new address format (the account key doubles as the
    stealth address).
  - **3b — sender/origin hiding. IN PROGRESS (primitives only, unaudited).**
    Hiding *which* account authorized a value-carrying spend needs four bricks
    (see [`ANON_SPEND.md`](ANON_SPEND.md)): **A** ownership + key image (`ring.rs`
    LSAG ✅), **B** decoy bounds (`membership.rs` `ValueInSetProof` ✅), **C**
    index-binding — tie the *owned* account to the *debited* one (`index_binding.rs`
    `IndexBindingProof` ✅ *this turn*, the exact brick both `ring.rs`/`membership.rs`
    flagged missing), and **D** *hidden-index solvency* (prove the hidden account
    could afford it — Anonymous-Zether many-out-of-many) ⬜ **not built**. A/B/C are
    tested primitives, **none wired into consensus**. D + integration are the
    research-grade, **audit-gated** remainder. Do not ship value on it before audit.
- **Phase 4 — Hybrid contracts & explorer polish.**

Each phase is independently testable and ships value before the next begins,
consistent with the milestone discipline in `SPEC.md` §8.

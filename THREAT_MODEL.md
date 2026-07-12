# Latebra — threat model & security posture

> Status: **testnet-grade, unaudited.** This document is an honest inventory of
> what Latebra's consensus and privacy guarantees do and do not cover today. Read
> it before running a node, and **before putting anything of value on the chain.**
> The short version: Latebra is a working dual-mode privacy L1 suitable for a
> public **testnet**; it is **not** ready to secure real value.

## 1. What is enforced (sound today)

These properties are checked by consensus on every node; a block that violates
them is rejected.

- **Value conservation.** Every transfer (public, confidential, anonymous)
  conserves value within a token — homomorphically for hidden amounts, in the
  clear for public ones.
- **Sender solvency.** The confidential transfer (`SolventTransfer`) proves
  `balance − amount − fee ≥ 0` against the sender's real on-chain balance, so a
  hidden balance cannot be overspent. The earlier non-solvent `Transfer` was
  removed from the type system entirely (wire tag `0x01` is retired).
- **Ownership & replay protection.** Transparent transactions carry a Schnorr
  signature by the account key; a per-account `nonce` versions every spend.
  Confidential/public spends share one nonce (one spend per account per block).
- **Ticker uniqueness.** A `$TICKER` is globally unique — only one can ever be
  created (Latebra's signature feature), enforced at the ledger.
- **Anti-spam registration.** Creating an account requires a small proof-of-work
  (`REGISTRATION_POW_BITS = 8` leading zero bits) — the cost that gates fee-less
  account/contract creation.
- **Anonymous-spend replay guard.** An `AnonTransfer` is authenticated by a
  linkable ring signature and scoped by an **epoch nullifier**: at most one
  anonymous spend per account per epoch (`EPOCH_BLOCKS = 20`), and a proof is
  valid only in the epoch it was built for. Ring members must be real, distinct,
  and cite their *current* on-chain balances (stale/fabricated balances are
  rejected).
- **Authenticated state.** Each block header commits a Sparse-Merkle-Tree
  `state_root` over all accounts/tokens/contracts/nullifiers; a light client can
  be handed an inclusion proof for a single account and verify it against the
  root. A block whose header commits a different state than it produces is
  rejected.
- **Bounded resources.** Consensus caps: minimum transfer fee
  (`MIN_TRANSFER_FEE`), contract bytecode size (`MAX_CONTRACT_CODE_BYTES = 24 KiB`),
  ring size (`MAX_RING_SIZE = 16`).

## 2. What is NOT covered (hard limitations)

Ranked by how much they matter for holding value.

1. **The cryptography is unaudited.** The confidential and — especially — the
   anonymous transfer constructions are clean-room implementations that have had
   **no external cryptographic audit.** This alone makes the chain unsuitable for
   real value. An audit is a multi-week engagement and a prerequisite for mainnet.
2. **Anonymous transfers now hide the amount too (v3 — unaudited).** `anon-send`
   hides *who pays whom* (sender in a ring, receiver behind a one-time stealth
   address) **and the amount** (a Pedersen debit commitment + aggregated range
   proof + receiver-credit link replaced the old public field). Only the fee is
   public, as on Zcash/Monero. Residual leaks: ring size, fee, epoch, and
   transfer *timing* remain visible, and sender anonymity is bounded by the
   ring size. Per limitation 1, none of this construction has been externally
   audited.
3. **Finality is probabilistic.** Consensus is Nakamoto proof-of-work with
   heaviest-cumulative-work fork choice. There is **no deterministic finality** —
   deep reorgs are possible with enough hashpower (BFT-PoS is roadmap M3). Wait
   for confirmations proportional to value.
4. **Networking is testnet-grade.** Peer discovery is seed-based (no DHT/mDNS,
   no hard-coded seed list in the binary — pass `--peer`). Transport is **plain
   TCP**: no encryption, no NAT traversal. Fine for a testnet of known nodes; a
   production upgrade otherwise.
5. **Economic parameters are unreviewed.** Emission, halving, fees, and premine
   (below) have had no economic/game-theory review. The testnet genesis and
   faucet use a **well-known seed** (`0x2a…`), so testnet "value" is meaningless
   by design — this must change for any real launch (see [LAUNCH.md](LAUNCH.md)).
6. **Launchpad curve is off-chain (beta).** In the latfun launchpad, on-chain
   `CreateToken` and ticker uniqueness are real; the **bonding-curve pricing runs
   off-chain** in the backend until the DVM curve contract ships (Phase 2). Do not
   treat curve balances as on-chain funds.
7. **Rate model.** One anonymous spend per account per epoch (20 blocks); one
   confidential/public spend per account per block. Known Zether-style tradeoffs;
   batching is future work.
8. **VM scope.** Contracts run on a simple deterministic stack VM with basic gas
   metering — adequate for the bonding-curve use case, not a general audited EVM.

## 3. Trust assumptions

- **Honest majority of hashpower.** As with any Nakamoto PoW chain, safety and
  liveness assume no single party controls a majority of mining power.
- **Client-side keys.** Wallets hold secret keys in the browser/CLI; a node only
  ever sees ciphertexts and public transaction fields. The explorer shows what is
  public and marks confidential values as `encrypted` — it never sees plaintext
  hidden amounts.
- **Same-genesis peers.** Nodes handshake on protocol version + genesis id and
  drop mismatches, so a node only ever syncs the network it was built for.

## 4. Explicitly out of scope (today)

- Any use with **real economic value** — testnet only.
- **Mainnet** — needs an audit, reviewed tokenomics, fresh genesis/faucet secrets,
  and the finality + networking upgrades above.
- Formal verification, side-channel resistance, and DoS hardening beyond the
  basic fee/PoW/size caps.

## 5. Reporting

This is pre-audit software. If you find a vulnerability, do not open a public
issue with exploit details — contact the maintainer privately first.

# Latebra

**A privacy-first proof-of-work blockchain.** Balances and transfer amounts are
encrypted on-chain; a unique global ticker namespace makes it a natural home for
tokens and memecoins.

Latebra is an **independent, clean-room implementation** in Rust. It is built from
public cryptography and audited, permissively-licensed libraries (MIT / Apache /
BSD) — it does not derive from, or carry the license of, any other project.

> **Status: testnet-grade.** The cryptography, consensus, and node are implemented
> and tested, and a daemon runs across machines. It has **not** been through a
> professional security audit and must not hold real value until it has. See
> [Status](#status).

---

## What it does

- **Confidential balances** — each account's balance is an encrypted (twisted
  ElGamal) ciphertext. The chain updates balances *homomorphically* and never
  sees a plaintext amount.
- **Solvency-proven transfers** — every transfer carries a zero-knowledge proof
  that value is conserved, the sender owns the account, the amount is
  non-negative, and the sender can afford it — all without revealing the amount
  (an integrated Σ-protocol + Bulletproofs range proofs).
- **Replay-safe spending** — per-account nonces prevent replay; received funds
  land in a `pending` pool (so an incoming transfer can't invalidate your
  in-flight outgoing proof) and are merged with a `rollover`.
- **Unique ticker namespace** — only one `$TICKER` can ever exist; `$doge`,
  `DOGE`, and `Doge` all map to the same registration. The whole initial supply
  goes to the creator, confidentially.
- **Smart contracts** — a deterministic, gas-metered bytecode VM with persistent
  per-contract storage. Deploy a program, call it, and its state updates
  identically on every node. (A v1 foundation, not yet a high-level language.)
- **Proof of work + fork choice** — difficulty retargets toward a target block
  time, and the heaviest-work branch wins, with full reorg support.
- **Mining rewards** — a halving emission schedule (50 LAT/block initially) pays
  miners, on top of the genesis premine.
- **Runs as a node** — `latebrad` persists to disk, networks over TCP (peer sync
  + gossip), serves an RPC, and mines.

## Quick start

Requires a recent Rust toolchain. **Always build in release** — the elliptic-curve
math is ~15× slower unoptimized.

```sh
# Run the narrated end-to-end demo (wallets, transfers, a memecoin, balances):
cargo run --release -p lat-node

# Run a mining node:
cargo run --release -p latebrad -- --mine --data ./node-a/chain.log --listen 127.0.0.1:4040

# Run a second node that syncs from the first:
cargo run --release -p latebrad -- --data ./node-b/chain.log --listen 127.0.0.1:4041 --peer 127.0.0.1:4040

# Run the test suite:
cargo test
```

## Architecture

A Cargo workspace of focused crates:

| Crate | Responsibility |
|---|---|
| `lat-crypto` | Encrypted balances, the confidential + solvent transfer proofs, range proofs |
| `lat-types`  | Addresses (`lat`/`latt` Bech32m), transactions, ticker normalization |
| `lat-vm`     | The smart-contract virtual machine (bytecode, storage, gas) |
| `lat-state`  | The ledger: per-account confidential balances, token registry, contracts, state transitions |
| `lat-chain`  | Blocks, PoW, difficulty retarget, the block tree + fork-choice/reorg, mempool, persistence |
| `lat-p2p`    | TCP networking: peer sync, gossip, RPC, and the node service |
| `lat-net`    | Transport-agnostic sync core (in-process) |
| `lat-wallet` | Seed-derived keys, addresses, building/scanning transfers, balances |
| `lat-node`   | The narrated demo binary |
| `latebrad`   | The node daemon |

## How privacy works (in one paragraph)

An account has a secret key `x` and public key `Y = x·G`. Its balance `b` is stored
as `(C, D) = (b·G + r·Y, r·G)` — an encryption only the owner can read. Adding two
such ciphertexts encrypts the sum, so the chain moves value without decrypting it.
A transfer publishes a ciphertext of the amount under both parties' keys plus a
proof tying it all together: the amount and the sender's remaining balance are
each committed (`v·G + s·H`, with `H` independent of `G`) and shown to be in
`[0, 2^64)` by a Bulletproofs range proof, while a Σ-protocol binds those
commitments to the on-chain ciphertexts and the sender's key. The result: nobody
learns the amount or balances, yet everyone can verify no money was created.

## Status

**Implemented & tested** (56 tests): the cryptography, the ledger, consensus
(PoW, retargeting, fork-choice/reorg), the mempool, persistence, TCP networking +
RPC, mining rewards, and the daemon.

**Before any real value, this needs:**

- A **professional security audit** of the cryptography and consensus. This is
  non-negotiable and is not something tests can substitute for.
- **RandomX** activated as the production PoW (wired behind `--features randomx`;
  building it requires CMake + a C/C++ toolchain). The default build uses BLAKE3,
  which is a valid PoW but ASIC-friendly.

**Known refinements (not correctness bugs):** reorg replays from genesis rather
than the common ancestor; cross-branch *network* reconciliation needs a locator
protocol; one spend per account per block (full epoch batching is future work).

## License

Latebra's own code is licensed `MIT OR Apache-2.0`. It depends only on
permissively-licensed third-party libraries.

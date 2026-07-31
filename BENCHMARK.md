# Latebra soak & benchmark results

Measured with `cargo run --release --example soak -p lat-attack`, which drives
every transaction type the chain accepts through the real wallet, cryptography
and consensus code — no mocks — mines them into real proof-of-work blocks, and
checks the ledger's invariants afterwards.

**Run date:** 2026-07-21 · **Build:** release · **Machine:** Windows 11, single
node, in-process (no network) · **Parameters:** 300 wallets, 12 rounds.

> These are **single-machine, in-process** numbers. There is no gossip, no
> propagation delay and no competing miners, so they are an upper bound on the
> execution cost, not a prediction of public-network throughput. Re-measure on
> the deployed testnet before quoting anything.

## Result

```
transactions attempted : 3415
transactions applied   : 3415
blocks mined           : 33
wall clock             : 76.88s
mine+apply per block   : 490.9 ms
ERRORS: none
```

**3415 of 3415 transactions applied. No errors.** All invariants held:
confidential balances all decrypted cleanly, all 12 bonding curves kept sane
reserves, and all 12 AMM pools kept both sides funded.

## Coverage — every transaction type

| Operation | Applied | Build cost / tx |
|---|---:|---:|
| Register (with anti-spam PoW) | 16 | 65 µs |
| PublicTransfer | 449 | 261 µs |
| Shield (public → private) | 450 | 286 µs |
| ShieldStealth (→ one-time address) | 450 | 383 µs |
| SolventTransfer (confidential) | 451 | **24.6 ms** |
| Unshield (private → public) | 451 | **24.2 ms** |
| AnonTransfer (ring = 8) | 8 | **43.5 ms** |
| Rollover | 452 | 148 µs |
| CreateToken | 12 | 112 µs |
| CurveTrade buy / sell | 374 / 75 | ~140 µs |
| AddLiquidity | 12 | 141 µs |
| Swap | 171 | 144 µs |
| DeployContract | 8 | 145 µs |
| Stake / Unstake | 8 / 4 | ~130 µs |
| HtlcLock / Claim / Refund | 12 / 6 / 6 | µs-scale |

### What the numbers say

**Transparent operations are essentially free** — 100–400 µs to build, dominated
by a single signature. Tokens, swaps, curve trades, staking, contracts and HTLCs
all sit in this band.

**Privacy costs about 100× more, and it is all client-side.** A confidential
transfer takes ~25 ms to build (Σ-protocol + Bulletproofs range proof) and an
anonymous one ~44 ms at ring size 8. That is the price of the proof, paid on the
sender's machine, not by the network. It is a per-user latency, not a throughput
ceiling — but a phone will be slower than this desktop, which matters for wallet
UX.

**Block cost is ~491 ms to mine and apply**, at ~100 transactions per block.

## Known constraint found by this soak: anonymous-transfer ring contention

An anonymous transfer's proof binds the **exact balance ciphertext of every ring
member**. Any other transaction that moves a decoy's confidential balance
invalidates it, and the ledger rejects it as `StaleRingBalance`.

Two consequences, both measured:

1. **An anon transfer cannot share a block with ordinary confidential activity.**
   Batched with ~300 shields/transfers/rollovers, *all 8* anon transfers failed.
2. **Anon transfers collide with each other.** In a block containing only the 8
   anon transfers, **5 landed and 3 failed** — the first to apply moved a decoy's
   balance and stale-ed the rings that included it. Serialised one per block, all
   8 applied.

This is not a bug: binding the ring to current balances is what stops a prover
citing an old, richer balance. But it is a real liveness limit — with 300
accounts and ring size 8, roughly a third of concurrent anonymous spends had to
be rebuilt. On a busy chain, wallets must expect to rebuild an anonymous transfer
against a fresh tip and retry, and anonymous throughput is well below the
transparent lane's. Worth stating plainly in user-facing docs.

## Reproducing

```sh
cargo run --release --example soak -p lat-attack                      # defaults
cargo run --release --example soak -p lat-attack -- --wallets 300 --rounds 12
```

Exits non-zero if any transaction fails to apply or any invariant breaks.

### A note on wall-clock

Difficulty retargets toward the 3 s target on **every** block, clamped to 2×. A
harness that mines back to back therefore drives difficulty up until each block
costs seconds of real work — the chain regulating itself exactly as designed. So
wall-clock here is dominated by proof-of-work, and throughput is best increased
by packing more transactions per block rather than mining more blocks.

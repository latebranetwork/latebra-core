# Latebra: A Privacy-First Proof-of-Work Blockchain

**Working paper — testnet-grade. Not audited. Do not use for real value yet.**

Version 0.1 · 2026

---

## Abstract

Latebra is a proof-of-work blockchain whose account balances and transfer amounts
are encrypted on-chain, combined with a global, first-come registry that
guarantees every token ticker is unique. It is designed as a home for private
tokens and memecoins: the amounts you hold and move are hidden, and a `$TICKER`
can only ever be claimed once. Latebra is an independent, clean-room
implementation in Rust, built from public cryptography and permissively-licensed
libraries; it derives from no other project's code or license. This paper
describes the design as implemented, and is explicit about what is finished, what
is in progress, and what must happen before the chain can safely hold value.

---

## 1. Motivation

Public blockchains are radically transparent: anyone can see every balance and
every transfer. For payments, payroll, treasuries, and trading that transparency
is a liability. Privacy chains (Monero, Zcash, DERO) address this, but none is
built around a token/memecoin ecosystem, and launching a token elsewhere means
fighting over ticker names that anyone can duplicate.

Latebra combines two ideas:

1. **Confidential value.** Balances and amounts are encrypted; the network
   verifies transfers are valid without learning the numbers.
2. **A unique ticker namespace.** Only one `$DOGE` can ever exist. `$doge`,
   `DOGE`, and `Doge` all resolve to the same registration, enforced at consensus
   level — no squatting, no duplicates, no confusion.

## 2. Design goals and non-goals

**Goals.** Confidential balances and amounts; a unique global ticker namespace;
fair, ASIC-resistant proof-of-work; programmable contracts; a runnable node that
anyone can join.

**Non-goals (stated plainly).** Latebra does **not** aim to match the throughput
of transparent high-performance chains such as Solana. Confidential transactions
require per-transaction zero-knowledge proofs — orders of magnitude more
computation than checking a signature — and proof-of-work blocks are measured in
seconds, not milliseconds. Realistic throughput is tens to low hundreds of
transactions per second. Privacy and raw speed are in direct tension; Latebra
chooses privacy. It is "private and fast enough," not "faster than Solana," and
we will not claim otherwise.

## 3. Confidential balances

Each account has a secret scalar `x` and public key `Y = x·G` on the ristretto255
group. A balance `b` is stored as a twisted-ElGamal ciphertext:

```
C = b·G + r·Y      D = r·G
```

Only the owner's secret key decrypts it (`C − x·D = b·G`, then a bounded
discrete-log recovers `b`). Because the scheme is additively homomorphic, the
chain can add and subtract encrypted amounts without ever decrypting — this is
what lets balances move while the numbers stay hidden.

## 4. Confidential, solvency-proven transfers

A transfer publishes a ciphertext of the amount under both parties' keys and a
zero-knowledge proof establishing, without revealing the amount, that:

- value is conserved (the same hidden amount leaves the sender and reaches the
  receiver),
- the sender owns the account,
- the amount is non-negative, and
- the sender can afford it (remaining balance ≥ 0).

This is an integrated Σ-protocol combined with Bulletproofs range proofs. The
integration matters: proving each of these in isolation is not sound; the amount
and the sender's remaining balance are bound together so a sender cannot overspend
or mint coins. Consensus accepts **only** solvency-proven transfers.

## 5. Nonces and the pending pool

Two practical problems accompany confidential transfers: replay, and an incoming
payment invalidating your own in-flight outgoing proof (which is bound to a
balance snapshot). Latebra solves both: every account has a spend **nonce** bound
into each proof (preventing replay), and incoming funds land in a **pending** pool
that is merged into the spendable balance by an explicit **rollover** — so
receiving money never disturbs a payment you are already making.

## 6. The unique ticker namespace

A single on-chain registry maps a normalized ticker to a token. Creating a token
fails at consensus if the ticker already exists. Normalization strips a leading
`$`, uppercases, and bounds length, so casing and the dollar sign never create
duplicates. The creator receives the entire initial supply as a confidential
balance. This is the feature that makes Latebra a natural token/memecoin chain.

## 7. Smart contracts

Latebra includes a deterministic, sandboxed bytecode virtual machine. Contracts
have persistent key→value storage and run under a strict gas (step) limit, so
execution always terminates and produces identical results on every node.
Contracts are deployed and called by transactions. This is a v1 foundation — real
and programmable, but not yet a high-level language, and its state is transparent
(separate from the confidential-money layer).

## 8. Consensus

Latebra uses Nakamoto proof-of-work. Block difficulty retargets toward a target
block time, and nodes follow the branch with the most cumulative work, with full
reorganization support (a heavier competing branch causes a node to switch and
rebuild state). The production hash function is **RandomX** (ASIC-resistant, as in
Monero), available as a build option; the default build uses BLAKE3, which is a
valid proof-of-work suitable for a testnet.

## 9. Tokenomics

Supply has two sources: a genesis premine and ongoing mining emission. The block
reward begins at 50 LAT and halves on a fixed interval, giving a capped total
supply. LAT has five decimal places. Mining is therefore economically
incentivized, not merely a way to confirm transactions.

## 10. Node and ecosystem

A Latebra node (`latebrad`) persists its chain to disk (an append-only block log,
replayed on restart), synchronizes with peers over TCP (block sync and gossip),
serves an RPC for wallets and tools, and mines. A block explorer ("Latscan")
renders the chain — stats, blocks, and transaction types — from a live node. A
wallet derives keys from a seed, builds and scans transfers, and reads balances
locally (the node never sees a decrypted amount).

## 11. Toward sender/receiver anonymity

Latebra hides *amounts* today. Hiding *who transacts with whom* — as DERO and
Monero do with anonymity sets — is in progress. The cryptographic building blocks
are implemented and individually tested: a one-of-many ring proof, a linkable key
image (double-spend prevention), a balance-conservation proof, and a
set-membership proof.

We are deliberately explicit here: **these primitives are not yet composed into a
production anonymous transfer.** Composing them soundly — with the amount hidden
and the spend bound to the true sender among the ring — is research-grade work
whose correctness cannot be established by unit tests alone. It, and the rest of
the protocol, must undergo a professional cryptographic audit before Latebra holds
real value.

## 12. How Latebra compares to DERO

Latebra reimplements DERO HE's confidential-balance model from scratch (owing it
no code or license) and adds the unique-ticker namespace.

| | DERO HE | Latebra |
|---|---|---|
| Confidential balances | Yes | Yes |
| Smart contracts | Yes (DVM) | Yes (v1 VM) |
| Unique ticker namespace | No | Yes |
| Sender/receiver anonymity | Yes | In progress (primitives built) |
| Mature, years-live network | Yes | No — testnet-grade |

## 13. Status and security

As implemented and tested (a large automated test suite): the cryptography of
confidential balances and solvent transfers, the ledger, the token registry, the
smart-contract VM, consensus with fork-choice, tokenomics, persistence, TCP
networking with RPC, the node daemon, and the explorer.

**Before Latebra can safely hold value it requires:** a professional security
audit of the cryptography and consensus (non-negotiable, and not substitutable by
testing); completion and audit of the sender/receiver anonymity construction; and
production hardening. Until then it is testnet-grade software.

## 14. Conclusion

Latebra is an independent, working privacy blockchain with a distinctive purpose:
private tokens under a globally-unique ticker namespace. Its confidential-value
core, consensus, contracts, tokenomics, and node software are built and tested.
Its headline privacy frontier — full sender/receiver anonymity — has its
foundations in place and a clear, honest path to completion through specialist
review and audit. The project's guiding principle is to state plainly what is
done, what is not, and what must be true before anyone trusts it with value.

---

*Latebra's code is licensed MIT OR Apache-2.0 and depends only on
permissively-licensed libraries.*

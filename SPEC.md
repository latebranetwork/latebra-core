# Latebra — Design Specification (v0.1)

> A privacy-first proof-of-work blockchain with encrypted balances, a global
> unique-ticker namespace for tokens, and WASM smart contracts.
>
> **This is an independent, clean-room design.** It is implemented from public
> cryptographic concepts and the descriptions in this document — NOT from the
> source code of any existing project. No third-party source files are copied,
> translated, or adapted into this tree. All dependencies are permissively
> licensed (MIT / Apache-2.0 / BSD).

> **Architecture direction (2026-07):** this document specifies the engine as
> built — an *all-private*, account + homomorphic-ElGamal chain. The target
> architecture adds a **transparent state alongside the private one** (one wallet,
> two balances, with shield / unshield between them). That dual-state design and
> its phased build plan live in
> [`PRIVACY_ARCHITECTURE.md`](PRIVACY_ARCHITECTURE.md). Where the two documents
> differ, `PRIVACY_ARCHITECTURE.md` is the forward direction and this file is the
> current state.

---

## 0. Why this document exists (clean-room discipline)

To keep Latebra legally and cryptographically clean:

1. We implement from **specifications and public primitives**, never by editing or
   paraphrasing another project's code.
2. Every cryptographic primitive comes from an **audited, permissively-licensed
   library** — we do not hand-roll field arithmetic, curves, or proof systems.
3. This SPEC is the source of truth. Code is written from the SPEC, not the
   reverse.

---

## 1. Goals & non-goals

**Goals**
- Confidential balances and transfer amounts (nobody sees who holds what, or how
  much moves).
- An **account model** (not UTXO) — simpler UX, one address = one balance.
- A **global unique-ticker namespace**: only one `$TICKER` can ever exist,
  enforced by a single on-chain registry. (The memecoin killer feature.)
- Fast, fair proof-of-work that resists ASICs at launch.
- WASM smart contracts for the registry + future programmability.

**Non-goals (be honest)**
- We are **not** going to out-throughput Solana. Privacy crypto is heavier per tx
  by design. Target: strong privacy + practical speed, not record TPS.
- No anonymous-by-default networking in v1 (Tor/i2p integration is later).

---

## 2. Language & core stack

| Layer | Choice | License | Why |
|---|---|---|---|
| Language | **Rust** | — | Best ZK ecosystem, memory safety, speed |
| Curve / group | **ristretto255** (`curve25519-dalek`) | MIT | Fast prime-order group, no cofactor footguns |
| Range proofs | **Bulletproofs** (`bulletproofs`) | MIT | Compact, no trusted setup |
| Hashing | BLAKE3, SHA-256 | CC0/Apache | Fast, standard |
| PoW | **RandomX** (`randomx` bindings) | BSD-3 | ASIC-resistant, Monero-proven |
| State DB | `sled` or RocksDB + Merkle layer | MIT / Apache | Embedded, authenticated state |
| Smart contracts | **wasmtime** | Apache-2.0 | Standard, sandboxed WASM VM |
| Networking | `libp2p` (Rust) | MIT | Battle-tested P2P |
| Serialization | `borsh` or `bincode` | MIT/Apache | Deterministic encoding |

---

## 3. Privacy model (the core)

**Encrypted balances via additively-homomorphic ElGamal on ristretto255.**

- Each account's balance is stored on-chain as an ElGamal ciphertext
  `(C, D) = (g^b · y^r, g^r)` where `b` is the hidden balance, `y` the account's
  public key, `r` randomness.
- Because ElGamal is additively homomorphic, the chain can **add/subtract
  encrypted amounts without decrypting** — this is what lets a transfer update
  sender and receiver balances while keeping amounts secret.
- Only the account's secret key can decrypt `b`. Decryption recovers `g^b`, then a
  bounded discrete-log lookup table recovers `b` (balances assumed < 2^40).

**A confidential transfer proves, in zero knowledge:**
1. The sender knows their secret key and their true balance.
2. `new_balance = old_balance − amount ≥ 0` (no overflow / no spending more than
   you have) — via **Bulletproofs** range proof.
3. The same hidden `amount` was subtracted from sender and added to receiver
   (consistency) — via **sigma protocols**.
4. The transaction is correctly signed.

No amounts, no balances, and (with an anonymity set) no clear sender/receiver are
revealed on-chain.

> Note: this is the same *family* of techniques several privacy chains use
> (homomorphic ElGamal + Bulletproofs + sigma proofs). The techniques are public
> cryptography; our implementation is original.

---

## 4. Accounts & registration

- An address is a Bech32m string with HRP `lat` (mainnet) / `latt` (testnet),
  encoding the account public key.
- **Registration**: before first use, an account is added to the state tree. To
  prevent spam, registration requires a tiny proof-of-work (a few leading zero
  bytes on the registration tx hash) — must complete in well under a second.
  *(Carried over as a design lesson: keep the wallet, mempool, and block-verify
  PoW targets identical or registrations silently fail.)*

---

## 5. Consensus

- **Proof of Work**, RandomX, retargeted per block.
- Target block time: **single-digit seconds** (start ~9s, tune down with orphan
  rate in mind).
- v1: simplest correct longest-chain rule. A DAG/miniblock scheme (faster
  confirmations) is a **v2** enhancement, designed fresh if/when we add it — not
  required for launch.

### 5.1 Transaction fees

- Every `SolventTransfer` carries a **public fee** (miners must see it to price
  inclusion), bound into the solvency proof so it cannot be edited after
  signing. The proof covers `balance − amount − fee ≥ 0`; the ledger debits the
  sender by amount + fee; the block credits every collected fee to the miner,
  on top of the coinbase emission.
- Consensus enforces a **fee floor** (`MIN_TRANSFER_FEE`, 0.01 LAT): a block
  containing a transfer that underpays is invalid. The same constant gates
  mempool admission and is the wallets' default fee — one constant, three
  users, never allowed to diverge (the registration-PoW lesson).
- The mempool drains **highest fee first** (FIFO among equal fees), so paying
  above the floor buys priority under congestion — a real fee market.
- Honest limitations, for later: the fee is denominated in the *transferred*
  token (native-LAT fees on non-LAT transfers need a second balance proof);
  `Register` is fee-less but PoW-gated; `CreateToken` / `Rollover` / contract
  transactions are fee-less (authenticated + anti-spam-gated, but pricing them
  requires a fee-payment proof and is a known open item).

### 5.2 Transaction authentication

- Confidential transfers prove account ownership inside their integrated
  Σ-proof. The **transparent** types are authenticated with a **Schnorr
  signature** (ristretto255, deterministic EdDSA-style nonce) by the named
  account key, over the transaction's canonical encoding minus the signature:
  - `CreateToken` — signed by `creator` (replay-proof: the ticker is unique).
  - `DeployContract` — signed by `deployer`, who must be a registered (PoW-paid)
    account; code capped at `MAX_CONTRACT_CODE_BYTES` (24 KiB).
  - `CallContract` — signed by `caller` and bound to the caller's **spend
    nonce** (a signed call must not be replayable — it re-runs the contract).
  - `Rollover` — signed by the account and nonce-bound: a *forced* rollover
    changes the spendable balance and would invalidate the owner's in-flight
    solvency proofs (a free griefing attack otherwise).
- `Register` stays signature-free (it *introduces* the key) — gated by its
  anti-spam PoW instead.

### 5.3 Node robustness rules

- Wire messages are length-capped (`MAX_MSG_BYTES`, 4 MiB) — peer-supplied
  lengths and counts must never drive allocations.
- All wire decoding is total (returns `None`/error on any malformed input);
  the P2P server must survive arbitrary garbage bytes on any connection.
- The miner pre-validates mempool transactions against a copy of state
  (`select_valid`) so one bad transaction can only drop itself, never void the
  block or halt production.
- A panicked worker thread must not poison the node: locks recover, since state
  transitions are validated on a clone and swapped atomically.

### 5.4 Networking: discovery, gossip, fork sync

- **Peer exchange**: a node announces its reachable address with `Hello` and
  learns others via `GetPeers` — one seed peer is enough to discover the
  network. The peer set is capped (`MAX_PEERS`, 64) and address strings length-
  capped; entries are peer-claimed and unauthenticated (testnet trust level).
- **Gossip forwarding**: a node that accepts a block it did NOT already have
  re-announces it to its peers, so blocks flood the network once and loops die
  out at nodes that already know them. Topology need not be fully connected.
- **Fork-capable sync**: the syncing node sends a **block locator**
  (active-chain ids, newest first, exponentially spaced, ending at genesis);
  the peer answers with the most recent common active block. Sync pulls the
  peer's branch from there, and fork-choice reorgs onto it if it's heavier —
  so nodes that mined apart (offline, or across the internet) reconcile
  automatically. Locators are count-capped (`MAX_LOCATOR_IDS`).
- **Internet nodes**: listen on `0.0.0.0`, advertise a reachable
  `--public-addr` (port-forwarded). No NAT traversal / transport encryption
  yet — that's the libp2p-grade production upgrade.

---

## 6. Token & ticker namespace (the differentiator)

- A single built-in **Registry smart contract** owns the `$TICKER → token` map.
- Registering a ticker is a transaction that **fails if the ticker already
  exists** — enforcing global uniqueness at consensus level.
- Optional community rename via on-chain vote (designed later; tension with hidden
  balances noted — voting weight vs. privacy needs a real solution).
- Native coin: **LAT**, 5 decimals (matching prior Latebra convention).

---

## 7. Repository layout (Rust workspace)

```
latebra-core/
  Cargo.toml            # workspace
  crates/
    lat-crypto/         # ElGamal, sigma proofs, Bulletproofs wiring (uses dalek)
    lat-types/          # addresses, amounts, tx/block structs, serialization
    lat-state/          # account/state tree, Merkle commitment, DB
    lat-consensus/      # PoW (RandomX), difficulty, chain rules
    lat-vm/             # wasmtime host + Registry contract
    lat-p2p/            # libp2p networking, sync
    lat-node/           # the daemon binary (latebrad)
    lat-wallet/         # wallet core + CLI
  SPEC.md               # this file
```

---

## 8. Build roadmap (honest milestones)

1. **M1 — Crypto core** (`lat-crypto`): ElGamal encrypt/decrypt + balance
   recovery table; one confidential transfer proof that verifies in a unit test.
   *This is the make-or-break milestone — everything depends on it.*
2. **M2 — Types & state** (`lat-types`, `lat-state`): accounts, tx format, a state
   tree that applies a transfer.
3. **M3 — Single-node chain** (`lat-consensus`, `lat-node`): genesis, mine blocks
   with RandomX, apply txs. No networking yet.
4. **M4 — Wallet** (`lat-wallet`): keygen, address, build/scan/decrypt a transfer.
5. **M5 — Networking** (`lat-p2p`): two nodes sync and agree.
6. **M6 — Registry contract** (`lat-vm`): unique-ticker enforcement.
7. **M7 — Hardening**: test vectors, fuzzing, and — before any real value — a
   professional crypto audit. Non-negotiable for a money chain.

Each milestone is independently testable. We do not move on until the previous
one passes its tests.

---

## 9. What we are explicitly NOT doing

- Not copying, translating, or "90%-editing" any existing project's source.
- Not hand-implementing low-level cryptography we can get from an audited library.
- Not launching anything that holds real value before M7 (audit).

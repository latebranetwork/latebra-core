# Latebra — Performance Program Checkpoint

> Living document. Paste "continue from the latest checkpoint" in a new
> conversation and work resumes from the **Current Task** below.
> Last updated: 2026-07-06 (Checkpoint 8 — T6 pruning + archive mode).

## 0. Mission

Evolve Latebra (existing Rust L1, DERO-HE-lineage privacy chain) toward the
strongest justifiable claim as a highest-performance smart-contract L1, subject
to strategic direction chosen by the project owner (see §4). Correctness is
never traded for speed. Every performance claim must be backed by a benchmark in
the repo's bench suite (`cargo run --release --example bench -p lat-attack`).

## 1. Current-state audit (measured 2026-07-04)

Codebase: ~11k LOC, 16 crates. Working: stack VM, contracts, confidential +
anonymous transfers, PoW consensus, P2P + RPC, node daemon, explorer, CLI, web
wallet, privacy red-team (`lat-attack`).

Foundational properties (baseline to improve from):

- **Consensus:** Nakamoto PoW, heaviest-cumulative-work fork choice. Finality is
  probabilistic. No BFT / voting / deterministic finality.
- **Execution:** fully serial. No threads, no scheduler, no conflict detection.
- **State storage:** in-memory `HashMap`; optional file block-log + snapshot.
  No persistent authenticated state DB (no RocksDB/MDBX, no state trie beyond a
  `state_root` hash).
- **Privacy:** confidential proof generation is the dominant system cost.

## 2. Baseline benchmarks (release, single core, this machine)

| Operation | Median/op | ops/sec |
|---|---:|---:|
| Keypair generation | 600 ns | 1,666,667 |
| Account registration PoW (8 bits) | 74.3 µs | 13,459 |
| Balance decryption (discrete log) | 115.2 µs | 8,681 |
| Public transfer: build + sign | 139.9 µs | 7,148 |
| Confidential transfer: build proof | 22.88 ms | 44 |
| Anonymous transfer: build (ring 2 / 8 / 16) | 15.77 / 23.31 / 30.57 ms | 63 / 43 / 33 |
| Block validation + apply (1 confidential tx) | 5.84 ms | 171 |
| Contract call: validate + apply | 781.8 µs | 1,279 |
| Block PoW mine (empty, D=256) | 757.1 µs | 1,321 |
| Block encode / decode | 64.5 / 66.0 µs | 15,504 / 15,152 |

Bench harness: `crates/lat-attack/examples/bench.rs`.

### State trie (SMT) — T2 (`cargo run --release --example smt_bench -p lat-store`)

| Operation | Median/op | Note |
|---|---:|---|
| Single-key update @ 1k / 10k / 100k keys | 50.8 / 63.9 / 95.4 µs | ~flat as state grows 100× ⇒ **O(log n)** |
| Prove @ 100k keys | 21.5 µs | avg proof depth 17.9 ≈ log2(n) |
| Verify proof @ 100k keys | 52.0 µs | |

Contrast: the previous `state_root` rehashed the whole state O(n) per block.

### Persistent backend — T4 (`cargo run --release --example store_bench -p lat-store`)

100k keys, batched 1k/commit. redb (durable) vs MemStore:

| Operation | MemStore | RedbStore |
|---|---:|---:|
| Commit (per op) | 1.6 µs | 33.4 µs (fsync-durable) |
| Random read (per op) | 0.9 µs | 2.4 µs |
| Open/boot 100k-key DB | — | 15.2 ms |
| Full scan (100k) | — | 58.6 ms |

Durable writes pay fsync; a node commits once per block. Payoff: boot-from-disk
in ~15 ms vs replaying the whole chain from genesis.

### CoW overlay — T4b (`cargo run --release --example clone_bench -p lat-state`)

Ledger clone cost (speculative execution), overlay top-full vs flushed:

| Accounts | Clone (top full) | Clone (flushed) | Trie copy saved |
|---:|---:|---:|---:|
| 1,000 | 4.0 ms | 0.46 ms | 8.9× |
| 10,000 | 80.8 ms | 3.7 ms | 21.7× |
| 50,000 | 459.7 ms | 15.8 ms | 29.1× |

"Flushed" is the real cost (chain flushes every block). The residual was the
account-map deep-copy — **now retired by T5b** (see below).

### Disk-resident objects — T5b (same `clone_bench`, same machine)

Accounts/tokens/contracts/nullifiers moved from side `HashMap`s into store
records, so they ride the CoW overlay with the trie nodes. The flushed clone is
now ~O(1) instead of O(accounts):

| Accounts | Clone flushed (T4b) | Clone flushed (T5b) | Speedup |
|---:|---:|---:|---:|
| 1,000 | 0.46 ms | 0.10 ms | 4.8× |
| 10,000 | 3.7 ms | 0.30 ms | 12× |
| 50,000 | 15.8 ms | 1.14 ms | 14× |

Block-apply is unchanged in practice: it is dominated by confidential-proof
verification (~ms), and T5b adds only microsecond-scale record encode/decode per
touched account (2 per transfer). All 200+ workspace tests pass, incl. the
incremental-vs-full-rebuild oracle and the snapshot roundtrip.

## 3. Strategic tensions (must be resolved before roadmap is final)

1. **Privacy vs. speed** — 23 ms confidential proof is 160× a public transfer.
   Cannot be both fastest and most private.
2. **PoW vs. deterministic finality** — PoW gives probabilistic finality only;
   deterministic fast finality requires BFT/PoS.

## 4. Strategic decisions (SET 2026-07-04)

- [x] **D1 — Privacy posture: HYBRID, privacy-forward (dual-mode).** Transparent
  fast path is the high-throughput default; confidential + anonymous transfers
  are first-class opt-in. Privacy remains the flagship identity. Goal: first L1
  that is simultaneously a fast public chain and a private one.
- [x] **D2 — Consensus: BFT-PoS deterministic finality.** Replace PoW. Consensus
  is orthogonal to privacy (privacy lives in execution/state), so this costs no
  privacy. Sequenced AFTER the storage foundation. Interim: PoW stays runnable
  until BFT-PoS lands.
- [x] **D3 — First milestone: persistent state DB + authenticated trie.** The
  foundation parallel execution, snapshot sync, pruning, and archive depend on.

## 5. Roadmap (dependency-ordered; one task ≈ one conversation)

Legend: [x] done · [~] in progress · [ ] todo. Arrows = hard dependency.

### M0 — Program setup
- [x] T0 Decisions, roadmap, checkpoint mechanism, baseline bench.

### M1 — Storage foundation (current milestone)
- [x] **T1 `lat-store`: KVStore abstraction + in-memory backend.** Pluggable
  key/value layer with column families + atomic write batches + ordered prefix
  scan. `MemStore` reference backend, 7 tests, clippy-clean. No perf regression
  (additive crate; not yet wired into hot paths).
- [x] **T2 Authenticated state trie over KVStore.** Compact Sparse Merkle Tree
  (`lat_store::smt`): content-addressed nodes, incremental O(log n) updates,
  membership + non-membership proofs, canonical (order-independent) roots. 16
  tests incl. random-workload cross-check vs. reference model; clippy-clean.
- [x] **T3 Wire `Ledger` onto the trie-backed KVStore.** `state_root` is now the
  authoritative SMT root, maintained incrementally via a dirty-set and reconciled
  lazily in `state_root()` (interior mutability, so speculative clones that never
  ask for the root pay nothing). `HashMap`s stay the O(1) read layer; snapshot
  decode rebuilds the commitment. `account_proof`/`verify_account_proof` migrated
  to SMT proofs. All 80+ workspace tests pass incl. a randomized incremental-vs-
  full-rebuild oracle; consensus (block apply, snapshot boot, fork reorg) intact.
- [x] **T4 Persistent `KVStore` backend (`RedbStore`).** redb (pure-Rust, ACID,
  MVCC) instead of RocksDB — no clang toolchain needed (see ADR-0004). Column→
  table, atomic durable `write`, ordered `scan_prefix`, open/reopen lifecycle.
  Proven end-to-end: an SMT built on disk reopens from just its root with proofs
  intact. `KVStore` made object-safe (`Arc<dyn KVStore>` now possible).
- [x] **T4b Copy-on-write overlay + ledger-on-overlay.** `OverlayStore` (shared
  read-only base + in-memory write top + tombstones; `clone` shares the base,
  `flush` folds top→base). `Ledger` now holds an `OverlayStore` (stays concrete —
  no generic ripple); `Ledger::with_base(Arc<dyn KVStore>)` runs over a persistent
  base, `flush()` after each block keeps clones cheap. lat-chain flushes at every
  state commit (genesis, tip-extend, reorg). **Measured: ledger clone 460ms→16ms
  at 50k accounts (29×);** consensus tests all pass. Remaining clone cost is the
  account HashMaps (disk-resident accounts = future work).
- [x] **T5 Block DB + transaction index on KVStore.** `ChainStore` (lat-chain)
  replaces the bespoke append-only file log: blocks in `Column::Blocks` (seq-keyed,
  replayed in order on boot), a tx index in `Column::TxIndex` (tx hash → block id +
  position), `id→seq` map in `Meta`. `Blockchain::open` now boots from a `RedbStore`;
  new `tx_location`/`block_by_id` queries (explorer/RPC). 40 lat-chain tests pass.
- [x] **T5b Disk-resident objects.** Accounts, tokens, contracts and nullifiers
  moved from side `HashMap`s into store records in a new `Column::Objects`, read
  through a bounded write-through account cache (`ACCOUNT_CACHE_CAP`). They now
  ride the same CoW `OverlayStore` as the trie nodes, so `Ledger::clone` copies
  nothing that scales with state (**15.8ms→1.14ms flushed clone at 50k, 14×**),
  memory is bounded by the cache, and the object records persist to a `RedbStore`
  base (`Ledger::with_base`, tested end-to-end). Snapshot encode/decode and the
  incremental commitment now stream from records; `Ledger`'s `Clone` is manual
  (shares the store base, drops the cache). NB: the running chain's ledger still
  uses an in-memory base (`Ledger::new`) — booting a node's *state* from the
  on-disk records without replay is T7 (snapshot sync).  ← T3, T4
- [x] **T6 Pruning + archive mode.** Mark-and-sweep GC for the commitment trie:
  `lat_store::smt::{reachable_nodes, prune}` (re-exported as `prune_state`)
  marks every node reachable from a set of retained roots and deletes the rest
  from `Column::State` — safe by construction (nodes are content-addressed and
  immutable, so unreachable ⇒ unreferenceable; retained roots stay fully
  readable and provable since leaves carry their values).
  `Ledger::prune_history(retain_roots)` reconciles + flushes, then sweeps the
  committed base (never through the overlay). `Blockchain::set_prune_window(w)`
  sweeps every `w` blocks retaining the last `w` block state-roots + current;
  unset = **archive mode** (default — behavior unchanged). `latebrad` prunes
  with window 64 by default; `--archive` opts out. Reorg safety: rebuild
  replays blocks into a fresh base, never reads pruned nodes. **Measured
  (prune_bench): churn grows the trie with history, not state — 10k accounts ×
  50 touch-all rounds = 7.95M nodes, 97k live (81.6× shrink)**; sweep is
  O(history) (~1.6 s/10k×10, ~17 s/50k×10 in-memory) — fine at a 64-block
  cadence, revisit (incremental refcounts) if it ever bites. Subtlety found: a
  leaf at depth d shares its content-address with internal(leaf@d+1, empty), so
  two stores can hold different — equally valid — physical materializations of
  the same root; cross-store node counts are not comparable.  ← T3, T5
- [ ] T7 Snapshot format + fast snapshot sync.  ← T3, T5

### M2 — Execution performance
- [ ] T8 Deterministic parallel scheduler (Block-STM style) over transparent
  state; conflict detection + deterministic replay.  ← T3
- [ ] T9 Per-tx access lists / state-dependency hints.  ← T8
- [ ] T10 Parallel + batched signature verification.  ← T8
- [ ] T11 VM optimization (dispatch, gas metering, memory model).  ← T8
- [ ] T12 Privacy lane: parallelizable confidential/anon verification + proof
  batching (keeps the 23ms path off the hot transparent path).  ← T8

### M3 — Consensus & finality (BFT-PoS)
- [ ] T13 Validator set + staking module.  ← T3
- [ ] T14 BFT-PoS deterministic finality engine.  ← T13
- [ ] T15 Fork choice integrated with finality.  ← T14
- [ ] T16 Slashing, epochs, governance parameters.  ← T14

### M4 — Networking
- [ ] T17 Efficient block/tx propagation (structured gossip) + compression.  ← T14
- [ ] T18 Peer discovery, DNS seeds, bootstrap nodes.
- [ ] T19 Fast sync + state sync integration.  ← T7, T14

### M5 — Ecosystem & APIs
- [ ] T20 RPC / REST / WS / gRPC surface.  ← T3
- [ ] T21 SDKs, contract stdlib, tooling, debugger.  ← T11

### M6 — Ops, QA, security (continuous)
- [ ] T22 Metrics, logging, monitoring, Docker/K8s, CI/CD.
- [ ] T23 Fuzzing, integration tests, testnet, threat model.

## 6. Architectural Decision Records (ADRs)

- ADR-0000: Evolve Latebra, not greenfield (owner: "based on ours").
- ADR-0001: Dual-mode privacy — transparent default + opt-in confidential/anon.
- ADR-0002: BFT-PoS deterministic finality replaces PoW (privacy-orthogonal).
- ADR-0003: Storage-first — pluggable KVStore abstraction under all state so the
  backend (in-mem → RocksDB/MDBX) and trie can evolve without touching consensus.
- ADR-0004: Persistent backend is **redb** (pure-Rust, ACID, MVCC), not
  RocksDB/MDBX. Rationale: RocksDB's `-sys` crate needs a clang/LLVM toolchain
  (absent here); redb needs no C toolchain and its MVCC read snapshots suit a
  future CoW overlay. Still behind `KVStore`, so RocksDB remains a drop-in later
  if raw throughput is ever measured to require it.

## 7. Public interfaces (append as they land)

- `lat-store` (T1):
  - `trait KVStore: Send + Sync` — `get`, `contains`, `write(WriteBatch)`,
    `scan_prefix` (ordered), + `put`/`delete` convenience.
  - `enum Column { State, Blocks, TxIndex, Meta, Objects }` with stable `id()`
    u8 (0–4). `Objects` (T5b) holds ledger object records, kind-prefixed.
  - `struct WriteBatch` — ordered, atomic, last-writer-wins.
  - `struct MemStore` — in-memory reference backend (BTreeMap per column).
  - `struct RedbStore` (T4) — persistent backend. `open(path) -> Result` creates
    or reopens the DB (boot-from-disk); implements `KVStore` durably.
  - `WriteBatch::ops()` — public `(Column, key, Option<value>)` iterator so any
    backend can consume a batch. `KVStore` is object-safe (`put`/`delete` are
    `where Self: Sized`).
  - `struct OverlayStore` (T4b) — CoW `KVStore`: `new(Arc<dyn KVStore>)`,
    `in_memory()`, `flush()`; cheap `clone` (shares base). `MemStore::clear()`.
- `lat-state::Ledger` (T4b): `with_base(Arc<dyn KVStore>)` (persistent base),
  `flush()` (fold committed writes into base — semantically a no-op, keeps clones
  cheap). Store field is an `OverlayStore`.
- `lat-state::Ledger` (T5b): no more `accounts`/`tokens`/`contracts`/
  `spent_nullifiers` fields — all are records in `Column::Objects`. `Clone` is
  manual (shares store base, empty cache). `token(&str)` now returns an **owned**
  `Option<TokenMeta>` (was `Option<&TokenMeta>`; callers drop `.cloned()`).
  `with_base` **wipes any stale `Objects` records** on open (a fresh ledger is
  empty state; a stale account record would read as live and corrupt replay).
  **Invariant:** only ever `flush()` an adopted ledger — speculative clones share
  the base, so flushing a clone would publish its records into every sibling.
- `lat-chain` (T5): `struct ChainStore` (`new(Arc<dyn KVStore>)`, `append`,
  `blocks_in_order`, `block_by_id`, `tx_location`). `Blockchain::tx_location(&[u8;32])
  -> Option<([u8;32], u32)>` and `block_by_id(&[u8;32]) -> Option<Vec<u8>>`.
  `Blockchain::open` boots from a redb DB at the given path (exclusive lock — a node
  owns its DB; can't file-copy while open).
- `lat-store::smt` (T2):
  - `struct Smt<'a, S: KVStore>` — `new`/`from_root`, `root`, `get`, `update`,
    `remove`, `prove`. Nodes live in `Column::State`; key path = 32-byte key.
  - `struct Proof { siblings, terminal }`, `enum Terminal { Empty, Leaf }`.
  - `fn verify(root, key, expected: Option<&[u8]>, proof) -> bool` (re-exported
    as `verify_proof`) — membership when `Some`, exclusion when `None`.
- T6 pruning:
  - `lat-store::smt`: `fn reachable_nodes(store, roots) -> HashSet<Hash>` (mark),
    `fn prune(store, retain: &[Hash]) -> PruneStats { kept, dropped }` (sweep;
    re-exported as `prune_state`). `Smt` is now `S: KVStore + ?Sized` (works
    over `&dyn KVStore`). Call `prune` on the committed **base**, not an overlay.
  - `lat-state::Ledger`: `prune_history(retain_roots) -> PruneStats` (reconciles,
    flushes, sweeps the base; same adopted-ledger invariant as `flush`),
    `state_node_count()` (diagnostics; meaningful after a flush).
  - `lat-chain::Blockchain`: `set_prune_window(w)` — sweep every `w` blocks
    retaining the last `w` block state-roots; unset = archive (default).
  - `latebrad`: `--archive` flag (default prunes with window 64).

## 8. Known limitations / follow-ups

- **Chain ledger base is still in-memory.** The running chain builds its ledger
  with `Ledger::new()` (in-memory `MemStore` base), so a node's *state* still sits
  in RAM behind the store and is rebuilt by replay on boot. T5b makes disk-backed
  state *possible* (`with_base` + `RedbStore`, tested) and cheap to clone, but
  wiring the live chain onto a durable ledger base needs care (reorg builds a
  fresh ledger; speculative clones share the base; `with_base` wipes on open) and
  is coupled to booting-state-without-replay — that's **T7 (snapshot sync)**.
- **Prune sweep is O(history), not incremental.** T6's mark-and-sweep scans the
  whole `Column::State` and marks from the retained roots on every sweep (~17 s
  at 10M stranded nodes, in-memory). Amortized over a 64-block window this is
  acceptable; if it ever dominates, move to incremental reference counting or
  generational sweeps. Also: the mark set holds every live node hash in RAM
  (32 B each), and `scan_prefix` materializes the column — fine now, revisit
  with a streaming iterator API if state reaches hundreds of millions of nodes.
- **Account cache is clear-on-cap, not LRU.** `ACCOUNT_CACHE_CAP` (65 536) bounds
  memory by wiping the whole cache at the cap rather than evicting LRU. Bounded
  and allocation-free on the hit path; a hot set larger than the cap thrashes.
  Swap in a real LRU if a bench ever shows it matters.
- **Small-state block-apply.** ~0.8 ms trie overhead per block at tiny state
  (~64 accounts); wins decisively at large state (O(log n) vs O(n)).

## 9. Current Task

**T7 — Snapshot format + fast snapshot sync** (M1's last open task; T6 done).
Goal: boot a node's *state* from the on-disk object records + trie without a
from-genesis replay, and serve/verify state snapshots to syncing peers. This is
also the gate for wiring the live chain ledger onto a durable `RedbStore` base
(§8: reorg builds a fresh ledger, speculative clones share the base, `with_base`
wipes Objects on open — all three interactions must be redesigned together).
Sketch: (1) a versioned snapshot manifest = block id + state_root + object-record
range digests; (2) `Ledger::from_records(base)` that trusts records only after
recomputing the trie root against the header's `state_root`; (3) chunked
transfer over P2P with per-chunk verification against the root (SMT proofs);
(4) reorg = open a fresh base (directory/generation per adopted branch) instead
of wipe-in-place. Depends on: T3, T5. T6's pruning keeps what a snapshot must
carry small.

Alternative order:
- Jump to **M2 parallel execution** (T8, biggest throughput lever) — the state
  model is settled; T7 is about boot/sync ergonomics, not correctness.

### Build/verify commands
- Tests: `cargo test -p lat-store` (+ per-crate as tasks land).
- Chain bench: `cargo run --release --example bench -p lat-attack`.
- Store bench: `cargo run --release --example store_bench -p lat-store`.
- Clone bench: `cargo run --release --example clone_bench -p lat-state`.
- Prune bench: `cargo run --release --example prune_bench -p lat-state`.
- Note: `latfun.exe` may hold a file lock during `--workspace` builds if running;
  build with `--exclude latfun` or stop that process.

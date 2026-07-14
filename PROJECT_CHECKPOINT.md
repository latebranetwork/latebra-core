# Latebra — Performance Program Checkpoint

> Living document. Paste "continue from the latest checkpoint" in a new
> conversation and work resumes from the **Current Task** below.
> Last updated: 2026-07-14 (Checkpoint 23 — D4: contract-platform scope decision;
> VM rewrite deferred, privacy lane is the shipping claim).

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

### D4 — Contract platform scope (SET 2026-07-14)

- [x] **D4 — DEFER the VM rewrite. The confidential lane is the shipping claim.**
  Prompted by the question "can Latebra host NFTs/DeFi/tokens at Solana scale
  while keeping privacy?". Audited `lat-vm` to answer it. Findings:

  **`lat-vm` v1 is an arithmetic sandbox, not a contract platform.** 579 LOC,
  22 opcodes, `u64 → u64` storage, revert-by-divide-by-zero. It has no
  value-transfer opcode, no cross-contract `CALL`, no hash, no events/logs, no
  block context, and no words wider than 64 bits. Consequences, per asked-for
  feature:
  - **Native tokens: SHIP.** `CreateToken` + the token registry are native
    transaction types, not contracts. Unaffected by any of this.
  - **NFTs: NOT POSSIBLE as contracts.** Need metadata (byte strings) and
    events (indexers). Would have to become a native tx type like tokens.
  - **Composable DeFi: NOT POSSIBLE.** DeFi *is* composability; with no `CALL`
    opcode a contract cannot invoke a token contract. This is structural, not
    a tuning problem.
  - **Privacy × DeFi: ARCHITECTURALLY EXCLUDED, and that is fine.** A contract
    cannot compute on a Pedersen commitment it cannot open. This is why Zcash
    has no DeFi and why Aleo/Aztec are ZK-circuit architectures, not stack VMs.
    D1's dual-mode already answers it: privacy lane = transfers, transparent
    lane = contracts, user picks per tx. **Say this publicly rather than
    implying both at once.** There is no private AMM on this design.

  **Positioning follows from the measurements, not from ambition.** The
  transparent lane's headline (~23–30k tx/s, T8) is the lane the launchpad does
  *not* primarily use — contracts are a serial barrier at ~1,280 calls/s. But
  the confidential lane at ~650 tx/s (T12) is **20–60× Monero/Zcash shielded
  throughput (~10–30 TPS)**. That is a first-in-class claim, it is already
  built, and it needs a testnet + audit rather than a rewrite. Chasing Solana
  on DeFi means a VM rewrite → compiler → language → tooling → developers, at
  the end of which Latebra is a slower Solana that also does privacy.

  **Sequencing consequence — T9/T10/T11 are blocked BY THIS DECISION, not by
  effort.** T8's parallelism rests on transparent txs having *exact static
  access sets*. A `CALL` opcode destroys static access sets (you cannot know
  what a contract touches without running it) — which is precisely why Solana
  makes every tx declare its accounts upfront. So T9's design is downstream of
  the VM decision: build T9 against the v1 VM and it is rebuilt after any
  rewrite. **Decide the VM, then parallelize against it.**

  **Decision:** ship the privacy chain as-is with native tokens and the bonding
  curve, with the latfun settlement gap documented honestly (see §8) rather than
  hidden. Prove the confidential numbers on a public testnet. THEN, only if
  traction justifies it, open the VM rewrite as its own program (M7) with the
  atomicity gap as task one — it is a live soundness issue today, not a future
  nice-to-have.

## 5. Roadmap (dependency-ordered; one task ≈ one conversation)

Legend: [x] done · [~] in progress · [ ] todo. Arrows = hard dependency.

### M0 — Program setup
- [x] T0 Decisions, roadmap, checkpoint mechanism, baseline bench.

### M1 — Storage foundation (COMPLETE 2026-07-06)
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
- [x] **T7 Boot-from-records + durable live state** (the local half of snapshot
  sync). Persistent chains now keep their ledger ON the chain DB: the active
  state's overlay base is the same redb store as the blocks, every adopted
  block's flush commits state changes durably, and a **boot anchor**
  (`Meta:"state/anchor"` = height ‖ block id) rides the *same atomic batch* —
  the records on disk always describe exactly the anchored block.
  `Ledger::from_records(base)` boots replay-free: decodes + validates every
  object record, rebuilds the commitment from scratch (root is derived, never
  read from disk), rebuilds the ticker index; lat-chain then applies the same
  placement + PoW-bound-header `state_root` verification and tail replay as the
  snapshot-file boot. `Ledger::rehome(base, staged_meta)` adopts an off-base
  state (reorg rebuild, snapshot/replay boot) onto the durable base in ONE
  atomic batch (old state out, new in, anchor included) — no wipe-then-replay
  crash window. Boot order: records → `.snap` file → full replay; every
  corruption/tamper case falls back and re-homes clean state. `BootMode`
  enum replaces the bool (`latebrad` prints it). Closes §8 “chain ledger base
  is still in-memory”: node state RAM is now bounded by the account cache.
  Verified live: latebrad kill → restart boots "state records + tail replay"
  at the exact tip. **Deferred to T19 (needs T14 peers):** serving/fetching
  state chunks over P2P with per-chunk SMT-proof verification — the local
  anchor + records format is the manifest groundwork.  ← T3, T5

### M2 — Execution performance (current milestone)
- [x] **T8 Deterministic parallel execution over the transparent lane.**
  `lat_state::apply_block_parallel` — semantics identical to the sequential
  apply loop, wired into lat-chain's `apply_txs_and_reward` (tip-extend, reorg
  rebuild, snapshot tail replay all benefit). Design: transparent transactions
  (`PublicTransfer`/`Shield` = {from,to}, `Register` = {pubkey}) have **exact
  static access sets** (fees are already deferred to the coinbase), so instead
  of optimistic Block-STM re-execution we do **conflict-free wave scheduling**:
  runs of parallel-lane txs are split into waves by earliest-wave list
  scheduling (conflicting txs execute in block order across waves; same-wave
  txs are pairwise account-disjoint by construction), each wave fans out over
  `thread::scope` workers on cheap Ledger clones (T5b) and merges written
  account records back. Result is provably bit-identical to sequential — each
  tx observes exactly its sequential pre-state; block accept/reject identical.
  Everything else (confidential proofs, contracts, CreateToken) is a serial
  barrier — proof batching is T12, dynamic access lists are T9/T11. INVARIANT
  (documented at `access_set`): a parallel-lane apply arm must never touch
  state outside its static set — a randomized parallel-vs-sequential root
  oracle test guards it. **Measured (parallel_bench, 8 logical cores): 2000
  disjoint public transfers 244→86 ms (~2.9–3.1×, ~23–30k tx/s); hot-receiver
  worst case exactly 1.00× (zero overhead).**  ← T3
- [ ] T9 Per-tx access lists / state-dependency hints.  ← T8, **D4**
  (BLOCKED BY DECISION: a `CALL` opcode kills static access sets, so the design
  — declared lists à la Solana vs. optimistic Block-STM — is downstream of the
  VM choice. Building this against the v1 VM is rework.)
- [ ] T10 Parallel + batched signature verification.  ← T8
  (Not blocked by D4; the sig-verify wall is real at any TPS. Highest-value M2
  task that survives either VM outcome.)
- [ ] T11 VM optimization (dispatch, gas metering, memory model).  ← T8, **D4**
  (BLOCKED BY DECISION: do not optimize a VM that may be replaced.)
- [x] **T12 Parallel confidential-proof verification.** A pre-pass in
  `apply_block_parallel` verifies confidential zero-knowledge proofs across
  all cores *before* application, and the apply arms reuse the evidence
  (`ProofPass`, crate-internal) instead of re-running the expensive math.
  Soundness is structural, never scheduling-dependent: an `AnonTransfer` ring
  proof is a **pure function of the transfer** (it binds the *claimed* ring
  balances; apply still compares claimed vs live), so its evidence is
  unconditionally reusable; a `SolventTransfer`/`Unshield` proof is
  pre-verified against the block-START sender balance and the apply arm skips
  re-verification **only if the live ciphertext is bit-identical** — write-set
  prediction is a pure perf heuristic, a wrong guess costs a serial re-verify,
  never correctness. Failed pre-verifications yield no evidence (apply
  re-verifies and reports the exact sequential error). Every other check
  (nonce, epoch, nullifier, ring binding, registration) still runs in the
  serial barrier. **Measured: 32 solvent transfers 161→49 ms (3.3× on 8
  logical cores)**; mixed transparent+confidential oracle test incl. the
  ineligible-fallback path; `lat-attack` red-team green (same checks, just
  scheduled earlier).  ← T8

### M3 — Consensus & finality (BFT-PoS) (COMPLETE 2026-07-07, hybrid form)
- [x] **T13 Validator set + staking module.** New transparent transactions
  `Stake`/`Unstake` (wire tags 0x0C/0x0D; Schnorr-signed, nonce-bound, LAT
  only). Stake bonds from the public balance into a validator record
  (`Column::Objects` kind `v`); Unstake moves bonded stake into an unbonding
  entry that releases after `UNBONDING_BLOCKS` (240) — matured entries sweep
  back on the account's next Stake/Unstake, so `Stake { amount: 0 }` is the
  explicit claim tx (deterministic: driven by block height, never wall
  clock). A fully-drained record is DELETED, keeping roots canonical.
  Staking is committed state: `DirtyKey::Validator` + `LAT-state-val` leaf, so
  headers bind it and T14 can trust `validator_set()` = every account with
  ≥ `MIN_VALIDATOR_STAKE` (1,000 LAT), stake desc / id asc, capped at
  `MAX_VALIDATORS` (64) — derived purely from committed records (identical on
  every node; proven by snapshot-roundtrip + records-boot tests). Snapshot
  magic bumped LATLEDG2→3 (old snapshots fall back to replay). Errors:
  `InsufficientStake`. Stake txs are serial barriers in the parallel engine
  (rare; they'd need validator-record merge support otherwise). Explorer
  renders both kinds. LAUNCH.md: 3 new params + a validator-genesis
  mainnet-must-decide note. PoW still produces blocks — T14 swaps finality
  and only *reads* this module.  ← T3
- [x] **T14 Finality certificates (v1, hybrid)** — `lat_chain::finality`:
  validators sign a `Vote` (domain-separated Schnorr over block id ‖ height);
  votes for one block summing to **strictly >2/3** of the stake of the
  validator set THAT BLOCK COMMITS (recorded from `Ledger::validator_set()`
  when the chain adopts it — a `FINALITY_SET_WINDOW`=64 rolling window) form a
  `Certificate` that finalizes it. PoW keeps producing blocks (hybrid);
  **an empty validator set = pure PoW, semantics unchanged** (dev UX + the
  live testnet). Vote pool + `cast_vote`/`add_vote`/`accept_cert` live in
  `NodeState`; `Msg::FinalityVote`/`FinalityCert` (tags 26/27) gossip with
  the same flood-once semantics as `NewBlock`; `GetFinalized` RPC (28/29);
  `latebrad --validator` votes with the miner wallet's key on every adopted
  tip. Watermark persists in the chain DB (`Meta:"finality/anchor"`) and is
  restored on boot (position re-checked). Honest v1 limits (documented in the
  module): no slashing yet (T16 — >1/3 colluding stake could equivocate
  without loss), no liveness rounds (a height may never certify; PoW carries
  on), no proposer rotation (PoW is the producer), and certificates older
  than the set window are ignored (finality = recent anti-reorg; deep history
  is secured by work). Proven over real TCP in tests.  ← T13
- [x] **T15 Fork choice integrated with finality** (landed with T14): the
  chain keeps a finalized watermark and `apply_block` refuses any
  reorganization whose path does not include the finalized block — however
  heavy the rival branch — keeping it as a side branch instead. Behavioral
  test: a 2× heavier rival forking below the watermark is refused; forks
  above it reorg normally. Reorg adoption clears the (branch-specific)
  validator-set window and re-records at the new tip.  ← T14
- [x] **T16 Slashing + validator operations** (M3 COMPLETE 2026-07-07).
  `Transaction::SlashEvidence` (tag 0x0E, fixed 233 bytes): two signed
  finality votes by one validator for DIFFERENT blocks at one height — a
  self-authenticating fraud proof (`finality_vote_signing_bytes` moved to
  lat-types so the ledger verifies it without a dep cycle), so the tx needs
  no signature/nonce and anyone may submit it. Penalty: **full burn** of
  bonded stake AND unbonding entries (the unbonding window exists exactly so
  the exit door doesn't dodge it); replay finds `NothingToSlash` and is
  rejected; the offender drops out of every future validator set. Validator
  UX: `Wallet::{stake_tx, unstake_tx}` + lat-wallet-cli `stake` / `unstake` /
  `staking` commands, `GetStake` RPC (tags 30/31), LAUNCH.md "Becoming a
  validator" walkthrough + finality/slash parameter rows. Liveness: a
  validator re-votes for its tip on boot and on every 15 s heartbeat (the
  vote pool dedups, so no spam) — restarts and missed gossip converge.
  Deferred (revisit when real): partial-slash fractions + whistleblower
  reward, epoch-boundary set snapshots, proposer rotation (meaningless while
  PoW produces), governance parameters (there is no on-chain governance to
  parameterize yet).  ← T14

### M4 — Networking
- [x] **T17 Tx gossip + compact block announces.** (1) `Msg::NewTx` (tag 32):
  transactions flood node-to-node with the same flood-once semantics as
  blocks — and a wallet's `SubmitTx` now triggers the same forward, so a tx
  submitted to ANY node reaches every miner's mempool (previously it only
  ever sat in the one node it was sent to). Dedup = the mempool's duplicate
  check. (2) `Msg::BlockAnnounce { id, height }` (tag 33): announce ~40 bytes
  first; the peer replies "send it" only if it lacks the block, so gossip to
  peers that already hold a block costs an announce, not a re-transmitted
  body. Both the miner's announce and the relay path use it. Proven by a TCP
  test that offers a GARBAGE body with a known id — never read — vs an
  unknown id — fetched and rejected. `PROTOCOL_VERSION` bumped 1→2 (the
  handshake refuses old nodes; all testnet binaries must be rebuilt
  together). Deferred: compression (blocks are small until traffic says
  otherwise), set-reconciliation gossip (Erlay-style) at real scale.  ← T14
- [ ] T18 Peer discovery, DNS seeds, bootstrap nodes. (PARKED: code is a
  seed-list constant + resolve loop; needs the user's real deployment hosts.)
- [x] **T19 Fast sync + state sync integration.** A fresh node bootstraps by
  downloading the peer's object records instead of replaying every historical
  proof. New P2P messages (tags 34–37): `GetStateManifest` → `StateManifest`
  (anchor height/id + record count + chunk count; the peer captures anchor +
  records atomically under ONE node lock and keeps them per-connection, so
  chunks stay consistent while it mines) and `GetStateChunk(n)` → `StateChunk`
  (≤1 MiB record runs, under MAX_MSG_BYTES). No per-chunk digests needed: the
  syncing node rebuilds the commitment locally (`Ledger::from_records`) and
  `Blockchain::fast_sync_adopt` accepts only if the derived root equals the
  anchor header's `state_root` on a chain whose every header passed full
  structural+PoW validation (`insert_skeleton`), with the post-anchor tail
  fully replayed — same guarantee as replay, minus re-running the proofs.
  Only a FRESH chain (height 0) may fast-sync; any failure leaves it
  untouched and the caller falls back to `sync_shared`. `latebrad` tries it
  in the peer loop when at height 0; new `BootMode::FastSync`. Proven live:
  a fresh node jumped to height 52 in one shot, tracked the miner to 57, and
  RESTARTED as "state records + tail replay" at the tip (T7 anchor persisted
  by `rehome_state`). Tests: 3 lat-chain (adopt / tampered-record reject /
  wrong-network + non-fresh reject) + 1 lat-p2p TCP end-to-end.  ← T7, T14

### M5 — Ecosystem & APIs
- [x] **T20 JSON-RPC surface** (2026-07-12, Gap-5). JSON-RPC 2.0 over
  `POST /rpc` on latebrad's metrics port (loopback by default; 1 MiB body
  cap): `lat_status`, `lat_blockByHeight`, `lat_txByHash`,
  `lat_publicBalance`, `lat_encryptedBalance`, `lat_pending`, `lat_nonce`,
  `lat_stake`, `lat_contractStorage`, `lat_ringCandidates`, `lat_submitTx`
  (accepted txs gossip on, same as binary SubmitTx). Positional params,
  hex ids, `null` for missing entities. `rpc_handle` split from HTTP
  plumbing for direct unit testing; verified live via curl against a
  mining node. Reference: RPC.md. Deferred: REST/WS/gRPC variants,
  subscriptions.  ← T3
- [ ] T21 SDKs, contract stdlib, tooling, debugger.  ← T11

### M6 — Ops, QA, security (continuous)
- [x] **T22 Metrics, monitoring, Docker, CI.** (2026-07-11) `latebrad
  --metrics <addr|off>` (default loopback :4090) serves `GET /status` (JSON:
  height/tip/difficulty/peers/mempool/finalized/boot_mode/uptime) and
  `GET /metrics` (Prometheus text exposition) — one brief node lock per
  request, verified live against a mining node. Multi-stage `Dockerfile`
  (rust:1-slim → bookworm-slim; BLAKE3 PoW default needs no C toolchain) +
  `docker-compose.yml` (miner/validator + 2 followers — the second discovers
  the miner via peer exchange and exercises T19 fast sync — + explorer).
  GitHub Actions CI (`.github/workflows/ci.yml`): clippy `-D warnings`
  (allowing only type_complexity/too_many_arguments), full workspace tests
  (excl. latfun), release build, and a docker-build job. Repo made
  clippy-clean under that gate (auto-fix + 3 manual). rustfmt deliberately
  NOT enforced (would churn 18k LOC of git blame right before audit).
  LAUNCH.md updated (Docker bring-up, monitoring, fast-sync bootstrap).
  Deferred: K8s manifests, structured logging, Grafana dashboards.
- [x] **T23 Decoder fuzzing + multi-node soak.** (2026-07-11) Fuzz-style
  property tests over every untrusted-input decoder, deterministic xorshift
  (failures reproduce exactly): `lat-p2p` `Msg::decode` (40k inputs: random
  buffers sweeping all tag bytes + byte-flip/truncate/extend mutations of one
  representative of EVERY wire variant, with a full round-trip test kept in
  sync with the enum) and `lat-chain` `Block`/`BlockHeader`/`Transaction`/
  `Vote`/`Certificate::decode` (25k inputs mutated from real mined blocks w/
  registration + confidential-transfer txs and a real vote/cert). Invariants:
  never panic, and anything that DOES decode from hostile bytes must
  re-encode decodably. Zero panics found. `scripts/soak-testnet.ps1`: 3-node
  soak (miner/validator + 2 followers) with chaos kills/restarts of node-c
  every N secs, /status polling, miner-stall detection, and an end-of-run
  frozen-tip convergence assertion (exit 1 on divergence/death/stall) —
  4-min live run PASSED with restarts exercising the records boot path.
  Chosen over cargo-fuzz: nightly+libFuzzer is awkward on Windows and the
  seeded property tests run in normal `cargo test`, so CI runs them on every
  push. THREAT_MODEL.md already existed (launch track).

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
- ADR-0005: Contract platform deferred (D4). `lat-vm` v1 stays an arithmetic
  sandbox for the bonding curve; NFTs/composable DeFi are out of scope until a
  VM rewrite is justified by traction. Rationale: the confidential lane is
  already 20–60× shielded-chain throughput and is the defensible claim, while
  DeFi parity needs VM → compiler → language → tooling → developers. Corollary:
  T9/T10/T11 wait on the VM decision, since cross-contract `CALL` invalidates
  T8's static access sets.

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
- T7 durable state / records boot:
  - `lat-state::Ledger`: `from_records(Arc<dyn KVStore>) -> Option<Ledger>`
    (validate + rebuild commitment from `Column::Objects`; caller MUST verify
    the returned `state_root()` against a trusted header),
    `rehome(self, base, staged_meta) -> Ledger` (atomically replace `base`'s
    State+Objects with this ledger's, staged Meta writes in the same batch),
    `stage_meta(key, value)` (Meta write folded into the next `flush`).
  - `lat-chain`: `enum BootMode { Records, Snapshot, FullReplay }`,
    `Blockchain::boot_mode()`; boot anchor at `Meta:"state/anchor"`
    (`height u64 LE ‖ block id [32]`), written atomically with every adopted
    flush/rehome. `booted_from_snapshot()` = `boot_mode() != FullReplay`.
  - `lat-store::Smt` is `S: KVStore + ?Sized`.
- T8 parallel execution:
  - `lat_state::apply_block_parallel(&mut Ledger, &[Transaction], height)
    -> Result<(), LedgerError>` — drop-in equivalent of the sequential
    `apply_at` loop (same state, same block-level accept/reject); transparent
    lane runs across cores, everything else is a serial barrier. lat-chain's
    `apply_txs_and_reward` uses it; the mempool's `select_valid` deliberately
    stays sequential (per-tx admission, different problem).

- T13 staking:
  - `lat-types`: `Transaction::Stake`/`Unstake { validator, amount, nonce, sig }`
    (tags 0x0C/0x0D, fixed 113 bytes).
  - `lat-state`: `MIN_VALIDATOR_STAKE`, `UNBONDING_BLOCKS`, `MAX_VALIDATORS`,
    `struct Validator { staked, unbonding: Vec<(amount, release_height)> }`,
    `Ledger::{staked, unbonding, validator_set}`,
    `LedgerError::InsufficientStake`. Snapshot magic `LATLEDG3`.
- T14/T15 finality:
  - `lat-chain::finality`: `Vote { block_id, height, validator, sig }`
    (`sign`/`verify`/136-byte codec), `Certificate { block_id, height, votes }`
    (`verify(set)` = distinct staked signers, valid sigs, >2/3 stake).
  - `lat-chain`: `FINALITY_SET_WINDOW` (64), `Blockchain::{validator_set_at,
    finalized, try_finalize, active_id_at}`; watermark at
    `Meta:"finality/anchor"`; re-exports `MIN_VALIDATOR_STAKE` etc.
  - `lat-p2p`: `NodeState::{set_validator_key, add_vote, accept_cert,
    cast_vote}`; `Msg::FinalityVote`/`FinalityCert`/`GetFinalized` (26–29);
    `announce_vote`/`announce_cert`/`get_finalized` client fns.
  - `lat-wallet`: `Wallet::secret_key()`. `latebrad --validator`.
- T16 slashing + validator ops:
  - `lat-types`: `finality_vote_signing_bytes` (moved from lat-chain),
    `Transaction::SlashEvidence { validator, height, block_a, sig_a, block_b,
    sig_b }` (tag 0x0E, 233 bytes, unsigned — self-authenticating).
  - `lat-state`: `LedgerError::{BadEvidence, NothingToSlash}`.
  - `lat-wallet`: `stake_tx`/`unstake_tx`; CLI `stake`/`unstake`/`staking`.
  - `lat-p2p`: `Msg::GetStake`/`StakeReply` (30/31), `get_stake` client;
    `lat-chain`: `Blockchain::{staked, unbonding}`.

## 8. Known limitations / follow-ups

- **latfun's bonding curve is NOT atomic with its settlement (D4, live issue).**
  `lat-vm` cannot move LAT — it only reads/writes `u64` storage — so the deployed
  contract is the *pricing and accounting* half only, and the actual LAT movement
  is a **separate transparent transfer** that latfun orchestrates alongside the
  `CallContract`. The two are not bound by consensus. If latfun fails, crashes,
  or is interrupted between the two steps, on-chain holdings and real LAT
  diverge, with no chain-level rollback: the curve's storage says one thing and
  the treasury balance says another. Today this is bounded by latfun being the
  only orchestrator (a trusted server doing the money half — which is precisely
  the property the on-chain curve was built to remove). **This is task one of any
  VM program (M7): a VM-native token-transfer opcode so a trade is one atomic
  call.** Documented honestly at `lat-contracts/src/lib.rs` ("Honest boundary
  (v1 VM)"); do not ship launchpad marketing that implies consensus-enforced
  settlement until this closes.
- **RESOLVED by T7** (was: chain ledger base is still in-memory). Persistent
  chains commit state to the chain DB per adopted block and boot from records.
  Remaining T7 residue: an in-memory chain (`Blockchain::genesis`) still keeps
  everything in RAM by design; a **reorg rebuild still replays from genesis
  in memory first** (correct, but O(chain) RAM+time at reorg) — replace with a
  bounded undo-window when reorg depth matters; the records boot rebuilds the
  whole commitment (O(state log state) hashing at boot, ~the cost the snapshot
  boot already paid to decode+rehash).
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

**SCOPE SET BY D4 (2026-07-14): the remaining path is testnet → audit → mainnet
on the PRIVACY claim. No further VM/DeFi engineering before traction.** The
shipping claim is the confidential lane (~650 tx/s vs. ~10–30 TPS for Monero /
Zcash shielded), not Solana parity — NFTs and composable DeFi are out of scope
until a VM rewrite is justified (§4 D4, ADR-0005). T9/T11 are parked behind that
decision; T10 (parallel sig verification) is the only M2 task still worth doing
unconditionally. Do not let a VM detour displace the four gates below.

**PROGRAM CODE-COMPLETE for the testnet→audit→mainnet path.** M0–M4 + M6
done; M5 T20 JSON-RPC now DONE (T21 SDKs remain post-launch polish), T18 is an hour
of work once real seed hosts exist.

**F2 CLOSED (2026-07-12): hidden-amount anonymous transfers (v3).** The
pre-audit gap-closing pass (chosen after a chain-comparison review) hid the
`AnonTransfer` amount: public `amount` field replaced by a Pedersen debit
commitment `C_debit`; brick B is now a per-member CDS OR (`C_i ∈ ⟨H⟩` OR
`C_i − C_debit ∈ ⟨H⟩`) needing no public set; the fused relations (b)/(c)
and conservation run against `C_debit` (blindings fold into existing
witnesses); ONE aggregated Bulletproof range-proves the remaining balance
AND the amount via `C_amt = C_debit − fee·G` (rules out `debit < fee`
wraparound); the receiver credit rides as an ElGamal ciphertext under the
stealth one-time key, linked to `C_amt` by a two-base Schnorr, and the
ledger credits `xfer.credit` (plaintext `Ciphertext::mint` gone). Fee stays
public (fee-floor enforcement + miner credit). Domain tags bumped v2→v3;
wire format changed (testnet-only break, rebuild all binaries). Wallet
scan_stealth decrypts the credit with the derived one-time key
(BALANCE_BITS); explorer shows "hidden"; lat-attack's AnonSighting has no
amount field left to harvest. All ~256 tests green incl. the full
mine→apply→stealth-receive e2e and new tamper tests (shifted C_debit,
inflated credit, shifted fee all rejected). THREAT_MODEL.md §2 +
ANON_INTEGRATION.md updated. Anon path now hides sender, receiver, AND
amount — only fee/ring-size/epoch/timing remain visible.

**Gap-1 pre-audit hardening DONE (2026-07-12):** wrote `CRYPTO_SPEC.md` —
the auditor-facing math of the whole privacy scheme (ElGamal balances,
solvent transfer's 7 fused relations, AnonTransfer v3 full statement +
verification, stealth, epoch nullifier, finality sig; assumptions + known
limitations + code map) — linked from THREAT_MODEL.md and README as the
review scoping doc. Added adversarial regressions: chain-level
supply-conservation oracle (`anon_transfer_conserves_total_supply_no_inflation`,
lat-state — decrypts every balance before/after, asserts ring_before ==
ring_after + received + fee, so a hidden over-credit surfaces as minted
supply); malleability sweep (`malleability_sweep_every_byte_flip_is_rejected`,
~64 strided bit-flips, each mutant must decode-but-not-verify or not decode);
insolvent-sender forgery refusal; and range-proof splicing rejection. All
green; clippy gate clean.

**Gap-6 consensus economics DONE (2026-07-12):** replaced full-burn slashing
with the Cosmos-style model. `SlashEvidence` gained a `beneficiary` field
(wire tag 0x0E now 264-byte body). On valid equivocation evidence: slash
`SLASH_FRACTION_BPS` (10%) of the offender's bonded + unbonding stake, pay
`SLASH_REWARD_BPS` (5% of the slash) to the whistleblower's public balance,
burn the rest, and **tombstone** the validator (`Validator.tombstoned` — new
field, encode/decode + snapshot magic LATLEDG3→LATLEDG4; barred from
`validator_set`, and the tombstone is the replay guard against double-slash
now that residual stake remains). Validator cap parameterized:
`DEFAULT_MAX_VALIDATORS` + `Ledger::{max_validators, set_max_validators}` (a
consensus param a chain re-applies at boot like premine/difficulty).
LAUNCH.md mainnet table + CRYPTO_SPEC §4 updated. Tests rewritten
(`slash_evidence_partial_slash_reward_and_tombstone`, `validator_cap_is_configurable`).
NB: one PRE-EXISTING flaky test (`prune_window_bounds…`, timestamp-dependent
reorg under parallel load — passes in isolation) flagged as a separate task,
not caused by this change.

The remaining gates are NOT code tasks:

1. **User deploys the public testnet** (LAUNCH.md §3–4: VPS seeds + miner +
   explorer + launchpad, or `docker compose up`), pushes the repo to GitHub
   (CI goes live), publishes seed addresses → then T18 (DNS seeds).
2. **Longer soak** on the deployed net: `./scripts/soak-testnet.ps1
   -Minutes 480` locally and/or let the public testnet run for days;
   watch /metrics.
3. **External audit** (THREAT_MODEL.md is the scoping doc; the crypto —
   solvency proofs, ring signatures, finality — is unaudited and this is a
   HARD gate before real value).
4. **Mainnet-must-change list** (LAUNCH.md §5): fresh genesis + premine
   ceremony, real seed hosts, difficulty/emission review, RandomX decision.

If more engineering IS wanted meanwhile, the highest-value options that survive
D4: **T10** (parallel + batched signature verification — the sig-verify wall is
real under either VM outcome), an incremental prune sweep (§8 known debt), or
the pre-existing flaky `prune_window_bounds…` test. NB: T20 and the T16
partial-slash deferral, listed here previously, are both DONE. Do **not** start
T9/T11 — see D4.

### Build/verify commands
- Tests: `cargo test -p lat-store` (+ per-crate as tasks land).
- Chain bench: `cargo run --release --example bench -p lat-attack`.
- Store bench: `cargo run --release --example store_bench -p lat-store`.
- Clone bench: `cargo run --release --example clone_bench -p lat-state`.
- Prune bench: `cargo run --release --example prune_bench -p lat-state`.
- Parallel-exec bench: `cargo run --release --example parallel_bench -p lat-state`.
- Note: `latfun.exe` may hold a file lock during `--workspace` builds if running;
  build with `--exclude latfun` or stop that process.

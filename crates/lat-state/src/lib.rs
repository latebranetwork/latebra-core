//! Latebra ledger state (clean-room, from `SPEC.md`).
//!
//! The ledger holds, per account, a **confidential balance for each token**, and
//! a global **token registry** that enforces Latebra's signature feature: a
//! ticker is globally unique — only one `$TICKER` can ever exist.
//!
//! Transactions:
//! * `Register` — add an account.
//! * `CreateToken` — mint a new token under a unique ticker; fails if the ticker
//!   is already taken (this is the uniqueness guarantee), crediting the whole
//!   initial supply to the creator.
//! * `SolventTransfer { token, .. }` — move a hidden amount of one token by
//!   homomorphic arithmetic, after verifying a zero-knowledge proof of value
//!   conservation **and sender solvency** (`balance − amount − fee ≥ 0`).
//!
//! ## Security scope
//! The confidential `SolventTransfer` enforces value conservation, account
//! ownership (nonce-bound), AND sender solvency, so a hidden balance cannot be
//! overspent. (An earlier `Transfer` that proved conservation but not solvency
//! has been removed from the type system entirely.) The token id is named in the
//! transaction but not bound inside the ZK proof; the ledger applies it
//! consistently to both sides, so value is conserved within a token.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use lat_crypto::{Ciphertext, PublicKey, Signature};
use lat_store::{Column, KVStore, OverlayStore, Smt, WriteBatch};
use lat_types::{normalize_ticker, Transaction};

mod parallel;
pub use parallel::apply_block_parallel;

/// The native coin LAT is token id 0.
pub const LAT_TOKEN: u32 = 0;

/// Blocks per anonymity **epoch** (consensus parameter). An `AnonTransfer`'s
/// nullifier is scoped to one epoch: an account can make at most one anonymous
/// spend per epoch (the Zether anti-replay tradeoff — see `ANON_INTEGRATION.md`
/// §4), and a proof built in epoch `t` is only valid in a block of epoch `t`.
pub const EPOCH_BLOCKS: u64 = 20;

/// The anonymity epoch a block at `height` belongs to.
pub fn epoch_of(height: u64) -> u64 {
    height / EPOCH_BLOCKS
}

// -- staking parameters (T13, consensus) -------------------------------------
// TESTNET values — LAUNCH.md's mainnet-must-change table covers all three.

/// Minimum bonded stake to be eligible for the validator set: 1,000 LAT
/// (units are 5-decimal, so 1 LAT = 100_000).
pub const MIN_VALIDATOR_STAKE: u64 = 1_000 * 100_000;

/// Blocks between an `Unstake` and the funds releasing back to the public
/// balance. The delay is what makes misbehavior slashable after the fact
/// (T16) — stake can't vanish the moment it equivocates.
pub const UNBONDING_BLOCKS: u64 = 240;

/// Default upper bound on the validator set (top-N by stake). This is the
/// genesis default; a chain may override it via [`Ledger::set_max_validators`]
/// (a consensus parameter, so every node must agree — set it identically at
/// genesis). LAUNCH.md's mainnet table flags it.
pub const DEFAULT_MAX_VALIDATORS: usize = 64;

/// Slashing penalty as a fraction of the offender's total (bonded + unbonding)
/// stake, expressed in basis points (1000 = 10%). Partial slashing (Gap-6):
/// equivocation is punished proportionally rather than by full confiscation,
/// which is the modern PoS norm (e.g. Cosmos ~5%). Mainnet-tunable.
pub const SLASH_FRACTION_BPS: u64 = 1000;

/// Fraction of the *slashed* amount paid to the evidence submitter
/// (whistleblower), in basis points (500 = 5% of the slash). The remainder is
/// burned. Incentivizes nodes to actually submit equivocation proofs.
pub const SLASH_REWARD_BPS: u64 = 500;

/// Upper bound on the validator set — legacy alias of
/// [`DEFAULT_MAX_VALIDATORS`] kept for callers/tests that read the constant
/// directly. Prefer [`Ledger::max_validators`] for the effective (possibly
/// overridden) value.
pub const MAX_VALIDATORS: usize = DEFAULT_MAX_VALIDATORS;

/// A validator's staking state (T13): the bonded weight the BFT-PoS validator
/// set is derived from, plus any unbonding entries still in their delay window.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Validator {
    /// Currently bonded stake in public LAT — the validator-set weight.
    pub staked: u64,
    /// Unbonding entries as `(amount, release_height)`, oldest first. Matured
    /// entries sweep back into the public balance on the account's next
    /// `Stake`/`Unstake` (deterministic: driven by that tx's block height).
    pub unbonding: Vec<(u64, u64)>,
    /// Tombstoned (Gap-6): the validator was slashed for equivocation. Partial
    /// slashing leaves residual stake, so a permanent tombstone is what stops a
    /// second slash for the same offense (replay) and bars re-entry to the
    /// validator set — the Cosmos-style "one equivocation and you're out"
    /// model. The residual stake can still be unbonded and withdrawn.
    pub tombstoned: bool,
}

/// Drain every unbonding entry whose release height has passed, returning the
/// total released back to the public balance.
fn release_matured(v: &mut Validator, height: u64) -> u64 {
    let mut released = 0u64;
    v.unbonding.retain(|(amount, release)| {
        if *release <= height {
            released += *amount;
            false
        } else {
            true
        }
    });
    released
}

/// Metadata recorded for each created token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenMeta {
    pub id: u32,
    pub ticker: String,
    pub creator: [u8; 32],
    pub supply: u64,
}

/// One account's state.
///
/// Confidential value is split into `balances` (spendable now) and `pending`
/// (received but not yet rolled in). Incoming transfers land in `pending` so they
/// never change the balance an in-flight outgoing proof was built against. A
/// `Rollover` merges `pending` into `balances`. `nonce` versions outgoing spends
/// to prevent replay.
#[derive(Clone, Default)]
pub struct Account {
    balances: HashMap<u32, Ciphertext>,
    pending: HashMap<u32, Ciphertext>,
    /// Transparent, plaintext balance per token — the *public* half of Latebra's
    /// dual-state model. Fully visible on-chain; moved by `PublicTransfer` (and,
    /// later, shield/unshield). The `nonce` below is shared with confidential
    /// spends, so a public transfer also advances it (one spend counter per key).
    public: HashMap<u32, u64>,
    nonce: u64,
}

impl Account {
    fn balance(&self, token: u32) -> Ciphertext {
        self.balances.get(&token).copied().unwrap_or_else(Ciphertext::zero)
    }
    fn pending(&self, token: u32) -> Ciphertext {
        self.pending.get(&token).copied().unwrap_or_else(Ciphertext::zero)
    }
    fn set(&mut self, token: u32, ct: Ciphertext) {
        self.balances.insert(token, ct);
    }
    fn set_pending(&mut self, token: u32, ct: Ciphertext) {
        self.pending.insert(token, ct);
    }
    fn public(&self, token: u32) -> u64 {
        self.public.get(&token).copied().unwrap_or(0)
    }
    fn set_public(&mut self, token: u32, amount: u64) {
        self.public.insert(token, amount);
    }
}

/// A deployed smart contract: its bytecode and persistent storage.
#[derive(Clone, Default)]
pub struct Contract {
    pub code: Vec<u8>,
    pub storage: lat_vm::Storage,
}

/// One state entry whose leaf in the commitment trie needs (re)computing. The
/// `HashMap`s remain the authoritative O(1) read layer; this identifies *what*
/// changed so [`Ledger::state_root`] can update only the affected trie leaves
/// (O(log n) each) instead of rehashing the whole state.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum DirtyKey {
    Account([u8; 32]),
    Token(u32),
    Contract([u8; 32]),
    Nullifier([u8; 32]),
    /// A validator's staking record (T13).
    Validator([u8; 32]),
    /// The `next_token_id` meta record.
    Meta,
}

/// The authenticated state commitment: the current trie root plus the set of
/// entries changed since it was last computed. Interior-mutable so `state_root`
/// can reconcile lazily through `&self` (Blockchain calls it that way).
#[derive(Clone)]
struct Commitment {
    root: [u8; 32],
    dirty: HashSet<DirtyKey>,
}

impl Default for Commitment {
    fn default() -> Self {
        Commitment { root: lat_store::empty_root(), dirty: HashSet::new() }
    }
}

/// The full ledger (T5b: disk-resident). Every state object — accounts, tokens,
/// contracts, spent nullifiers — lives as an encoded record in the store's
/// [`Column::Objects`], layered by the same copy-on-write [`OverlayStore`] that
/// holds the commitment trie's nodes ([`Column::State`]). Nothing is required
/// to stay in RAM: memory is bounded by the read cache, and
/// [`clone`](Clone::clone) copies only the overlay's uncommitted write layer
/// (empty right after a per-block [`flush`](Self::flush)) — O(1)-ish however
/// large the state grows.
///
/// The authoritative `state_root` is a persistent Sparse Merkle Tree (an
/// [`Smt`] over the same store) updated incrementally from the `dirty` set.
pub struct Ledger {
    next_token_id: u32,
    /// Object records + trie nodes, as a copy-on-write overlay: reads fall
    /// through to the shared committed base, writes stay in the in-memory top
    /// until [`flush`](Self::flush) folds them down once per committed block.
    store: OverlayStore,
    /// Cached root + pending changes, reconciled lazily by `state_root`.
    commitment: RefCell<Commitment>,
    /// Write-through read cache over the hot account records, so repeated reads
    /// don't re-decode (and re-validate ciphertext points) from record bytes.
    /// Bounded: wholesale-cleared at [`ACCOUNT_CACHE_CAP`], never a correctness
    /// layer — every entry mirrors what the store holds. Clones start empty.
    cache: RefCell<HashMap<[u8; 32], Account>>,
    /// Effective validator-set cap (Gap-6). A consensus parameter, not derived
    /// from committed records, so a chain overriding the default must re-apply
    /// it after a boot (snapshot/records/replay) the same way it re-applies
    /// premine/difficulty. Defaults to [`DEFAULT_MAX_VALIDATORS`].
    max_validators: usize,
}

/// Upper bound on cached account records (~a few hundred bytes each). Reaching
/// it clears the cache outright — crude versus LRU, but bounded, allocation-
/// free on the hit path, and the next block simply re-warms its working set.
const ACCOUNT_CACHE_CAP: usize = 65_536;

impl Clone for Ledger {
    /// Shares the store's committed base and copies only the uncommitted write
    /// top (the speculative-execution path: miner block-building, mempool
    /// filtering). The read cache is not carried over — it re-warms on use.
    fn clone(&self) -> Self {
        Ledger {
            next_token_id: self.next_token_id,
            store: self.store.clone(),
            commitment: RefCell::new(self.commitment.borrow().clone()),
            cache: RefCell::new(HashMap::new()),
            max_validators: self.max_validators,
        }
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Ledger::new()
    }
}

/// T12: evidence from the parallel pre-pass that a confidential transaction's
/// **expensive** zero-knowledge verification already ran and passed. The apply
/// path treats it as a *hint*, never an authority:
///
/// * [`ProofPass::Anon`] — `AnonTransfer::verify()` is a pure function of the
///   transfer bytes (the proof binds to the transfer's *claimed* ring
///   balances; the apply arm separately compares claimed vs. live balances),
///   so a passing pre-verification is unconditionally reusable.
/// * [`ProofPass::AgainstBalance`] — a `SolventTransfer`/`Unshield` proof was
///   verified against exactly this sender balance ciphertext. The apply arm
///   skips re-verification **only if the live balance it reads is
///   bit-identical** to this one, so soundness never depends on the pre-pass
///   having predicted write sets correctly — a wrong guess just costs the
///   serial re-verify it would have cost anyway.
#[allow(clippy::large_enum_variant)] // a 64-byte ciphertext; short-lived, few per block
pub(crate) enum ProofPass {
    Anon,
    AgainstBalance(Ciphertext),
}

/// Verify a transparent transaction's Schnorr signature by the account key `id`
/// over the transaction's signing bytes.
fn check_sig(id: &[u8; 32], tx: &Transaction, sig: &[u8; 64]) -> Result<(), LedgerError> {
    let pk = PublicKey::from_bytes(id).ok_or(LedgerError::BadSignature)?;
    let sig = Signature::from_bytes(sig).ok_or(LedgerError::BadSignature)?;
    if pk.verify(&tx.signing_bytes(), &sig) {
        Ok(())
    } else {
        Err(LedgerError::BadSignature)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LedgerError {
    AlreadyRegistered,
    SenderNotRegistered,
    ReceiverNotRegistered,
    CreatorNotRegistered,
    InvalidProof,
    InvalidTicker,
    TickerTaken,
    /// The transfer's nonce did not match the sender's current account nonce
    /// (stale or replayed).
    BadNonce,
    /// A contract already exists at the derived address.
    ContractExists,
    /// No contract is deployed at the given address.
    NoSuchContract,
    /// The contract's execution failed (bad opcode, out of gas, etc.).
    ContractFailed,
    /// A transparent transaction's Schnorr signature is missing/invalid, or the
    /// named account key doesn't decode to a valid public key.
    BadSignature,
    /// A public transfer would spend more than the sender's transparent balance
    /// (amount + fee exceeds the plaintext public balance).
    InsufficientPublicBalance,
    /// An unshield's confidential receiver is not the public unshield view key,
    /// so its amount cannot be soundly revealed.
    WrongUnshieldReceiver,
    /// An unshield's declared public amount does not match the amount actually
    /// encrypted in its confidential proof.
    UnshieldAmountMismatch,
    /// An anonymous transfer's epoch does not match the containing block's
    /// epoch (stale or premature proof).
    WrongEpoch,
    /// An anonymous transfer's nullifier was already spent — a second anonymous
    /// spend by the same account within the same epoch.
    NullifierSeen,
    /// A ring member of an anonymous transfer is not a registered account, or
    /// appears in the ring more than once.
    BadRing,
    /// A ring member's claimed balance ciphertext does not match its current
    /// on-chain balance (the proof binds to stale or fabricated state).
    StaleRingBalance,
    /// An `Unstake` asked for more than the validator's bonded stake.
    InsufficientStake,
    /// A `SlashEvidence` transaction is not a valid equivocation proof (same
    /// block twice, a bad signature, or a key that doesn't decode).
    BadEvidence,
    /// Valid evidence, but the named validator holds no stake and no
    /// unbonding funds — already slashed (a replay) or never bonded.
    NothingToSlash,
}

impl Ledger {
    pub fn new() -> Self {
        Ledger::with_store(OverlayStore::in_memory())
    }

    /// A ledger whose committed trie nodes and object records are read from
    /// (and, on [`flush`], written to) `base` — e.g. a `RedbStore` for on-disk
    /// persistence. Uncommitted writes stay in the overlay's in-memory top until
    /// flushed.
    ///
    /// A fresh ledger is EMPTY state by definition, so any object records a
    /// previous run left in `base` are wiped first: unlike trie nodes (content-
    /// addressed, so stale ones are unreachable garbage at worst), a stale
    /// account record would read back as live state and corrupt the replay
    /// that rebuilds this ledger. (Booting state directly from the records —
    /// skipping replay — is the T7 snapshot-sync milestone.)
    pub fn with_base(base: Arc<dyn KVStore>) -> Self {
        let stale = base.scan_prefix(Column::Objects, b"");
        if !stale.is_empty() {
            let mut batch = WriteBatch::new();
            for (key, _) in stale {
                batch.delete(Column::Objects, key);
            }
            base.write(batch);
        }
        Ledger::with_store(OverlayStore::new(base))
    }

    fn with_store(store: OverlayStore) -> Self {
        // The meta record (binding `next_token_id`) is part of the committed
        // state from the start, so seed it dirty — otherwise an empty ledger and
        // a freshly-rebuilt one would commit different roots.
        let mut commitment = Commitment::default();
        commitment.dirty.insert(DirtyKey::Meta);
        Ledger {
            next_token_id: 1, // 0 is reserved for native LAT
            store,
            commitment: RefCell::new(commitment),
            cache: RefCell::new(HashMap::new()),
            max_validators: DEFAULT_MAX_VALIDATORS,
        }
    }

    /// Fold uncommitted writes (trie nodes + object records) into the store's
    /// base (durably, if the base is on disk). Semantically a no-op — it does
    /// not change `state_root` — but it keeps the overlay's write layer small so
    /// the next [`clone`](Clone::clone) stays cheap. Call it once per committed
    /// block.
    ///
    /// **Only ever flush an adopted state.** Clones share the base, so a
    /// speculative clone that flushed would publish its object records into
    /// every sibling ledger. (With T5b this is a hard invariant: trie nodes are
    /// content-addressed and merely accumulate, but object records are keyed by
    /// id and would silently overwrite the canonical state.) lat-chain flushes
    /// only at genesis, tip-adoption, and reorg-adoption — never from `mine` /
    /// `select_valid` clones.
    pub fn flush(&self) {
        self.store.flush();
    }

    /// Boot a ledger from the object records a previous run committed into
    /// `base` (T7) — the replay-free inverse of [`with_base`](Self::with_base)'s
    /// wipe. Every record is decoded (and thereby validated: ciphertext points,
    /// bounds, exact lengths) and marked dirty, and the commitment is rebuilt
    /// from scratch, so the returned ledger's `state_root()` is **derived from
    /// the records themselves**, never read from disk. The caller MUST compare
    /// that root against a trusted commitment (a PoW-bound block header) before
    /// adopting the ledger — this is exactly the snapshot-file trust model.
    ///
    /// The ticker-uniqueness index is rebuilt from the decoded tokens (it is
    /// not part of the commitment, so it can't be trusted from disk).
    ///
    /// `None` if `base` holds no state or any record is malformed — every
    /// failure has the same correct handling: fall back to replay.
    pub fn from_records(base: Arc<dyn KVStore>) -> Option<Ledger> {
        // No records at all = nothing to boot from. The meta record only exists
        // once a token has been created (`put_token` writes it); its absence on
        // a token-less state simply means the initial id. A *wrong* value can't
        // slip through either way: the commitment covers `next_token_id`, so
        // the caller's header-root check catches any mismatch.
        if base.scan_prefix(Column::Objects, b"").is_empty() {
            return None;
        }
        let next_token_id = match base.get(Column::Objects, &[REC_META]) {
            Some(meta) => u32::from_le_bytes(meta.as_slice().try_into().ok()?),
            None => 1,
        };
        let mut ledger = Ledger::with_store(OverlayStore::new(base));
        ledger.next_token_id = next_token_id;

        let mut dirty: Vec<DirtyKey> = vec![DirtyKey::Meta];
        for (key, body) in ledger.store.scan_prefix(Column::Objects, &[REC_ACCOUNT]) {
            let id: [u8; 32] = key.get(1..)?.try_into().ok()?;
            decode_account(&body)?;
            dirty.push(DirtyKey::Account(id));
        }
        let mut tickers = Vec::new();
        for (key, body) in ledger.store.scan_prefix(Column::Objects, &[REC_TOKEN]) {
            let t = decode_token(&body)?;
            // The record key must be the token's own id, or reads by id would
            // silently diverge from what the commitment covers.
            if key.get(1..)? != t.id.to_be_bytes() {
                return None;
            }
            tickers.push((t.ticker.clone(), t.id));
            dirty.push(DirtyKey::Token(t.id));
        }
        for (key, body) in ledger.store.scan_prefix(Column::Objects, &[REC_CONTRACT]) {
            let id: [u8; 32] = key.get(1..)?.try_into().ok()?;
            decode_contract(&body)?;
            dirty.push(DirtyKey::Contract(id));
        }
        for (key, _) in ledger.store.scan_prefix(Column::Objects, &[REC_NULLIFIER]) {
            let nf: [u8; 32] = key.get(1..)?.try_into().ok()?;
            dirty.push(DirtyKey::Nullifier(nf));
        }
        for (key, body) in ledger.store.scan_prefix(Column::Objects, &[REC_VALIDATOR]) {
            let id: [u8; 32] = key.get(1..)?.try_into().ok()?;
            decode_validator(&body)?;
            dirty.push(DirtyKey::Validator(id));
        }
        // Rebuild the ticker index from committed tokens (self-heals tampering).
        for (ticker, id) in tickers {
            ledger.store.put(
                Column::Objects,
                rec_key(REC_TICKER, ticker.as_bytes()),
                id.to_be_bytes().to_vec(),
            );
        }
        ledger.mark_all(dirty);
        ledger.state_root(); // rebuild the commitment; caller verifies this root
        Some(ledger)
    }

    /// Atomically move this ledger's committed state onto `base`, replacing
    /// whatever state `base` held: one write batch deletes `base`'s old
    /// `Objects` + `State` keys, writes this ledger's, and appends
    /// `staged_meta` (e.g. the chain's boot anchor, so the anchor can never
    /// disagree with the state it describes). Returns the same logical ledger
    /// now living over `base`. Used to adopt a reorg-rebuilt (in-memory) state
    /// onto the durable store without a wipe-then-replay crash window: `base`
    /// flips from old state to new in a single atomic commit.
    pub fn rehome(
        self,
        base: Arc<dyn KVStore>,
        staged_meta: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Ledger {
        self.state_root(); // reconcile pending trie updates
        self.flush(); // fold everything into our own base so one scan sees it all
        let mut batch = WriteBatch::new();
        for (key, _) in base.scan_prefix(Column::Objects, b"") {
            batch.delete(Column::Objects, key);
        }
        for (key, _) in base.scan_prefix(Column::State, b"") {
            batch.delete(Column::State, key);
        }
        // Ordered batch, last-writer-wins: puts land after the deletes above.
        for (key, value) in self.store.scan_prefix(Column::Objects, b"") {
            batch.put(Column::Objects, key, value);
        }
        for (key, value) in self.store.scan_prefix(Column::State, b"") {
            batch.put(Column::State, key, value);
        }
        for (key, value) in staged_meta {
            batch.put(Column::Meta, key, value);
        }
        base.write(batch);

        let mut fresh = Ledger::with_store(OverlayStore::new(base));
        fresh.next_token_id = self.next_token_id;
        // Carry the reconciled commitment (root current, dirty set empty).
        *fresh.commitment.get_mut() = self.commitment.borrow().clone();
        fresh
    }

    /// Stage a chain-metadata write into this ledger's overlay so it commits
    /// atomically with the next [`flush`](Self::flush) — e.g. the boot anchor
    /// riding the same durable batch as the state it describes.
    pub fn stage_meta(&self, key: Vec<u8>, value: Vec<u8>) {
        self.store.put(Column::Meta, key, value);
    }

    /// Garbage-collect the commitment trie (T6): drop from the committed base
    /// every trie node unreachable from the current `state_root` or from one of
    /// `retain_roots` (a window of recent historical roots kept queryable for
    /// proofs). Content-addressed nodes accumulate forever otherwise — every
    /// account update strands its old path.
    ///
    /// Reconciles and flushes first, so the sweep sees the complete current
    /// state in the base. Semantically a no-op for the current state and every
    /// retained root; roots *not* retained become unreadable. **Same invariant
    /// as [`flush`](Self::flush): only call on the adopted ledger**, and retain
    /// every root a live speculative clone may have been forked from. Archive
    /// nodes simply never call this.
    pub fn prune_history(&self, retain_roots: &[[u8; 32]]) -> lat_store::PruneStats {
        let mut roots = Vec::with_capacity(retain_roots.len() + 1);
        roots.push(self.state_root()); // reconciles pending dirty entries
        roots.extend_from_slice(retain_roots);
        self.flush(); // the base must hold every node before the sweep
        lat_store::prune_state(self.store.base().as_ref(), &roots)
    }

    /// Every object record (accounts, tokens, ticker index, contracts,
    /// nullifiers, validators, meta), key-ordered — the full material state.
    /// T19 fast sync serves these to a syncing peer, which rebuilds and
    /// verifies the commitment from them via [`from_records`](Self::from_records).
    pub fn object_records(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.store.scan_prefix(Column::Objects, b"")
    }

    /// Commitment-trie nodes currently in the committed base (diagnostics /
    /// benchmarks — e.g. asserting [`prune_history`](Self::prune_history)
    /// actually shrank the store). Meaningful after a [`flush`](Self::flush);
    /// uncommitted nodes still in the overlay's write top are not counted.
    pub fn state_node_count(&self) -> usize {
        self.store.base().scan_prefix(Column::State, b"").len()
    }

    // -- object records ---------------------------------------------------------
    // Accounts, tokens, contracts and nullifiers are encoded records in
    // `Column::Objects`, read through a bounded write-through cache (accounts
    // only — they are the hot set). A record that exists but fails to decode is
    // a corrupt store, which is fatal (same policy as the redb backend): better
    // a loud crash than a node that silently computes wrong state.

    /// Read one account record (cache, then store).
    fn account(&self, id: &[u8; 32]) -> Option<Account> {
        if let Some(a) = self.cache.borrow().get(id) {
            return Some(a.clone());
        }
        let bytes = self.store.get(Column::Objects, &rec_key(REC_ACCOUNT, id))?;
        let a = decode_account(&bytes).expect("corrupt account record");
        let mut cache = self.cache.borrow_mut();
        if cache.len() >= ACCOUNT_CACHE_CAP {
            cache.clear();
        }
        cache.insert(*id, a.clone());
        Some(a)
    }

    /// Write one account record (store + cache, so the next read hits).
    fn put_account(&mut self, id: &[u8; 32], a: Account) {
        self.store.put(Column::Objects, rec_key(REC_ACCOUNT, id), encode_account(&a));
        let mut cache = self.cache.borrow_mut();
        if cache.len() >= ACCOUNT_CACHE_CAP {
            cache.clear();
        }
        cache.insert(*id, a);
    }

    /// Raw account record bytes (T8 crate-internal: a parallel worker's view
    /// exports its writes as records for the merge back into the main ledger).
    fn account_record(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        self.store.get(Column::Objects, &rec_key(REC_ACCOUNT, id))
    }

    /// Adopt an account record produced by a parallel worker's view (T8
    /// crate-internal). Bypasses the typed write path, so the cache entry must
    /// be dropped (it would otherwise serve the stale pre-wave account) and the
    /// commitment leaf re-marked.
    fn adopt_account_record(&mut self, id: &[u8; 32], bytes: Vec<u8>) {
        self.store.put(Column::Objects, rec_key(REC_ACCOUNT, id), bytes);
        self.cache.get_mut().remove(id);
        self.mark(DirtyKey::Account(*id));
    }

    /// Read one token record by id.
    fn token_by_id(&self, id: u32) -> Option<TokenMeta> {
        let bytes = self.store.get(Column::Objects, &rec_key(REC_TOKEN, &id.to_be_bytes()))?;
        Some(decode_token(&bytes).expect("corrupt token record"))
    }

    /// Write one token record + its ticker index + the `next_token_id` meta
    /// record, atomically (they must never disagree).
    fn put_token(&mut self, t: &TokenMeta) {
        let mut batch = WriteBatch::new();
        batch
            .put(Column::Objects, rec_key(REC_TOKEN, &t.id.to_be_bytes()), encode_token(t))
            .put(Column::Objects, rec_key(REC_TICKER, t.ticker.as_bytes()), t.id.to_be_bytes().to_vec())
            .put(Column::Objects, vec![REC_META], self.next_token_id.to_le_bytes().to_vec());
        self.store.write(batch);
    }

    /// Whether a (normalized) ticker is already registered.
    fn ticker_taken(&self, norm: &str) -> bool {
        self.store.contains(Column::Objects, &rec_key(REC_TICKER, norm.as_bytes()))
    }

    /// Read one contract record.
    fn contract(&self, id: &[u8; 32]) -> Option<Contract> {
        let bytes = self.store.get(Column::Objects, &rec_key(REC_CONTRACT, id))?;
        Some(decode_contract(&bytes).expect("corrupt contract record"))
    }

    /// Write one contract record.
    fn put_contract(&mut self, id: &[u8; 32], c: &Contract) {
        self.store.put(Column::Objects, rec_key(REC_CONTRACT, id), encode_contract(c));
    }

    /// Record an anonymous-spend nullifier as spent.
    fn insert_nullifier(&mut self, nf: &[u8; 32]) {
        self.store.put(Column::Objects, rec_key(REC_NULLIFIER, nf), vec![1u8]);
    }

    /// Read one validator staking record.
    fn validator(&self, id: &[u8; 32]) -> Option<Validator> {
        let bytes = self.store.get(Column::Objects, &rec_key(REC_VALIDATOR, id))?;
        Some(decode_validator(&bytes).expect("corrupt validator record"))
    }

    /// Write one validator record. A fully-drained record (no stake, no
    /// unbonding) is DELETED rather than stored empty, so the committed state
    /// is canonical: it matches a chain where the account never staked.
    fn put_validator(&mut self, id: &[u8; 32], v: &Validator) {
        if v.staked == 0 && v.unbonding.is_empty() {
            self.store.delete(Column::Objects, rec_key(REC_VALIDATOR, id));
        } else {
            self.store.put(Column::Objects, rec_key(REC_VALIDATOR, id), encode_validator(v));
        }
    }

    /// The validator's currently bonded stake (0 if it never staked).
    pub fn staked(&self, id: &[u8; 32]) -> u64 {
        self.validator(id).map(|v| v.staked).unwrap_or(0)
    }

    /// The validator's unbonding entries as `(amount, release_height)`.
    pub fn unbonding(&self, id: &[u8; 32]) -> Vec<(u64, u64)> {
        self.validator(id).map(|v| v.unbonding).unwrap_or_default()
    }

    /// The deterministic validator set at the current state (T13): every
    /// non-tombstoned account with at least [`MIN_VALIDATOR_STAKE`] bonded,
    /// ordered by stake descending then id ascending, capped at the effective
    /// [`max_validators`](Self::max_validators). Derived purely from committed
    /// records, so every node computes the identical set — the input BFT-PoS
    /// finality (T14) selects proposers/voters from.
    pub fn validator_set(&self) -> Vec<([u8; 32], u64)> {
        let mut set: Vec<([u8; 32], u64)> = self
            .store
            .scan_prefix(Column::Objects, &[REC_VALIDATOR])
            .into_iter()
            .filter_map(|(key, body)| {
                let id: [u8; 32] = key.get(1..)?.try_into().ok()?;
                let v = decode_validator(&body)?;
                // Tombstoned validators (slashed for equivocation) are barred.
                (!v.tombstoned && v.staked >= MIN_VALIDATOR_STAKE).then_some((id, v.staked))
            })
            .collect();
        set.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        set.truncate(self.max_validators());
        set
    }

    /// The effective cap on the validator set. Defaults to
    /// [`DEFAULT_MAX_VALIDATORS`]; a chain may override it at genesis via
    /// [`set_max_validators`](Self::set_max_validators). This is a consensus
    /// parameter — every node MUST use the same value or their validator sets
    /// (and thus finality) diverge.
    pub fn max_validators(&self) -> usize {
        self.max_validators
    }

    /// Override the validator-set cap (consensus parameter — set identically on
    /// every node, at genesis). Panics if `n == 0` (an empty set can never
    /// finalize).
    pub fn set_max_validators(&mut self, n: usize) {
        assert!(n > 0, "validator cap must be positive");
        self.max_validators = n;
    }

    /// Flag one state entry for re-commitment on the next `state_root`. Cheap:
    /// no hashing happens here, only at the next root computation.
    fn mark(&mut self, key: DirtyKey) {
        self.commitment.get_mut().dirty.insert(key);
    }

    fn mark_all(&mut self, keys: impl IntoIterator<Item = DirtyKey>) {
        let dirty = &mut self.commitment.get_mut().dirty;
        dirty.extend(keys);
    }

    /// The state entries a successfully-applied `tx` may have changed. A
    /// *superset* is always safe (an unchanged leaf recomputes to the same
    /// value), so this errs toward marking extra rather than missing one.
    fn dirty_keys_for(&self, tx: &Transaction) -> Vec<DirtyKey> {
        match tx {
            Transaction::Register { pubkey, .. } => vec![DirtyKey::Account(*pubkey)],
            Transaction::CreateToken { creator, .. } => {
                // The token just created got id `next_token_id - 1`.
                vec![
                    DirtyKey::Account(*creator),
                    DirtyKey::Token(self.next_token_id.saturating_sub(1)),
                    DirtyKey::Meta,
                ]
            }
            Transaction::SolventTransfer { xfer, .. } => {
                vec![DirtyKey::Account(xfer.sender.to_bytes()), DirtyKey::Account(xfer.receiver.to_bytes())]
            }
            Transaction::Rollover { account, .. } => vec![DirtyKey::Account(*account)],
            Transaction::DeployContract { deployer, code, .. } => {
                vec![DirtyKey::Contract(lat_vm::contract_id(deployer, code)), DirtyKey::Account(*deployer)]
            }
            Transaction::CallContract { contract, caller, .. } => {
                vec![DirtyKey::Contract(*contract), DirtyKey::Account(*caller)]
            }
            Transaction::PublicTransfer { from, to, .. } => {
                vec![DirtyKey::Account(*from), DirtyKey::Account(*to)]
            }
            Transaction::Shield { from, to, .. } => vec![DirtyKey::Account(*from), DirtyKey::Account(*to)],
            Transaction::Unshield { to, xfer, .. } => {
                vec![DirtyKey::Account(xfer.sender.to_bytes()), DirtyKey::Account(*to)]
            }
            Transaction::ShieldStealth { from, one_time, .. } => {
                vec![DirtyKey::Account(*from), DirtyKey::Account(*one_time)]
            }
            Transaction::AnonTransfer { xfer, .. } => {
                let mut keys: Vec<DirtyKey> =
                    xfer.ring.iter().map(|m| DirtyKey::Account(m.to_bytes())).collect();
                keys.push(DirtyKey::Account(xfer.output.one_time.to_bytes()));
                keys.push(DirtyKey::Nullifier(xfer.nullifier()));
                keys
            }
            Transaction::Stake { validator, .. } | Transaction::Unstake { validator, .. } => {
                vec![DirtyKey::Account(*validator), DirtyKey::Validator(*validator)]
            }
            Transaction::SlashEvidence { validator, .. } => {
                vec![DirtyKey::Validator(*validator)]
            }
        }
    }

    /// Whether an anonymous-spend nullifier has already been used (mempools use
    /// this to reject a conflicting in-flight spend early).
    pub fn nullifier_seen(&self, nullifier: &[u8; 32]) -> bool {
        self.store.contains(Column::Objects, &rec_key(REC_NULLIFIER, nullifier))
    }

    /// The decoy pool for anonymous transfers: every registered account with an
    /// explicitly-set confidential balance ciphertext of `token` (even one that
    /// encrypts 0 — an observer can't tell), with that ciphertext, sorted by
    /// account id. Wallets sample ring decoys from this list; an `AnonTransfer`
    /// naming a member/balance not in it is rejected by `apply_at`.
    pub fn ring_candidates(&self, token: u32) -> Vec<([u8; 32], Ciphertext)> {
        // Records scan in ascending id order, so the output is already sorted.
        let mut out = Vec::new();
        for (key, body) in self.store.scan_prefix(Column::Objects, &[REC_ACCOUNT]) {
            let Some(id) = key.get(1..).and_then(|s| <[u8; 32]>::try_from(s).ok()) else { continue };
            let a = decode_account(&body).expect("corrupt account record");
            if let Some(ct) = a.balances.get(&token) {
                out.push((id, *ct));
            }
        }
        out
    }

    pub fn is_registered(&self, id: &[u8; 32]) -> bool {
        self.cache.borrow().contains_key(id)
            || self.store.contains(Column::Objects, &rec_key(REC_ACCOUNT, id))
    }

    /// The spendable encrypted balance of `token` held by `id`, if registered.
    pub fn balance(&self, id: &[u8; 32], token: u32) -> Option<Ciphertext> {
        self.account(id).map(|a| a.balance(token))
    }

    /// The pending (received, not yet rolled-over) encrypted balance of `token`.
    pub fn pending(&self, id: &[u8; 32], token: u32) -> Option<Ciphertext> {
        self.account(id).map(|a| a.pending(token))
    }

    /// The account's current spend nonce (next outgoing transfer must use it).
    pub fn nonce(&self, id: &[u8; 32]) -> Option<u64> {
        self.account(id).map(|a| a.nonce)
    }

    /// The transparent (plaintext) public balance of `token` held by `id`, if
    /// registered. Returns 0 for a registered account that holds none.
    pub fn public_balance(&self, id: &[u8; 32], token: u32) -> Option<u64> {
        self.account(id).map(|a| a.public(token))
    }

    /// Credit `amount` of `token` to `id`'s transparent public balance,
    /// registering the account if needed. Used for the genesis public premine,
    /// public transfer fees to the miner, and (later) unshielding. Saturating so
    /// consensus can never panic on an overflow it didn't cause.
    pub fn credit_public(&mut self, id: &[u8; 32], token: u32, amount: u64) {
        if amount == 0 {
            return;
        }
        let mut acct = self.account(id).unwrap_or_default();
        let new = acct.public(token).saturating_add(amount);
        acct.set_public(token, new);
        self.put_account(id, acct);
        self.mark(DirtyKey::Account(*id));
    }

    /// Look up a token's metadata by (normalized) ticker.
    pub fn token(&self, ticker: &str) -> Option<TokenMeta> {
        let norm = normalize_ticker(ticker)?;
        let idx = self.store.get(Column::Objects, &rec_key(REC_TICKER, norm.as_bytes()))?;
        let id = u32::from_be_bytes(idx.try_into().ok()?);
        self.token_by_id(id)
    }

    /// Number of tokens registered (excluding native LAT).
    pub fn token_count(&self) -> usize {
        self.store.scan_prefix(Column::Objects, &[REC_TICKER]).len()
    }

    /// Read a slot from a deployed contract's storage (`0` if unset/no contract).
    pub fn contract_storage(&self, contract: &[u8; 32], key: u64) -> u64 {
        self.contract(contract)
            .and_then(|c| c.storage.get(&key).copied())
            .unwrap_or(0)
    }

    /// Whether a contract is deployed at `id`.
    pub fn has_contract(&self, id: &[u8; 32]) -> bool {
        self.store.contains(Column::Objects, &rec_key(REC_CONTRACT, id))
    }

    /// Register a new account.
    pub fn register(&mut self, id: [u8; 32]) -> Result<(), LedgerError> {
        if self.is_registered(&id) {
            return Err(LedgerError::AlreadyRegistered);
        }
        self.put_account(&id, Account::default());
        self.mark(DirtyKey::Account(id));
        Ok(())
    }

    /// Credit a miner a coinbase reward or a collected fee of `token`, registering
    /// the account if needed. Transparent/public by design, like the premine.
    pub fn reward_miner(&mut self, miner: &[u8; 32], token: u32, amount: u64) {
        if amount == 0 {
            return;
        }
        let mut acct = self.account(miner).unwrap_or_default();
        let new = acct.balance(token).add(&Ciphertext::mint(amount));
        acct.set(token, new);
        self.put_account(miner, acct);
        self.mark(DirtyKey::Account(*miner));
    }

    /// Genesis premine / coinbase of native LAT (transparent, public by design).
    pub fn credit_genesis(&mut self, id: &[u8; 32], amount: u64) -> Result<(), LedgerError> {
        let mut acct = self.account(id).ok_or(LedgerError::ReceiverNotRegistered)?;
        let new = acct.balance(LAT_TOKEN).add(&Ciphertext::mint(amount));
        acct.set(LAT_TOKEN, new);
        self.put_account(id, acct);
        self.mark(DirtyKey::Account(*id));
        Ok(())
    }

    /// Apply a transaction with no block context (height 0). Only correct for
    /// height-independent transaction types; consensus always goes through
    /// [`apply_at`](Self::apply_at), which enforces the epoch rules of
    /// `AnonTransfer`. Kept for tests and tools.
    pub fn apply(&mut self, tx: &Transaction) -> Result<(), LedgerError> {
        self.apply_at(tx, 0)
    }

    /// Apply a transaction in the context of the block at `height` (which fixes
    /// the anonymity epoch an `AnonTransfer` must match). On success, the state
    /// entries it touched are flagged for re-commitment (the trie root updates
    /// lazily on the next [`state_root`](Self::state_root)).
    pub fn apply_at(&mut self, tx: &Transaction, height: u64) -> Result<(), LedgerError> {
        self.apply_at_with(tx, height, None)
    }

    /// Like [`apply_at`](Self::apply_at), with optional evidence from the T12
    /// parallel pre-pass that this transaction's expensive zero-knowledge
    /// verification already ran (see [`ProofPass`]). Every other check still
    /// runs; the verdict is identical either way.
    pub(crate) fn apply_at_with(
        &mut self,
        tx: &Transaction,
        height: u64,
        pre: Option<&ProofPass>,
    ) -> Result<(), LedgerError> {
        let result = self.apply_inner(tx, height, pre);
        if result.is_ok() {
            let keys = self.dirty_keys_for(tx);
            self.mark_all(keys);
        }
        result
    }

    fn apply_inner(
        &mut self,
        tx: &Transaction,
        height: u64,
        pre: Option<&ProofPass>,
    ) -> Result<(), LedgerError> {
        match tx {
            Transaction::Register { pubkey, .. } => self.register(*pubkey),

            Transaction::CreateToken {
                ticker,
                creator,
                supply,
                sig,
            } => {
                check_sig(creator, tx, sig)?;
                let norm = normalize_ticker(ticker).ok_or(LedgerError::InvalidTicker)?;
                // THE uniqueness guarantee: one ticker, ever.
                if self.ticker_taken(&norm) {
                    return Err(LedgerError::TickerTaken);
                }
                let mut acct = self.account(creator).ok_or(LedgerError::CreatorNotRegistered)?;
                let id = self.next_token_id;
                self.next_token_id += 1;
                self.put_token(&TokenMeta {
                    id,
                    ticker: norm,
                    creator: *creator,
                    supply: *supply,
                });
                // Credit the whole initial supply to the creator.
                let new = acct.balance(id).add(&Ciphertext::mint(*supply));
                acct.set(id, new);
                self.put_account(creator, acct);
                Ok(())
            }

            Transaction::SolventTransfer { token, xfer } => {
                let sender_id = xfer.sender.to_bytes();
                let receiver_id = xfer.receiver.to_bytes();
                let (sender_bal, sender_nonce) = match self.account(&sender_id) {
                    Some(a) => (a.balance(*token), a.nonce),
                    None => return Err(LedgerError::SenderNotRegistered),
                };
                // Replay protection: the spend must use the account's current nonce
                // (and the nonce is bound into the proof, so it can't be edited).
                if xfer.nonce != sender_nonce {
                    return Err(LedgerError::BadNonce);
                }
                // Solvency against the sender's current SPENDABLE balance. The
                // T12 pre-pass may have verified this proof already — reusable
                // only if it verified against this exact ciphertext.
                let preverified =
                    matches!(pre, Some(ProofPass::AgainstBalance(b)) if *b == sender_bal);
                if !preverified && !xfer.verify(&sender_bal) {
                    return Err(LedgerError::InvalidProof);
                }
                if !self.is_registered(&receiver_id) {
                    return Err(LedgerError::ReceiverNotRegistered);
                }

                // Debit the sender's spendable balance by the amount AND the public
                // fee, then bump their nonce. (The fee goes to the block's miner,
                // credited at the block level in lat-chain.) The debit is written
                // back BEFORE the credit is read, so a self-transfer sees it.
                if let Some(mut s) = self.account(&sender_id) {
                    let mut new = s.balance(*token).sub(&xfer.sender_ciphertext());
                    if xfer.fee > 0 {
                        new = new.sub(&Ciphertext::mint(xfer.fee));
                    }
                    s.set(*token, new);
                    s.nonce += 1;
                    self.put_account(&sender_id, s);
                }
                // Credit the receiver's PENDING pool (not spendable until rolled over),
                // so this transfer can't invalidate the receiver's own in-flight proofs.
                if let Some(mut r) = self.account(&receiver_id) {
                    let new = r.pending(*token).add(&xfer.receiver_ciphertext());
                    r.set_pending(*token, new);
                    self.put_account(&receiver_id, r);
                }
                Ok(())
            }

            Transaction::Rollover { account, nonce, sig } => {
                // Only the account's owner may roll over: a forced rollover
                // changes the spendable balance and would invalidate the owner's
                // in-flight solvency proofs (a free griefing attack otherwise).
                check_sig(account, tx, sig)?;
                let mut acct = self.account(account).ok_or(LedgerError::SenderNotRegistered)?;
                if *nonce != acct.nonce {
                    return Err(LedgerError::BadNonce);
                }
                // Merge every pending token into spendable balance.
                let tokens: Vec<u32> = acct.pending.keys().copied().collect();
                for token in tokens {
                    let merged = acct.balance(token).add(&acct.pending(token));
                    acct.set(token, merged);
                    acct.set_pending(token, Ciphertext::zero());
                }
                acct.nonce += 1;
                self.put_account(account, acct);
                Ok(())
            }

            Transaction::DeployContract { deployer, code, sig } => {
                check_sig(deployer, tx, sig)?;
                // Deployment requires a registered account — registration is
                // PoW-gated, which is the anti-spam cost for (fee-less) deploys.
                if !self.is_registered(deployer) {
                    return Err(LedgerError::SenderNotRegistered);
                }
                let id = lat_vm::contract_id(deployer, code);
                if self.has_contract(&id) {
                    return Err(LedgerError::ContractExists);
                }
                self.put_contract(&id, &Contract { code: code.clone(), storage: lat_vm::Storage::new() });
                Ok(())
            }

            Transaction::CallContract { contract, caller, input, nonce, sig } => {
                // The CALLER opcode exposes the caller to contract code, so the
                // caller identity must be unforgeable — and nonce-bound, or a
                // signed call could be replayed to re-run the contract.
                check_sig(caller, tx, sig)?;
                let acct_nonce = self
                    .account(caller)
                    .ok_or(LedgerError::SenderNotRegistered)?
                    .nonce;
                if *nonce != acct_nonce {
                    return Err(LedgerError::BadNonce);
                }
                let mut c = self.contract(contract).ok_or(LedgerError::NoSuchContract)?;
                // Run on our decoded copy of storage; write back only on success.
                lat_vm::execute(&c.code, &mut c.storage, caller, *input, lat_vm::DEFAULT_GAS)
                    .map_err(|_| LedgerError::ContractFailed)?;
                self.put_contract(contract, &c);
                if let Some(mut a) = self.account(caller) {
                    a.nonce += 1;
                    self.put_account(caller, a);
                }
                Ok(())
            }

            Transaction::PublicTransfer { token, from, to, amount, fee, nonce, sig } => {
                // Transparent transfer: everything is in the clear, so authenticity
                // is a plain Schnorr signature by `from` plus a solvency check on
                // the visible public balance (no ZK proof needed).
                check_sig(from, tx, sig)?;
                let (sender_pub, sender_nonce) = match self.account(from) {
                    Some(a) => (a.public(*token), a.nonce),
                    None => return Err(LedgerError::SenderNotRegistered),
                };
                // Replay protection: same spend nonce as confidential transfers.
                if *nonce != sender_nonce {
                    return Err(LedgerError::BadNonce);
                }
                if !self.is_registered(to) {
                    return Err(LedgerError::ReceiverNotRegistered);
                }
                // Solvency in the clear: amount + fee must not exceed the balance
                // (checked_add so a crafted overflow reads as "insufficient").
                let total = amount
                    .checked_add(*fee)
                    .ok_or(LedgerError::InsufficientPublicBalance)?;
                if sender_pub < total {
                    return Err(LedgerError::InsufficientPublicBalance);
                }
                // Debit sender (amount + fee) and advance the shared spend nonce.
                // Written back before the credit reads, so `from == to` is safe.
                if let Some(mut s) = self.account(from) {
                    s.set_public(*token, s.public(*token) - total);
                    s.nonce += 1;
                    self.put_account(from, s);
                }
                // Credit the receiver the amount. The fee is credited to the
                // block's miner at the block level (lat-chain), exactly like the
                // confidential fee path.
                if let Some(mut r) = self.account(to) {
                    let new = r.public(*token).saturating_add(*amount);
                    r.set_public(*token, new);
                    self.put_account(to, r);
                }
                Ok(())
            }

            Transaction::Shield { token, from, to, amount, fee, nonce, sig } => {
                // Public → private. Authenticated like a public transfer (the
                // sender is transparent); the amount leaves the public balance in
                // the clear.
                check_sig(from, tx, sig)?;
                let (sender_pub, sender_nonce) = match self.account(from) {
                    Some(a) => (a.public(*token), a.nonce),
                    None => return Err(LedgerError::SenderNotRegistered),
                };
                if *nonce != sender_nonce {
                    return Err(LedgerError::BadNonce);
                }
                if !self.is_registered(to) {
                    return Err(LedgerError::ReceiverNotRegistered);
                }
                let total = amount
                    .checked_add(*fee)
                    .ok_or(LedgerError::InsufficientPublicBalance)?;
                if sender_pub < total {
                    return Err(LedgerError::InsufficientPublicBalance);
                }
                // Debit the sender's PUBLIC balance; advance the shared nonce.
                // Written back before the credit reads, so a self-shield is safe.
                if let Some(mut s) = self.account(from) {
                    s.set_public(*token, s.public(*token) - total);
                    s.nonce += 1;
                    self.put_account(from, s);
                }
                // Credit the receiver's PRIVATE pending pool. The amount is public
                // now (mint ciphertext), but becomes hidden once the recipient
                // rolls it over and later spends it confidentially. Pending (not
                // spendable) so it can't disturb the receiver's in-flight proofs.
                if let Some(mut r) = self.account(to) {
                    let new = r.pending(*token).add(&Ciphertext::mint(*amount));
                    r.set_pending(*token, new);
                    self.put_account(to, r);
                }
                Ok(())
            }

            Transaction::Unshield { token, to, amount, xfer, sig } => {
                // Private → public. The confidential spend is an ordinary solvent
                // transfer to the public view key; the sender (revealed by the
                // proof) also Schnorr-signs to bind the destination `to`/`amount`.
                let sender_id = xfer.sender.to_bytes();
                check_sig(&sender_id, tx, sig)?;
                // Receiver must be the view key, or the amount can't be revealed.
                if xfer.receiver != lat_crypto::unshield_view_key() {
                    return Err(LedgerError::WrongUnshieldReceiver);
                }
                let (sender_bal, sender_nonce) = match self.account(&sender_id) {
                    Some(a) => (a.balance(*token), a.nonce),
                    None => return Err(LedgerError::SenderNotRegistered),
                };
                if xfer.nonce != sender_nonce {
                    return Err(LedgerError::BadNonce);
                }
                // Solvency + conservation against the sender's real confidential
                // balance (proves balance − amount − fee ≥ 0). Same T12 reuse
                // rule as SolventTransfer: identical ciphertext or re-verify.
                let preverified =
                    matches!(pre, Some(ProofPass::AgainstBalance(b)) if *b == sender_bal);
                if !preverified && !xfer.verify(&sender_bal) {
                    return Err(LedgerError::InvalidProof);
                }
                // Reveal: the hidden amount must equal the declared public amount.
                if !lat_crypto::unshield_reveals(&xfer.receiver_ciphertext(), *amount) {
                    return Err(LedgerError::UnshieldAmountMismatch);
                }
                if !self.is_registered(to) {
                    return Err(LedgerError::ReceiverNotRegistered);
                }
                // Debit the sender's CONFIDENTIAL balance by amount + fee (same as
                // a solvent transfer); advance nonce. Written back before the
                // public credit reads, so a self-unshield is safe.
                if let Some(mut s) = self.account(&sender_id) {
                    let mut new = s.balance(*token).sub(&xfer.sender_ciphertext());
                    if xfer.fee > 0 {
                        new = new.sub(&Ciphertext::mint(xfer.fee));
                    }
                    s.set(*token, new);
                    s.nonce += 1;
                    self.put_account(&sender_id, s);
                }
                // Credit the revealed amount to the destination's PUBLIC balance.
                self.credit_public(to, *token, *amount);
                Ok(())
            }

            Transaction::ShieldStealth { token, from, one_time, amount, fee, nonce, sig, .. } => {
                // Public → private with the RECIPIENT hidden. Authenticated by the
                // (public) sender, exactly like a plain shield.
                check_sig(from, tx, sig)?;
                let (sender_pub, sender_nonce) = match self.account(from) {
                    Some(a) => (a.public(*token), a.nonce),
                    None => return Err(LedgerError::SenderNotRegistered),
                };
                if *nonce != sender_nonce {
                    return Err(LedgerError::BadNonce);
                }
                let total = amount
                    .checked_add(*fee)
                    .ok_or(LedgerError::InsufficientPublicBalance)?;
                if sender_pub < total {
                    return Err(LedgerError::InsufficientPublicBalance);
                }
                // Debit the sender's public balance; advance nonce. Written back
                // before the credit reads, in case `one_time` aliases `from`.
                if let Some(mut s) = self.account(from) {
                    s.set_public(*token, s.public(*token) - total);
                    s.nonce += 1;
                    self.put_account(from, s);
                }
                // Credit the ONE-TIME account's private pending pool, auto-
                // registering it (the shield paid a fee, so no separate anti-spam
                // PoW is needed). Only the recipient — using the ephemeral key
                // carried in the tx — can detect and spend this account, so the
                // recipient is unlinkable to any observer.
                let mut r = self.account(one_time).unwrap_or_default();
                let new = r.pending(*token).add(&Ciphertext::mint(*amount));
                r.set_pending(*token, new);
                self.put_account(one_time, r);
                Ok(())
            }

            Transaction::AnonTransfer { token, xfer } => {
                // Fully private spend: the sender hides in the ring, the
                // receiver behind a one-time stealth account. The proof itself
                // authenticates (ownership of one ring member); replay is
                // stopped by the epoch nullifier, not an account nonce.

                // The proof is only valid in the epoch it was built for —
                // that's what scopes its nullifier.
                if xfer.epoch != epoch_of(height) {
                    return Err(LedgerError::WrongEpoch);
                }
                let nullifier = xfer.nullifier();
                if self.nullifier_seen(&nullifier) {
                    return Err(LedgerError::NullifierSeen);
                }
                // Every ring member must be a real, distinct account, and the
                // balance ciphertexts the proof binds to must be their CURRENT
                // on-chain balances — otherwise a prover could cite an old
                // (richer) balance and overspend.
                let n = xfer.ring.len();
                if xfer.balances.len() != n || xfer.enc.len() != n {
                    return Err(LedgerError::BadRing);
                }
                let mut seen_ids = HashSet::with_capacity(n);
                for (member, claimed) in xfer.ring.iter().zip(&xfer.balances) {
                    let id = member.to_bytes();
                    if !seen_ids.insert(id) {
                        return Err(LedgerError::BadRing);
                    }
                    let acct = self.account(&id).ok_or(LedgerError::BadRing)?;
                    if acct.balance(*token) != *claimed {
                        return Err(LedgerError::StaleRingBalance);
                    }
                }
                // The ring proof is a pure function of the transfer (it binds
                // the CLAIMED balances checked just above), so a passing T12
                // pre-verification is unconditionally reusable.
                if !matches!(pre, Some(ProofPass::Anon)) && !xfer.verify() {
                    return Err(LedgerError::InvalidProof);
                }

                // Debit EVERY ring member homomorphically: the real sender's
                // ciphertext subtracts amount + fee, every decoy's subtracts an
                // encryption of 0 — so which balance actually moved is hidden.
                // No nonce bump for anyone: naming the spender would defeat the
                // point, and decoys did not spend.
                for (member, debit) in xfer.ring.iter().zip(&xfer.enc) {
                    let member_id = member.to_bytes();
                    if let Some(mut a) = self.account(&member_id) {
                        let new = a.balance(*token).sub(debit);
                        a.set(*token, new);
                        self.put_account(&member_id, a);
                    }
                }
                // Credit the carried ciphertext (v3: the amount is HIDDEN — the
                // proof guarantees it encrypts exactly debit − fee under the
                // one-time key) to the stealth account's pending pool,
                // auto-registering it (the spend paid a fee, so no separate
                // anti-spam PoW) — the same mechanism as ShieldStealth. The fee
                // is credited to the miner at the block level. Read AFTER the
                // ring debits are written back, in case `one_time` aliases a
                // ring member.
                let one_time = xfer.output.one_time.to_bytes();
                let mut r = self.account(&one_time).unwrap_or_default();
                let new = r.pending(*token).add(&xfer.credit);
                r.set_pending(*token, new);
                self.put_account(&one_time, r);

                self.insert_nullifier(&nullifier);
                Ok(())
            }

            Transaction::Stake { validator, amount, nonce, sig } => {
                // Bond public LAT into validator stake. Transparent auth, and
                // any matured unbonding entries sweep back first — so `Stake`
                // with amount 0 is the explicit "claim released funds" tx.
                check_sig(validator, tx, sig)?;
                let mut acct =
                    self.account(validator).ok_or(LedgerError::SenderNotRegistered)?;
                if *nonce != acct.nonce {
                    return Err(LedgerError::BadNonce);
                }
                let mut val = self.validator(validator).unwrap_or_default();
                let released = release_matured(&mut val, height);
                let available = acct.public(LAT_TOKEN).saturating_add(released);
                if available < *amount {
                    return Err(LedgerError::InsufficientPublicBalance);
                }
                acct.set_public(LAT_TOKEN, available - amount);
                acct.nonce += 1;
                val.staked = val.staked.saturating_add(*amount);
                self.put_account(validator, acct);
                self.put_validator(validator, &val);
                Ok(())
            }

            Transaction::Unstake { validator, amount, nonce, sig } => {
                // Move bonded stake into an unbonding entry that releases after
                // the delay window (sweeping already-matured entries first).
                check_sig(validator, tx, sig)?;
                let mut acct =
                    self.account(validator).ok_or(LedgerError::SenderNotRegistered)?;
                if *nonce != acct.nonce {
                    return Err(LedgerError::BadNonce);
                }
                let mut val = self.validator(validator).unwrap_or_default();
                let released = release_matured(&mut val, height);
                if val.staked < *amount {
                    return Err(LedgerError::InsufficientStake);
                }
                val.staked -= amount;
                if *amount > 0 {
                    val.unbonding.push((*amount, height + UNBONDING_BLOCKS));
                }
                acct.set_public(LAT_TOKEN, acct.public(LAT_TOKEN).saturating_add(released));
                acct.nonce += 1;
                self.put_account(validator, acct);
                self.put_validator(validator, &val);
                Ok(())
            }

            Transaction::SlashEvidence { validator, beneficiary, height: vote_height, block_a, sig_a, block_b, sig_b } => {
                // Equivocation proof (T16): the same validator signed finality
                // votes for two DIFFERENT blocks at one height. The evidence
                // authenticates itself — both signatures must verify — so the
                // transaction carries no signature or nonce of its own; anyone
                // may submit it. Partial slashing (Gap-6): the penalty takes
                // SLASH_FRACTION_BPS of the offender's total (bonded +
                // unbonding) stake — the unbonding delay (T13) exists precisely
                // so this can still bite after the validator heads for the
                // exit. SLASH_REWARD_BPS of the slashed amount is paid to the
                // whistleblower `beneficiary`; the rest is burned.
                if block_a == block_b {
                    return Err(LedgerError::BadEvidence);
                }
                let pk =
                    PublicKey::from_bytes(validator).ok_or(LedgerError::BadEvidence)?;
                for (block, sig) in [(block_a, sig_a), (block_b, sig_b)] {
                    let sig = Signature::from_bytes(sig).ok_or(LedgerError::BadEvidence)?;
                    let msg = lat_types::finality_vote_signing_bytes(block, *vote_height);
                    if !pk.verify(&msg, &sig) {
                        return Err(LedgerError::BadEvidence);
                    }
                }
                let mut val = self.validator(validator).unwrap_or_default();
                // Tombstoned = already slashed for equivocation: partial
                // slashing leaves residual stake, so the tombstone (not a
                // zero balance) is the replay guard against double-slashing.
                if val.tombstoned {
                    return Err(LedgerError::NothingToSlash);
                }
                let total: u64 =
                    val.staked.saturating_add(val.unbonding.iter().map(|(a, _)| *a).sum());
                if total == 0 {
                    return Err(LedgerError::NothingToSlash); // never bonded
                }
                // Slashed amount, floored at 1 unit so any equivocation with a
                // non-empty stake always has an effect (no free equivocation on
                // dust) and the replay guard below always trips.
                let slashed = ((total as u128 * SLASH_FRACTION_BPS as u128 / 10_000) as u64).max(1);
                // Take it proportionally from bonded first, then unbonding, so
                // the derived validator-set weight drops immediately.
                let mut remaining = slashed;
                let from_bonded = remaining.min(val.staked);
                val.staked -= from_bonded;
                remaining -= from_bonded;
                let mut i = 0;
                while remaining > 0 && i < val.unbonding.len() {
                    let take = remaining.min(val.unbonding[i].0);
                    val.unbonding[i].0 -= take;
                    remaining -= take;
                    i += 1;
                }
                val.unbonding.retain(|(a, _)| *a > 0);
                // Tombstone: bars re-entry to the validator set and any future
                // slash for this (or any later) equivocation by this key.
                val.tombstoned = true;
                self.put_validator(validator, &val);

                // Whistleblower reward: pay SLASH_REWARD_BPS of the slash to the
                // submitter's PUBLIC balance (only if it is a registered
                // account); the rest is burned by simply not re-crediting it.
                let reward = (slashed as u128 * SLASH_REWARD_BPS as u128 / 10_000) as u64;
                if reward > 0 {
                    if let Some(mut acct) = self.account(beneficiary) {
                        let bal = acct.public(LAT_TOKEN).saturating_add(reward);
                        acct.set_public(LAT_TOKEN, bal);
                        self.put_account(beneficiary, acct);
                    }
                }
                Ok(())
            }
        }
    }

    // -- state commitment ------------------------------------------------------
    // The authoritative state root is a persistent Sparse Merkle Tree over every
    // account, token, contract and spent nullifier (plus a meta record binding
    // `next_token_id`). It is carried in each block header so any node can verify
    // a block yields the one true state, and a light client can be handed an
    // inclusion proof for a single account. Updates are incremental: only the
    // entries flagged dirty since the last computation are rehashed (O(log n)
    // each), rather than rebuilding a tree over the whole state every block.

    /// The canonical, deterministic **state root**. Reconciles any pending
    /// changes into the commitment trie, then returns the cached root. Takes
    /// `&self` (via interior mutability) so a caller holding only a shared
    /// reference — like the chain — can still read it.
    pub fn state_root(&self) -> [u8; 32] {
        let mut commit = self.commitment.borrow_mut();
        if !commit.dirty.is_empty() {
            let dirty: Vec<DirtyKey> = commit.dirty.iter().copied().collect();
            let mut trie = Smt::from_root(&self.store, commit.root);
            for key in &dirty {
                let (trie_key, value) = self.trie_kv(key);
                match value {
                    Some(v) => {
                        trie.update(&trie_key, &v);
                    }
                    None => {
                        trie.remove(&trie_key);
                    }
                }
            }
            commit.root = trie.root();
            commit.dirty.clear();
        }
        commit.root
    }

    /// The trie path and current leaf value for one state entry. A `None` value
    /// means the entry no longer exists (and is removed from the trie).
    fn trie_kv(&self, key: &DirtyKey) -> ([u8; 32], Option<Vec<u8>>) {
        match key {
            DirtyKey::Account(id) => {
                (trie_key_account(id), self.account(id).map(|a| account_leaf_preimage(id, &a)))
            }
            DirtyKey::Token(tid) => {
                (trie_key_token(*tid), self.token_by_id(*tid).map(|t| token_leaf_preimage(&t)))
            }
            DirtyKey::Contract(id) => {
                (trie_key_contract(id), self.contract(id).map(|c| contract_leaf_preimage(id, &c)))
            }
            DirtyKey::Nullifier(nf) => {
                (trie_key_nullifier(nf), self.nullifier_seen(nf).then(|| vec![1u8]))
            }
            DirtyKey::Validator(id) => (
                trie_key_validator(id),
                self.validator(id).map(|v| validator_leaf_preimage(id, &v)),
            ),
            DirtyKey::Meta => (trie_key_meta(), Some(self.next_token_id.to_le_bytes().to_vec())),
        }
    }

    /// Build an inclusion proof that `id`'s account is committed by the current
    /// [`state_root`](Self::state_root). `None` if the account is unregistered.
    /// A verifier holding only the root checks it via [`verify_account_proof`].
    pub fn account_proof(&self, id: &[u8; 32]) -> Option<AccountProof> {
        let preimage = {
            let acct = self.account(id)?;
            account_leaf_preimage(id, &acct)
        };
        let root = self.state_root();
        let trie = Smt::from_root(&self.store, root);
        let proof = trie.prove(&trie_key_account(id));
        Some(AccountProof { preimage, proof })
    }
}

// ---------------------------------------------------------------------------
// State-commitment helpers
// ---------------------------------------------------------------------------

/// 32-byte trie path for a state entry. Domain-separated per entry kind so two
/// different entities can never land on the same path.
fn trie_key(tag: &[u8], body: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"LAT-trie/");
    h.update(tag);
    h.update(body);
    *h.finalize().as_bytes()
}
fn trie_key_account(id: &[u8; 32]) -> [u8; 32] {
    trie_key(b"acct", id)
}
fn trie_key_token(id: u32) -> [u8; 32] {
    trie_key(b"tokn", &id.to_le_bytes())
}
fn trie_key_contract(id: &[u8; 32]) -> [u8; 32] {
    trie_key(b"ctrt", id)
}
fn trie_key_nullifier(nf: &[u8; 32]) -> [u8; 32] {
    trie_key(b"null", nf)
}
fn trie_key_meta() -> [u8; 32] {
    trie_key(b"meta", b"")
}
fn trie_key_validator(id: &[u8; 32]) -> [u8; 32] {
    trie_key(b"val", id)
}

/// Canonical byte preimage of a validator leaf (tag + id + record body), so
/// headers commit the staking state and T14 can bind validator sets to roots.
fn validator_leaf_preimage(id: &[u8; 32], v: &Validator) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"LAT-state-val");
    b.extend_from_slice(id);
    b.extend_from_slice(&encode_validator(v));
    b
}

/// Canonical byte preimage of an account leaf (the trie hashes it). Begins with
/// the 14-byte `"LAT-state-acct"` tag then the 32-byte id, so a proof verifier
/// can read *who* it commits before trusting the balances that follow.
fn account_leaf_preimage(id: &[u8; 32], a: &Account) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"LAT-state-acct");
    v.extend_from_slice(id);
    v.extend_from_slice(&a.nonce.to_le_bytes());
    encode_ct_map(&mut v, &a.balances);
    encode_ct_map(&mut v, &a.pending);
    encode_u64_map(&mut v, &a.public);
    v
}

fn token_leaf_preimage(t: &TokenMeta) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"LAT-state-token");
    v.extend_from_slice(&t.id.to_le_bytes());
    v.extend_from_slice(&(t.ticker.len() as u32).to_le_bytes());
    v.extend_from_slice(t.ticker.as_bytes());
    v.extend_from_slice(&t.creator);
    v.extend_from_slice(&t.supply.to_le_bytes());
    v
}

fn contract_leaf_preimage(id: &[u8; 32], c: &Contract) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"LAT-state-contract");
    v.extend_from_slice(id);
    v.extend_from_slice(&(c.code.len() as u32).to_le_bytes());
    v.extend_from_slice(&c.code);
    let mut keys: Vec<u64> = c.storage.keys().copied().collect();
    keys.sort_unstable();
    v.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys {
        v.extend_from_slice(&k.to_le_bytes());
        v.extend_from_slice(&c.storage[&k].to_le_bytes());
    }
    v
}

fn encode_ct_map(v: &mut Vec<u8>, m: &HashMap<u32, Ciphertext>) {
    let mut keys: Vec<u32> = m.keys().copied().collect();
    keys.sort_unstable();
    v.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys {
        v.extend_from_slice(&k.to_le_bytes());
        v.extend_from_slice(&m[&k].to_bytes());
    }
}

fn encode_u64_map(v: &mut Vec<u8>, m: &HashMap<u32, u64>) {
    let mut keys: Vec<u32> = m.keys().copied().collect();
    keys.sort_unstable();
    v.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys {
        v.extend_from_slice(&k.to_le_bytes());
        v.extend_from_slice(&m[&k].to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Object records (T5b)
// ---------------------------------------------------------------------------
// One encoded record per state object in `Column::Objects`, keyed by a 1-byte
// kind tag + the object's id, so each kind occupies a contiguous, ordered key
// range (scan `[REC_ACCOUNT]` = every account, ascending by id). Record bodies
// reuse the snapshot encoding of the same object, so a snapshot is a straight
// concatenation of records (see `Ledger::encode`). Token keys use BIG-endian
// ids: lexicographic key order must equal numeric id order for scans.

const REC_ACCOUNT: u8 = b'a';
const REC_TOKEN: u8 = b't';
/// Ticker → token-id index (the uniqueness guarantee lives on this key range).
const REC_TICKER: u8 = b'u';
const REC_CONTRACT: u8 = b'c';
const REC_NULLIFIER: u8 = b'n';
/// Validator staking records (T13).
const REC_VALIDATOR: u8 = b'v';
/// The single `next_token_id` meta record.
const REC_META: u8 = b'm';

fn rec_key(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + body.len());
    k.push(tag);
    k.extend_from_slice(body);
    k
}

/// Account record body: nonce + balances + pending + public. Identical to the
/// per-account snapshot entry minus the leading id (the id is the record key).
fn encode_account(a: &Account) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&a.nonce.to_le_bytes());
    encode_ct_map(&mut v, &a.balances);
    encode_ct_map(&mut v, &a.pending);
    encode_u64_map(&mut v, &a.public);
    v
}

fn decode_account(b: &[u8]) -> Option<Account> {
    let mut r = Reader { b, off: 0 };
    let nonce = r.u64()?;
    let balances = r.ct_map()?;
    let pending = r.ct_map()?;
    let public = r.u64_map()?;
    (r.off == b.len()).then_some(Account { balances, pending, public, nonce })
}

/// Token record body: the full snapshot token entry (id included, so the body
/// can be emitted into a snapshot verbatim).
fn encode_token(t: &TokenMeta) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&t.id.to_le_bytes());
    v.extend_from_slice(&(t.ticker.len() as u32).to_le_bytes());
    v.extend_from_slice(t.ticker.as_bytes());
    v.extend_from_slice(&t.creator);
    v.extend_from_slice(&t.supply.to_le_bytes());
    v
}

fn decode_token(b: &[u8]) -> Option<TokenMeta> {
    let mut r = Reader { b, off: 0 };
    let id = r.u32()?;
    let tick_len = r.u32()? as usize;
    let ticker = String::from_utf8(r.take(tick_len)?.to_vec()).ok()?;
    let creator = r.arr32()?;
    let supply = r.u64()?;
    (r.off == b.len()).then_some(TokenMeta { id, ticker, creator, supply })
}

/// Contract record body: code + sorted storage slots (the snapshot contract
/// entry minus the leading id).
fn encode_contract(c: &Contract) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(c.code.len() as u32).to_le_bytes());
    v.extend_from_slice(&c.code);
    let mut keys: Vec<u64> = c.storage.keys().copied().collect();
    keys.sort_unstable();
    v.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys {
        v.extend_from_slice(&k.to_le_bytes());
        v.extend_from_slice(&c.storage[&k].to_le_bytes());
    }
    v
}

/// Validator record body: staked + unbonding entries (the snapshot validator
/// entry minus the leading id).
fn encode_validator(v: &Validator) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + 4 + v.unbonding.len() * 16 + 1);
    b.extend_from_slice(&v.staked.to_le_bytes());
    b.extend_from_slice(&(v.unbonding.len() as u32).to_le_bytes());
    for (amount, release) in &v.unbonding {
        b.extend_from_slice(&amount.to_le_bytes());
        b.extend_from_slice(&release.to_le_bytes());
    }
    b.push(v.tombstoned as u8);
    b
}

fn decode_validator(b: &[u8]) -> Option<Validator> {
    let mut r = Reader { b, off: 0 };
    let staked = r.u64()?;
    let n = r.u32()?;
    let mut unbonding = Vec::new();
    for _ in 0..n {
        let amount = r.u64()?;
        let release = r.u64()?;
        unbonding.push((amount, release));
    }
    let tombstoned = r.take(1)?[0] != 0;
    (r.off == b.len()).then_some(Validator { staked, unbonding, tombstoned })
}

fn decode_contract(b: &[u8]) -> Option<Contract> {
    let mut r = Reader { b, off: 0 };
    let code_len = r.u32()? as usize;
    let code = r.take(code_len)?.to_vec();
    let mut storage = lat_vm::Storage::new();
    for _ in 0..r.u32()? {
        let k = r.u64()?;
        storage.insert(k, r.u64()?);
    }
    (r.off == b.len()).then_some(Contract { code, storage })
}

/// A light-client inclusion proof for one account against a state root: the
/// account's committed leaf bytes plus the Sparse Merkle Tree path to the root.
#[derive(Clone, Debug)]
pub struct AccountProof {
    /// The exact bytes committed by the account's leaf. Begins with the 14-byte
    /// `"LAT-state-acct"` tag then the 32-byte account id, so a verifier can read
    /// *who* it proves before trusting the balances that follow.
    pub preimage: Vec<u8>,
    /// The SMT membership proof for this account's trie key.
    proof: lat_store::Proof,
}

impl AccountProof {
    /// The account id this proof is about (the 32 bytes after the domain tag).
    pub fn account_id(&self) -> Option<[u8; 32]> {
        self.preimage.get(14..46)?.try_into().ok()
    }
}

/// Verify an [`AccountProof`] against a claimed `state_root`: derive the trie
/// key from the proof's own account id and check the SMT path commits exactly
/// this account's leaf bytes under `root`.
pub fn verify_account_proof(root: &[u8; 32], proof: &AccountProof) -> bool {
    let Some(id) = proof.account_id() else {
        return false;
    };
    lat_store::verify_proof(root, &trie_key_account(&id), Some(&proof.preimage), &proof.proof)
}

// ---------------------------------------------------------------------------
// Ledger snapshots (L8)
// ---------------------------------------------------------------------------
// A canonical byte serialization of the WHOLE ledger, so a node can persist the
// state at a block and boot from it instead of replaying (and re-verifying)
// every block from genesis. The encoding is deterministic (everything sorted)
// and preserves map entries verbatim — including explicit zero balances — so a
// decoded ledger recomputes the exact `state_root` the original committed.
// A snapshot is trusted only after that root matches the block header's; the
// chain layer enforces this (see lat-chain).

/// Version tag heading every ledger snapshot encoding. Bumped to 2 when the
/// anonymous-spend nullifier set joined the encoding, and to 3 when validator
/// staking records (T13) did; an old snapshot no longer decodes, which simply
/// costs one full replay on the next boot.
const LEDGER_MAGIC: &[u8; 8] = b"LATLEDG4";

impl Ledger {
    /// Canonical snapshot encoding of the full ledger (see the section note).
    /// Object-record bodies reuse the snapshot's per-entry encoding, and record
    /// scans come back id-ordered, so a snapshot is a straight concatenation of
    /// records — the byte format is unchanged from the map-backed ledger.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(LEDGER_MAGIC);
        v.extend_from_slice(&self.next_token_id.to_le_bytes());

        let accounts = self.store.scan_prefix(Column::Objects, &[REC_ACCOUNT]);
        v.extend_from_slice(&(accounts.len() as u32).to_le_bytes());
        for (key, body) in accounts {
            v.extend_from_slice(&key[1..]); // account id
            v.extend_from_slice(&body); // nonce + balances + pending + public
        }

        let tokens = self.store.scan_prefix(Column::Objects, &[REC_TOKEN]);
        v.extend_from_slice(&(tokens.len() as u32).to_le_bytes());
        for (_key, body) in tokens {
            v.extend_from_slice(&body); // id + ticker + creator + supply
        }

        let contracts = self.store.scan_prefix(Column::Objects, &[REC_CONTRACT]);
        v.extend_from_slice(&(contracts.len() as u32).to_le_bytes());
        for (key, body) in contracts {
            v.extend_from_slice(&key[1..]); // contract id
            v.extend_from_slice(&body); // code + storage slots
        }

        let nfs = self.store.scan_prefix(Column::Objects, &[REC_NULLIFIER]);
        v.extend_from_slice(&(nfs.len() as u32).to_le_bytes());
        for (key, _) in nfs {
            v.extend_from_slice(&key[1..]);
        }

        let validators = self.store.scan_prefix(Column::Objects, &[REC_VALIDATOR]);
        v.extend_from_slice(&(validators.len() as u32).to_le_bytes());
        for (key, body) in validators {
            v.extend_from_slice(&key[1..]); // validator id
            v.extend_from_slice(&body); // staked + unbonding entries
        }
        v
    }

    /// Decode a snapshot produced by [`encode`](Self::encode). `None` on any
    /// malformed input (wrong magic, truncation, bad ciphertext point, trailing
    /// garbage) — the input may be a corrupt or hostile file, so counts are
    /// never trusted for pre-allocation and every read is bounds-checked.
    pub fn decode(b: &[u8]) -> Option<Ledger> {
        let mut r = Reader { b, off: 0 };
        if r.take(8)? != LEDGER_MAGIC {
            return None;
        }
        // Decode into a fresh in-memory ledger, inserting each validated object
        // as a record and flagging it dirty; the single `state_root()` at the
        // end rebuilds the whole authenticated commitment from scratch, so the
        // decoded ledger reproduces the exact root the snapshot committed.
        let mut ledger = Ledger::with_store(OverlayStore::in_memory());
        ledger.next_token_id = r.u32()?;
        ledger
            .store
            .put(Column::Objects, vec![REC_META], ledger.next_token_id.to_le_bytes().to_vec());

        for _ in 0..r.u32()? {
            let id = r.arr32()?;
            let nonce = r.u64()?;
            let balances = r.ct_map()?;
            let pending = r.ct_map()?;
            let public = r.u64_map()?;
            ledger.put_account(&id, Account { balances, pending, public, nonce });
            ledger.mark(DirtyKey::Account(id));
        }

        for _ in 0..r.u32()? {
            let id = r.u32()?;
            let tick_len = r.u32()? as usize;
            let ticker = String::from_utf8(r.take(tick_len)?.to_vec()).ok()?;
            let creator = r.arr32()?;
            let supply = r.u64()?;
            ledger.put_token(&TokenMeta { id, ticker, creator, supply });
            ledger.mark(DirtyKey::Token(id));
        }

        for _ in 0..r.u32()? {
            let id = r.arr32()?;
            let code_len = r.u32()? as usize;
            let code = r.take(code_len)?.to_vec();
            let mut storage = lat_vm::Storage::new();
            for _ in 0..r.u32()? {
                let k = r.u64()?;
                storage.insert(k, r.u64()?);
            }
            ledger.put_contract(&id, &Contract { code, storage });
            ledger.mark(DirtyKey::Contract(id));
        }

        for _ in 0..r.u32()? {
            let nf = r.arr32()?;
            ledger.insert_nullifier(&nf);
            ledger.mark(DirtyKey::Nullifier(nf));
        }

        for _ in 0..r.u32()? {
            let id = r.arr32()?;
            let staked = r.u64()?;
            let mut unbonding = Vec::new();
            for _ in 0..r.u32()? {
                let amount = r.u64()?;
                let release = r.u64()?;
                unbonding.push((amount, release));
            }
            let tombstoned = r.take(1)?[0] != 0;
            ledger.put_validator(&id, &Validator { staked, unbonding, tombstoned });
            ledger.mark(DirtyKey::Validator(id));
        }

        // Reject trailing garbage — an encoding is exactly its contents.
        if r.off != b.len() {
            return None;
        }
        ledger.state_root(); // reconcile now, so the cached root is ready
        Some(ledger)
    }
}

/// Bounds-checked cursor over snapshot bytes.
struct Reader<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.off..self.off.checked_add(n)?)?;
        self.off += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }
    fn ct_map(&mut self) -> Option<HashMap<u32, Ciphertext>> {
        let mut m = HashMap::new();
        for _ in 0..self.u32()? {
            let k = self.u32()?;
            let ct: [u8; 64] = self.take(64)?.try_into().ok()?;
            m.insert(k, Ciphertext::from_bytes(&ct)?);
        }
        Some(m)
    }
    fn u64_map(&mut self) -> Option<HashMap<u32, u64>> {
        let mut m = HashMap::new();
        for _ in 0..self.u32()? {
            let k = self.u32()?;
            m.insert(k, self.u64()?);
        }
        Some(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lat_crypto::SecretKey;
    use rand::rngs::OsRng;

    /// Build + sign a transparent tx with `sk`, filling the `sig` field the way
    /// a wallet would.
    fn signed(mut tx: Transaction, sk: &SecretKey) -> Transaction {
        let sig_bytes = sk.sign(&tx.signing_bytes()).to_bytes();
        match &mut tx {
            Transaction::CreateToken { sig, .. }
            | Transaction::Rollover { sig, .. }
            | Transaction::DeployContract { sig, .. }
            | Transaction::CallContract { sig, .. }
            | Transaction::PublicTransfer { sig, .. }
            | Transaction::Shield { sig, .. }
            | Transaction::Unshield { sig, .. }
            | Transaction::ShieldStealth { sig, .. }
            | Transaction::Stake { sig, .. }
            | Transaction::Unstake { sig, .. } => *sig = sig_bytes,
            _ => {}
        }
        tx
    }

    /// Ledger with `n` registered accounts each holding `amount` confidential LAT.
    /// (`pub(crate)`: the parallel module's tests reuse it.)
    pub(crate) fn ledger_with_ring(
        n: usize,
        amount: u64,
        rng: &mut OsRng,
    ) -> (Ledger, Vec<SecretKey>, Vec<[u8; 32]>) {
        let sks: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(rng)).collect();
        let ids: Vec<[u8; 32]> = sks.iter().map(|s| s.public_key().to_bytes()).collect();
        let mut ledger = Ledger::new();
        for id in &ids {
            ledger.register(*id).unwrap();
            ledger.credit_genesis(id, amount).unwrap();
        }
        (ledger, sks, ids)
    }

    /// Build an `AnonTransfer` tx from `sks[sender]` against the ledger's CURRENT
    /// balances, for the epoch of `height`. (`pub(crate)`: parallel tests reuse it.)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn anon_tx(
        ledger: &Ledger,
        sks: &[SecretKey],
        ids: &[[u8; 32]],
        sender: usize,
        sender_balance: u64,
        receiver: &lat_crypto::PublicKey,
        amount: u64,
        fee: u64,
        height: u64,
        rng: &mut OsRng,
    ) -> Transaction {
        let ring: Vec<_> = sks.iter().map(|s| s.public_key()).collect();
        let balances: Vec<_> = ids.iter().map(|id| ledger.balance(id, LAT_TOKEN).unwrap()).collect();
        let xfer = lat_crypto::AnonTransfer::create(
            &ring, &balances, &sks[sender], sender, sender_balance, receiver, amount, fee,
            epoch_of(height), rng,
        )
        .expect("solvent");
        Transaction::AnonTransfer { token: LAT_TOKEN, xfer }
    }

    #[test]
    fn anon_transfer_debits_hidden_sender_and_credits_stealth_receiver() {
        let mut rng = OsRng;
        let (mut ledger, sks, ids) = ledger_with_ring(4, 100_000, &mut rng);
        let receiver = SecretKey::random(&mut rng);
        let height = 42; // epoch 2 at EPOCH_BLOCKS = 20

        let tx = anon_tx(&ledger, &sks, &ids, 1, 100_000, &receiver.public_key(), 5_000, 1_000, height, &mut rng);
        let (nullifier, output) = match &tx {
            Transaction::AnonTransfer { xfer, .. } => (xfer.nullifier(), xfer.output),
            _ => unreachable!(),
        };
        ledger.apply_at(&tx, height).unwrap();

        // The real sender lost amount + fee; every decoy's balance still
        // decrypts to what it held (an encryption of 0 was subtracted).
        assert_eq!(sks[1].decrypt(&ledger.balance(&ids[1], LAT_TOKEN).unwrap(), 24), Some(94_000));
        for i in [0, 2, 3] {
            assert_eq!(sks[i].decrypt(&ledger.balance(&ids[i], LAT_TOKEN).unwrap(), 24), Some(100_000));
        }

        // Only the true receiver can find and read the stealth credit.
        let spend = lat_crypto::stealth_receive(&receiver, &output.ephemeral, &output.one_time).unwrap();
        let ot = spend.public_key().to_bytes();
        assert_eq!(spend.decrypt(&ledger.pending(&ot, LAT_TOKEN).unwrap(), 24), Some(5_000));

        // The nullifier is recorded; replaying the exact tx is rejected on it.
        assert!(ledger.nullifier_seen(&nullifier));
        assert_eq!(ledger.apply_at(&tx, height), Err(LedgerError::NullifierSeen));
    }

    #[test]
    fn anon_transfer_conserves_total_supply_no_inflation() {
        // Red-team (Gap 1): the strongest inflation check — decrypt EVERY
        // balance before and after an anonymous transfer and assert the total
        // is exactly conserved (sender's whole ring + receiver + the fee that
        // will go to the miner). A hidden amount that credited more than it
        // debited would show up here as minted supply.
        let mut rng = OsRng;
        let (mut ledger, sks, ids) = ledger_with_ring(5, 100_000, &mut rng);
        let receiver = SecretKey::random(&mut rng);
        let height = 3 * EPOCH_BLOCKS as usize as u64;

        let ring_before: u64 =
            sks.iter().zip(&ids).map(|(s, id)| s.decrypt(&ledger.balance(id, LAT_TOKEN).unwrap(), 24).unwrap()).sum();

        let amount = 12_345;
        let fee = 1_000;
        let tx = anon_tx(&ledger, &sks, &ids, 2, 100_000, &receiver.public_key(), amount, fee, height, &mut rng);
        let output = match &tx {
            Transaction::AnonTransfer { xfer, .. } => xfer.output,
            _ => unreachable!(),
        };
        ledger.apply_at(&tx, height).unwrap();

        let ring_after: u64 =
            sks.iter().zip(&ids).map(|(s, id)| s.decrypt(&ledger.balance(id, LAT_TOKEN).unwrap(), 24).unwrap()).sum();
        let spend = lat_crypto::stealth_receive(&receiver, &output.ephemeral, &output.one_time).unwrap();
        let received = spend.decrypt(&ledger.pending(&spend.public_key().to_bytes(), LAT_TOKEN).unwrap(), 24).unwrap();

        // Value out of the ring == value into the receiver + fee (fee is
        // credited to the miner at the block level, not modelled in apply_at).
        assert_eq!(ring_before - ring_after, amount + fee, "debit total = amount + fee");
        assert_eq!(received, amount, "receiver credited exactly the hidden amount");
        assert_eq!(ring_before, ring_after + received + fee, "no supply created or destroyed");
    }

    #[test]
    fn anon_transfer_second_spend_same_epoch_is_rejected() {
        let mut rng = OsRng;
        let (mut ledger, sks, ids) = ledger_with_ring(3, 100_000, &mut rng);
        let receiver = SecretKey::random(&mut rng).public_key();
        let height = 5;

        let tx = anon_tx(&ledger, &sks, &ids, 0, 100_000, &receiver, 2_000, 1_000, height, &mut rng);
        ledger.apply_at(&tx, height).unwrap();

        // A FRESH proof by the same sender, against the updated balances, in the
        // same epoch: derives the same nullifier and is rejected.
        let again = anon_tx(&ledger, &sks, &ids, 0, 97_000, &receiver, 1_000, 1_000, height + 1, &mut rng);
        assert_eq!(ledger.apply_at(&again, height + 1), Err(LedgerError::NullifierSeen));

        // In the NEXT epoch the same sender can spend again (new nullifier base).
        let next_epoch_height = height + EPOCH_BLOCKS;
        let next = anon_tx(&ledger, &sks, &ids, 0, 97_000, &receiver, 1_000, 1_000, next_epoch_height, &mut rng);
        ledger.apply_at(&next, next_epoch_height).unwrap();
    }

    #[test]
    fn anon_transfer_wrong_epoch_stale_balance_and_bad_ring_are_rejected() {
        let mut rng = OsRng;
        let (mut ledger, sks, ids) = ledger_with_ring(3, 100_000, &mut rng);
        let receiver = SecretKey::random(&mut rng).public_key();

        // Built for epoch 2, presented in a block of epoch 0.
        let tx = anon_tx(&ledger, &sks, &ids, 0, 100_000, &receiver, 2_000, 1_000, 2 * EPOCH_BLOCKS, &mut rng);
        assert_eq!(ledger.apply_at(&tx, 1), Err(LedgerError::WrongEpoch));

        // Proof bound to balances that are no longer current (member 0 spent in
        // between): rejected, or the prover could cite an old richer balance.
        let stale = anon_tx(&ledger, &sks, &ids, 1, 100_000, &receiver, 2_000, 1_000, 1, &mut rng);
        ledger.apply_at(&tx, 2 * EPOCH_BLOCKS).unwrap(); // changes every ring balance
        assert_eq!(ledger.apply_at(&stale, 1), Err(LedgerError::StaleRingBalance));

        // A ring naming an unregistered account is rejected outright.
        let ghost = SecretKey::random(&mut rng);
        let mut ring: Vec<_> = sks.iter().map(|s| s.public_key()).collect();
        ring[2] = ghost.public_key();
        let mut bals: Vec<_> = ids.iter().map(|id| ledger.balance(id, LAT_TOKEN).unwrap()).collect();
        bals[2] = ghost.public_key().encrypt(50_000, &mut rng);
        let sender_bal = sks[1].decrypt(&bals[1], 24).unwrap();
        let xfer = lat_crypto::AnonTransfer::create(
            &ring, &bals, &sks[1], 1, sender_bal, &receiver, 1_000, 1_000, epoch_of(45), &mut rng,
        )
        .unwrap();
        assert_eq!(
            ledger.apply_at(&Transaction::AnonTransfer { token: LAT_TOKEN, xfer }, 45),
            Err(LedgerError::BadRing)
        );
    }

    #[test]
    fn anon_transfer_nullifiers_are_committed_and_snapshot_roundtrips() {
        let mut rng = OsRng;
        let (mut ledger, sks, ids) = ledger_with_ring(3, 100_000, &mut rng);
        let receiver = SecretKey::random(&mut rng).public_key();

        let root_before = ledger.state_root();
        let tx = anon_tx(&ledger, &sks, &ids, 2, 100_000, &receiver, 2_000, 1_000, 7, &mut rng);
        let nullifier = match &tx {
            Transaction::AnonTransfer { xfer, .. } => xfer.nullifier(),
            _ => unreachable!(),
        };
        ledger.apply_at(&tx, 7).unwrap();
        assert_ne!(ledger.state_root(), root_before, "nullifier + balances change the root");

        // Snapshot roundtrip carries the nullifier set (forgetting it would
        // re-open the double-spend).
        let decoded = Ledger::decode(&ledger.encode()).expect("snapshot decodes");
        assert_eq!(decoded.state_root(), ledger.state_root());
        assert!(decoded.nullifier_seen(&nullifier));
    }

    #[test]
    fn shield_stealth_credits_hidden_one_time_account() {
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let sender = sender_sk.public_key().to_bytes();
        let recipient_sk = SecretKey::random(&mut rng);

        let mut ledger = Ledger::new();
        ledger.register(sender).unwrap();
        ledger.credit_public(&sender, LAT_TOKEN, 1_000);

        // Sender derives a one-time output paying the recipient, and shields to it.
        let out = lat_crypto::stealth_send(&recipient_sk.public_key(), &mut rng);
        let tx = signed(
            Transaction::ShieldStealth {
                token: LAT_TOKEN,
                from: sender,
                ephemeral: out.ephemeral.to_bytes(),
                one_time: out.one_time.to_bytes(),
                amount: 400,
                fee: 100,
                nonce: 0,
                sig: [0u8; 64],
            },
            &sender_sk,
        );
        ledger.apply(&tx).unwrap();

        // Sender's public balance is debited amount + fee.
        assert_eq!(ledger.public_balance(&sender, LAT_TOKEN), Some(500));

        // The recipient derives the one-time spend key and reads the credited
        // PRIVATE pending — nobody else can even find the account.
        let p = lat_crypto::stealth_receive(&recipient_sk, &out.ephemeral, &out.one_time).unwrap();
        let ot_id = p.public_key().to_bytes();
        assert_eq!(p.decrypt(&ledger.pending(&ot_id, LAT_TOKEN).unwrap(), 24), Some(400));

        // A stranger can't recognize the output at all.
        let stranger = SecretKey::random(&mut rng);
        assert!(lat_crypto::stealth_receive(&stranger, &out.ephemeral, &out.one_time).is_none());
    }

    #[test]
    fn shield_moves_public_to_private() {
        let mut rng = OsRng;
        let user_sk = SecretKey::random(&mut rng);
        let user = user_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(user).unwrap();
        ledger.credit_public(&user, LAT_TOKEN, 1_000);

        // Self-shield 400 (+100 fee): public → my own private pending.
        let tx = signed(
            Transaction::Shield {
                token: LAT_TOKEN, from: user, to: user, amount: 400, fee: 100, nonce: 0, sig: [0u8; 64],
            },
            &user_sk,
        );
        ledger.apply(&tx).unwrap();

        // Public balance debited amount + fee.
        assert_eq!(ledger.public_balance(&user, LAT_TOKEN), Some(500));
        // The shielded value is in the PRIVATE pending pool (public at shield time,
        // so still decryptable here), spendable after a rollover.
        assert_eq!(user_sk.decrypt(&ledger.pending(&user, LAT_TOKEN).unwrap(), 24), Some(400));
        assert_eq!(ledger.nonce(&user), Some(1));
    }

    #[test]
    fn unshield_moves_private_to_public() {
        let mut rng = OsRng;
        let user_sk = SecretKey::random(&mut rng);
        let user = user_sk.public_key().to_bytes();
        let dest_sk = SecretKey::random(&mut rng);
        let dest = dest_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(user).unwrap();
        ledger.register(dest).unwrap();
        ledger.credit_genesis(&user, 1_000).unwrap(); // confidential balance

        let bal = ledger.balance(&user, LAT_TOKEN).unwrap();
        let xfer = lat_crypto::SolventTransfer::create(
            &user_sk, &lat_crypto::unshield_view_key(), 400, 10, 1_000, &bal, 0, &mut rng,
        )
        .unwrap();
        let tx = signed(
            Transaction::Unshield { token: LAT_TOKEN, to: dest, amount: 400, xfer, sig: [0u8; 64] },
            &user_sk,
        );
        ledger.apply(&tx).unwrap();

        // Sender's confidential balance debited amount + fee; dest's PUBLIC balance
        // credited the revealed amount.
        assert_eq!(user_sk.decrypt(&ledger.balance(&user, LAT_TOKEN).unwrap(), 24), Some(590));
        assert_eq!(ledger.public_balance(&dest, LAT_TOKEN), Some(400));
        assert_eq!(ledger.nonce(&user), Some(1));
    }

    #[test]
    fn unshield_amount_mismatch_and_wrong_receiver_rejected() {
        let mut rng = OsRng;
        let user_sk = SecretKey::random(&mut rng);
        let user = user_sk.public_key().to_bytes();
        let dest_sk = SecretKey::random(&mut rng);
        let dest = dest_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(user).unwrap();
        ledger.register(dest).unwrap();
        ledger.credit_genesis(&user, 1_000).unwrap();

        // Honest confidential spend of 400, but the tx DECLARES 401 → mismatch.
        let bal = ledger.balance(&user, LAT_TOKEN).unwrap();
        let xfer = lat_crypto::SolventTransfer::create(
            &user_sk, &lat_crypto::unshield_view_key(), 400, 10, 1_000, &bal, 0, &mut rng,
        )
        .unwrap();
        let bad_amt = signed(
            Transaction::Unshield { token: LAT_TOKEN, to: dest, amount: 401, xfer, sig: [0u8; 64] },
            &user_sk,
        );
        assert_eq!(ledger.apply(&bad_amt), Err(LedgerError::UnshieldAmountMismatch));

        // Confidential receiver is NOT the view key → can't be soundly revealed.
        let wrong = lat_crypto::SolventTransfer::create(
            &user_sk, &dest_sk.public_key(), 400, 10, 1_000, &bal, 0, &mut rng,
        )
        .unwrap();
        let bad_recv = signed(
            Transaction::Unshield { token: LAT_TOKEN, to: dest, amount: 400, xfer: wrong, sig: [0u8; 64] },
            &user_sk,
        );
        assert_eq!(ledger.apply(&bad_recv), Err(LedgerError::WrongUnshieldReceiver));

        // Both rejected before any state change.
        assert_eq!(ledger.public_balance(&dest, LAT_TOKEN), Some(0));
        assert_eq!(ledger.nonce(&user), Some(0));
    }

    #[test]
    fn tampering_unshield_destination_is_rejected() {
        // Attack: intercept a valid unshield and repoint `to` at the attacker.
        // The Schnorr signature covers `to`, so consensus refuses it — no theft.
        let mut rng = OsRng;
        let user_sk = SecretKey::random(&mut rng);
        let user = user_sk.public_key().to_bytes();
        let dest_sk = SecretKey::random(&mut rng);
        let dest = dest_sk.public_key().to_bytes();
        let attacker = SecretKey::random(&mut rng).public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(user).unwrap();
        ledger.register(dest).unwrap();
        ledger.register(attacker).unwrap();
        ledger.credit_genesis(&user, 1_000).unwrap();

        let bal = ledger.balance(&user, LAT_TOKEN).unwrap();
        let xfer = lat_crypto::SolventTransfer::create(
            &user_sk, &lat_crypto::unshield_view_key(), 400, 10, 1_000, &bal, 0, &mut rng,
        )
        .unwrap();
        let mut tx = signed(
            Transaction::Unshield { token: LAT_TOKEN, to: dest, amount: 400, xfer, sig: [0u8; 64] },
            &user_sk,
        );
        // Attacker repoints the destination but can't re-sign as the user.
        if let Transaction::Unshield { to, .. } = &mut tx {
            *to = attacker;
        }
        assert_eq!(ledger.apply(&tx), Err(LedgerError::BadSignature));
        assert_eq!(ledger.public_balance(&attacker, LAT_TOKEN), Some(0), "no funds stolen");
    }

    #[test]
    fn cannot_spend_another_accounts_public_balance() {
        // Attack: Mallory names Alice as `from` to drain Alice's public balance,
        // but signs with her own key. The signature check stops it.
        let mut rng = OsRng;
        let alice_sk = SecretKey::random(&mut rng);
        let alice = alice_sk.public_key().to_bytes();
        let mallory_sk = SecretKey::random(&mut rng);
        let mallory = mallory_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(alice).unwrap();
        ledger.register(mallory).unwrap();
        ledger.credit_public(&alice, LAT_TOKEN, 1_000);

        let tx = signed(
            Transaction::PublicTransfer {
                token: LAT_TOKEN, from: alice, to: mallory, amount: 900, fee: 100, nonce: 0, sig: [0u8; 64],
            },
            &mallory_sk,
        );
        assert_eq!(ledger.apply(&tx), Err(LedgerError::BadSignature));
        assert_eq!(ledger.public_balance(&alice, LAT_TOKEN), Some(1_000), "Alice's funds untouched");
    }

    #[test]
    fn public_transfer_moves_plaintext_value() {
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let receiver_sk = SecretKey::random(&mut rng);
        let sender = sender_sk.public_key().to_bytes();
        let receiver = receiver_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(sender).unwrap();
        ledger.register(receiver).unwrap();
        ledger.credit_public(&sender, LAT_TOKEN, 1_000);

        // sender -> receiver: 400 + 100 fee, at nonce 0.
        let tx = signed(
            Transaction::PublicTransfer {
                token: LAT_TOKEN, from: sender, to: receiver, amount: 400, fee: 100, nonce: 0, sig: [0u8; 64],
            },
            &sender_sk,
        );
        ledger.apply(&tx).unwrap();

        // Sender debited amount + fee; receiver credited amount; nonce advanced.
        // (The 100 fee is credited to the block's miner at the chain layer.)
        assert_eq!(ledger.public_balance(&sender, LAT_TOKEN), Some(500));
        assert_eq!(ledger.public_balance(&receiver, LAT_TOKEN), Some(400));
        assert_eq!(ledger.nonce(&sender), Some(1));

        // Public and confidential balances are independent dimensions: the
        // transparent transfer left the (empty) encrypted balance untouched.
        assert_eq!(receiver_sk.decrypt(&ledger.balance(&receiver, LAT_TOKEN).unwrap(), 24), Some(0));
    }

    #[test]
    fn public_transfer_insufficient_balance_rejected() {
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let receiver_sk = SecretKey::random(&mut rng);
        let sender = sender_sk.public_key().to_bytes();
        let receiver = receiver_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(sender).unwrap();
        ledger.register(receiver).unwrap();
        ledger.credit_public(&sender, LAT_TOKEN, 500);

        // amount + fee = 501 > 500 -> rejected, nothing changes.
        let tx = signed(
            Transaction::PublicTransfer {
                token: LAT_TOKEN, from: sender, to: receiver, amount: 500, fee: 1, nonce: 0, sig: [0u8; 64],
            },
            &sender_sk,
        );
        assert_eq!(ledger.apply(&tx), Err(LedgerError::InsufficientPublicBalance));
        assert_eq!(ledger.public_balance(&sender, LAT_TOKEN), Some(500));
        assert_eq!(ledger.public_balance(&receiver, LAT_TOKEN), Some(0));
        assert_eq!(ledger.nonce(&sender), Some(0));
    }

    #[test]
    fn public_transfer_bad_signature_and_nonce_rejected() {
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let mallory_sk = SecretKey::random(&mut rng);
        let receiver_sk = SecretKey::random(&mut rng);
        let sender = sender_sk.public_key().to_bytes();
        let receiver = receiver_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(sender).unwrap();
        ledger.register(receiver).unwrap();
        ledger.credit_public(&sender, LAT_TOKEN, 1_000);

        // Mallory signs a spend FROM `sender` — the signature check catches it.
        let forged = signed(
            Transaction::PublicTransfer {
                token: LAT_TOKEN, from: sender, to: receiver, amount: 10, fee: 1, nonce: 0, sig: [0u8; 64],
            },
            &mallory_sk,
        );
        assert_eq!(ledger.apply(&forged), Err(LedgerError::BadSignature));

        // Correctly signed but stale nonce (5 != 0) — replay/ordering guard.
        let stale = signed(
            Transaction::PublicTransfer {
                token: LAT_TOKEN, from: sender, to: receiver, amount: 10, fee: 1, nonce: 5, sig: [0u8; 64],
            },
            &sender_sk,
        );
        assert_eq!(ledger.apply(&stale), Err(LedgerError::BadNonce));

        // Receiver must be a registered account.
        let no_recv = signed(
            Transaction::PublicTransfer {
                token: LAT_TOKEN, from: sender, to: [9u8; 32], amount: 10, fee: 1, nonce: 0, sig: [0u8; 64],
            },
            &sender_sk,
        );
        assert_eq!(ledger.apply(&no_recv), Err(LedgerError::ReceiverNotRegistered));

        // Nothing moved through any of the rejections.
        assert_eq!(ledger.public_balance(&sender, LAT_TOKEN), Some(1_000));
        assert_eq!(ledger.nonce(&sender), Some(0));
    }

    #[test]
    fn unique_ticker_is_enforced() {
        let mut rng = OsRng;
        let alice_sk = SecretKey::random(&mut rng);
        let bob_sk = SecretKey::random(&mut rng);
        let alice = alice_sk.public_key().to_bytes();
        let bob = bob_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(alice).unwrap();
        ledger.register(bob).unwrap();

        // Alice creates $DOGE.
        ledger
            .apply(&signed(
                Transaction::CreateToken {
                    ticker: "$doge".into(),
                    creator: alice,
                    supply: 1_000_000,
                    sig: [0u8; 64],
                },
                &alice_sk,
            ))
            .unwrap();
        assert_eq!(ledger.token_count(), 1);
        assert_eq!(ledger.token("DOGE").unwrap().creator, alice);

        // Bob tries to grab the same ticker (different case / with $) — rejected.
        assert_eq!(
            ledger.apply(&signed(
                Transaction::CreateToken {
                    ticker: "DOGE".into(),
                    creator: bob,
                    supply: 5,
                    sig: [0u8; 64],
                },
                &bob_sk,
            )),
            Err(LedgerError::TickerTaken)
        );
        assert_eq!(ledger.token_count(), 1);

        // The whole supply went to the creator, as a confidential balance.
        let doge = ledger.token("DOGE").unwrap().id;
        let creator_sk_balance = ledger.balance(&alice, doge).unwrap();
        // (decryptable only by Alice in a real wallet; here we just check it exists)
        let _ = creator_sk_balance;
    }

    #[test]
    fn invalid_ticker_rejected() {
        let mut rng = OsRng;
        let alice_sk = SecretKey::random(&mut rng);
        let alice = alice_sk.public_key().to_bytes();
        let mut ledger = Ledger::new();
        ledger.register(alice).unwrap();
        assert_eq!(
            ledger.apply(&signed(
                Transaction::CreateToken {
                    ticker: "way too long ticker!!".into(),
                    creator: alice,
                    supply: 1,
                    sig: [0u8; 64],
                },
                &alice_sk,
            )),
            Err(LedgerError::InvalidTicker)
        );
    }

    #[test]
    fn spoofed_creator_or_forced_rollover_rejected() {
        let mut rng = OsRng;
        let alice_sk = SecretKey::random(&mut rng);
        let mallory_sk = SecretKey::random(&mut rng);
        let alice = alice_sk.public_key().to_bytes();
        let mallory = mallory_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(alice).unwrap();
        ledger.register(mallory).unwrap();

        // Mallory names ALICE as creator but signs with her own key — rejected.
        assert_eq!(
            ledger.apply(&signed(
                Transaction::CreateToken {
                    ticker: "EVIL".into(),
                    creator: alice,
                    supply: 1,
                    sig: [0u8; 64],
                },
                &mallory_sk,
            )),
            Err(LedgerError::BadSignature)
        );
        // An entirely unsigned tx is also rejected.
        assert_eq!(
            ledger.apply(&Transaction::CreateToken {
                ticker: "EVIL".into(),
                creator: alice,
                supply: 1,
                sig: [0u8; 64],
            }),
            Err(LedgerError::BadSignature)
        );
        // Mallory can't force a rollover of Alice's account (which would
        // invalidate Alice's in-flight solvency proofs).
        assert_eq!(
            ledger.apply(&signed(
                Transaction::Rollover { account: alice, nonce: 0, sig: [0u8; 64] },
                &mallory_sk,
            )),
            Err(LedgerError::BadSignature)
        );
        // Alice herself can.
        ledger
            .apply(&signed(
                Transaction::Rollover { account: alice, nonce: 0, sig: [0u8; 64] },
                &alice_sk,
            ))
            .unwrap();
        // ...and a replay of that rollover is refused (nonce advanced to 1).
        assert_eq!(
            ledger.apply(&signed(
                Transaction::Rollover { account: alice, nonce: 0, sig: [0u8; 64] },
                &alice_sk,
            )),
            Err(LedgerError::BadNonce)
        );
    }

    #[test]
    fn rejects_transfer_from_unregistered_sender() {
        use lat_crypto::SolventTransfer;
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let receiver_sk = SecretKey::random(&mut rng);

        let mut ledger = Ledger::new();
        ledger.register(receiver_sk.public_key().to_bytes()).unwrap();

        // Sender is NOT registered — rejected before the proof is even checked.
        let bal = sender_sk.public_key().encrypt(1_000, &mut rng);
        let xfer =
            SolventTransfer::create(&sender_sk, &receiver_sk.public_key(), 1, 0, 1_000, &bal, 0, &mut rng).unwrap();
        assert_eq!(
            ledger.apply(&Transaction::SolventTransfer { token: LAT_TOKEN, xfer }),
            Err(LedgerError::SenderNotRegistered)
        );
    }

    #[test]
    fn solvent_transfer_uses_nonce_and_pending() {
        use lat_crypto::SolventTransfer;
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let receiver_sk = SecretKey::random(&mut rng);
        let sender_id = sender_sk.public_key().to_bytes();
        let receiver_id = receiver_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(sender_id).unwrap();
        ledger.register(receiver_id).unwrap();
        ledger.credit_genesis(&sender_id, 1_000).unwrap();

        // Honest solvent transfer at nonce 0.
        let bal = ledger.balance(&sender_id, LAT_TOKEN).unwrap();
        let xfer = SolventTransfer::create(&sender_sk, &receiver_sk.public_key(), 400, 0, 1_000, &bal, 0, &mut rng).unwrap();
        let tx = Transaction::SolventTransfer { token: LAT_TOKEN, xfer };
        let tx_bytes = tx.encode();
        ledger.apply(&tx).unwrap();

        // Sender debited + nonce advanced; receiver's funds are PENDING, not spendable.
        assert_eq!(sender_sk.decrypt(&ledger.balance(&sender_id, LAT_TOKEN).unwrap(), 24), Some(600));
        assert_eq!(ledger.nonce(&sender_id), Some(1));
        assert_eq!(receiver_sk.decrypt(&ledger.balance(&receiver_id, LAT_TOKEN).unwrap(), 24), Some(0));
        assert_eq!(receiver_sk.decrypt(&ledger.pending(&receiver_id, LAT_TOKEN).unwrap(), 24), Some(400));

        // Replay the exact same tx -> rejected (nonce is now 1, the tx used 0).
        let replay = Transaction::decode(&tx_bytes).unwrap();
        assert_eq!(ledger.apply(&replay), Err(LedgerError::BadNonce));

        // Rollover (signed by the receiver, at their nonce 0) makes the
        // receiver's pending spendable.
        ledger
            .apply(&signed(
                Transaction::Rollover { account: receiver_id, nonce: 0, sig: [0u8; 64] },
                &receiver_sk,
            ))
            .unwrap();
        assert_eq!(receiver_sk.decrypt(&ledger.balance(&receiver_id, LAT_TOKEN).unwrap(), 24), Some(400));
        assert_eq!(receiver_sk.decrypt(&ledger.pending(&receiver_id, LAT_TOKEN).unwrap(), 24), Some(0));
    }

    #[test]
    fn cheating_balance_rejected_at_matching_nonce() {
        use lat_crypto::SolventTransfer;
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let receiver_sk = SecretKey::random(&mut rng);
        let sender_id = sender_sk.public_key().to_bytes();
        let receiver_id = receiver_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(sender_id).unwrap();
        ledger.register(receiver_id).unwrap();
        ledger.credit_genesis(&sender_id, 1_000).unwrap();

        // Proof claims a 1,000,000 balance but the account holds 1,000. The nonce
        // (0) matches, so it clears the nonce gate and is caught by the solvency
        // check against the real balance.
        let fake = sender_sk.public_key().encrypt(1_000_000, &mut rng);
        let cheat = SolventTransfer::create(&sender_sk, &receiver_sk.public_key(), 900, 0, 1_000_000, &fake, 0, &mut rng).unwrap();
        assert_eq!(
            ledger.apply(&Transaction::SolventTransfer { token: LAT_TOKEN, xfer: cheat }),
            Err(LedgerError::InvalidProof)
        );
    }

    #[test]
    fn deploy_and_call_counter_contract() {
        use lat_vm::asm;
        // A counter contract: each call does storage[0] += 1.
        let mut code = asm::push(0);
        code.extend(asm::push(0));
        code.push(asm::SLOAD);
        code.extend(asm::push(1));
        code.push(asm::ADD);
        code.push(asm::SSTORE);
        code.push(asm::STOP);

        let deployer_sk = SecretKey::random(&mut OsRng);
        let deployer = deployer_sk.public_key().to_bytes();
        let id = lat_vm::contract_id(&deployer, &code);

        let mut ledger = Ledger::new();
        ledger.register(deployer).unwrap();
        ledger
            .apply(&signed(
                Transaction::DeployContract { deployer, code, sig: [0u8; 64] },
                &deployer_sk,
            ))
            .unwrap();
        assert!(ledger.has_contract(&id));

        // Call it three times (nonce advances each call); storage[0] ends at 3.
        for nonce in 0..3 {
            ledger
                .apply(&signed(
                    Transaction::CallContract { contract: id, caller: deployer, input: 0, nonce, sig: [0u8; 64] },
                    &deployer_sk,
                ))
                .unwrap();
        }
        assert_eq!(ledger.contract_storage(&id, 0), 3);

        // Replaying the first call (nonce 0) is refused — calls can't be re-run.
        assert_eq!(
            ledger.apply(&signed(
                Transaction::CallContract { contract: id, caller: deployer, input: 0, nonce: 0, sig: [0u8; 64] },
                &deployer_sk,
            )),
            Err(LedgerError::BadNonce)
        );
    }

    #[test]
    fn calling_missing_contract_rejected() {
        let caller_sk = SecretKey::random(&mut OsRng);
        let caller = caller_sk.public_key().to_bytes();
        let mut ledger = Ledger::new();
        ledger.register(caller).unwrap();
        assert_eq!(
            ledger.apply(&signed(
                Transaction::CallContract { contract: [9u8; 32], caller, input: 0, nonce: 0, sig: [0u8; 64] },
                &caller_sk,
            )),
            Err(LedgerError::NoSuchContract)
        );
    }

    #[test]
    fn double_registration_rejected() {
        let id = SecretKey::random(&mut OsRng).public_key().to_bytes();
        let mut ledger = Ledger::new();
        ledger.register(id).unwrap();
        assert_eq!(ledger.register(id), Err(LedgerError::AlreadyRegistered));
    }

    #[test]
    fn state_root_commits_and_proves_accounts() {
        let mut rng = OsRng;
        let a = SecretKey::random(&mut rng).public_key().to_bytes();
        let b = SecretKey::random(&mut rng).public_key().to_bytes();

        let mut ledger = Ledger::new();
        // An empty ledger still commits a stable, non-zero root.
        let empty = ledger.state_root();
        assert_ne!(empty, [0u8; 32]);

        ledger.register(a).unwrap();
        ledger.credit_public(&a, LAT_TOKEN, 1_000);
        let r1 = ledger.state_root();
        assert_ne!(r1, empty, "registering + funding must change the root");

        ledger.register(b).unwrap();
        let r2 = ledger.state_root();
        assert_ne!(r2, r1);
        assert_eq!(ledger.state_root(), r2, "recomputation is deterministic");

        // A's inclusion proof verifies against the current root and names A.
        let proof = ledger.account_proof(&a).expect("A is registered");
        assert_eq!(proof.account_id(), Some(a));
        assert!(verify_account_proof(&r2, &proof));

        // It does NOT verify against a stale root, and B's proof is distinct.
        assert!(!verify_account_proof(&r1, &proof), "stale root must not verify");
        let pb = ledger.account_proof(&b).unwrap();
        assert!(verify_account_proof(&r2, &pb));
        assert_ne!(proof.preimage, pb.preimage);

        // A forged proof (swap in B's leaf, keep A's path) fails to verify.
        let mut forged = proof.clone();
        forged.preimage = pb.preimage.clone();
        assert!(!verify_account_proof(&r2, &forged));

        // An unregistered account has no proof.
        assert!(ledger.account_proof(&[7u8; 32]).is_none());
    }

    #[test]
    fn ledger_snapshot_roundtrip_preserves_state_root() {
        // Build a ledger exercising every kind of state a snapshot must carry:
        // confidential + pending + public balances, nonces, a token, a contract.
        let mut rng = OsRng;
        let alice_sk = SecretKey::random(&mut rng);
        let bob_sk = SecretKey::random(&mut rng);
        let alice = alice_sk.public_key().to_bytes();
        let bob = bob_sk.public_key().to_bytes();

        let mut ledger = Ledger::new();
        ledger.register(alice).unwrap();
        ledger.register(bob).unwrap();
        ledger.credit_genesis(&alice, 1_000_000).unwrap();
        ledger.credit_public(&alice, LAT_TOKEN, 5_000);
        ledger
            .apply(&signed(
                Transaction::CreateToken { ticker: "DOGE".into(), creator: alice, supply: 42, sig: [0u8; 64] },
                &alice_sk,
            ))
            .unwrap();
        // A solvent transfer, so bob holds PENDING value and alice's nonce is 1.
        let bal = ledger.balance(&alice, LAT_TOKEN).unwrap();
        let xfer = lat_crypto::SolventTransfer::create(
            &alice_sk, &bob_sk.public_key(), 400, 0, 1_000_000, &bal, 0, &mut rng,
        )
        .unwrap();
        ledger.apply(&Transaction::SolventTransfer { token: LAT_TOKEN, xfer }).unwrap();
        // A contract with storage.
        let code = vec![lat_vm::asm::STOP];
        ledger
            .apply(&signed(Transaction::DeployContract { deployer: bob, code, sig: [0u8; 64] }, &bob_sk))
            .unwrap();

        let bytes = ledger.encode();
        let decoded = Ledger::decode(&bytes).expect("decodes");

        // The decoded ledger commits the exact same state root — the property
        // the chain layer relies on to trust a snapshot.
        assert_eq!(decoded.state_root(), ledger.state_root());
        // And the re-encoding is stable (canonical form).
        assert_eq!(decoded.encode(), bytes);
        // Spot-check live state through the decoded copy.
        assert_eq!(decoded.nonce(&alice), Some(1));
        assert_eq!(decoded.public_balance(&alice, LAT_TOKEN), Some(5_000));
        assert_eq!(bob_sk.decrypt(&decoded.pending(&bob, LAT_TOKEN).unwrap(), 24), Some(400));
        assert_eq!(decoded.token("DOGE").unwrap().supply, 42);
    }

    #[test]
    fn ledger_snapshot_rejects_hostile_input() {
        let mut ledger = Ledger::new();
        ledger.register([1u8; 32]).unwrap();
        ledger.credit_public(&[1u8; 32], LAT_TOKEN, 7);
        let good = ledger.encode();

        // Every truncation decodes to None (or, at full length, Some) — never panics.
        for n in 0..good.len() {
            assert!(Ledger::decode(&good[..n]).is_none(), "truncation at {n} must fail");
        }
        // Trailing garbage is rejected.
        let mut padded = good.clone();
        padded.push(0);
        assert!(Ledger::decode(&padded).is_none());
        // Wrong magic is rejected.
        let mut bad = good.clone();
        bad[0] ^= 0xff;
        assert!(Ledger::decode(&bad).is_none());
        // A hostile count must not OOM: claim u32::MAX accounts.
        let mut huge = good.clone();
        huge[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Ledger::decode(&huge).is_none());
    }

    #[test]
    fn ledger_commitment_persists_to_disk_base() {
        // A ledger whose overlay base is a persistent RedbStore: after applying
        // state and flushing, the committed trie nodes live on disk, so a fresh
        // ledger over the reopened base reproduces and can prove the same root.
        use lat_store::RedbStore;
        use std::sync::Arc;

        let path = std::env::temp_dir().join(format!(
            "lat-ledger-persist-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));

        let mut rng = OsRng;
        let ids: Vec<[u8; 32]> =
            (0..16).map(|_| SecretKey::random(&mut rng).public_key().to_bytes()).collect();

        let (root, proof_id) = {
            let base = Arc::new(RedbStore::open(&path).unwrap());
            let mut ledger = Ledger::with_base(base);
            for id in &ids {
                ledger.register(*id).unwrap();
                ledger.credit_public(id, LAT_TOKEN, 500);
            }
            let root = ledger.state_root();
            ledger.flush(); // persist the trie nodes into the redb base
            (root, ids[3])
        };

        // Reopen the on-disk base and rebuild the trie from just the root: the
        // account proof still verifies, so the commitment truly persisted.
        let base = Arc::new(RedbStore::open(&path).unwrap());
        let trie = Smt::from_root(base.as_ref(), root);
        let proof = trie.prove(&trie_key_account(&proof_id));
        assert!(matches!(proof.terminal, lat_store::Terminal::Leaf { .. }), "account leaf persisted");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn from_records_boots_the_exact_state_and_rejects_tampering() {
        let mut rng = OsRng;
        let mem = Arc::new(lat_store::MemStore::new());
        let base: Arc<dyn lat_store::KVStore> = mem.clone();
        let ids: Vec<[u8; 32]> =
            (0..6).map(|_| SecretKey::random(&mut rng).public_key().to_bytes()).collect();

        let root = {
            let mut ledger = Ledger::with_base(Arc::clone(&base));
            for id in &ids {
                ledger.register(*id).unwrap();
                ledger.credit_public(id, LAT_TOKEN, 777);
                ledger.credit_genesis(id, 1_000).unwrap();
            }
            ledger
                .apply(&signed(
                    Transaction::CreateToken {
                        ticker: "BOOT".into(),
                        creator: ids[0],
                        supply: 500,
                        sig: [0u8; 64],
                    },
                    &SecretKey::random(&mut rng),
                ))
                .unwrap_err(); // wrong key — just proves apply path is live
            ledger.insert_nullifier(&[5u8; 32]);
            ledger.mark(DirtyKey::Nullifier([5u8; 32]));
            let root = ledger.state_root();
            ledger.flush();
            root
        };

        // Boot from the records alone: identical root, identical reads.
        let booted = Ledger::from_records(Arc::clone(&base)).expect("records boot");
        assert_eq!(booted.state_root(), root);
        assert_eq!(booted.public_balance(&ids[0], LAT_TOKEN), Some(777));
        assert!(booted.nullifier_seen(&[5u8; 32]));
        // …and it keeps working (this also proves the ticker index is usable).
        let mut booted = booted;
        booted.credit_public(&ids[1], LAT_TOKEN, 1);
        assert_ne!(booted.state_root(), root);

        // Tamper one account record: the boot either fails to decode or commits
        // a different root — never silently reproduces `root`.
        let (key, mut body) =
            base.scan_prefix(Column::Objects, &[REC_ACCOUNT]).into_iter().next().unwrap();
        let last = body.len() - 1;
        body[last] ^= 0xff;
        mem.put(Column::Objects, key, body);
        match Ledger::from_records(Arc::clone(&base)) {
            None => {}
            Some(l) => assert_ne!(l.state_root(), root, "tampering must change the root"),
        }

        // A base with no meta record is not bootable state at all.
        let empty: Arc<dyn lat_store::KVStore> = Arc::new(lat_store::MemStore::new());
        assert!(Ledger::from_records(empty).is_none());
    }

    #[test]
    fn rehome_atomically_replaces_the_base_state() {
        let mut rng = OsRng;
        let old_id = SecretKey::random(&mut rng).public_key().to_bytes();
        let new_id = SecretKey::random(&mut rng).public_key().to_bytes();

        // The durable base holds an OLD state (as after an abandoned branch).
        let base: Arc<dyn lat_store::KVStore> = Arc::new(lat_store::MemStore::new());
        {
            let mut old = Ledger::with_base(Arc::clone(&base));
            old.register(old_id).unwrap();
            old.credit_public(&old_id, LAT_TOKEN, 111);
            old.state_root();
            old.flush();
        }

        // A NEW state built off-base (as a reorg rebuild is), re-homed onto it
        // with a staged meta write riding the same batch.
        let mut fresh = Ledger::new();
        fresh.register(new_id).unwrap();
        fresh.credit_public(&new_id, LAT_TOKEN, 222);
        let root = fresh.state_root();
        let rehomed =
            fresh.rehome(Arc::clone(&base), vec![(b"anchor-test".to_vec(), vec![7u8])]);

        assert_eq!(rehomed.state_root(), root, "the logical state survives the move");
        assert_eq!(rehomed.public_balance(&new_id, LAT_TOKEN), Some(222));
        assert!(!rehomed.is_registered(&old_id), "the old base state is gone");
        assert_eq!(base.get(Column::Meta, b"anchor-test"), Some(vec![7u8]));
        // And the base now boots the new state directly.
        let booted = Ledger::from_records(base).expect("records boot after rehome");
        assert_eq!(booted.state_root(), root);
        assert!(!booted.is_registered(&old_id));
    }

    fn stake_tx(sk: &SecretKey, amount: u64, nonce: u64) -> Transaction {
        signed(
            Transaction::Stake { validator: sk.public_key().to_bytes(), amount, nonce, sig: [0u8; 64] },
            sk,
        )
    }
    fn unstake_tx(sk: &SecretKey, amount: u64, nonce: u64) -> Transaction {
        signed(
            Transaction::Unstake { validator: sk.public_key().to_bytes(), amount, nonce, sig: [0u8; 64] },
            sk,
        )
    }

    #[test]
    fn stake_unstake_lifecycle_with_unbonding_window() {
        let mut rng = OsRng;
        let sk = SecretKey::random(&mut rng);
        let id = sk.public_key().to_bytes();
        let mut l = Ledger::new();
        l.register(id).unwrap();
        l.credit_public(&id, LAT_TOKEN, 3 * MIN_VALIDATOR_STAKE);

        // Bond twice the minimum: balance moves into stake, root changes.
        let r0 = l.state_root();
        l.apply_at(&stake_tx(&sk, 2 * MIN_VALIDATOR_STAKE, 0), 10).unwrap();
        assert_eq!(l.staked(&id), 2 * MIN_VALIDATOR_STAKE);
        assert_eq!(l.public_balance(&id, LAT_TOKEN), Some(MIN_VALIDATOR_STAKE));
        assert_eq!(l.validator_set(), vec![(id, 2 * MIN_VALIDATOR_STAKE)]);
        assert_ne!(l.state_root(), r0, "staking is committed state");

        // Unbond half: stake drops immediately, funds wait out the window.
        l.apply_at(&unstake_tx(&sk, MIN_VALIDATOR_STAKE, 1), 20).unwrap();
        assert_eq!(l.staked(&id), MIN_VALIDATOR_STAKE);
        assert_eq!(l.unbonding(&id), vec![(MIN_VALIDATOR_STAKE, 20 + UNBONDING_BLOCKS)]);
        assert_eq!(
            l.public_balance(&id, LAT_TOKEN),
            Some(MIN_VALIDATOR_STAKE),
            "nothing released before the window"
        );

        // A zero-amount Stake BEFORE maturity sweeps nothing…
        l.apply_at(&stake_tx(&sk, 0, 2), 20 + UNBONDING_BLOCKS - 1).unwrap();
        assert_eq!(l.public_balance(&id, LAT_TOKEN), Some(MIN_VALIDATOR_STAKE));
        // …and AT maturity releases the entry back to the public balance.
        l.apply_at(&stake_tx(&sk, 0, 3), 20 + UNBONDING_BLOCKS).unwrap();
        assert_eq!(l.public_balance(&id, LAT_TOKEN), Some(2 * MIN_VALIDATOR_STAKE));
        assert!(l.unbonding(&id).is_empty());

        // Guardrails: can't unstake more than bonded; can't stake more than held.
        assert_eq!(
            l.apply_at(&unstake_tx(&sk, 2 * MIN_VALIDATOR_STAKE, 4), 300),
            Err(LedgerError::InsufficientStake)
        );
        assert_eq!(
            l.apply_at(&stake_tx(&sk, u64::MAX, 4), 300),
            Err(LedgerError::InsufficientPublicBalance)
        );
        // Draining everything deletes the record — canonical empty state.
        l.apply_at(&unstake_tx(&sk, MIN_VALIDATOR_STAKE, 4), 300).unwrap();
        l.apply_at(&stake_tx(&sk, 0, 5), 300 + UNBONDING_BLOCKS).unwrap();
        assert_eq!(l.staked(&id), 0);
        assert!(l.validator_set().is_empty());
        assert_eq!(l.public_balance(&id, LAT_TOKEN), Some(3 * MIN_VALIDATOR_STAKE));
    }

    #[test]
    fn slash_evidence_partial_slash_reward_and_tombstone() {
        let mut rng = OsRng;
        let sk = SecretKey::random(&mut rng);
        let id = sk.public_key().to_bytes();
        // A separate whistleblower who submits the evidence and earns the reward.
        let wb = SecretKey::random(&mut rng).public_key().to_bytes();
        let mut l = Ledger::new();
        l.register(id).unwrap();
        l.register(wb).unwrap();
        l.credit_public(&id, LAT_TOKEN, 4 * MIN_VALIDATOR_STAKE);
        l.apply_at(&stake_tx(&sk, 2 * MIN_VALIDATOR_STAKE, 0), 5).unwrap();
        l.apply_at(&unstake_tx(&sk, MIN_VALIDATOR_STAKE, 1), 6).unwrap();
        assert_eq!(l.staked(&id), MIN_VALIDATOR_STAKE);
        assert_eq!(l.unbonding(&id).len(), 1);
        // Total at-risk stake = bonded + unbonding = 2 * MIN_VALIDATOR_STAKE.
        let total = 2 * MIN_VALIDATOR_STAKE;

        // Equivocation: two finality votes at one height for different blocks.
        let vote = |block: [u8; 32]| {
            sk.sign(&lat_types::finality_vote_signing_bytes(&block, 9)).to_bytes()
        };
        let evidence = Transaction::SlashEvidence {
            validator: id,
            beneficiary: wb,
            height: 9,
            block_a: [1u8; 32],
            sig_a: vote([1u8; 32]),
            block_b: [2u8; 32],
            sig_b: vote([2u8; 32]),
        };

        // Fabrications are rejected before anything is slashed.
        let mut same_block = evidence.clone();
        if let Transaction::SlashEvidence { block_b, sig_b, .. } = &mut same_block {
            *block_b = [1u8; 32];
            *sig_b = vote([1u8; 32]);
        }
        assert_eq!(l.apply_at(&same_block, 10), Err(LedgerError::BadEvidence));
        let mut bad_sig = evidence.clone();
        if let Transaction::SlashEvidence { sig_b, .. } = &mut bad_sig {
            sig_b[0] ^= 1;
        }
        assert_eq!(l.apply_at(&bad_sig, 10), Err(LedgerError::BadEvidence));

        // Real evidence slashes SLASH_FRACTION_BPS of the total at-risk stake,
        // pays SLASH_REWARD_BPS of that to the whistleblower, and tombstones
        // the offender (removed from the set, residual stake kept).
        let slashed = total * SLASH_FRACTION_BPS / 10_000;
        let reward = slashed * SLASH_REWARD_BPS / 10_000;
        let root_before = l.state_root();
        l.apply_at(&evidence, 10).unwrap();
        assert_eq!(l.staked(&id) + l.unbonding(&id).iter().map(|(a, _)| *a).sum::<u64>(), total - slashed);
        assert!(l.validator_set().is_empty(), "tombstoned validator is out of the set");
        assert_eq!(l.public_balance(&wb, LAT_TOKEN), Some(reward), "whistleblower rewarded");
        assert_ne!(l.state_root(), root_before, "slashing is committed state");

        // Even though residual stake remains, the tombstone blocks a re-slash.
        assert_eq!(l.apply_at(&evidence, 11), Err(LedgerError::NothingToSlash));
        // A never-bonded bystander can't be slashed by valid-looking votes.
        let other = SecretKey::random(&mut rng);
        let ovote = |block: [u8; 32]| {
            other.sign(&lat_types::finality_vote_signing_bytes(&block, 9)).to_bytes()
        };
        let bystander = Transaction::SlashEvidence {
            validator: other.public_key().to_bytes(),
            beneficiary: wb,
            height: 9,
            block_a: [1u8; 32],
            sig_a: ovote([1u8; 32]),
            block_b: [2u8; 32],
            sig_b: ovote([2u8; 32]),
        };
        assert_eq!(l.apply_at(&bystander, 11), Err(LedgerError::NothingToSlash));
    }

    #[test]
    fn validator_cap_is_configurable() {
        let mut rng = OsRng;
        let sks: Vec<SecretKey> = (0..3).map(|_| SecretKey::random(&mut rng)).collect();
        let ids: Vec<[u8; 32]> = sks.iter().map(|s| s.public_key().to_bytes()).collect();
        let mut l = Ledger::new();
        l.set_max_validators(2);
        for (i, (sk, id)) in sks.iter().zip(&ids).enumerate() {
            l.register(*id).unwrap();
            l.credit_public(id, LAT_TOKEN, 10 * MIN_VALIDATOR_STAKE);
            // Distinct stakes so ordering is unambiguous.
            l.apply_at(&stake_tx(sk, (i as u64 + 1) * MIN_VALIDATOR_STAKE, 0), 5).unwrap();
        }
        let set = l.validator_set();
        assert_eq!(set.len(), 2, "cap of 2 keeps only the top two by stake");
        assert_eq!(set[0].1, 3 * MIN_VALIDATOR_STAKE);
        assert_eq!(set[1].1, 2 * MIN_VALIDATOR_STAKE);
    }

    #[test]
    fn validator_set_is_deterministic_ordered_and_thresholded() {
        let mut rng = OsRng;
        let sks: Vec<SecretKey> = (0..4).map(|_| SecretKey::random(&mut rng)).collect();
        let ids: Vec<[u8; 32]> = sks.iter().map(|s| s.public_key().to_bytes()).collect();
        let mut l = Ledger::new();
        for id in &ids {
            l.register(*id).unwrap();
            l.credit_public(id, LAT_TOKEN, 10 * MIN_VALIDATOR_STAKE);
        }
        // Stakes: [3×min, 5×min, 5×min, below-min].
        l.apply_at(&stake_tx(&sks[0], 3 * MIN_VALIDATOR_STAKE, 0), 1).unwrap();
        l.apply_at(&stake_tx(&sks[1], 5 * MIN_VALIDATOR_STAKE, 0), 1).unwrap();
        l.apply_at(&stake_tx(&sks[2], 5 * MIN_VALIDATOR_STAKE, 0), 1).unwrap();
        l.apply_at(&stake_tx(&sks[3], MIN_VALIDATOR_STAKE - 1, 0), 1).unwrap();

        let set = l.validator_set();
        assert_eq!(set.len(), 3, "below-threshold stake is not a validator");
        // Stake descending; the two 5×min entries tie-break by ascending id.
        assert_eq!(set[0].1, 5 * MIN_VALIDATOR_STAKE);
        assert_eq!(set[1].1, 5 * MIN_VALIDATOR_STAKE);
        assert!(set[0].0 < set[1].0, "ties order by id");
        assert_eq!(set[2], (ids[0], 3 * MIN_VALIDATOR_STAKE));

        // Deterministic from committed state alone: a snapshot roundtrip and a
        // records boot both reproduce the identical set and root.
        let decoded = Ledger::decode(&l.encode()).expect("snapshot decodes");
        assert_eq!(decoded.validator_set(), set);
        assert_eq!(decoded.state_root(), l.state_root());

        l.state_root();
        l.flush();
        let booted = Ledger::from_records(l.store.base()).expect("records boot");
        assert_eq!(booted.validator_set(), set);
        assert_eq!(booted.state_root(), l.state_root());
    }

    #[test]
    fn prune_history_shrinks_trie_and_keeps_state_intact() {
        let mut rng = OsRng;
        let mut ledger = Ledger::new();
        let ids: Vec<[u8; 32]> =
            (0..12).map(|_| SecretKey::random(&mut rng).public_key().to_bytes()).collect();
        for id in &ids {
            ledger.register(*id).unwrap();
            ledger.credit_public(id, LAT_TOKEN, 1_000);
        }
        ledger.state_root();
        ledger.flush();

        // Churn across simulated committed blocks: every balance change strands
        // the old trie path. Keep the recent roots like a chain would.
        let mut roots = Vec::new();
        for round in 1..=20u64 {
            for id in &ids {
                ledger.credit_public(id, LAT_TOKEN, round);
            }
            roots.push(ledger.state_root());
            ledger.flush();
        }
        let before = ledger.state_node_count();
        let root_before = ledger.state_root();

        // Retain a 4-root window; everything older is garbage-collected.
        let window = &roots[roots.len() - 4..];
        let stats = ledger.prune_history(window);
        assert!(stats.dropped > 0, "churn must leave prunable garbage");
        let after = ledger.state_node_count();
        assert_eq!(after, before - stats.dropped);
        assert_eq!(after, stats.kept);

        // Current state is untouched: same root, proofs verify, balances read.
        assert_eq!(ledger.state_root(), root_before);
        let proof = ledger.account_proof(&ids[0]).unwrap();
        assert!(verify_account_proof(&root_before, &proof));
        assert_eq!(ledger.public_balance(&ids[0], LAT_TOKEN), Some(1_000 + (1..=20).sum::<u64>()));

        // A retained historical root still serves trie reads (archive window)…
        let old_root = window[0];
        let base = ledger.store.base();
        let old_trie = Smt::from_root(base.as_ref(), old_root);
        assert!(matches!(
            old_trie.prove(&trie_key_account(&ids[0])).terminal,
            lat_store::Terminal::Leaf { .. }
        ));

        // …and the ledger keeps working normally after the sweep.
        ledger.credit_public(&ids[1], LAT_TOKEN, 5);
        assert_ne!(ledger.state_root(), root_before);
        let rebuilt = Ledger::decode(&ledger.encode()).expect("snapshot decodes");
        assert_eq!(rebuilt.state_root(), ledger.state_root(), "roundtrip after prune");
    }

    #[test]
    fn incremental_root_matches_full_rebuild_over_random_workload() {
        // The heart of T3's correctness: the incrementally-maintained state root
        // must equal a from-scratch rebuild after ANY sequence of state changes.
        // `Ledger::decode(encode())` rebuilds the commitment from the raw maps
        // (via `rebuild_commitment`), so it is the independent full-recompute
        // oracle. We compare it to the live incremental root after each step.
        let mut rng = OsRng;
        let mut ledger = Ledger::new();

        // A pool of registered, funded accounts.
        let sks: Vec<SecretKey> = (0..8).map(|_| SecretKey::random(&mut rng)).collect();
        let ids: Vec<[u8; 32]> = sks.iter().map(|s| s.public_key().to_bytes()).collect();
        for id in &ids {
            ledger.register(*id).unwrap();
            ledger.credit_public(id, LAT_TOKEN, 1_000_000);
            ledger.credit_genesis(id, 1_000_000).unwrap();
        }

        let check = |l: &Ledger| {
            let rebuilt = Ledger::decode(&l.encode()).expect("snapshot decodes");
            assert_eq!(l.state_root(), rebuilt.state_root(), "incremental root diverged from full rebuild");
        };
        check(&ledger);

        // A token creation (exercises the Token + Meta leaves).
        ledger
            .apply(&signed(
                Transaction::CreateToken { ticker: "TEST".into(), creator: ids[0], supply: 500, sig: [0u8; 64] },
                &sks[0],
            ))
            .unwrap();
        check(&ledger);

        // A contract deploy + several calls (Contract leaf, storage churn).
        let code = {
            let mut c = lat_vm::asm::push(0);
            c.extend(lat_vm::asm::push(0));
            c.push(lat_vm::asm::SLOAD);
            c.extend(lat_vm::asm::push(1));
            c.push(lat_vm::asm::ADD);
            c.push(lat_vm::asm::SSTORE);
            c.push(lat_vm::asm::STOP);
            c
        };
        let cid = lat_vm::contract_id(&ids[1], &code);
        ledger.apply(&signed(Transaction::DeployContract { deployer: ids[1], code, sig: [0u8; 64] }, &sks[1])).unwrap();
        check(&ledger);

        // Many public transfers between random accounts (Account leaf churn).
        for i in 0..40u64 {
            let from = (i as usize) % ids.len();
            let to = (i as usize + 1) % ids.len();
            let nonce = ledger.nonce(&ids[from]).unwrap();
            let tx = signed(
                Transaction::PublicTransfer {
                    token: LAT_TOKEN,
                    from: ids[from],
                    to: ids[to],
                    amount: 1,
                    fee: 0,
                    nonce,
                    sig: [0u8; 64],
                },
                &sks[from],
            );
            ledger.apply(&tx).unwrap();
            // A contract call interleaved, to churn contract storage too.
            let cnonce = ledger.nonce(&ids[1]).unwrap();
            ledger
                .apply(&signed(
                    Transaction::CallContract { contract: cid, caller: ids[1], input: 0, nonce: cnonce, sig: [0u8; 64] },
                    &sks[1],
                ))
                .unwrap();
            check(&ledger);
        }
    }

    #[test]
    fn state_root_is_insertion_order_independent() {
        // The root depends only on state contents, not on HashMap/insert order,
        // so every honest node computes the same commitment.
        let mut rng = OsRng;
        let ids: Vec<[u8; 32]> =
            (0..6).map(|_| SecretKey::random(&mut rng).public_key().to_bytes()).collect();

        let mut l1 = Ledger::new();
        for id in ids.iter() {
            l1.register(*id).unwrap();
            l1.credit_public(id, LAT_TOKEN, 10);
        }
        let mut l2 = Ledger::new();
        for id in ids.iter().rev() {
            l2.register(*id).unwrap();
            l2.credit_public(id, LAT_TOKEN, 10);
        }
        assert_eq!(l1.state_root(), l2.state_root());
    }
}

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
        }
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Ledger::new()
    }
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
        let result = self.apply_inner(tx, height);
        if result.is_ok() {
            let keys = self.dirty_keys_for(tx);
            self.mark_all(keys);
        }
        result
    }

    fn apply_inner(&mut self, tx: &Transaction, height: u64) -> Result<(), LedgerError> {
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
                // Solvency against the sender's current SPENDABLE balance.
                if !xfer.verify(&sender_bal) {
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
                // balance (proves balance − amount − fee ≥ 0).
                if !xfer.verify(&sender_bal) {
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
                if !xfer.verify() {
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
                // Credit the public amount to the one-time stealth account's
                // pending pool, auto-registering it (the spend paid a fee, so no
                // separate anti-spam PoW) — the same mechanism as ShieldStealth.
                // The fee is credited to the miner at the block level. Read AFTER
                // the ring debits are written back, in case `one_time` aliases a
                // ring member.
                let one_time = xfer.output.one_time.to_bytes();
                let mut r = self.account(&one_time).unwrap_or_default();
                let new = r.pending(*token).add(&Ciphertext::mint(xfer.amount));
                r.set_pending(*token, new);
                self.put_account(&one_time, r);

                self.insert_nullifier(&nullifier);
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
/// anonymous-spend nullifier set joined the encoding; a v1 snapshot no longer
/// decodes, which simply costs one full replay on the next boot.
const LEDGER_MAGIC: &[u8; 8] = b"LATLEDG2";

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
            | Transaction::ShieldStealth { sig, .. } => *sig = sig_bytes,
            _ => {}
        }
        tx
    }

    /// Ledger with `n` registered accounts each holding `amount` confidential LAT.
    fn ledger_with_ring(
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
    /// balances, for the epoch of `height`.
    fn anon_tx(
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
            Transaction::AnonTransfer { xfer, .. } => (xfer.nullifier(), xfer.output.clone()),
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

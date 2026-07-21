//! Latebra single-node chain: genesis, proof-of-work, and block production
//! (clean-room, from `SPEC.md`).
//!
//! A block bundles transactions; mining finds a header nonce whose hash meets the
//! difficulty target; applying a block validates it and commits its transactions
//! to the ledger atomically.
//!
//! ## PoW note (honest)
//! The proof-of-work hash is a single seam: [`pow_hash`]. By default it is
//! **BLAKE3** (fast, builds everywhere; ASIC-friendly, which is fine for a
//! testnet). Building with `--features randomx` switches it to **RandomX**
//! (Monero-style, ASIC-resistant) — which requires the native RandomX library
//! (CMake + a C/C++ toolchain). Everything else (difficulty, mining, verification)
//! is identical; only this one function changes.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use lat_state::{Ledger, LedgerError};
use lat_store::{Column, KVStore, RedbStore};
use lat_types::Transaction;

use lat_crypto::Ciphertext;

pub mod finality;
mod mempool;
mod snapshot;
mod store;
pub use finality::{Certificate, Vote};
pub use mempool::{tx_hash, Mempool};
pub use store::ChainStore;

/// Anonymity-epoch parameters, re-exported so wallets/tools don't need a direct
/// `lat-state` dependency to target the right epoch.
pub use lat_state::{epoch_of, EPOCH_BLOCKS};

/// Staking parameters (T13), re-exported for node/tooling crates.
pub use lat_state::{MAX_VALIDATORS, MIN_VALIDATOR_STAKE, UNBONDING_BLOCKS};

/// Starting block-PoW difficulty `D`: a block is valid when the top 64 bits of
/// its hash are `<= u64::MAX / D`, so the chance per hash is ~`1/D`. Low here so
/// tests/demo mine instantly; the chain then retargets toward a target block time.
pub const DEFAULT_DIFFICULTY: u64 = 256;

/// Target seconds between blocks; difficulty is steered toward this.
pub const TARGET_BLOCK_TIME_SECS: u64 = 3;

/// Per-block retarget clamp: difficulty can change by at most this factor each
/// block, damping swings (a smoothing window is a later refinement).
const RETARGET_CLAMP: u64 = 2;

/// Anti-spam difficulty for account registration (leading zero bits). ONE
/// constant, used by both the miner ([`mine_registration`]) and the verifier
/// ([`verify_registration_pow`]). (The hard-won lesson from the old chain: if
/// these targets ever diverge, registrations silently fail.)
pub const REGISTRATION_POW_BITS: u32 = 8;

const GENESIS_TIMESTAMP: u64 = 1_750_000_000;

/// Minimum fee a `SolventTransfer` must pay (base units of the token being
/// transferred; 1,000 = 0.01 LAT at 5 decimals). ONE constant shared by the
/// wallet (default fee), the mempool (admission), and block validation
/// (consensus) — like the registration PoW targets, these must never diverge.
///
/// Honest note: the fee is denominated in the *transferred* token (the solvency
/// proof debits amount + fee from that one balance). Requiring native-LAT fees
/// on non-LAT transfers needs a second balance proof — a later refinement.
pub const MIN_TRANSFER_FEE: u64 = 1_000;

/// The fee a transaction pays its block's miner (0 for types with no fee field:
/// `Register` pays with anti-spam PoW instead).
pub fn tx_fee(tx: &Transaction) -> u64 {
    match tx {
        Transaction::SolventTransfer { xfer, .. } => xfer.fee,
        Transaction::Unshield { xfer, .. } => xfer.fee,
        Transaction::AnonTransfer { xfer, .. } => xfer.fee,
        Transaction::PublicTransfer { fee, .. }
        | Transaction::Shield { fee, .. }
        | Transaction::ShieldStealth { fee, .. }
        | Transaction::AddLiquidity { fee, .. }
        | Transaction::RemoveLiquidity { fee, .. }
        | Transaction::Swap { fee, .. }
        | Transaction::CurveTrade { fee, .. }
        | Transaction::HtlcLock { fee, .. } => *fee,
        // HtlcClaim / HtlcRefund are fee-less by design, like SlashEvidence:
        // each consumes an existing lock record, so they can't be spammed.
        // Flat-fee types (C-1): no fee field, a fixed cost charged in apply.
        Transaction::CreateToken { .. }
        | Transaction::DeployContract { .. }
        | Transaction::CallContract { .. } => lat_state::FLAT_TX_FEE,
        _ => 0,
    }
}

/// Consensus cap on deployed contract bytecode. A deploy pays a flat fee
/// (`lat_state::FLAT_TX_FEE`, C-1) and is gated by the deployer's PoW
/// registration, but a per-tx cap still bounds how much a single paid deploy
/// can bloat the chain.
pub const MAX_CONTRACT_CODE_BYTES: usize = 24 * 1024;

/// Consensus cap on how many transactions one block may carry.
///
/// This is a **consensus rule, not miner policy** — that distinction is the
/// whole point. Proof-of-work covers only the header, so a block costs the same
/// to mine whether it holds one transaction or a million, while every node on
/// the network must validate all of them. Worse, fees do not deter it: the
/// attacker *is* the miner, so every fee they pay to stuff their own block comes
/// straight back as coinbase. Without a rule here, one cheap block can stall the
/// whole network (a confidential transfer costs ~5.8 ms to verify; 100k of them
/// is minutes per node).
///
/// The value matches what `latebrad` already produced, so honest miners see no
/// change — it makes an existing assumption enforceable by everyone else.
///
/// KNOWN CRUDENESS: a *count* cap prices a 140 µs public transfer the same as a
/// 5.8 ms confidential one — a ~40x spread — so this bounds the worst case far
/// more loosely than it bounds the typical one. A weight/gas-metered block limit
/// is the correct long-term fix (it is why Ethereum meters gas rather than
/// counting transactions). Until then this is deliberately sized so that even an
/// all-confidential block stays inside the block interval: 1000 × 5.8 ms ≈ 5.8 s
/// serial, ≈ 1.8 s with T12's parallel proof pre-pass, against a 3 s target.
pub const MAX_TXS_PER_BLOCK: usize = 1000;

/// Blocks between ledger snapshots (L8). Every time the active chain reaches a
/// multiple of this height, the node persists the full ledger next to the block
/// log so the next startup replays only the blocks after it (~25 min of blocks
/// at the 3 s target). Node-local tuning, not consensus — nodes with different
/// intervals still agree on state.
pub const SNAPSHOT_INTERVAL: u64 = 500;

/// Stateless per-transaction consensus rules, checked before a block's
/// transactions touch the ledger. ONE function used by block validation and by
/// the miner's mempool selection ([`Blockchain::select_valid`]), so the two can
/// never diverge.
pub fn check_tx(tx: &Transaction) -> Result<(), ChainError> {
    match tx {
        Transaction::Register { pubkey, pow_nonce } => {
            if !verify_registration_pow(pubkey, *pow_nonce) {
                return Err(ChainError::BadRegistrationPow);
            }
        }
        // The fee floor. (The fee itself is bound into the transfer's proof, so
        // it can't be lowered after the fact; here we require it was set high
        // enough in the first place.)
        Transaction::SolventTransfer { xfer, .. } => {
            if xfer.fee < MIN_TRANSFER_FEE {
                return Err(ChainError::FeeTooLow);
            }
        }
        // Same fee floor for transparent transfers — one constant, every path,
        // never allowed to diverge (the registration-PoW lesson from SPEC.md).
        Transaction::PublicTransfer { fee, .. }
        | Transaction::Shield { fee, .. }
        | Transaction::ShieldStealth { fee, .. }
        | Transaction::AddLiquidity { fee, .. }
        | Transaction::RemoveLiquidity { fee, .. }
        | Transaction::Swap { fee, .. }
        | Transaction::CurveTrade { fee, .. }
        | Transaction::HtlcLock { fee, .. } => {
            if *fee < MIN_TRANSFER_FEE {
                return Err(ChainError::FeeTooLow);
            }
        }
        // Unshield's fee lives inside its confidential proof, bound so it can't be
        // lowered after signing; here we require it was set to at least the floor.
        Transaction::Unshield { xfer, .. } => {
            if xfer.fee < MIN_TRANSFER_FEE {
                return Err(ChainError::FeeTooLow);
            }
        }
        Transaction::DeployContract { code, .. } => {
            if code.len() > MAX_CONTRACT_CODE_BYTES {
                return Err(ChainError::OversizedContract);
            }
        }
        // Anonymous transfers: same fee floor (fee is public and bound into the
        // proof), plus a cap on the ring so verification cost per tx is bounded
        // — verify is O(N) group ops plus a Bulletproof.
        Transaction::AnonTransfer { xfer, .. } => {
            if xfer.fee < MIN_TRANSFER_FEE {
                return Err(ChainError::FeeTooLow);
            }
            if xfer.ring.len() > MAX_RING_SIZE {
                return Err(ChainError::RingTooLarge);
            }
        }
        _ => {}
    }
    Ok(())
}

/// Consensus cap on an anonymous transfer's ring (anonymity-set) size. Wire
/// decoding enforces both bounds (2..=MAX) before allocating, so this is the
/// crypto crate's constant re-exported — the two can never diverge.
pub const MAX_RING_SIZE: usize = lat_crypto::MAX_RING_SIZE;

/// Initial block reward: 50 LAT (5 decimals → 5,000,000 base units).
pub const INITIAL_BLOCK_REWARD: u64 = 5_000_000;
/// Blocks between reward halvings.
pub const HALVING_INTERVAL: u64 = 131_072;

/// The coinbase reward for a block at `height` — halves every [`HALVING_INTERVAL`]
/// blocks, reaching zero after 64 halvings (capped supply).
pub fn emission(height: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    if halvings >= 64 {
        0
    } else {
        INITIAL_BLOCK_REWARD >> halvings
    }
}

/// Proof-of-work hash — the single algorithm seam (see the module note).
/// BLAKE3 by default; RandomX with `--features randomx`.
pub fn pow_hash(bytes: &[u8]) -> [u8; 32] {
    #[cfg(feature = "randomx")]
    {
        randomx_pow::hash(bytes)
    }
    #[cfg(not(feature = "randomx"))]
    {
        *blake3::hash(bytes).as_bytes()
    }
}

/// RandomX backend (built only with `--features randomx`). A process-wide VM is
/// initialized once from a fixed key and reused for every hash, so mining (which
/// hashes per nonce) and verification share one cheap-to-call instance.
///
/// NOTE: this is a reference integration. It requires the native RandomX library
/// (CMake + a C/C++ toolchain) to compile, and has not been built/tested on the
/// development machine (no CMake). The fixed key should later rotate per epoch
/// (Monero swaps it every ~2048 blocks via a "key block").
#[cfg(feature = "randomx")]
mod randomx_pow {
    use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
    use std::cell::RefCell;

    const KEY: &[u8] = b"Latebra-RandomX-v1";

    // The RandomX VM holds raw pointers and is not Send/Sync, so it can't be a
    // global. Each thread lazily builds its own VM (light mode) and reuses it —
    // which also avoids lock contention while mining.
    thread_local! {
        static VM: RefCell<Option<RandomXVM>> = const { RefCell::new(None) };
    }

    pub fn hash(input: &[u8]) -> [u8; 32] {
        VM.with(|cell| {
            let mut slot = cell.borrow_mut();
            if slot.is_none() {
                let flags = RandomXFlag::get_recommended_flags();
                let cache = RandomXCache::new(flags, KEY).expect("init RandomX cache");
                *slot = Some(RandomXVM::new(flags, Some(cache), None).expect("init RandomX VM"));
            }
            let vm = slot.as_mut().expect("randomx vm");
            let h = vm.calculate_hash(input).expect("randomx hash");
            let mut out = [0u8; 32];
            out.copy_from_slice(&h);
            out
        })
    }
}

/// Number of leading zero bits in a 32-byte hash.
fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut count = 0;
    for &b in hash {
        if b == 0 {
            count += 8;
        } else {
            count += b.leading_zeros();
            break;
        }
    }
    count
}

/// Whether a hash satisfies `bits` leading zero bits (used for registration PoW).
pub fn meets_bits(hash: &[u8; 32], bits: u32) -> bool {
    leading_zero_bits(hash) >= bits
}

/// Top 64 bits of a hash as a big-endian integer.
fn hash_to_u64(hash: &[u8; 32]) -> u64 {
    u64::from_be_bytes(hash[0..8].try_into().expect("32 >= 8"))
}

/// Whether a hash meets block difficulty `D`: `hash_top64 <= u64::MAX / D`.
pub fn meets_difficulty(hash: &[u8; 32], difficulty: u64) -> bool {
    if difficulty <= 1 {
        return true;
    }
    hash_to_u64(hash) <= u64::MAX / difficulty
}

/// Compute the next block's difficulty from the previous one and how long the
/// last block actually took. Faster-than-target blocks raise difficulty; slower
/// ones lower it. The resulting change is clamped to within `RETARGET_CLAMP`× of
/// the current difficulty, so a single outlier block can't swing it wildly.
pub fn retarget(current: u64, actual_secs: u64) -> u64 {
    let target = TARGET_BLOCK_TIME_SECS;
    let actual = actual_secs.max(1);
    // new = current * target / actual  (actual < target => harder).
    let raw = (current as u128 * target as u128 / actual as u128) as u64;
    let lo = current / RETARGET_CLAMP;
    let hi = current.saturating_mul(RETARGET_CLAMP);
    raw.clamp(lo, hi).max(1)
}

// ---------------------------------------------------------------------------
// Registration anti-spam PoW
// ---------------------------------------------------------------------------

fn registration_pow_hash(pubkey: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"LAT-REG");
    hasher.update(pubkey);
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Verify a registration transaction solved its anti-spam PoW.
pub fn verify_registration_pow(pubkey: &[u8; 32], nonce: u64) -> bool {
    meets_bits(&registration_pow_hash(pubkey, nonce), REGISTRATION_POW_BITS)
}

/// Find a nonce that solves the registration PoW and return the ready-to-mine tx.
pub fn mine_registration(pubkey: [u8; 32]) -> Transaction {
    let mut nonce = 0u64;
    while !meets_bits(&registration_pow_hash(&pubkey, nonce), REGISTRATION_POW_BITS) {
        nonce += 1;
    }
    Transaction::Register {
        pubkey,
        pow_nonce: nonce,
    }
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct BlockHeader {
    pub prev_hash: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub tx_root: [u8; 32],
    /// Authenticated commitment to the **ledger state after this block applies**
    /// (see [`lat_state::Ledger::state_root`]). Consensus recomputes the state
    /// after applying the block and rejects it unless the roots match, so no
    /// node can serve or extend a block on top of a forged state.
    pub state_root: [u8; 32],
    /// Account that receives this block's coinbase reward. All-zero means "no
    /// reward" (used by tests/tools that mine without claiming emission).
    pub miner: [u8; 32],
    pub nonce: u64,
}

/// Fixed on-wire size of an encoded header (bytes).
pub const HEADER_LEN: usize = 32 + 8 + 8 + 32 + 32 + 32 + 8; // = 152

impl BlockHeader {
    /// Canonical encoding hashed for the block id / PoW.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_LEN);
        v.extend_from_slice(&self.prev_hash);
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(&self.timestamp.to_le_bytes());
        v.extend_from_slice(&self.tx_root);
        v.extend_from_slice(&self.state_root);
        v.extend_from_slice(&self.miner);
        v.extend_from_slice(&self.nonce.to_le_bytes());
        v
    }

    /// Block id = PoW hash of the header.
    pub fn id(&self) -> [u8; 32] {
        pow_hash(&self.encode())
    }

    /// Decode a header from its fixed [`HEADER_LEN`]-byte encoding.
    pub fn decode(b: &[u8]) -> Option<BlockHeader> {
        if b.len() != HEADER_LEN {
            return None;
        }
        Some(BlockHeader {
            prev_hash: b[0..32].try_into().ok()?,
            height: u64::from_le_bytes(b[32..40].try_into().ok()?),
            timestamp: u64::from_le_bytes(b[40..48].try_into().ok()?),
            tx_root: b[48..80].try_into().ok()?,
            state_root: b[80..112].try_into().ok()?,
            miner: b[112..144].try_into().ok()?,
            nonce: u64::from_le_bytes(b[144..152].try_into().ok()?),
        })
    }
}

pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Transaction>,
}

impl Block {
    /// Canonical wire encoding: header, then a length-prefixed list of txs.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.header.encode();
        v.extend_from_slice(&(self.txs.len() as u32).to_le_bytes());
        for tx in &self.txs {
            let e = tx.encode();
            v.extend_from_slice(&(e.len() as u32).to_le_bytes());
            v.extend_from_slice(&e);
        }
        v
    }

    /// Decode a block from its wire encoding (inverse of [`encode`](Self::encode)).
    pub fn decode(b: &[u8]) -> Option<Block> {
        let header = BlockHeader::decode(b.get(0..HEADER_LEN)?)?;
        let mut off = HEADER_LEN;
        let count = u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?) as usize;
        off += 4;
        // The count is wire-controlled: grow as we parse instead of trusting it
        // for a pre-allocation (a hostile 4-billion count must not OOM us).
        let mut txs = Vec::new();
        for _ in 0..count {
            let len = u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?) as usize;
            off += 4;
            let txb = b.get(off..off + len)?;
            off += len;
            txs.push(Transaction::decode(txb)?);
        }
        // Reject trailing garbage.
        if off != b.len() {
            return None;
        }
        Some(Block { header, txs })
    }
}

/// Commitment over a block's transactions. (A simple sequential hash for now; a
/// full Merkle tree — enabling light-client proofs — is a later refinement.)
pub fn tx_root(txs: &[Transaction]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"LAT-txroot");
    for tx in txs {
        hasher.update(blake3::hash(&tx.encode()).as_bytes());
    }
    *hasher.finalize().as_bytes()
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum ChainError {
    /// The block's parent is not in the tree (arrived before its parent).
    OrphanBlock,
    BadHeight,
    BadTxRoot,
    /// The state produced by applying the block does not match the `state_root`
    /// its header commits — the block claims a ledger state it doesn't produce.
    BadStateRoot,
    BadPow,
    BadRegistrationPow,
    Ledger(LedgerError),
    /// Failed to persist the block to the durable store.
    Storage,
    /// A transfer pays less than [`MIN_TRANSFER_FEE`].
    FeeTooLow,
    /// A contract deploy exceeds [`MAX_CONTRACT_CODE_BYTES`].
    OversizedContract,
    /// The block carries more than [`MAX_TXS_PER_BLOCK`] transactions.
    TooManyTxs,
    /// An anonymous transfer's ring exceeds [`MAX_RING_SIZE`].
    RingTooLarge,
}

/// A block in the tree, with the metadata fork-choice needs.
struct TreeNode {
    encoded: Vec<u8>,
    header: BlockHeader,
    height: u64,
    /// Difficulty this block's children must meet (retarget from this block's).
    child_difficulty: u64,
    /// Cumulative work from genesis = sum of `required` along the path.
    cum_work: u128,
}

pub struct Blockchain {
    /// All known blocks by id — the active chain plus any side branches.
    tree: HashMap<[u8; 32], TreeNode>,
    genesis_id: [u8; 32],
    /// Genesis premine, kept so state can be rebuilt from scratch on a reorg.
    premine: Vec<([u8; 32], u64)>,
    /// Genesis **public** (transparent) premine, kept for the same reason. Part
    /// of consensus genesis, so it must be replayed identically on reorg/`open`.
    public_premine: Vec<([u8; 32], u64)>,
    /// The active (heaviest-work) chain.
    active_tip: [u8; 32],
    active_height: u64,
    active_state: Ledger,
    /// Active block ids by height (`active_chain[0]` = genesis).
    active_chain: Vec<[u8; 32]>,
    /// Optional durable block store + transaction index (every accepted block,
    /// active or side branch). `None` for a purely in-memory chain.
    store: Option<ChainStore>,
    /// Where ledger snapshots are written (persistent chains only).
    snapshot_path: Option<PathBuf>,
    /// How this instance's state was booted (observability: tests assert on
    /// it, the daemon prints it).
    boot_mode: BootMode,
    /// T6 pruning: `Some(w)` sweeps unreachable trie nodes every `w` blocks,
    /// keeping the last `w` block state-roots queryable. `None` = archive mode
    /// (every historical root stays readable forever) — the default.
    prune_window: Option<u64>,
    /// T7 durable state: the shared persistent store (the same redb DB that
    /// holds the blocks) the active ledger commits into. `None` for in-memory
    /// chains. When set, every adopted flush also commits the boot anchor, so
    /// the next open can boot from records instead of replaying.
    state_base: Option<Arc<dyn KVStore>>,
    /// T14/T15 finality watermark: the highest certified block. Fork choice
    /// refuses any reorganization that does not descend from it.
    finalized: Option<(u64, [u8; 32])>,
    /// The validator set committed by each recently adopted active block
    /// (newest last, ≤ [`FINALITY_SET_WINDOW`] entries) — what certificates
    /// for those blocks are judged against. Cleared on reorg (old-branch sets
    /// don't apply to the new branch) and rebuilt as blocks are adopted.
    recent_sets: std::collections::VecDeque<(u64, ValidatorSet)>,
}

/// A validator set as `(account id, bonded stake)` pairs (see
/// `Ledger::validator_set` — stake descending, id ascending, capped).
pub type ValidatorSet = Vec<([u8; 32], u64)>;

/// How many recent blocks' validator sets are kept verifiable. Certificates
/// older than this window are ignored — finality is a recent anti-reorg
/// guarantee; deep history is secured by accumulated work.
pub const FINALITY_SET_WINDOW: usize = 64;

/// Meta key persisting the finality watermark: `height (8 LE) ‖ block id (32)
/// ‖ certificate bytes`. Local data, trusted like the node's own block DB.
const FINALITY_ANCHOR: &[u8] = b"finality/anchor";

/// How a chain instance obtained its boot-time state (fastest first).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    /// From the object records + boot anchor in the chain DB (T7): the
    /// commitment was rebuilt from the records, verified against the anchored
    /// block's PoW-bound header, then only the tail was replayed.
    Records,
    /// From the sibling `.snap` ledger-snapshot file (L8), same verification.
    Snapshot,
    /// From genesis, re-validating every block (also the fresh-chain case).
    FullReplay,
    /// T19: state records downloaded from a peer, commitment rebuilt locally
    /// and verified against the PoW-validated header chain — no historical
    /// proof re-verification.
    FastSync,
}

/// Meta key holding the boot anchor: `height (8 LE) ‖ block id (32)` — which
/// block's state the durably-committed object records represent. Written
/// atomically WITH the state (same flush batch / rehome batch), so it can
/// never disagree with the records; verified against the anchored header's
/// `state_root` on boot regardless.
const STATE_ANCHOR: &[u8] = b"state/anchor";

fn anchor_bytes(height: u64, block_id: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(40);
    v.extend_from_slice(&height.to_le_bytes());
    v.extend_from_slice(block_id);
    v
}

impl Blockchain {
    /// Create a chain from a genesis premine (transparent, public by design).
    /// `difficulty` is the starting block difficulty (see [`DEFAULT_DIFFICULTY`]).
    pub fn genesis(premine: &[([u8; 32], u64)], difficulty: u64) -> Blockchain {
        Self::genesis_with_public(premine, &[], difficulty)
    }

    /// Like [`genesis`](Self::genesis) but also seeds transparent **public**
    /// balances — the public half of Latebra's dual-state model. Both premines
    /// are part of consensus genesis and are replayed identically on reorg and
    /// on [`open`](Self::open), so a reopened chain reconstructs the same state.
    pub fn genesis_with_public(
        premine: &[([u8; 32], u64)],
        public_premine: &[([u8; 32], u64)],
        difficulty: u64,
    ) -> Blockchain {
        let difficulty = difficulty.max(1);
        let state = Self::genesis_state(premine, public_premine);

        let header = BlockHeader {
            prev_hash: [0u8; 32],
            height: 0,
            timestamp: GENESIS_TIMESTAMP,
            tx_root: [0u8; 32],
            state_root: state.state_root(),
            miner: [0u8; 32],
            nonce: 0,
        };
        let gid = header.id();
        let genesis_node = TreeNode {
            encoded: Block { header: header.clone(), txs: Vec::new() }.encode(),
            header,
            height: 0,
            child_difficulty: difficulty, // block 1 must meet the genesis difficulty
            cum_work: 0,
        };
        let mut tree = HashMap::new();
        tree.insert(gid, genesis_node);

        let mut chain = Blockchain {
            tree,
            genesis_id: gid,
            premine: premine.to_vec(),
            public_premine: public_premine.to_vec(),
            active_tip: gid,
            active_height: 0,
            active_state: state,
            active_chain: vec![gid],
            store: None,
            snapshot_path: None,
            boot_mode: BootMode::FullReplay,
            prune_window: None,
            state_base: None,
            finalized: None,
            recent_sets: std::collections::VecDeque::new(),
        };
        chain.note_validator_set();
        chain
    }

    /// Enable state-trie pruning (T6): every `window` blocks, trie nodes not
    /// reachable from the last `window` block state-roots (or the current root)
    /// are swept from the committed base. Bounds state-storage growth under
    /// churn; historical roots older than the window can no longer serve
    /// proofs. Leave unset for an archive node. `window` is clamped to ≥ 1.
    pub fn set_prune_window(&mut self, window: u64) {
        self.prune_window = Some(window.max(1));
    }

    fn genesis_state(
        premine: &[([u8; 32], u64)],
        public_premine: &[([u8; 32], u64)],
    ) -> Ledger {
        let mut state = Ledger::new();
        for (id, amount) in premine {
            let _ = state.register(*id);
            state.credit_genesis(id, *amount).expect("genesis account registered");
        }
        // Transparent public premine — spendable, plaintext public LAT.
        for (id, amount) in public_premine {
            let _ = state.register(*id);
            state.credit_public(id, lat_state::LAT_TOKEN, *amount);
        }
        // Fold the premine's trie writes into the base so the first block's
        // speculative clone starts from an empty overlay (cheap clone).
        state.flush();
        state
    }

    /// Open a persistent chain backed by an append-only block log at `path`,
    /// rebuilding the tree (and active chain) by replaying any stored blocks. The
    /// `premine` and `difficulty` MUST match the chain's original genesis values.
    pub fn open<P: AsRef<Path>>(
        path: P,
        premine: &[([u8; 32], u64)],
        difficulty: u64,
    ) -> io::Result<Blockchain> {
        Self::open_with_public(path, premine, &[], difficulty)
    }

    /// Like [`open`](Self::open) but also carries the transparent public premine.
    /// The `premine`, `public_premine`, and `difficulty` MUST match the chain's
    /// original genesis values, or the replayed state will diverge.
    ///
    /// Startup uses a **ledger snapshot** (L8) when a valid one sits next to the
    /// log: the block tree is rebuilt structurally (headers + PoW, no proof
    /// re-verification), the snapshot's ledger is checked against the
    /// `state_root` committed in its block's header, and only the blocks after
    /// it are fully replayed. Any problem with the snapshot falls back to the
    /// full from-genesis replay — the log remains the source of truth.
    pub fn open_with_public<P: AsRef<Path>>(
        path: P,
        premine: &[([u8; 32], u64)],
        public_premine: &[([u8; 32], u64)],
        difficulty: u64,
    ) -> io::Result<Blockchain> {
        let path = path.as_ref();
        // Blocks + tx index + (T7) the committed ledger state all live in one
        // redb database at `path`; the ledger snapshot is a sibling file (a
        // legacy fallback the records boot supersedes).
        let kv: Arc<dyn KVStore> = Arc::new(RedbStore::open(path).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("open block db: {e}"))
        })?);
        let block_store = ChainStore::new(Arc::clone(&kv));
        let existing = block_store.blocks_in_order();
        let snap_path = snapshot::snapshot_path(path);

        // Boot the state, fastest sound path first: (1) the object records the
        // last run committed (verified against the anchored header), (2) the
        // snapshot file, (3) full replay. Every path ends in the same state.
        let fast = Self::boot_from_records(&kv, &existing, premine, public_premine, difficulty)
            .or_else(|| {
                snapshot::read(&snap_path).and_then(|snap| {
                    Self::replay_from_snapshot(snap, &existing, premine, public_premine, difficulty)
                })
            });
        let mut chain = match fast {
            Some(chain) => chain,
            None => {
                let mut chain = Blockchain::genesis_with_public(premine, public_premine, difficulty);
                for bytes in &existing {
                    let block = Block::decode(bytes).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "corrupt block in store")
                    })?;
                    chain.apply_block(&block).map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("invalid stored block: {e:?}"))
                    })?;
                }
                chain
            }
        };

        chain.snapshot_path = Some(snap_path);
        // After a full replay of a non-trivial chain, snapshot the tip now so the
        // NEXT boot is fast even before the interval trigger fires again.
        if chain.boot_mode == BootMode::FullReplay && chain.active_height > 0 {
            chain.write_snapshot();
        }
        chain.store = Some(block_store);
        chain.state_base = Some(Arc::clone(&kv));
        if chain.boot_mode == BootMode::Records {
            // The tail replay may have advanced past the anchored height: stage
            // the tip anchor and commit it atomically with the tail's state.
            chain.active_state.stage_meta(
                STATE_ANCHOR.to_vec(),
                anchor_bytes(chain.active_height, &chain.active_tip),
            );
            chain.active_state.flush();
        } else {
            // The state was built off-base (snapshot or replay): move it onto
            // the durable base so the NEXT open boots from records.
            chain.rehome_state();
        }
        // Fast boots skip apply_block, so the set window may hold stale
        // entries: re-record at the booted tip, then restore the persisted
        // finality watermark (trusted local data, position re-checked).
        chain.recent_sets.clear();
        chain.note_validator_set();
        chain.restore_finality_anchor();
        Ok(chain)
    }

    /// T7 records boot: read the boot anchor, rebuild the ledger commitment
    /// from the object records in `kv`, and hand it to the same
    /// placement + header-root verification and tail replay the snapshot boot
    /// uses. `None` on any problem — missing anchor, malformed record, root
    /// mismatch — and the caller falls back to the next boot path.
    fn boot_from_records(
        kv: &Arc<dyn KVStore>,
        existing: &[Vec<u8>],
        premine: &[([u8; 32], u64)],
        public_premine: &[([u8; 32], u64)],
        difficulty: u64,
    ) -> Option<Blockchain> {
        let anchor = kv.get(Column::Meta, STATE_ANCHOR)?;
        if anchor.len() != 40 {
            return None;
        }
        let height = u64::from_le_bytes(anchor[..8].try_into().ok()?);
        let block_id: [u8; 32] = anchor[8..40].try_into().ok()?;
        let ledger = Ledger::from_records(Arc::clone(kv))?;
        let snap = snapshot::Snapshot { height, block_id, ledger };
        let mut chain =
            Self::replay_from_snapshot(snap, existing, premine, public_premine, difficulty)?;
        chain.boot_mode = BootMode::Records;
        Some(chain)
    }

    /// T19 fast sync: adopt a peer-supplied chain WITHOUT replaying historical
    /// transactions. `blocks` is the peer's full block list (height 1..=tip,
    /// genesis excluded); `(anchor_height, anchor_id)` names the block whose
    /// state the `records` (raw `Column::Objects` entries) represent.
    ///
    /// Trust model — nothing from the peer is believed, everything is checked:
    /// every block passes full structural + PoW validation (`insert_skeleton`:
    /// linkage, tx roots, difficulty retarget chain), the records are decoded
    /// and the commitment REBUILT from them locally (`Ledger::from_records`),
    /// and the derived root must equal the anchored header's `state_root` —
    /// the same guarantee replaying would give, minus re-running years of
    /// proofs. Blocks after the anchor are fully replayed. Faking any of it
    /// requires out-mining the whole chain.
    ///
    /// Only a FRESH chain (height 0) may fast-sync. Returns whether the chain
    /// was adopted; on `false` the chain is untouched and the caller falls
    /// back to ordinary full-validation sync.
    pub fn fast_sync_adopt(
        &mut self,
        blocks: &[Vec<u8>],
        anchor_height: u64,
        anchor_id: [u8; 32],
        records: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> bool {
        if self.active_height != 0 || anchor_height == 0 || records.is_empty() {
            return false;
        }
        // Rebuild the ledger from the raw records on a fresh in-memory base.
        let base: Arc<dyn KVStore> = Arc::new(lat_store::MemStore::new());
        {
            let mut batch = lat_store::WriteBatch::new();
            for (key, value) in records {
                batch.put(Column::Objects, key, value);
            }
            base.write(batch);
        }
        let Some(ledger) = Ledger::from_records(base) else { return false };
        let snap =
            snapshot::Snapshot { height: anchor_height, block_id: anchor_id, ledger };
        let genesis_difficulty = self.tree[&self.genesis_id].child_difficulty;
        let Some(built) = Self::replay_from_snapshot(
            snap,
            blocks,
            &self.premine,
            &self.public_premine,
            genesis_difficulty,
        ) else {
            return false;
        };
        if built.genesis_id != self.genesis_id {
            return false; // wrong network
        }
        // Verified: adopt the tree + state, keep OUR stores/config, persist
        // every block, and move the state onto the durable base (T7 anchor).
        for bytes in blocks {
            let Some(block) = Block::decode(bytes) else { return false };
            if let Some(s) = &self.store {
                s.append(&block.header.id(), bytes, &block.txs);
            }
        }
        self.tree = built.tree;
        self.active_tip = built.active_tip;
        self.active_height = built.active_height;
        self.active_chain = built.active_chain;
        self.active_state = built.active_state;
        self.recent_sets.clear();
        self.note_validator_set();
        self.rehome_state();
        self.boot_mode = BootMode::FastSync;
        true
    }

    /// Move the active state onto the durable base (with the tip anchor in the
    /// same atomic batch), replacing whatever state the base held. Called when
    /// the active ledger lives off-base: after a snapshot/full-replay boot and
    /// after a reorg (whose rebuild is in-memory). No-op for in-memory chains.
    fn rehome_state(&mut self) {
        let Some(base) = &self.state_base else { return };
        let staged =
            vec![(STATE_ANCHOR.to_vec(), anchor_bytes(self.active_height, &self.active_tip))];
        let old = std::mem::take(&mut self.active_state);
        self.active_state = old.rehome(Arc::clone(base), staged);
    }

    /// Fast boot (L8): rebuild the tree from `existing` without state, verify
    /// `snap`'s ledger against the header-committed state root of its block,
    /// then fully replay only the active-chain blocks after it. `None` on any
    /// mismatch — the caller falls back to full replay.
    fn replay_from_snapshot(
        snap: snapshot::Snapshot,
        existing: &[Vec<u8>],
        premine: &[([u8; 32], u64)],
        public_premine: &[([u8; 32], u64)],
        difficulty: u64,
    ) -> Option<Blockchain> {
        let mut chain = Blockchain::genesis_with_public(premine, public_premine, difficulty);
        // Pass 1 — structural skeleton: rebuild the block tree and run the same
        // fork-choice sequence as the original acceptance, but skip transaction
        // application entirely (every block in our own log was fully validated
        // when it was first accepted; see `persist` call sites).
        for bytes in existing {
            let block = Block::decode(bytes)?;
            chain.insert_skeleton(block, bytes.clone()).ok()?;
        }
        // The snapshot must sit on the resulting ACTIVE chain at its claimed
        // height — a snapshot from a since-reorged-away branch is useless.
        if chain.active_chain.get(snap.height as usize) != Some(&snap.block_id) {
            return None;
        }
        // The decoded ledger must commit exactly the state root that block's
        // PoW-bound header commits. This is what makes the snapshot trustless:
        // it can only ever reproduce a state the chain already agreed on.
        if snap.ledger.state_root() != chain.tree.get(&snap.block_id)?.header.state_root {
            return None;
        }
        // Pass 2 — full replay of only the tail (same checks as apply_block).
        let mut state = snap.ledger;
        for id in &chain.active_chain[snap.height as usize + 1..] {
            let block = Block::decode(&chain.tree.get(id)?.encoded)?;
            for tx in &block.txs {
                check_tx(tx).ok()?;
            }
            apply_block_state(&mut state, &block).ok()?;
        }
        chain.active_state = state;
        chain.boot_mode = BootMode::Snapshot;
        Some(chain)
    }

    /// Insert an already-validated block into the tree WITHOUT applying its
    /// transactions — the structural half of [`apply_block`] (parent linkage,
    /// height, tx root, PoW, fork choice). Sound only where skipped tx
    /// application is re-checked elsewhere: replaying our own log (blocks were
    /// fully validated when first accepted) and T19 fast sync (the anchor's
    /// state is verified against the header-committed root, and the tail after
    /// it is fully replayed).
    fn insert_skeleton(&mut self, block: Block, encoded: Vec<u8>) -> Result<(), ChainError> {
        let id = block.header.id();
        if self.tree.contains_key(&id) {
            return Ok(());
        }
        // Same guard as apply_block, and for the same reason: reject before
        // tx_root walks every transaction. Both paths need it — a skeleton
        // insert is reachable from a peer's block just as apply_block is.
        if block.txs.len() > MAX_TXS_PER_BLOCK {
            return Err(ChainError::TooManyTxs);
        }
        let parent = self
            .tree
            .get(&block.header.prev_hash)
            .ok_or(ChainError::OrphanBlock)?;
        if block.header.height != parent.height + 1 {
            return Err(ChainError::BadHeight);
        }
        if block.header.tx_root != tx_root(&block.txs) {
            return Err(ChainError::BadTxRoot);
        }
        let required = parent.child_difficulty;
        if !meets_difficulty(&id, required) {
            return Err(ChainError::BadPow);
        }
        let parent_ts = parent.header.timestamp;
        let cum_work = parent.cum_work + required as u128;
        let child_difficulty = retarget(required, block.header.timestamp.saturating_sub(parent_ts));
        let extends_tip = block.header.prev_hash == self.active_tip;
        let active_cum = self.tree[&self.active_tip].cum_work;
        self.tree.insert(
            id,
            TreeNode { encoded, header: block.header.clone(), height: block.header.height, child_difficulty, cum_work },
        );
        // Same fork-choice rules as apply_block, so the replayed active chain
        // lands exactly where the original acceptance sequence left it.
        if extends_tip {
            self.active_tip = id;
            self.active_height = block.header.height;
            self.active_chain.push(id);
        } else if cum_work > active_cum {
            self.active_chain = self.path_to(&id);
            self.active_tip = id;
            self.active_height = block.header.height;
        }
        Ok(())
    }

    /// Best-effort: persist a ledger snapshot at the current active tip. Failure
    /// is deliberately swallowed — the block log stays the source of truth and a
    /// missing snapshot only costs the next boot a full replay.
    pub fn write_snapshot(&self) {
        if let Some(p) = &self.snapshot_path {
            let _ = snapshot::write(p, self.active_height, &self.active_tip, &self.active_state);
        }
    }

    /// Whether this instance booted from a snapshot — the durable records (T7)
    /// or the snapshot file (L8) — rather than a full replay.
    pub fn booted_from_snapshot(&self) -> bool {
        self.boot_mode != BootMode::FullReplay
    }

    /// How this instance's boot-time state was obtained.
    pub fn boot_mode(&self) -> BootMode {
        self.boot_mode
    }

    /// The state root of the active ledger (what the next mined block commits).
    pub fn state_root(&self) -> [u8; 32] {
        self.active_state.state_root()
    }

    /// The difficulty the next block on the active tip must meet.
    pub fn difficulty(&self) -> u64 {
        self.tree[&self.active_tip].child_difficulty
    }

    /// Encoded block at `height` on the ACTIVE chain (0 = genesis). `None` if
    /// beyond the tip.
    pub fn block_bytes(&self, height: u64) -> Option<&[u8]> {
        let id = self.active_chain.get(height as usize)?;
        Some(self.tree.get(id)?.encoded.as_slice())
    }

    /// Whether a block id is known (active chain OR a side branch).
    pub fn has_block(&self, id: &[u8; 32]) -> bool {
        self.tree.contains_key(id)
    }

    /// T19 fast-sync serving side: the active tip's `(height, block id)` anchor
    /// plus every object record of the state AT that tip, key-ordered. A
    /// syncing peer rebuilds the commitment from the records and verifies the
    /// derived root against this anchor block's header — so the whole payload
    /// is self-authenticating and needs no extra digests. `None` at height 0
    /// (a fresh chain has nothing worth fast-syncing).
    ///
    /// Capture this under one node lock (records and anchor must describe the
    /// SAME tip) and serve chunks from the captured copy.
    pub fn state_sync_payload(&self) -> Option<(u64, [u8; 32], Vec<(Vec<u8>, Vec<u8>)>)> {
        if self.active_height == 0 {
            return None;
        }
        Some((self.active_height, self.active_tip, self.active_state.object_records()))
    }

    /// A block locator: ids of the ACTIVE chain, newest first, exponentially
    /// spaced (tip, tip−1, tip−2, tip−4, …, genesis). A peer scans it for the
    /// most recent block it shares with us — the common ancestor two forked
    /// nodes must sync from. Always ends at genesis, so two nodes with the same
    /// genesis always find *some* common point.
    pub fn locator(&self) -> Vec<[u8; 32]> {
        let mut ids = Vec::new();
        let tip = self.active_height;
        let mut back: u64 = 0;
        let mut step: u64 = 1;
        loop {
            let h = tip.saturating_sub(back);
            if let Some(id) = self.active_chain.get(h as usize) {
                ids.push(*id);
            }
            if h == 0 {
                break;
            }
            back += step;
            if ids.len() >= 8 {
                step *= 2; // dense near the tip, sparse toward genesis
            }
        }
        ids
    }

    /// Height of `id` on the ACTIVE chain (`None` if unknown or side-branch).
    pub fn active_height_of(&self, id: &[u8; 32]) -> Option<u64> {
        let h = self.tree.get(id)?.height;
        (self.active_chain.get(h as usize) == Some(id)).then_some(h)
    }

    /// The active-chain block id at `height`, if the chain reaches it.
    pub fn active_id_at(&self, height: u64) -> Option<[u8; 32]> {
        self.active_chain.get(height as usize).copied()
    }

    /// An account's bonded validator stake (0 if none) — T13.
    pub fn staked(&self, id: &[u8; 32]) -> u64 {
        self.active_state.staked(id)
    }

    /// An account's unbonding entries as `(amount, release height)` — T13.
    pub fn unbonding(&self, id: &[u8; 32]) -> Vec<(u64, u64)> {
        self.active_state.unbonding(id)
    }

    pub fn height(&self) -> u64 {
        self.active_height
    }

    pub fn tip(&self) -> [u8; 32] {
        self.active_tip
    }

    /// The genesis block id — the network's fingerprint. Two nodes agree on a
    /// chain only if their genesis ids match (same premine + difficulty), so the
    /// P2P handshake compares this to refuse cross-network peers.
    pub fn genesis_id(&self) -> [u8; 32] {
        self.genesis_id
    }

    pub fn is_registered(&self, id: &[u8; 32]) -> bool {
        self.active_state.is_registered(id)
    }

    pub fn balance(&self, id: &[u8; 32], token: u32) -> Option<Ciphertext> {
        self.active_state.balance(id, token)
    }

    /// Pending (received, not yet rolled-over) encrypted balance of `token`.
    pub fn pending(&self, id: &[u8; 32], token: u32) -> Option<Ciphertext> {
        self.active_state.pending(id, token)
    }

    /// The account's current spend nonce (the next outgoing transfer must use it).
    pub fn nonce(&self, id: &[u8; 32]) -> Option<u64> {
        self.active_state.nonce(id)
    }

    /// The transparent (plaintext) public balance of `token` held by `id`.
    pub fn public_balance(&self, id: &[u8; 32], token: u32) -> Option<u64> {
        self.active_state.public_balance(id, token)
    }

    /// The DEX pool for `token` on the active chain, if one exists.
    pub fn pool(&self, token: u32) -> Option<lat_state::Pool> {
        self.active_state.pool(token)
    }

    /// Every live DEX pool on the active chain.
    pub fn pools(&self) -> Vec<lat_state::Pool> {
        self.active_state.pools()
    }

    /// A token's native bonding curve, or `None` if none has opened.
    pub fn curve(&self, token: u32) -> Option<lat_state::CurvePool> {
        self.active_state.curve(token)
    }

    /// Every live bonding curve (launchpad listing).
    pub fn curves(&self) -> Vec<lat_state::CurvePool> {
        self.active_state.curves()
    }

    /// A provider's LP shares in the pool for `token` (0 if none).
    pub fn lp_shares(&self, token: u32, provider: &[u8; 32]) -> u64 {
        self.active_state.lp_shares(token, provider)
    }

    /// An open HTLC by id on the active chain.
    pub fn htlc(&self, id: &[u8; 32]) -> Option<lat_state::Htlc> {
        self.active_state.htlc(id)
    }

    /// Every open HTLC as `(id, lock)` on the active chain.
    pub fn htlcs(&self) -> Vec<([u8; 32], lat_state::Htlc)> {
        self.active_state.htlcs()
    }

    /// Whether an anonymous-spend nullifier is already spent on the active chain.
    pub fn nullifier_seen(&self, nullifier: &[u8; 32]) -> bool {
        self.active_state.nullifier_seen(nullifier)
    }

    /// The anonymous-transfer decoy pool on the active chain (see
    /// [`lat_state::Ledger::ring_candidates`]).
    pub fn ring_candidates(&self, token: u32) -> Vec<([u8; 32], Ciphertext)> {
        self.active_state.ring_candidates(token)
    }

    /// Read a storage slot of a deployed contract on the active chain (0 if the
    /// contract or slot is unset). Lets a client read on-chain contract state —
    /// e.g. a bonding curve's reserves — over RPC.
    pub fn contract_storage(&self, contract: &[u8; 32], key: u64) -> u64 {
        self.active_state.contract_storage(contract, key)
    }

    /// Whether a contract is deployed at `id` on the active chain.
    pub fn has_contract(&self, id: &[u8; 32]) -> bool {
        self.active_state.has_contract(id)
    }

    /// Look up a registered token's metadata by ticker.
    pub fn token(&self, ticker: &str) -> Option<lat_state::TokenMeta> {
        self.active_state.token(ticker)
    }

    /// Filter `txs` down to those includable in the next block on the active
    /// tip: the per-tx consensus rules pass AND they apply cleanly, in order, to
    /// a copy of the current state. The miner uses this so one bad mempool tx
    /// (stale nonce, duplicate ticker, bad signature, ...) is dropped instead of
    /// invalidating the whole mined block.
    pub fn select_valid(&self, txs: Vec<Transaction>) -> Vec<Transaction> {
        let mut state = self.active_state.clone();
        let next_height = self.active_height + 1;
        txs.into_iter()
            .filter(|tx| check_tx(tx).is_ok() && state.apply_at(tx, next_height).is_ok())
            .collect()
    }

    /// Mine a new block on top of the active tip (no coinbase reward claimed).
    pub fn mine(&self, txs: Vec<Transaction>) -> Block {
        self.mine_with_reward([0u8; 32], txs)
    }

    /// Mine a new block, crediting this block's coinbase reward to `miner`.
    pub fn mine_with_reward(&self, miner: [u8; 32], txs: Vec<Transaction>) -> Block {
        let difficulty = self.difficulty();
        let height = self.active_height + 1;
        // Commit the state that results from applying this block's txs + coinbase.
        // (Callers pre-filter via `select_valid`, so this applies cleanly; if a
        // caller mines invalid txs anyway the resulting root simply won't match
        // and `apply_block` will reject it.)
        let mut post = self.active_state.clone();
        let _ = apply_txs_and_reward(&mut post, &txs, miner, height);
        let mut header = BlockHeader {
            prev_hash: self.active_tip,
            height,
            timestamp: now(),
            tx_root: tx_root(&txs),
            state_root: post.state_root(),
            miner,
            nonce: 0,
        };
        while !meets_difficulty(&header.id(), difficulty) {
            header.nonce += 1;
        }
        Block { header, txs }
    }

    /// Add a block to the tree, validating it and reorganizing to the heaviest
    /// branch if this block (or its branch) now has the most cumulative work.
    ///
    /// - A block extending the active tip is applied incrementally (the common,
    ///   cheap case).
    /// - A block that makes a *different* branch heaviest triggers a **reorg**:
    ///   state is rebuilt from genesis along the new branch, re-validating its
    ///   transactions; if any is invalid the block is rejected.
    /// - A valid-but-not-heaviest block is kept as a side branch (it may become
    ///   active once its branch is extended).
    pub fn apply_block(&mut self, block: &Block) -> Result<(), ChainError> {
        let id = block.header.id();
        if self.tree.contains_key(&id) {
            return Ok(()); // already known — idempotent
        }

        // --- structural + PoW validation against the parent ---
        // Cheapest rejection first: bail before tx_root, which hashes every
        // transaction in the block and is exactly the work an oversized block is
        // trying to make us do.
        if block.txs.len() > MAX_TXS_PER_BLOCK {
            return Err(ChainError::TooManyTxs);
        }
        let parent = self
            .tree
            .get(&block.header.prev_hash)
            .ok_or(ChainError::OrphanBlock)?;
        if block.header.height != parent.height + 1 {
            return Err(ChainError::BadHeight);
        }
        if block.header.tx_root != tx_root(&block.txs) {
            return Err(ChainError::BadTxRoot);
        }
        let required = parent.child_difficulty;
        if !meets_difficulty(&id, required) {
            return Err(ChainError::BadPow);
        }
        for tx in &block.txs {
            check_tx(tx)?;
        }

        let parent_ts = parent.header.timestamp;
        let cum_work = parent.cum_work + required as u128;
        let child_difficulty = retarget(required, block.header.timestamp.saturating_sub(parent_ts));
        let encoded = block.encode();
        let node = TreeNode {
            encoded: encoded.clone(),
            header: block.header.clone(),
            height: block.header.height,
            child_difficulty,
            cum_work,
        };

        let active_cum = self.tree[&self.active_tip].cum_work;
        let extends_tip = block.header.prev_hash == self.active_tip;

        if extends_tip {
            // Cheap path: a block on the tip is always heavier; apply incrementally.
            let mut next = self.active_state.clone();
            apply_block_state(&mut next, block)?;
            self.persist(block, &encoded)?;
            self.tree.insert(id, node);
            self.active_state = next;
            self.active_tip = id;
            self.active_height = block.header.height;
            self.active_chain.push(id);
            self.note_validator_set();
            // Commit this block's trie writes into the overlay base, so the next
            // block's clone starts from an empty overlay (keeps clones cheap).
            // On a durable base the boot anchor rides the same atomic batch, so
            // the records on disk always describe exactly the anchored block.
            if self.state_base.is_some() {
                self.active_state.stage_meta(
                    STATE_ANCHOR.to_vec(),
                    anchor_bytes(block.header.height, &id),
                );
            }
            self.active_state.flush();
            self.maybe_prune();
            self.maybe_snapshot();
            Ok(())
        } else if cum_work > active_cum {
            // Reorg: this competing branch is now heaviest. Rebuild + revalidate.
            self.tree.insert(id, node);
            let path = self.path_to(&id);
            // T15: finality overrides work. A branch that does not descend from
            // the finalized block cannot become active, however heavy — keep it
            // as a side branch (same handling as valid-but-not-heaviest).
            if let Some((fh, fid)) = self.finalized {
                if path.get(fh as usize) != Some(&fid) {
                    self.persist(block, &encoded)?;
                    return Ok(());
                }
            }
            match self.rebuild_state(&path) {
                Ok(new_state) => {
                    if let Err(e) = self.persist(block, &encoded) {
                        self.tree.remove(&id);
                        return Err(e);
                    }
                    self.active_state = new_state;
                    self.active_tip = id;
                    self.active_height = block.header.height;
                    self.active_chain = path;
                    // The old branch's recorded validator sets don't describe
                    // the new branch — drop them and record the new tip's.
                    self.recent_sets.clear();
                    self.note_validator_set();
                    // The rebuild is in-memory: adopt it onto the durable base
                    // (old branch's state out, new branch's in, one atomic batch).
                    self.rehome_state();
                    self.maybe_prune();
                    self.maybe_snapshot();
                    Ok(())
                }
                Err(e) => {
                    self.tree.remove(&id);
                    Err(e)
                }
            }
        } else {
            // Valid but not heaviest — keep as a side branch for possible later use.
            self.persist(block, &encoded)?;
            self.tree.insert(id, node);
            Ok(())
        }
    }

    fn persist(&mut self, block: &Block, encoded: &[u8]) -> Result<(), ChainError> {
        if let Some(s) = &self.store {
            s.append(&block.header.id(), encoded, &block.txs);
        }
        Ok(())
    }

    /// Locate a transaction on the persistent chain by its [`tx_hash`]: the id of
    /// the block containing it and its index within that block. `None` if unknown
    /// (or the chain has no durable store). Backs explorer / RPC tx lookups.
    pub fn tx_location(&self, tx_hash: &[u8; 32]) -> Option<([u8; 32], u32)> {
        self.store.as_ref()?.tx_location(tx_hash)
    }

    /// The encoded block with the given id, from the in-memory tree (any known
    /// block, active chain or side branch).
    pub fn block_by_id(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        self.tree.get(id).map(|n| n.encoded.clone())
    }

    // --- finality (T14/T15) --------------------------------------------------

    /// Record the validator set the just-adopted active block commits (from
    /// the active ledger — T13), so certificates for it can be judged later.
    fn note_validator_set(&mut self) {
        let set = self.active_state.validator_set();
        self.recent_sets.push_back((self.active_height, set));
        while self.recent_sets.len() > FINALITY_SET_WINDOW {
            self.recent_sets.pop_front();
        }
    }

    /// The validator set committed by the active block at `height`, if it is
    /// still inside the recent window.
    pub fn validator_set_at(&self, height: u64) -> Option<&[([u8; 32], u64)]> {
        self.recent_sets
            .iter()
            .rev()
            .find(|(h, _)| *h == height)
            .map(|(_, set)| set.as_slice())
    }

    /// The finality watermark, if any block has been certified.
    pub fn finalized(&self) -> Option<(u64, [u8; 32])> {
        self.finalized
    }

    /// Adopt a finality certificate: the block must sit on the ACTIVE chain at
    /// its claimed height, be newer than the current watermark, and carry
    /// more than 2/3 of the stake of the validator set that block itself
    /// commits (see the `finality` module). Returns whether the watermark
    /// advanced. The watermark persists (with its certificate) in the chain DB.
    pub fn try_finalize(&mut self, cert: &Certificate) -> bool {
        if let Some((fh, _)) = self.finalized {
            if cert.height <= fh {
                return false;
            }
        }
        if self.active_chain.get(cert.height as usize) != Some(&cert.block_id) {
            return false;
        }
        let Some(set) = self.validator_set_at(cert.height) else { return false };
        if !cert.verify(set) {
            return false;
        }
        self.finalized = Some((cert.height, cert.block_id));
        if let Some(base) = &self.state_base {
            let mut value = Vec::with_capacity(40 + cert.votes.len() * 96);
            value.extend_from_slice(&cert.height.to_le_bytes());
            value.extend_from_slice(&cert.block_id);
            value.extend_from_slice(&cert.encode());
            let mut batch = lat_store::WriteBatch::new();
            batch.put(Column::Meta, FINALITY_ANCHOR.to_vec(), value);
            base.write(batch);
        }
        true
    }

    /// Restore the persisted finality watermark (boot): trusted like the rest
    /// of the node's own DB, but only adopted if the anchored block is still
    /// on the active chain at its height.
    fn restore_finality_anchor(&mut self) {
        let Some(base) = &self.state_base else { return };
        let Some(bytes) = base.get(Column::Meta, FINALITY_ANCHOR) else { return };
        let (Some(h), Some(id)) = (
            bytes.get(0..8).and_then(|b| b.try_into().ok().map(u64::from_le_bytes)),
            bytes.get(8..40).and_then(|b| <[u8; 32]>::try_from(b).ok()),
        ) else {
            return;
        };
        if self.active_chain.get(h as usize) == Some(&id) {
            self.finalized = Some((h, id));
        }
    }

    /// Sweep unreachable trie nodes every `prune_window` blocks (no-op in
    /// archive mode). Retains the state roots of the last `window` active
    /// blocks plus the current root, so proofs within the window keep working
    /// and any speculative clone forked from the adopted tip stays valid.
    fn maybe_prune(&self) {
        let Some(window) = self.prune_window else { return };
        if self.active_height == 0 || !self.active_height.is_multiple_of(window) {
            return;
        }
        let retain: Vec<[u8; 32]> = self
            .active_chain
            .iter()
            .rev()
            .take(window as usize + 1)
            .filter_map(|id| self.tree.get(id).map(|n| n.header.state_root))
            .collect();
        self.active_state.prune_history(&retain);
    }

    /// Snapshot the active state every [`SNAPSHOT_INTERVAL`] blocks (persistent
    /// chains only — an in-memory chain has nowhere to put one).
    fn maybe_snapshot(&self) {
        if self.snapshot_path.is_some() && self.active_height.is_multiple_of(SNAPSHOT_INTERVAL) {
            self.write_snapshot();
        }
    }

    /// Ids from genesis to `id` (inclusive), genesis first.
    fn path_to(&self, id: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut path = Vec::new();
        let mut cur = *id;
        loop {
            path.push(cur);
            if cur == self.genesis_id {
                break;
            }
            match self.tree.get(&cur) {
                Some(node) => cur = node.header.prev_hash,
                None => break,
            }
        }
        path.reverse();
        path
    }

    /// Rebuild ledger state by replaying `path` (genesis first), re-validating
    /// every transaction. Errors if any block on the path has an invalid tx.
    fn rebuild_state(&self, path: &[[u8; 32]]) -> Result<Ledger, ChainError> {
        let mut state = Self::genesis_state(&self.premine, &self.public_premine);
        for id in path {
            if *id == self.genesis_id {
                continue;
            }
            let node = self.tree.get(id).ok_or(ChainError::OrphanBlock)?;
            let block = Block::decode(&node.encoded).ok_or(ChainError::BadTxRoot)?;
            apply_block_state(&mut state, &block)?;
        }
        state.flush(); // collapse the replay's writes into the overlay base
        Ok(state)
    }
}

/// Apply a block's full state transition (txs + coinbase) **and verify** the
/// resulting state matches the block's committed `state_root`. Used by both the
/// incremental tip-extension and reorg-rebuild paths, so neither can adopt a
/// block whose header commits a state different from the one it actually
/// produces.
fn apply_block_state(state: &mut Ledger, block: &Block) -> Result<(), ChainError> {
    apply_txs_and_reward(state, &block.txs, block.header.miner, block.header.height)?;
    if state.state_root() != block.header.state_root {
        return Err(ChainError::BadStateRoot);
    }
    Ok(())
}

/// Apply a block's transactions then credit the miner its coinbase + fees. This
/// is the state transition *without* the state-root check, so the miner can use
/// it to compute the root it must commit (see [`Blockchain::mine_with_reward`]).
fn apply_txs_and_reward(
    state: &mut Ledger,
    txs: &[Transaction],
    miner: [u8; 32],
    height: u64,
) -> Result<(), ChainError> {
    // Apply the block's transactions — the transparent lane runs across all
    // cores (T8), with a result bit-identical to the sequential order.
    lat_state::apply_block_parallel(state, txs, height).map_err(ChainError::Ledger)?;
    // Collect the fees each transaction pays (per token) from the transaction
    // data alone. Fees are split by state: confidential-transfer fees are paid
    // into the miner's *encrypted* balance, public-transfer fees into the
    // miner's *public* balance.
    let mut fees: Vec<(u32, u64)> = Vec::new();
    let mut public_fees: Vec<(u32, u64)> = Vec::new();
    for tx in txs {
        match tx {
            // Confidential-side fees (paid from an encrypted balance) → miner's
            // encrypted balance. Unshield's fee is debited from the private side,
            // so it belongs here too.
            Transaction::SolventTransfer { token, xfer } if xfer.fee > 0 => {
                fees.push((*token, xfer.fee));
            }
            Transaction::Unshield { token, xfer, .. } if xfer.fee > 0 => {
                fees.push((*token, xfer.fee));
            }
            // The anonymous debit (amount + fee) left a hidden ring member's
            // ENCRYPTED balance; the public fee half goes to the miner's
            // encrypted balance like every confidential-side fee.
            Transaction::AnonTransfer { token, xfer } if xfer.fee > 0 => {
                fees.push((*token, xfer.fee));
            }
            // Transparent-side fees (paid from a public balance) → miner's public
            // balance. Shield's fee is debited from the public side.
            Transaction::PublicTransfer { token, fee, .. } if *fee > 0 => {
                public_fees.push((*token, *fee));
            }
            Transaction::Shield { token, fee, .. } if *fee > 0 => {
                public_fees.push((*token, *fee));
            }
            Transaction::ShieldStealth { token, fee, .. } if *fee > 0 => {
                public_fees.push((*token, *fee));
            }
            // DEX + HTLC fees are always denominated in native LAT and debited
            // from the signer's public LAT balance in the ledger's apply arm.
            Transaction::AddLiquidity { fee, .. }
            | Transaction::RemoveLiquidity { fee, .. }
            | Transaction::Swap { fee, .. }
            | Transaction::CurveTrade { fee, .. }
            | Transaction::HtlcLock { fee, .. }
                if *fee > 0 =>
            {
                public_fees.push((lat_state::LAT_TOKEN, *fee));
            }
            // Flat-fee, fee-less-field types (C-1): the ledger debited
            // `FLAT_TX_FEE` in LAT from the signer's public balance, so the
            // miner is credited the same into its public balance.
            Transaction::CreateToken { .. }
            | Transaction::DeployContract { .. }
            | Transaction::CallContract { .. } => {
                public_fees.push((lat_state::LAT_TOKEN, lat_state::FLAT_TX_FEE));
            }
            _ => {}
        }
    }
    // The miner earns the coinbase (native LAT) plus every collected fee.
    if miner != [0u8; 32] {
        state.reward_miner(&miner, lat_state::LAT_TOKEN, emission(height));
        for (token, fee) in fees {
            state.reward_miner(&miner, token, fee);
        }
        for (token, fee) in public_fees {
            state.credit_public(&miner, token, fee);
        }
    }
    Ok(())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(GENESIS_TIMESTAMP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lat_crypto::{SecretKey, SolventTransfer};
    use rand::rngs::OsRng;

    #[test]
    fn mine_and_apply_solvent_transfer() {
        let mut rng = OsRng;
        let genesis_sk = SecretKey::random(&mut rng);
        let receiver_sk = SecretKey::random(&mut rng);
        let genesis_id = genesis_sk.public_key().to_bytes();
        let receiver_id = receiver_sk.public_key().to_bytes();
        let lat = lat_state::LAT_TOKEN;

        let mut chain = Blockchain::genesis(&[(genesis_id, 1_000_000)], DEFAULT_DIFFICULTY);

        // Block 1: register the receiver.
        let block1 = chain.mine(vec![mine_registration(receiver_id)]);
        chain.apply_block(&block1).unwrap();
        assert!(chain.is_registered(&receiver_id));

        // Block 2: genesis sends 250,000 (solvency-proven). It lands in pending.
        let bal = chain.balance(&genesis_id, lat).unwrap();
        let xfer = SolventTransfer::create(&genesis_sk, &receiver_sk.public_key(), lat_state::LAT_TOKEN, 250_000, MIN_TRANSFER_FEE, 1_000_000, &bal, 0, &mut rng).unwrap();
        let block2 = chain.mine(vec![Transaction::SolventTransfer { token: lat, xfer }]);
        chain.apply_block(&block2).unwrap();
        assert_eq!(chain.height(), 2);
        assert_eq!(
            genesis_sk.decrypt(&chain.balance(&genesis_id, lat).unwrap(), 24),
            Some(750_000 - MIN_TRANSFER_FEE)
        );
        assert_eq!(receiver_sk.decrypt(&chain.pending(&receiver_id, lat).unwrap(), 24), Some(250_000));

        // Block 3: receiver rolls pending into spendable (signed, at nonce 0).
        let mut rollover = Transaction::Rollover { account: receiver_id, nonce: 0, sig: [0u8; 64] };
        let sig = receiver_sk.sign(&rollover.signing_bytes()).to_bytes();
        if let Transaction::Rollover { sig: s, .. } = &mut rollover {
            *s = sig;
        }
        let block3 = chain.mine(vec![rollover]);
        chain.apply_block(&block3).unwrap();
        assert_eq!(receiver_sk.decrypt(&chain.balance(&receiver_id, lat).unwrap(), 24), Some(250_000));
    }

    #[test]
    fn mine_and_apply_anonymous_transfer_end_to_end() {
        let mut rng = OsRng;
        let lat = lat_state::LAT_TOKEN;
        let sks: Vec<SecretKey> = (0..4).map(|_| SecretKey::random(&mut rng)).collect();
        let ids: Vec<[u8; 32]> = sks.iter().map(|s| s.public_key().to_bytes()).collect();
        let ring: Vec<_> = sks.iter().map(|s| s.public_key()).collect();
        let premine: Vec<_> = ids.iter().map(|id| (*id, 1_000_000u64)).collect();
        let receiver_sk = SecretKey::random(&mut rng);
        let miner_sk = SecretKey::random(&mut rng);
        let miner_id = miner_sk.public_key().to_bytes();

        let mut chain = Blockchain::genesis(&premine, DEFAULT_DIFFICULTY);

        // Block 1 (epoch 0): member 2 spends anonymously to a stealth receiver.
        let balances: Vec<_> = ids.iter().map(|id| chain.balance(id, lat).unwrap()).collect();
        let xfer = lat_crypto::AnonTransfer::create(
            &ring, &balances, &sks[2], 2, 1_000_000, &receiver_sk.public_key(),
            lat, 40_000, MIN_TRANSFER_FEE, lat_state::epoch_of(1), &mut rng,
        )
        .unwrap();
        let nullifier = xfer.nullifier();
        let output = xfer.output;
        let tx = Transaction::AnonTransfer { token: lat, xfer };
        assert!(check_tx(&tx).is_ok());
        let block1 = chain.mine_with_reward(miner_id, vec![tx.clone()]);
        chain.apply_block(&block1).unwrap();

        // Hidden sender debited, decoys intact, stealth receiver credited.
        assert_eq!(sks[2].decrypt(&chain.balance(&ids[2], lat).unwrap(), 24), Some(960_000 - MIN_TRANSFER_FEE));
        for i in [0, 1, 3] {
            assert_eq!(sks[i].decrypt(&chain.balance(&ids[i], lat).unwrap(), 24), Some(1_000_000));
        }
        let spend = lat_crypto::stealth_receive(&receiver_sk, &output.ephemeral, &output.one_time).unwrap();
        let ot = spend.public_key().to_bytes();
        assert_eq!(spend.decrypt(&chain.pending(&ot, lat).unwrap(), 24), Some(40_000));

        // The miner earned coinbase + the anonymous fee into its encrypted balance.
        assert_eq!(
            miner_sk.decrypt(&chain.balance(&miner_id, lat).unwrap(), 24),
            Some(emission(1) + MIN_TRANSFER_FEE)
        );

        // Replaying the same anonymous spend in the same epoch is consensus-invalid.
        let replay_block = chain.mine(vec![tx.clone()]);
        assert_eq!(
            chain.apply_block(&replay_block),
            Err(ChainError::Ledger(lat_state::LedgerError::NullifierSeen))
        );
        // ... and select_valid (the miner's filter) silently drops it.
        assert!(chain.select_valid(vec![tx]).is_empty());
        assert!(chain.nullifier_seen(&nullifier));

        // A proof built for a future epoch is rejected as WrongEpoch.
        let balances2: Vec<_> = ids.iter().map(|id| chain.balance(id, lat).unwrap()).collect();
        let bal0 = sks[0].decrypt(&balances2[0], 24).unwrap();
        let future = lat_crypto::AnonTransfer::create(
            &ring, &balances2, &sks[0], 0, bal0, &receiver_sk.public_key(),
            lat, 1_000, MIN_TRANSFER_FEE, lat_state::epoch_of(2) + 1, &mut rng,
        )
        .unwrap();
        let future_block = chain.mine(vec![Transaction::AnonTransfer { token: lat, xfer: future }]);
        assert_eq!(
            chain.apply_block(&future_block),
            Err(ChainError::Ledger(lat_state::LedgerError::WrongEpoch))
        );
        assert!(chain.height() == 1, "invalid blocks never advanced the tip");
    }

    #[test]
    fn consensus_rejects_underpaying_transfer() {
        let mut rng = OsRng;
        let genesis_sk = SecretKey::random(&mut rng);
        let genesis_id = genesis_sk.public_key().to_bytes();
        let receiver_pk = SecretKey::random(&mut rng).public_key();
        let mut chain = Blockchain::genesis(&[(genesis_id, 1_000_000)], DEFAULT_DIFFICULTY);

        let bal = chain.balance(&genesis_id, lat_state::LAT_TOKEN).unwrap();
        let xfer = SolventTransfer::create(
            &genesis_sk, &receiver_pk, lat_state::LAT_TOKEN, 100, MIN_TRANSFER_FEE - 1, 1_000_000, &bal, 0, &mut rng,
        )
        .unwrap();
        let block = chain.mine(vec![Transaction::SolventTransfer { token: lat_state::LAT_TOKEN, xfer }]);
        assert_eq!(chain.apply_block(&block), Err(ChainError::FeeTooLow));
    }

    #[test]
    fn miner_collects_the_transfer_fee() {
        let mut rng = OsRng;
        let lat = lat_state::LAT_TOKEN;
        let genesis_sk = SecretKey::random(&mut rng);
        let genesis_id = genesis_sk.public_key().to_bytes();
        let receiver_pk = SecretKey::random(&mut rng).public_key();
        let miner_sk = SecretKey::random(&mut rng);
        let miner_id = miner_sk.public_key().to_bytes();
        let mut chain = Blockchain::genesis(&[(genesis_id, 1_000_000)], DEFAULT_DIFFICULTY);

        // Block 1: register the receiver so the transfer can land.
        let block1 = chain.mine(vec![mine_registration(receiver_pk.to_bytes())]);
        chain.apply_block(&block1).unwrap();

        let fee = MIN_TRANSFER_FEE * 3; // overpaying is allowed — a fee market
        let bal = chain.balance(&genesis_id, lat).unwrap();
        let xfer =
            SolventTransfer::create(&genesis_sk, &receiver_pk, lat_state::LAT_TOKEN, 100, fee, 1_000_000, &bal, 0, &mut rng).unwrap();
        let block2 = chain.mine_with_reward(miner_id, vec![Transaction::SolventTransfer { token: lat, xfer }]);
        chain.apply_block(&block2).unwrap();

        // The miner holds the block-2 emission plus the transfer's fee.
        assert_eq!(
            miner_sk.decrypt(&chain.balance(&miner_id, lat).unwrap(), 24),
            Some(emission(2) + fee)
        );
    }

    #[test]
    fn block_wire_roundtrip() {
        let mut rng = OsRng;
        let genesis_sk = SecretKey::random(&mut rng);
        let receiver_pk = SecretKey::random(&mut rng).public_key();
        let genesis_id = genesis_sk.public_key().to_bytes();

        let chain = Blockchain::genesis(&[(genesis_id, 1_000_000)], DEFAULT_DIFFICULTY);
        let bal = chain.balance(&genesis_id, lat_state::LAT_TOKEN).unwrap();
        let xfer = SolventTransfer::create(&genesis_sk, &receiver_pk, lat_state::LAT_TOKEN, 7, 0, 1_000_000, &bal, 0, &mut rng).unwrap();
        let block = chain.mine(vec![
            mine_registration([5u8; 32]),
            Transaction::SolventTransfer { token: lat_state::LAT_TOKEN, xfer },
        ]);

        let bytes = block.encode();
        let decoded = Block::decode(&bytes).expect("decodes");
        assert_eq!(decoded.encode(), bytes, "round-trip is stable");
        assert_eq!(decoded.header.id(), block.header.id());
        assert_eq!(decoded.txs.len(), 2);
    }

    #[test]
    fn decode_rejects_hostile_input_without_allocating() {
        // A header claiming u32::MAX transactions must fail fast, not OOM.
        let chain = Blockchain::genesis(&[([1u8; 32], 10)], DEFAULT_DIFFICULTY);
        let mut bytes = chain.block_bytes(0).unwrap().to_vec();
        bytes[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Block::decode(&bytes).is_none());

        // Truncations and garbage at every prefix length decode to None, never panic.
        let block = chain.mine(vec![mine_registration([5u8; 32])]);
        let good = block.encode();
        for n in 0..good.len() {
            let _ = Block::decode(&good[..n]);
        }
        assert!(Block::decode(&[0xC7; 300]).is_none());
        assert!(Transaction::decode(&[0xC7; 300]).is_none());
        assert!(Transaction::decode(&[]).is_none());
    }

    #[test]
    fn rejects_orphan_block() {
        let chain_id = SecretKey::random(&mut OsRng).public_key().to_bytes();
        let mut chain = Blockchain::genesis(&[(chain_id, 10)], DEFAULT_DIFFICULTY);
        let mut block = chain.mine(vec![]);
        block.header.prev_hash = [9u8; 32]; // unknown parent
        assert_eq!(chain.apply_block(&block), Err(ChainError::OrphanBlock));
    }

    #[test]
    fn heavier_branch_triggers_reorg() {
        let prem = [([1u8; 32], 100u64)];
        let x = [9u8; 32]; // an account that only the B branch registers

        // Node A builds a 2-block chain (no registration of X).
        let mut a = Blockchain::genesis(&prem, DEFAULT_DIFFICULTY);
        let a1 = a.mine(vec![]);
        a.apply_block(&a1).unwrap();
        let a2 = a.mine(vec![]);
        a.apply_block(&a2).unwrap();
        assert_eq!(a.height(), 2);
        assert!(!a.is_registered(&x));

        // A competing chain B builds 3 blocks, registering X in block 2.
        let mut b = Blockchain::genesis(&prem, DEFAULT_DIFFICULTY);
        let b1 = b.mine(vec![]);
        b.apply_block(&b1).unwrap();
        let b2 = b.mine(vec![mine_registration(x)]);
        b.apply_block(&b2).unwrap();
        let b3 = b.mine(vec![]);
        b.apply_block(&b3).unwrap();

        let bb1 = b.block_bytes(1).unwrap().to_vec();
        let bb2 = b.block_bytes(2).unwrap().to_vec();
        let bb3 = b.block_bytes(3).unwrap().to_vec();

        // B1 is a valid side branch — not heavier, so A doesn't switch.
        a.apply_block(&Block::decode(&bb1).unwrap()).unwrap();
        assert_eq!(a.height(), 2, "side branch must not change the active tip");
        a.apply_block(&Block::decode(&bb2).unwrap()).unwrap();

        // B3 makes the B branch heaviest -> A reorgs and rebuilds state along B.
        a.apply_block(&Block::decode(&bb3).unwrap()).unwrap();
        assert_eq!(a.height(), 3, "reorged to the heavier branch");
        assert_eq!(a.tip(), b.tip());
        assert!(a.is_registered(&x), "state was rebuilt along the new branch");
    }

    #[test]
    fn prune_window_bounds_state_growth_and_chains_agree() {
        let prem = [([1u8; 32], 100u64)];
        let mut archive = Blockchain::genesis(&prem, DEFAULT_DIFFICULTY);
        let mut pruned = Blockchain::genesis(&prem, DEFAULT_DIFFICULTY);
        pruned.set_prune_window(4);

        // Identical blocks into both chains; registrations churn the trie.
        for i in 0..16u8 {
            let block = archive.mine(vec![mine_registration([i + 10; 32])]);
            archive.apply_block(&block).unwrap();
            pruned.apply_block(&block).unwrap();
        }
        assert_eq!(pruned.tip(), archive.tip());
        assert_eq!(pruned.state_root(), archive.state_root(), "pruning never changes state");
        assert!(
            pruned.active_state.state_node_count() < archive.active_state.state_node_count(),
            "the pruned chain must hold fewer trie nodes than the archive chain"
        );

        // The pruned chain keeps operating: extend the tip…
        let block = pruned.mine(vec![mine_registration([99u8; 32])]);
        pruned.apply_block(&block).unwrap();
        assert!(pruned.is_registered(&[99u8; 32]));

        // …and reorg (state is rebuilt from blocks, never from pruned nodes).
        let mut rival = Blockchain::genesis(&prem, DEFAULT_DIFFICULTY);
        for _ in 0..19 {
            let b = rival.mine(vec![]);
            rival.apply_block(&b).unwrap();
        }
        for h in 1..=19u64 {
            let b = Block::decode(rival.block_bytes(h).unwrap()).unwrap();
            pruned.apply_block(&b).unwrap();
        }
        assert_eq!(pruned.tip(), rival.tip(), "pruned chain reorged to the heavier branch");
        assert_eq!(pruned.state_root(), rival.state_root());
    }

    /// A signed `Stake` transaction by `sk` (helper for finality tests).
    fn stake_tx(sk: &SecretKey, amount: u64, nonce: u64) -> Transaction {
        let mut tx = Transaction::Stake {
            validator: sk.public_key().to_bytes(),
            amount,
            nonce,
            sig: [0u8; 64],
        };
        let sig = sk.sign(&tx.signing_bytes()).to_bytes();
        if let Transaction::Stake { sig: s, .. } = &mut tx {
            *s = sig;
        }
        tx
    }

    /// A chain whose genesis publicly funds `sk`'s account, with the stake
    /// bonded in block 1. Returns the chain (tip = height 1).
    fn chain_with_validator(sk: &SecretKey) -> Blockchain {
        let id = sk.public_key().to_bytes();
        let mut chain = Blockchain::genesis_with_public(
            &[],
            &[(id, 10 * lat_state::MIN_VALIDATOR_STAKE)],
            DEFAULT_DIFFICULTY,
        );
        let b1 = chain.mine(vec![stake_tx(sk, lat_state::MIN_VALIDATOR_STAKE, 0)]);
        chain.apply_block(&b1).unwrap();
        chain
    }

    #[test]
    fn finality_certificate_blocks_reorgs_across_the_watermark() {
        let sk = SecretKey::random(&mut OsRng);
        let id = sk.public_key().to_bytes();
        let mut chain = chain_with_validator(&sk);
        let b2 = chain.mine(vec![]);
        chain.apply_block(&b2).unwrap();
        assert_eq!(
            chain.validator_set_at(2),
            Some(&[(id, lat_state::MIN_VALIDATOR_STAKE)][..]),
            "the adopted block's committed validator set is recorded"
        );

        // Our sole validator is 100% of the stake: one vote certifies block 2.
        let vote = Vote::sign(&sk, chain.tip(), 2);
        let cert =
            Certificate { block_id: vote.block_id, height: 2, votes: vec![(vote.validator, vote.sig)] };
        assert!(chain.try_finalize(&cert));
        assert_eq!(chain.finalized(), Some((2, chain.tip())));
        // Monotonic: an older certificate can never move the watermark back.
        assert!(!chain.try_finalize(&cert));

        // A rival branch forking BELOW the watermark out-works us (4 blocks vs
        // 2 on a same-difficulty chain) — pre-T15 it would reorg. Now it must
        // be refused, however heavy it grows.
        let mut rival = Blockchain::genesis_with_public(
            &[],
            &[(id, 10 * lat_state::MIN_VALIDATOR_STAKE)],
            DEFAULT_DIFFICULTY,
        );
        for _ in 0..4 {
            let b = rival.mine(vec![]);
            rival.apply_block(&b).unwrap();
        }
        let tip_before = chain.tip();
        for h in 1..=4u64 {
            let b = Block::decode(rival.block_bytes(h).unwrap()).unwrap();
            chain.apply_block(&b).unwrap(); // accepted as side branch only
        }
        assert_eq!(chain.tip(), tip_before, "finality must override cumulative work");
        assert_eq!(chain.height(), 2);

        // A fork ABOVE the watermark still reorgs normally (it keeps block 2).
        let mut above = chain.mine(vec![]); // our own block 3 (kept private)
        chain.apply_block(&above).unwrap();
        above = chain.mine(vec![]);
        chain.apply_block(&above).unwrap();
        assert_eq!(chain.height(), 4);
        assert_eq!(chain.active_id_at(2), Some(cert.block_id), "finalized prefix intact");
    }

    #[test]
    fn empty_validator_set_means_pure_pow() {
        // No stake anywhere: no certificate can verify, and reorgs behave
        // exactly as before — the dev/single-node experience is unchanged.
        let sk = SecretKey::random(&mut OsRng);
        let mut chain = Blockchain::genesis(&[([1u8; 32], 100)], DEFAULT_DIFFICULTY);
        let b1 = chain.mine(vec![]);
        chain.apply_block(&b1).unwrap();
        assert_eq!(chain.validator_set_at(1), Some(&[][..]));

        let vote = Vote::sign(&sk, chain.tip(), 1);
        let cert =
            Certificate { block_id: vote.block_id, height: 1, votes: vec![(vote.validator, vote.sig)] };
        assert!(!chain.try_finalize(&cert), "no stake, no finality");
        assert_eq!(chain.finalized(), None);
    }

    #[test]
    fn finality_watermark_survives_reboot() {
        let sk = SecretKey::random(&mut OsRng);
        let id = sk.public_key().to_bytes();
        let path = std::env::temp_dir().join(format!(
            "lat-finality-{}-{}.dat",
            std::process::id(),
            id[0]
        ));
        let snap = super::snapshot::snapshot_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&snap);
        let public_premine = [(id, 10 * lat_state::MIN_VALIDATOR_STAKE)];

        let finalized = {
            let mut chain =
                Blockchain::open_with_public(&path, &[], &public_premine, DEFAULT_DIFFICULTY)
                    .unwrap();
            let b1 = chain.mine(vec![stake_tx(&sk, lat_state::MIN_VALIDATOR_STAKE, 0)]);
            chain.apply_block(&b1).unwrap();
            let b2 = chain.mine(vec![]);
            chain.apply_block(&b2).unwrap();
            let vote = Vote::sign(&sk, chain.tip(), 2);
            let cert = Certificate {
                block_id: vote.block_id,
                height: 2,
                votes: vec![(vote.validator, vote.sig)],
            };
            assert!(chain.try_finalize(&cert));
            chain.finalized().unwrap()
        };
        {
            let chain =
                Blockchain::open_with_public(&path, &[], &public_premine, DEFAULT_DIFFICULTY)
                    .unwrap();
            assert_eq!(chain.finalized(), Some(finalized), "watermark restored from the DB");
        }
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&snap);
    }

    #[test]
    fn rejects_tampered_tx_root() {
        let chain_id = SecretKey::random(&mut OsRng).public_key().to_bytes();
        let mut chain = Blockchain::genesis(&[(chain_id, 10)], DEFAULT_DIFFICULTY);
        let mut block = chain.mine(vec![]);
        block.header.tx_root = [1u8; 32];
        assert_eq!(chain.apply_block(&block), Err(ChainError::BadTxRoot));
    }

    #[test]
    fn genesis_commits_the_state_root() {
        // The genesis header commits the genesis ledger's state root, so a node
        // can verify the premine from the header alone.
        let prem = [([1u8; 32], 100u64)];
        let chain = Blockchain::genesis(&prem, DEFAULT_DIFFICULTY);
        let gh = BlockHeader::decode(chain.block_bytes(0).unwrap().get(0..HEADER_LEN).unwrap()).unwrap();
        assert_ne!(gh.state_root, [0u8; 32]);
        // Mining then applying a real block keeps header/state roots in agreement.
        let mut chain = chain;
        let block = chain.mine(vec![mine_registration([7u8; 32])]);
        assert_ne!(block.header.state_root, gh.state_root, "state changed, root must too");
        chain.apply_block(&block).unwrap();
    }

    /// Proof-of-work covers the header only, so a block costs the same to mine
    /// whether it carries one transaction or a million — while every node must
    /// validate all of them. Fees do not deter it either: the attacker is the
    /// miner, so the fees come back as coinbase. Only a consensus rule stops it.
    #[test]
    fn rejects_a_block_stuffed_past_the_tx_cap() {
        let chain_id = SecretKey::random(&mut OsRng).public_key().to_bytes();
        let mut chain = Blockchain::genesis(&[(chain_id, 10)], DEFAULT_DIFFICULTY);

        // One transaction over the line, each individually valid.
        let stuffing: Vec<Transaction> = (0..=MAX_TXS_PER_BLOCK)
            .map(|i| {
                let mut pk = [0u8; 32];
                pk[..8].copy_from_slice(&(i as u64).to_le_bytes());
                mine_registration(pk)
            })
            .collect();
        assert_eq!(stuffing.len(), MAX_TXS_PER_BLOCK + 1);

        let mut block = chain.mine(stuffing);
        // Re-mine so the header still satisfies PoW: the attacker can always do
        // this, so the cap — not the PoW — must be what rejects the block.
        let d = chain.difficulty();
        while !meets_difficulty(&block.header.id(), d) {
            block.header.nonce += 1;
        }

        assert_eq!(chain.apply_block(&block), Err(ChainError::TooManyTxs));
        assert_eq!(chain.height(), 0, "the stuffed block was not adopted");

        // And exactly at the cap is still fine — the rule must not cost honest
        // miners the block they were already allowed to produce.
        let ok: Vec<Transaction> = (0..MAX_TXS_PER_BLOCK)
            .map(|i| {
                let mut pk = [1u8; 32];
                pk[..8].copy_from_slice(&(i as u64).to_le_bytes());
                mine_registration(pk)
            })
            .collect();
        let good = chain.mine(ok);
        assert_eq!(chain.apply_block(&good), Ok(()));
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn rejects_forged_state_root() {
        // A miner commits a state root that doesn't match what the block produces.
        // Even after redoing the PoW over the forged header, consensus rejects it.
        let chain_id = SecretKey::random(&mut OsRng).public_key().to_bytes();
        let mut chain = Blockchain::genesis(&[(chain_id, 10)], DEFAULT_DIFFICULTY);
        let mut block = chain.mine(vec![mine_registration([5u8; 32])]);
        block.header.state_root = [0xabu8; 32]; // claim a state the block doesn't yield
        // Re-mine so the (now-different) header still satisfies PoW — the attacker
        // can do this, so the state-root check must be what stops the block.
        let d = chain.difficulty();
        while !meets_difficulty(&block.header.id(), d) {
            block.header.nonce += 1;
        }
        assert_eq!(chain.apply_block(&block), Err(ChainError::BadStateRoot));
        assert_eq!(chain.height(), 0, "the forged block was not adopted");
    }

    #[test]
    fn retarget_steers_toward_target() {
        // On-target span leaves difficulty unchanged.
        assert_eq!(retarget(1000, TARGET_BLOCK_TIME_SECS), 1000);
        // Faster than target -> harder; slower -> easier.
        assert!(retarget(1000, 1) > 1000);
        assert!(retarget(1000, 100) < 1000);
        // Never collapses to zero.
        assert!(retarget(1, 1_000_000) >= 1);
        // A single instant block cannot more than RETARGET_CLAMP× the difficulty.
        assert!(retarget(1000, 0) <= 1000 * RETARGET_CLAMP);
    }

    #[test]
    fn difficulty_threshold_extremes() {
        let big = [0xffu8; 32];
        assert!(meets_difficulty(&big, 1)); // difficulty 1 accepts anything
        assert!(!meets_difficulty(&big, u64::MAX)); // max difficulty rejects a large hash
        let zero = [0u8; 32];
        assert!(meets_difficulty(&zero, u64::MAX)); // the smallest hash always passes
    }

    // Relies on near-instant (BLAKE3) mining so blocks land faster than the target
    // and difficulty ratchets up. Under real RandomX, mining takes real time, so
    // this premise doesn't hold — the chain then correctly retargets downward.
    #[cfg(not(feature = "randomx"))]
    #[test]
    fn chain_difficulty_rises_on_fast_blocks() {
        let id = SecretKey::random(&mut OsRng).public_key().to_bytes();
        let mut chain = Blockchain::genesis(&[(id, 10)], DEFAULT_DIFFICULTY);
        let start = chain.difficulty();
        // Blocks are mined back-to-back (far faster than target), so difficulty climbs.
        for _ in 0..3 {
            let b = chain.mine(vec![]);
            chain.apply_block(&b).unwrap();
        }
        assert!(chain.difficulty() > start, "fast blocks should raise difficulty");
    }

    #[test]
    fn chain_persists_across_reopen() {
        let mut rng = OsRng;
        let gsk = SecretKey::random(&mut rng);
        let gid = gsk.public_key().to_bytes();
        let lat = lat_state::LAT_TOKEN;

        // Unique temp path so parallel test runs don't collide.
        let path = std::env::temp_dir().join(format!(
            "lat-store-{}-{}.dat",
            std::process::id(),
            gid[0]
        ));
        let _ = std::fs::remove_file(&path);
        let premine = [(gid, 1_000_000u64)];

        // Session 1: open fresh, mine two blocks, then drop the chain.
        {
            let mut chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            let b1 = chain.mine(vec![mine_registration([3u8; 32])]);
            chain.apply_block(&b1).unwrap();
            let b2 = chain.mine(vec![]);
            chain.apply_block(&b2).unwrap();
            assert_eq!(chain.height(), 2);
        }

        // Session 2: reopen — state is rebuilt purely by replaying the log.
        {
            let chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            assert_eq!(chain.height(), 2, "height restored from disk");
            assert!(chain.is_registered(&[3u8; 32]), "registration restored");
            assert_eq!(
                gsk.decrypt(&chain.balance(&gid, lat).unwrap(), 24),
                Some(1_000_000),
                "encrypted balance restored"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tx_index_locates_transactions_and_survives_reopen() {
        let gsk = SecretKey::random(&mut OsRng);
        let gid = gsk.public_key().to_bytes();
        let path = std::env::temp_dir().join(format!(
            "lat-txindex-{}-{}.redb",
            std::process::id(),
            gid[0]
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(super::snapshot::snapshot_path(&path));
        let premine = [(gid, 1_000_000u64)];

        let (block_id, txh) = {
            let mut chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            let tx = mine_registration([9u8; 32]);
            let txh = tx_hash(&tx);
            let block = chain.mine(vec![tx]);
            let block_id = block.header.id();
            chain.apply_block(&block).unwrap();

            // The tx is indexed at (its block, position 0); an unknown tx isn't.
            assert_eq!(chain.tx_location(&txh), Some((block_id, 0)));
            assert_eq!(chain.tx_location(&[0u8; 32]), None);
            // And the block is retrievable by id.
            assert_eq!(chain.block_by_id(&block_id), Some(block.encode()));
            (block_id, txh)
        };

        // Reopen from disk: the transaction index persisted.
        let chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
        assert_eq!(chain.tx_location(&txh), Some((block_id, 0)), "index survived restart");

        drop(chain);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(super::snapshot::snapshot_path(&path));
    }

    #[test]
    fn snapshot_boot_replays_only_the_tail() {
        let mut rng = OsRng;
        let gsk = SecretKey::random(&mut rng);
        let gid = gsk.public_key().to_bytes();
        let receiver_sk = SecretKey::random(&mut rng);
        let receiver_id = receiver_sk.public_key().to_bytes();
        let lat = lat_state::LAT_TOKEN;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("lat-snapboot-{}-{}.dat", std::process::id(), gid[0]));
        let snap = super::snapshot::snapshot_path(&path);
        let ref_path = dir.join(format!("lat-snapboot-ref-{}-{}.dat", std::process::id(), gid[0]));
        for p in [&path, &snap, &ref_path, &super::snapshot::snapshot_path(&ref_path)] {
            let _ = std::fs::remove_file(p);
        }
        let premine = [(gid, 1_000_000u64)];

        // Session 1: fresh chain — mine a registration and a solvent transfer.
        // Every adopted block commits state + boot anchor to the DB (T7).
        {
            let mut chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            assert_eq!(chain.boot_mode(), BootMode::FullReplay);
            assert!(!chain.booted_from_snapshot());
            let b1 = chain.mine(vec![mine_registration(receiver_id)]);
            chain.apply_block(&b1).unwrap();
            let bal = chain.balance(&gid, lat).unwrap();
            let xfer = SolventTransfer::create(
                &gsk, &receiver_sk.public_key(), lat_state::LAT_TOKEN, 250_000, MIN_TRANSFER_FEE, 1_000_000, &bal, 0, &mut rng,
            )
            .unwrap();
            let b2 = chain.mine(vec![Transaction::SolventTransfer { token: lat, xfer }]);
            chain.apply_block(&b2).unwrap();
        }
        assert!(!snap.exists(), "a fresh (height-0) open must not have snapshotted");

        // Session 2: boots straight from the durable records — no snapshot file
        // was ever needed or written.
        {
            let mut chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            assert_eq!(chain.boot_mode(), BootMode::Records);
            assert!(chain.booted_from_snapshot());
            assert!(!snap.exists(), "records boot never writes a snapshot file");
            let b3 = chain.mine(vec![]);
            chain.apply_block(&b3).unwrap();
        }

        // Session 3: records boot again at the new tip. Capture what a correct
        // boot must reproduce, then release the DB (redb holds an exclusive
        // lock, so the block DB can't be copied while open).
        let (tip, difficulty, root) = {
            let chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            assert_eq!(chain.boot_mode(), BootMode::Records);
            assert_eq!(chain.height(), 3);
            assert_eq!(
                gsk.decrypt(&chain.balance(&gid, lat).unwrap(), 24),
                Some(750_000 - MIN_TRANSFER_FEE)
            );
            assert_eq!(receiver_sk.decrypt(&chain.pending(&receiver_id, lat).unwrap(), 24), Some(250_000));
            (chain.tip(), chain.difficulty(), chain.state_root())
        };

        // Strip the anchor: with no records boot and no snapshot file the open
        // falls back to a FULL replay — and must land in the identical state.
        // That fallback also writes a snapshot file for the next boot.
        strip_state_anchor(&path);
        {
            let chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            assert_eq!(chain.boot_mode(), BootMode::FullReplay);
            assert_eq!((chain.tip(), chain.difficulty(), chain.state_root()), (tip, difficulty, root));
        }
        assert!(snap.exists(), "a full-replay open leaves a snapshot for next boot");

        // Strip the anchor again (the open above re-anchored on rehome): now the
        // SNAPSHOT-FILE path boots, and must land in the identical state too.
        strip_state_anchor(&path);
        {
            let chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            assert_eq!(chain.boot_mode(), BootMode::Snapshot);
            assert_eq!((chain.tip(), chain.difficulty(), chain.state_root()), (tip, difficulty, root));
        }

        // A copy of the DB (anchor stripped, no .snap sibling) full-replays to
        // the same state — the durable records never diverge from the blocks.
        std::fs::copy(&path, &ref_path).unwrap();
        strip_state_anchor(&ref_path);
        let full = Blockchain::open(&ref_path, &premine, DEFAULT_DIFFICULTY).unwrap();
        assert_eq!(full.boot_mode(), BootMode::FullReplay);
        assert_eq!(tip, full.tip());
        assert_eq!(difficulty, full.difficulty());
        assert_eq!(root, full.state_root(), "every boot path reproduces the exact state");

        drop(full);
        for p in [&path, &snap, &ref_path, &super::snapshot::snapshot_path(&ref_path)] {
            let _ = std::fs::remove_file(p);
        }
    }

    /// Delete the T7 boot anchor so the next open exercises the snapshot-file /
    /// full-replay paths (the records themselves are left in place).
    fn strip_state_anchor(path: &Path) {
        let kv = RedbStore::open(path).unwrap();
        kv.delete(Column::Meta, STATE_ANCHOR.to_vec());
    }

    #[test]
    fn corrupt_or_stale_snapshot_falls_back_to_full_replay() {
        let mut rng = OsRng;
        let gsk = SecretKey::random(&mut rng);
        let gid = gsk.public_key().to_bytes();
        let path = std::env::temp_dir().join(format!(
            "lat-snapcorrupt-{}-{}.dat",
            std::process::id(),
            gid[0]
        ));
        let snap = super::snapshot::snapshot_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&snap);
        let premine = [(gid, 1_000_000u64)];

        // Build a 2-block chain, then force a full-replay open (anchor stripped,
        // no snapshot yet) so it writes a snapshot file to attack.
        {
            let mut chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            let b1 = chain.mine(vec![mine_registration([3u8; 32])]);
            chain.apply_block(&b1).unwrap();
            let b2 = chain.mine(vec![]);
            chain.apply_block(&b2).unwrap();
        }
        strip_state_anchor(&path);
        { Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap(); }
        assert!(snap.exists());

        // Corrupt a byte of the ledger body — the checksum rejects the file and
        // boot falls back to full replay, ending in the same correct state.
        // (Anchor stripped each time so the snapshot path is actually reached.)
        let mut bytes = std::fs::read(&snap).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&snap, &bytes).unwrap();
        strip_state_anchor(&path);
        {
            let chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            assert_eq!(chain.boot_mode(), BootMode::FullReplay, "corrupt snapshot must be ignored");
            assert_eq!(chain.height(), 2);
            assert!(chain.is_registered(&[3u8; 32]));
        }

        // That fallback open rewrote a good snapshot. Now tamper the block-id
        // field (NOT covered by the body checksum): the snapshot no longer sits
        // on the active chain, so the placement check rejects it.
        let mut bytes = std::fs::read(&snap).unwrap();
        bytes[20] ^= 0xff; // inside the block_id at offset 16..48
        std::fs::write(&snap, &bytes).unwrap();
        strip_state_anchor(&path);
        {
            let chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            assert_eq!(chain.boot_mode(), BootMode::FullReplay, "misplaced snapshot must be ignored");
            assert_eq!(chain.height(), 2);
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&snap);
    }

    #[test]
    fn corrupt_state_records_fall_back_and_reboot_correctly() {
        let gid = SecretKey::random(&mut OsRng).public_key().to_bytes();
        let path = std::env::temp_dir().join(format!(
            "lat-reccorrupt-{}-{}.dat",
            std::process::id(),
            gid[0]
        ));
        let snap = super::snapshot::snapshot_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&snap);
        let premine = [(gid, 1_000_000u64)];

        let (tip, root) = {
            let mut chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            let b1 = chain.mine(vec![mine_registration([3u8; 32])]);
            chain.apply_block(&b1).unwrap();
            (chain.tip(), chain.state_root())
        };

        // Flip a byte inside an account record ('a'-prefixed key in Objects).
        // Whether that makes the record undecodable or just commit a different
        // root, the records boot must reject it and fall back — ending in the
        // exact state the blocks prescribe.
        {
            let kv = RedbStore::open(&path).unwrap();
            let accounts = kv.scan_prefix(Column::Objects, b"a");
            let (key, mut body) = accounts.into_iter().next().expect("an account record exists");
            let last = body.len() - 1;
            body[last] ^= 0xff;
            kv.put(Column::Objects, key, body);
        }
        {
            let chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            assert_ne!(chain.boot_mode(), BootMode::Records, "tampered records must be rejected");
            assert_eq!((chain.tip(), chain.state_root()), (tip, root));
            assert!(chain.is_registered(&[3u8; 32]));
        }
        // The fallback open re-homed clean records; the next boot uses them.
        {
            let chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            assert_eq!(chain.boot_mode(), BootMode::Records);
            assert_eq!((chain.tip(), chain.state_root()), (tip, root));
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&snap);
    }

    #[test]
    fn persistent_chain_reorgs_durably() {
        let gid = SecretKey::random(&mut OsRng).public_key().to_bytes();
        let path = std::env::temp_dir().join(format!(
            "lat-reorgdur-{}-{}.dat",
            std::process::id(),
            gid[0]
        ));
        let snap = super::snapshot::snapshot_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&snap);
        let premine = [(gid, 1_000_000u64)];
        let x = [9u8; 32]; // registered only on the rival branch

        // A rival in-memory chain builds the heavier branch.
        let mut rival = Blockchain::genesis(&premine, DEFAULT_DIFFICULTY);
        let r1 = rival.mine(vec![]);
        rival.apply_block(&r1).unwrap();
        let r2 = rival.mine(vec![mine_registration(x)]);
        rival.apply_block(&r2).unwrap();
        let r3 = rival.mine(vec![]);
        rival.apply_block(&r3).unwrap();

        // The persistent chain mines its own block, then reorgs to the rival.
        {
            let mut chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            let own = chain.mine(vec![mine_registration([7u8; 32])]);
            chain.apply_block(&own).unwrap();
            for h in 1..=3u64 {
                let b = Block::decode(rival.block_bytes(h).unwrap()).unwrap();
                chain.apply_block(&b).unwrap();
            }
            assert_eq!(chain.tip(), rival.tip(), "reorged to the heavier branch");
            assert!(chain.is_registered(&x));
            assert_eq!(chain.state_root(), rival.state_root());
        }
        // Reboot: the records boot must reproduce the REORGED state (the old
        // branch's records were atomically replaced on adoption).
        {
            let chain = Blockchain::open(&path, &premine, DEFAULT_DIFFICULTY).unwrap();
            assert_eq!(chain.boot_mode(), BootMode::Records);
            assert_eq!(chain.tip(), rival.tip());
            assert!(chain.is_registered(&x));
            assert!(!chain.is_registered(&[7u8; 32]), "the abandoned branch's state is gone");
            assert_eq!(chain.state_root(), rival.state_root());
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&snap);
    }

    #[test]
    fn coinbase_rewards_the_miner() {
        let lat = lat_state::LAT_TOKEN;
        let miner = [5u8; 32];
        let mut chain = Blockchain::genesis(&[([1u8; 32], 100)], DEFAULT_DIFFICULTY);
        assert!(chain.balance(&miner, lat).is_none(), "miner unregistered before");

        let b = chain.mine_with_reward(miner, vec![]);
        chain.apply_block(&b).unwrap();

        // Miner is auto-registered and holds exactly the block-1 emission.
        assert_eq!(
            chain.balance(&miner, lat),
            Some(lat_crypto::Ciphertext::mint(emission(1))),
        );
        // A plain mine() (no reward) leaves a different miner unrewarded.
        let b2 = chain.mine(vec![]);
        chain.apply_block(&b2).unwrap();
        assert!(chain.balance(&[6u8; 32], lat).is_none());
    }

    #[test]
    fn emission_halves() {
        assert_eq!(emission(0), INITIAL_BLOCK_REWARD);
        assert_eq!(emission(1), INITIAL_BLOCK_REWARD);
        assert_eq!(emission(HALVING_INTERVAL), INITIAL_BLOCK_REWARD / 2);
        assert_eq!(emission(HALVING_INTERVAL * 2), INITIAL_BLOCK_REWARD / 4);
        assert_eq!(emission(HALVING_INTERVAL * 64), 0, "supply is capped");
    }

    #[test]
    fn registration_pow_roundtrips() {
        let id = SecretKey::random(&mut OsRng).public_key().to_bytes();
        let tx = mine_registration(id);
        match tx {
            Transaction::Register { pubkey, pow_nonce } => {
                assert!(verify_registration_pow(&pubkey, pow_nonce));
                assert!(!verify_registration_pow(&pubkey, pow_nonce.wrapping_add(1)) || REGISTRATION_POW_BITS == 0);
            }
            _ => panic!("expected registration"),
        }
    }

    /// Sign a PublicTransfer with `sk`, filling its `sig` field like a wallet would.
    fn sign_public(mut tx: Transaction, sk: &SecretKey) -> Transaction {
        let sig = sk.sign(&tx.signing_bytes()).to_bytes();
        if let Transaction::PublicTransfer { sig: s, .. } = &mut tx {
            *s = sig;
        }
        tx
    }

    #[test]
    fn public_transfer_end_to_end_with_miner_fee() {
        let lat = lat_state::LAT_TOKEN;
        let mut rng = OsRng;
        let genesis_sk = SecretKey::random(&mut rng);
        let receiver_sk = SecretKey::random(&mut rng);
        let genesis_id = genesis_sk.public_key().to_bytes();
        let receiver_id = receiver_sk.public_key().to_bytes();
        let miner = [5u8; 32];

        // Genesis seeds a TRANSPARENT public premine (no confidential premine).
        let mut chain =
            Blockchain::genesis_with_public(&[], &[(genesis_id, 1_000_000)], DEFAULT_DIFFICULTY);
        assert_eq!(chain.public_balance(&genesis_id, lat), Some(1_000_000));

        // Register the receiver (public transfers still target a known account).
        let b1 = chain.mine_with_reward(miner, vec![mine_registration(receiver_id)]);
        chain.apply_block(&b1).unwrap();

        // Genesis publicly sends 250_000 + fee to the receiver.
        let fee = MIN_TRANSFER_FEE;
        let nonce = chain.nonce(&genesis_id).unwrap();
        let tx = sign_public(
            Transaction::PublicTransfer {
                token: lat, from: genesis_id, to: receiver_id, amount: 250_000, fee, nonce, sig: [0u8; 64],
            },
            &genesis_sk,
        );
        let b2 = chain.mine_with_reward(miner, vec![tx]);
        chain.apply_block(&b2).unwrap();

        // Sender debited amount + fee; receiver credited the amount.
        assert_eq!(chain.public_balance(&genesis_id, lat), Some(1_000_000 - 250_000 - fee));
        assert_eq!(chain.public_balance(&receiver_id, lat), Some(250_000));
        // The miner earned the public fee in its PUBLIC balance; the coinbase is
        // separate (in the encrypted balance), so the two never commingle.
        assert_eq!(chain.public_balance(&miner, lat), Some(fee));
    }

    #[test]
    fn flat_tx_fee_matches_the_transfer_fee_floor() {
        // C-1: the flat fee lives in lat-state; keep it in lock-step with the
        // chain's transfer fee floor so the fee market is uniform.
        assert_eq!(lat_state::FLAT_TX_FEE, MIN_TRANSFER_FEE);
    }

    #[test]
    fn contract_deploy_fee_is_paid_to_the_miner() {
        // C-1 end-to-end: a deploy debits FLAT_TX_FEE from the deployer's public
        // LAT and credits it to the block's miner (its public balance).
        let lat = lat_state::LAT_TOKEN;
        let deployer_sk = SecretKey::random(&mut OsRng);
        let deployer = deployer_sk.public_key().to_bytes();
        let miner = [7u8; 32];

        let mut chain =
            Blockchain::genesis_with_public(&[], &[(deployer, 1_000_000)], DEFAULT_DIFFICULTY);
        let code = vec![0x00u8]; // a single STOP opcode
        let mut tx = Transaction::DeployContract { deployer, code, sig: [0u8; 64] };
        let sig = deployer_sk.sign(&tx.signing_bytes()).to_bytes();
        if let Transaction::DeployContract { sig: s, .. } = &mut tx {
            *s = sig;
        }
        let b = chain.mine_with_reward(miner, vec![tx]);
        chain.apply_block(&b).unwrap();

        assert_eq!(
            chain.public_balance(&deployer, lat),
            Some(1_000_000 - lat_state::FLAT_TX_FEE),
            "deployer paid the flat fee",
        );
        assert_eq!(
            chain.public_balance(&miner, lat),
            Some(lat_state::FLAT_TX_FEE),
            "miner earned the flat fee in its public balance",
        );
    }

    #[test]
    fn public_transfer_under_fee_floor_rejected_by_consensus() {
        let sk = SecretKey::random(&mut OsRng);
        let id = sk.public_key().to_bytes();
        let tx = sign_public(
            Transaction::PublicTransfer {
                token: 0, from: id, to: [1u8; 32], amount: 1, fee: MIN_TRANSFER_FEE - 1, nonce: 0, sig: [0u8; 64],
            },
            &sk,
        );
        assert!(matches!(check_tx(&tx), Err(ChainError::FeeTooLow)));
    }

    /// Sign any signature-bearing tx with `sk` (test helper).
    fn sign_any(mut tx: Transaction, sk: &SecretKey) -> Transaction {
        let sig = sk.sign(&tx.signing_bytes()).to_bytes();
        match &mut tx {
            Transaction::Shield { sig: s, .. }
            | Transaction::Unshield { sig: s, .. }
            | Transaction::PublicTransfer { sig: s, .. }
            | Transaction::Rollover { sig: s, .. } => *s = sig,
            _ => {}
        }
        tx
    }

    #[test]
    fn shield_then_unshield_round_trips_through_blocks() {
        let lat = lat_state::LAT_TOKEN;
        let mut rng = OsRng;
        let user_sk = SecretKey::random(&mut rng);
        let user = user_sk.public_key().to_bytes();
        let dest_sk = SecretKey::random(&mut rng);
        let dest = dest_sk.public_key().to_bytes();
        let miner = [5u8; 32];
        let fee = MIN_TRANSFER_FEE;

        // User starts with 1,000,000 PUBLIC LAT; dest is registered.
        let mut chain =
            Blockchain::genesis_with_public(&[], &[(user, 1_000_000)], DEFAULT_DIFFICULTY);
        let b1 = chain.mine_with_reward(miner, vec![mine_registration(dest)]);
        chain.apply_block(&b1).unwrap();

        // SHIELD 300,000 of the user's public LAT into the user's OWN private side.
        let n0 = chain.nonce(&user).unwrap();
        let shield = sign_any(
            Transaction::Shield { token: lat, from: user, to: user, amount: 300_000, fee, nonce: n0, sig: [0u8; 64] },
            &user_sk,
        );
        let b2 = chain.mine_with_reward(miner, vec![shield]);
        chain.apply_block(&b2).unwrap();
        assert_eq!(chain.public_balance(&user, lat), Some(1_000_000 - 300_000 - fee));
        // The miner earned the shield fee in its PUBLIC balance.
        assert_eq!(chain.public_balance(&miner, lat), Some(fee));

        // Roll the shielded funds from private pending into spendable.
        let n1 = chain.nonce(&user).unwrap();
        let roll = sign_any(Transaction::Rollover { account: user, nonce: n1, sig: [0u8; 64] }, &user_sk);
        let b3 = chain.mine_with_reward(miner, vec![roll]);
        chain.apply_block(&b3).unwrap();
        assert_eq!(user_sk.decrypt(&chain.balance(&user, lat).unwrap(), 24), Some(300_000));

        // UNSHIELD 100,000 from the user's private balance to dest's PUBLIC balance.
        let n2 = chain.nonce(&user).unwrap();
        let bal = chain.balance(&user, lat).unwrap();
        let cur = user_sk.decrypt(&bal, 24).unwrap();
        let xfer = SolventTransfer::create(
            &user_sk, &lat_crypto::unshield_view_key(), lat_state::LAT_TOKEN, 100_000, fee, cur, &bal, n2, &mut rng,
        )
        .unwrap();
        let unshield = sign_any(
            Transaction::Unshield { token: lat, to: dest, amount: 100_000, xfer, sig: [0u8; 64] },
            &user_sk,
        );
        let b4 = chain.mine_with_reward(miner, vec![unshield]);
        chain.apply_block(&b4).unwrap();

        // Value made the full public → private → public round trip.
        assert_eq!(chain.public_balance(&dest, lat), Some(100_000));
        assert_eq!(user_sk.decrypt(&chain.balance(&user, lat).unwrap(), 24), Some(300_000 - 100_000 - fee));
    }

    #[test]
    fn unshield_under_fee_floor_rejected_by_consensus() {
        let mut rng = OsRng;
        let sk = SecretKey::random(&mut rng);
        let bal = sk.public_key().encrypt(1_000_000, &mut rng);
        let xfer = SolventTransfer::create(
            &sk, &lat_crypto::unshield_view_key(), lat_state::LAT_TOKEN, 1, MIN_TRANSFER_FEE - 1, 1_000_000, &bal, 0, &mut rng,
        )
        .unwrap();
        let tx = Transaction::Unshield { token: 0, to: [1u8; 32], amount: 1, xfer, sig: [0u8; 64] };
        assert!(matches!(check_tx(&tx), Err(ChainError::FeeTooLow)));
    }

    #[test]
    fn stealth_shield_under_fee_floor_rejected_by_consensus() {
        let sk = SecretKey::random(&mut OsRng);
        let id = sk.public_key().to_bytes();
        let tx = Transaction::ShieldStealth {
            token: 0, from: id, ephemeral: [1u8; 32], one_time: [2u8; 32],
            amount: 1, fee: MIN_TRANSFER_FEE - 1, nonce: 0, sig: [0u8; 64],
        };
        assert!(matches!(check_tx(&tx), Err(ChainError::FeeTooLow)));
    }

    // --- T19 fast sync ---

    /// A source chain with a few blocks of real state changes, plus its full
    /// encoded block list (height 1..=tip) and fast-sync payload.
    fn fast_sync_fixture() -> (Blockchain, Vec<Vec<u8>>, (u64, [u8; 32], Vec<(Vec<u8>, Vec<u8>)>)) {
        let mut rng = OsRng;
        let genesis_sk = SecretKey::random(&mut rng);
        let genesis_id = genesis_sk.public_key().to_bytes();
        let receiver_sk = SecretKey::random(&mut rng);
        let receiver_id = receiver_sk.public_key().to_bytes();
        let mut chain = Blockchain::genesis(&[(genesis_id, 1_000_000)], DEFAULT_DIFFICULTY);

        let block1 = chain.mine(vec![mine_registration(receiver_id)]);
        chain.apply_block(&block1).unwrap();
        // Block 2: a real confidential transfer, so the synced state carries
        // ciphertext balances, not just registrations.
        let bal = chain.balance(&genesis_id, lat_state::LAT_TOKEN).unwrap();
        let xfer = SolventTransfer::create(
            &genesis_sk, &receiver_sk.public_key(), lat_state::LAT_TOKEN, 250_000, MIN_TRANSFER_FEE,
            1_000_000, &bal, 0, &mut rng,
        )
        .unwrap();
        let block2 = chain.mine(chain.select_valid(vec![Transaction::SolventTransfer {
            token: lat_state::LAT_TOKEN,
            xfer,
        }]));
        chain.apply_block(&block2).unwrap();
        let block3 = chain.mine(Vec::new());
        chain.apply_block(&block3).unwrap();

        let blocks: Vec<Vec<u8>> =
            (1..=chain.height()).map(|h| chain.block_bytes(h).unwrap().to_vec()).collect();
        let payload = chain.state_sync_payload().unwrap();
        (chain, blocks, payload)
    }

    #[test]
    fn fast_sync_adopts_peer_chain_without_replaying_history() {
        let (source, blocks, (anchor_h, anchor_id, records)) = fast_sync_fixture();
        // Same genesis parameters = same network.
        let genesis_premine = source.premine.clone();
        let mut fresh = Blockchain::genesis(&genesis_premine, DEFAULT_DIFFICULTY);

        assert!(fresh.fast_sync_adopt(&blocks, anchor_h, anchor_id, records));
        assert_eq!(fresh.height(), source.height());
        assert_eq!(fresh.tip(), source.tip());
        assert_eq!(fresh.state_root(), source.state_root());
        assert_eq!(fresh.boot_mode(), BootMode::FastSync);
    }

    #[test]
    fn fast_sync_rejects_tampered_records() {
        let (source, blocks, (anchor_h, anchor_id, mut records)) = fast_sync_fixture();
        // Flip a byte in one record value: the rebuilt commitment can no longer
        // match the anchor header's state root.
        let v = &mut records.last_mut().unwrap().1;
        let last = v.len() - 1;
        v[last] ^= 1;

        let mut fresh = Blockchain::genesis(&source.premine.clone(), DEFAULT_DIFFICULTY);
        assert!(!fresh.fast_sync_adopt(&blocks, anchor_h, anchor_id, records));
        assert_eq!(fresh.height(), 0, "rejected sync must leave the chain untouched");
        assert_eq!(fresh.boot_mode(), BootMode::FullReplay);
    }

    #[test]
    fn fast_sync_rejects_wrong_network_and_non_fresh_chain() {
        let (source, blocks, (anchor_h, anchor_id, records)) = fast_sync_fixture();

        // Different premine = different genesis = foreign network.
        let other_id = SecretKey::random(&mut OsRng).public_key().to_bytes();
        let mut foreign = Blockchain::genesis(&[(other_id, 5)], DEFAULT_DIFFICULTY);
        assert!(!foreign.fast_sync_adopt(&blocks, anchor_h, anchor_id, records.clone()));
        assert_eq!(foreign.height(), 0);

        // A chain that already has blocks must full-sync, never fast-sync.
        let mut busy = Blockchain::genesis(&source.premine.clone(), DEFAULT_DIFFICULTY);
        let b1 = busy.mine(Vec::new());
        busy.apply_block(&b1).unwrap();
        assert!(!busy.fast_sync_adopt(&blocks, anchor_h, anchor_id, records));
        assert_eq!(busy.height(), 1);
    }

    // --- T23: decoder robustness (fuzz-style property tests) ---
    //
    // Blocks and transactions arrive from untrusted peers (NewBlock/NewTx
    // gossip, sync, SubmitTx RPC); finality votes/certificates likewise. All
    // of their decoders must never panic on arbitrary bytes — only return
    // `None`. Deterministic xorshift so failures reproduce exactly.

    struct XorShift(u64);
    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    #[test]
    fn chain_decoders_survive_random_and_mutated_input() {
        let mut rng = XorShift(0xb10c_dec0_de5e_ed01);

        // Real encodings to mutate: blocks with registration + confidential
        // transfer txs, their headers and txs, plus a finality vote + cert.
        let (_, blocks, _) = fast_sync_fixture();
        let mut originals: Vec<Vec<u8>> = blocks.clone();
        for bytes in &blocks {
            let block = Block::decode(bytes).unwrap();
            originals.push(block.header.encode());
            for tx in &block.txs {
                originals.push(tx.encode());
            }
        }
        let sk = lat_crypto::SecretKey::random(&mut OsRng);
        let vote = crate::finality::Vote::sign(&sk, [3u8; 32], 9);
        originals.push(vote.encode());
        originals.push(
            crate::finality::Certificate {
                block_id: vote.block_id,
                height: vote.height,
                votes: vec![(vote.validator, vote.sig)],
            }
            .encode(),
        );

        let decode_all = |buf: &[u8]| {
            // Every decoder that faces peer bytes; none may panic.
            let _ = Block::decode(buf);
            let _ = BlockHeader::decode(buf);
            let _ = Transaction::decode(buf);
            let _ = crate::finality::Vote::decode(buf);
            let _ = crate::finality::Certificate::decode(buf);
        };

        // Pure random buffers (first byte sweeps all tag values).
        for i in 0..5_000usize {
            let len = rng.below(400) + usize::from(i % 50 == 0) * rng.below(8192);
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                *b = rng.next() as u8;
            }
            if !buf.is_empty() {
                buf[0] = (i % 256) as u8;
            }
            decode_all(&buf);
        }

        // Valid encodings, damaged: byte flips, truncations, extensions.
        for _ in 0..20_000 {
            let mut buf = originals[rng.below(originals.len())].clone();
            match rng.below(3) {
                0 if !buf.is_empty() => {
                    let i = rng.below(buf.len());
                    buf[i] ^= (rng.next() as u8) | 1;
                }
                1 => {
                    let cut = rng.below(buf.len() + 1);
                    buf.truncate(cut);
                }
                _ => {
                    for _ in 0..rng.below(16) + 1 {
                        buf.push(rng.next() as u8);
                    }
                }
            }
            decode_all(&buf);
        }

        // And the valid encodings themselves still round-trip.
        for bytes in &blocks {
            let block = Block::decode(bytes).unwrap();
            assert_eq!(block.encode(), *bytes);
        }
    }
}

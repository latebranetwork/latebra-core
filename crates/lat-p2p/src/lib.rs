//! Latebra peer-to-peer networking over TCP (clean-room, from `SPEC.md`).
//!
//! This is **real over-the-wire networking**: a node listens on a socket, peers
//! connect by address, and they exchange blocks with a tiny length-prefixed
//! protocol. The trustless sync logic from the chain still applies — every block
//! a node receives is fully re-validated (PoW, proofs, linkage) before adoption.
//!
//! ## Honest scope
//! This uses plain TCP (`std::net`, thread-per-connection). It is sufficient for a
//! testnet of known nodes. It does NOT yet provide what libp2p would add on top:
//! transport encryption, stream multiplexing, NAT traversal, and automatic peer
//! discovery (DHT/mDNS). Those are a production upgrade — the message protocol and
//! sync logic here are what they'd carry.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use lat_chain::{Block, Blockchain, Certificate, Mempool, Vote};
use lat_types::Transaction;

/// P2P protocol version. Nodes refuse to peer across a version mismatch — a
/// simple guard so an incompatible wire format can't corrupt a sync. Bump it on
/// any breaking change to the [`Msg`] codec or sync semantics.
/// v2: finality gossip (T14/T16) + tx gossip and compact block announces (T17).
/// v3: native DEX + HTLC bridge — new transaction tags (0x0F–0x14), new state
/// records in snapshots/fast-sync, and the pool/HTLC read RPCs (tags 38–44).
pub const PROTOCOL_VERSION: u32 = 3;

/// Consecutive contact failures before a peer is evicted from the set. Keeps the
/// peer list self-healing: a node that goes offline is forgotten instead of
/// being retried forever.
pub const MAX_PEER_FAILURES: u32 = 5;

/// How long a client waits to establish a TCP connection to a peer before giving
/// up. Without a timeout a single unreachable peer (a stale persisted address)
/// could stall the whole discovery loop on a slow OS connect.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on a single wire message. The length prefix is peer-controlled;
/// without a cap a hostile peer could ask us to allocate 4 GiB (`u32::MAX`).
/// 4 MiB comfortably fits the largest legitimate message (a full block).
pub const MAX_MSG_BYTES: usize = 4 * 1024 * 1024;

/// Max simultaneous **inbound** connections a served node handles (audit
/// finding P-1). Beyond this, a new connection is closed immediately, so a
/// flood of sockets can't spawn unbounded threads or exhaust file descriptors.
pub const MAX_INBOUND_CONNS: usize = 128;

/// Idle/stall timeout on a served connection's socket reads and writes (P-1).
/// A peer that connects — or sends a length prefix — then goes silent is
/// dropped instead of pinning a thread and its read buffer forever (slowloris).
/// Generous enough for any inter-message gap during active sync.
pub const CONN_IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Lock the shared node, recovering from a poisoned lock. A worker thread that
/// panicked while holding the lock must not take the whole node down with it —
/// state transitions are applied atomically (validated on a clone, then
/// swapped), so the data is consistent even after a panic.
pub fn lock_node(node: &SharedNode) -> std::sync::MutexGuard<'_, NodeState> {
    node.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Most peer addresses a node keeps / returns in one `Peers` message. Learned
/// addresses are peer-supplied — cap them so a hostile peer can't balloon state.
pub const MAX_PEERS: usize = 64;
/// Longest peer address string accepted (host:port or DNS name).
pub const MAX_PEER_ADDR_LEN: usize = 128;
/// Most locator ids accepted in a `FindCommon` request.
pub const MAX_LOCATOR_IDS: usize = 64;
/// Most unbonding entries accepted in a `StakeReply` — a sane bound so a peer
/// can't make us loop over a huge (frame-bounded, but still nonsense) count.
pub const MAX_UNBONDING_ENTRIES: usize = 1024;

/// A node's mutable state: its chain, mempool, the address its mined blocks pay
/// coinbase rewards to (`[0; 32]` = don't claim rewards), and the peer
/// addresses it knows (seeds + learned via `Hello`/`GetPeers`).
/// A known peer and its recent contact health.
struct Peer {
    addr: String,
    /// Consecutive failed contacts; reset to 0 on success, evicted at
    /// [`MAX_PEER_FAILURES`].
    failures: u32,
}

/// One vote bucket: validator id → vote signature.
type VoteBucket = HashMap<[u8; 32], [u8; 64]>;

pub struct NodeState {
    pub chain: Blockchain,
    pub mempool: Mempool,
    pub miner: [u8; 32],
    peers: Vec<Peer>,
    /// This node's own advertised address, if known — never recorded as a peer
    /// (a node must not try to sync from itself).
    self_addr: Option<String>,
    /// T14 finality vote pool: `(height, block id)` → validator → signature.
    /// First vote per validator per bucket wins; pruned as blocks finalize.
    votes: HashMap<(u64, [u8; 32]), VoteBucket>,
    /// If set, this node is a validator: it signs a finality [`Vote`] for
    /// every block it adopts as its tip ([`cast_vote`](Self::cast_vote)).
    validator_key: Option<lat_crypto::SecretKey>,
}

impl NodeState {
    pub fn new(chain: Blockchain) -> Self {
        NodeState {
            chain,
            mempool: Mempool::new(),
            miner: [0u8; 32],
            peers: Vec::new(),
            self_addr: None,
            votes: HashMap::new(),
            validator_key: None,
        }
    }

    /// Like [`new`](Self::new) but mined blocks reward `miner`.
    pub fn with_miner(chain: Blockchain, miner: [u8; 32]) -> Self {
        let mut n = Self::new(chain);
        n.miner = miner;
        n
    }

    /// Make this node a validator: it will vote for blocks it adopts. The key
    /// must belong to a staked account or its votes are simply ignored.
    pub fn set_validator_key(&mut self, sk: lat_crypto::SecretKey) {
        self.validator_key = Some(sk);
    }

    /// Record this node's own advertised address so it's never added as a peer.
    pub fn set_self_addr(&mut self, addr: &str) {
        self.self_addr = Some(addr.trim().to_string());
    }

    /// Record a peer address (deduplicated, size- and count-capped, and never our
    /// own address). Returns whether it was newly added.
    pub fn add_peer(&mut self, addr: &str) -> bool {
        let addr = addr.trim();
        if addr.is_empty()
            || addr.len() > MAX_PEER_ADDR_LEN
            || self.self_addr.as_deref() == Some(addr)
            || self.peers.len() >= MAX_PEERS
            || self.peers.iter().any(|p| p.addr == addr)
        {
            return false;
        }
        self.peers.push(Peer { addr: addr.to_string(), failures: 0 });
        true
    }

    /// Forget a peer (e.g. one that failed the genesis handshake). Returns
    /// whether it was present.
    pub fn remove_peer(&mut self, addr: &str) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| p.addr != addr);
        self.peers.len() != before
    }

    /// Mark a successful contact with `addr`, clearing its failure count.
    pub fn record_peer_ok(&mut self, addr: &str) {
        if let Some(p) = self.peers.iter_mut().find(|p| p.addr == addr) {
            p.failures = 0;
        }
    }

    /// Mark a failed contact with `addr`. After [`MAX_PEER_FAILURES`] consecutive
    /// failures the peer is evicted. Returns whether the peer was evicted.
    pub fn record_peer_failure(&mut self, addr: &str) -> bool {
        if let Some(p) = self.peers.iter_mut().find(|p| p.addr == addr) {
            p.failures += 1;
            if p.failures >= MAX_PEER_FAILURES {
                self.peers.retain(|p| p.addr != addr);
                return true;
            }
        }
        false
    }

    /// The peer addresses this node currently knows.
    pub fn peers(&self) -> Vec<String> {
        self.peers.iter().map(|p| p.addr.clone()).collect()
    }

    /// Number of known peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Persist the known peer addresses to `path`, one per line, so the node
    /// rejoins the network on restart without needing `--peer` again. Best-effort.
    pub fn save_peers(&self, path: &Path) -> io::Result<()> {
        let body = self.peers.iter().map(|p| p.addr.as_str()).collect::<Vec<_>>().join("\n");
        std::fs::write(path, body)
    }

    /// Load peer addresses previously written by [`save_peers`](Self::save_peers),
    /// adding each (subject to the usual dedup / self / cap rules). Returns how
    /// many new peers were added. Missing file is not an error (returns 0).
    pub fn load_peers(&mut self, path: &Path) -> usize {
        let Ok(body) = std::fs::read_to_string(path) else {
            return 0;
        };
        body.lines().filter(|l| self.add_peer(l)).count()
    }

    /// Submit a transaction to the mempool. Returns `false` if it's a duplicate.
    pub fn submit_tx(&mut self, tx: Transaction) -> bool {
        // Gate on the stateless consensus rules first, so transactions a block
        // would never be allowed to contain (bad registration PoW, the legacy
        // unsound transfer, underpaid fees, oversized contracts) can't occupy
        // mempool space. State-dependent validity (solvency, nonce) is still
        // enforced when a block is built (`select_valid`).
        if lat_chain::check_tx(&tx).is_err() {
            return false;
        }
        self.mempool.add(tx)
    }

    /// Drain up to `max` mempool transactions, mine a block on the tip (paying the
    /// coinbase to `self.miner`), and apply it. Returns the encoded block to gossip.
    ///
    /// Drained transactions are filtered against current state first, so one bad
    /// mempool tx (stale nonce, duplicate ticker, bad signature, ...) is simply
    /// dropped instead of invalidating the whole mined block.
    pub fn produce_block(&mut self, max: usize) -> Option<Vec<u8>> {
        // Anonymous spends are epoch-scoped: drop any whose epoch can't match
        // the block about to be built.
        self.mempool.prune_expired(self.chain.height() + 1);
        let txs = self.chain.select_valid(self.mempool.drain(max));
        let block = self.chain.mine_with_reward(self.miner, txs);
        match self.chain.apply_block(&block) {
            Ok(()) => Some(block.encode()),
            Err(_) => None,
        }
    }

    /// Pool a finality vote from the network (or our own [`cast_vote`]).
    /// Returns `(newly pooled, certificate bytes if this vote completed one)`.
    /// A vote is pooled only if it is for a block on OUR active chain inside
    /// the recent set window, above the watermark, signed by a member of that
    /// block's validator set. When the pooled stake crosses 2/3 of the set, a
    /// [`Certificate`] is built, adopted (`Blockchain::try_finalize`), and
    /// returned for gossip.
    pub fn add_vote(&mut self, bytes: &[u8]) -> (bool, Option<Vec<u8>>) {
        let Some(vote) = Vote::decode(bytes) else { return (false, None) };
        if let Some((fh, _)) = self.chain.finalized() {
            if vote.height <= fh {
                return (false, None);
            }
        }
        if self.chain.active_id_at(vote.height) != Some(vote.block_id) {
            return (false, None);
        }
        // Copy what we need from the set before touching the pool (borrows).
        let Some(set) = self.chain.validator_set_at(vote.height).map(|s| s.to_vec()) else {
            return (false, None);
        };
        if !set.iter().any(|(id, _)| *id == vote.validator) || !vote.verify() {
            return (false, None);
        }

        let bucket = self.votes.entry((vote.height, vote.block_id)).or_default();
        if bucket.contains_key(&vote.validator) {
            return (false, None); // already pooled — gossip loop dies here
        }
        bucket.insert(vote.validator, vote.sig);

        let total: u128 = set.iter().map(|(_, s)| *s as u128).sum();
        let voted: u128 = set
            .iter()
            .filter(|(id, _)| bucket.contains_key(id))
            .map(|(_, s)| *s as u128)
            .sum();
        if 3 * voted > 2 * total {
            // Deterministic vote order (by validator id) for a canonical cert.
            let mut votes: Vec<([u8; 32], [u8; 64])> =
                bucket.iter().map(|(v, s)| (*v, *s)).collect();
            votes.sort_by_key(|(validator, _)| *validator);
            let cert = Certificate { block_id: vote.block_id, height: vote.height, votes };
            if self.chain.try_finalize(&cert) {
                let fh = vote.height;
                self.votes.retain(|(h, _), _| *h > fh);
                return (true, Some(cert.encode()));
            }
        }
        (true, None)
    }

    /// Adopt a finality certificate from a peer. `true` only if it advanced
    /// our watermark (so certificate gossip floods once and dies out).
    pub fn accept_cert(&mut self, bytes: &[u8]) -> bool {
        let Some(cert) = Certificate::decode(bytes) else { return false };
        if self.chain.try_finalize(&cert) {
            let fh = cert.height;
            self.votes.retain(|(h, _), _| *h > fh);
            true
        } else {
            false
        }
    }

    /// If this node is a validator, sign a vote for the current tip and pool
    /// it. Returns `(vote bytes to gossip, certificate bytes if it completed
    /// one)` — `None` when not a validator, not staked, or already voted.
    pub fn cast_vote(&mut self) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let sk = self.validator_key.as_ref()?;
        let vote = Vote::sign(sk, self.chain.tip(), self.chain.height());
        let bytes = vote.encode();
        let (pooled, cert) = self.add_vote(&bytes);
        pooled.then_some((bytes, cert))
    }

    /// Accept an encoded block from a peer. The chain's fork-choice decides what
    /// to do (extend, store as a side branch, or reorg); on success the block's
    /// transactions are dropped from the mempool. Returns whether it was accepted
    /// (a valid block, even if only stored as a side branch).
    pub fn accept_block_bytes(&mut self, bytes: &[u8]) -> bool {
        let Some(block) = Block::decode(bytes) else {
            return false;
        };
        if self.chain.apply_block(&block).is_ok() {
            self.mempool.remove_included(&block.txs);
            self.mempool.prune_expired(self.chain.height() + 1);
            true
        } else {
            false
        }
    }
}

/// A shared, lockable node a server serves from and a miner advances.
pub type SharedNode = Arc<Mutex<NodeState>>;

/// Wire messages exchanged between peers.
#[derive(Debug, PartialEq, Eq)]
enum Msg {
    /// Ask for the peer's current height.
    GetTip,
    /// Reply: current height.
    Tip(u64),
    /// Ask for the encoded block at a height.
    GetBlock(u64),
    /// Reply: encoded block bytes, or `None` if the peer doesn't have it.
    Block(Option<Vec<u8>>),
    /// Push a newly mined block to a peer (gossip).
    NewBlock(Vec<u8>),
    /// Reply to `NewBlock` / `SubmitTx`: whether it was accepted.
    Ack(bool),
    /// RPC: submit an encoded transaction to the node's mempool.
    SubmitTx(Vec<u8>),
    /// RPC: ask for an account's encrypted balance of a token.
    GetBalance { id: [u8; 32], token: u32 },
    /// Reply: the 64-byte encrypted balance, or `None` if not registered.
    BalanceReply(Option<Vec<u8>>),
    /// RPC: ask for an account's current spend nonce.
    GetNonce([u8; 32]),
    /// Reply: the nonce, or `None` if not registered.
    NonceReply(Option<u64>),
    /// RPC: ask for an account's pending (received, not rolled-over) balance.
    GetPending { id: [u8; 32], token: u32 },
    /// Peer exchange: "I'm a node too — here's the address I listen on."
    Hello(String),
    /// Peer exchange: ask for the peer's known node addresses.
    GetPeers,
    /// Reply: known node addresses (capped at [`MAX_PEERS`]).
    Peers(Vec<String>),
    /// Fork sync: a block locator (active-chain ids, newest first). The peer
    /// replies with the height of the most recent id on ITS active chain — the
    /// common ancestor to resume syncing from.
    FindCommon(Vec<[u8; 32]>),
    /// Reply to `FindCommon`: the height of the best shared active block.
    CommonHeight(u64),
    /// RPC: ask for an account's transparent (plaintext) public balance.
    GetPublicBalance { id: [u8; 32], token: u32 },
    /// Reply: the public balance, or `None` if the account isn't registered.
    PublicBalanceReply(Option<u64>),
    /// RPC: ask for up to `max` anonymous-transfer ring candidates for `token`
    /// (accounts holding a confidential balance, with their ciphertexts).
    GetRingCandidates { token: u32, max: u32 },
    /// Reply: `(account id, 64-byte encrypted balance)` pairs.
    RingCandidates(Vec<([u8; 32], [u8; 64])>),
    /// Network handshake: "I speak protocol `version`, my chain's genesis is
    /// `genesis`, reach me at `addr`." The receiver records `addr` only if it's
    /// compatible (same genesis + version), so cross-network peers never enter
    /// each other's peer sets.
    Handshake { version: u32, genesis: [u8; 32], addr: String },
    /// Reply to `Handshake`: the responder's own version + genesis, and whether
    /// it accepted the peer as compatible. The initiator double-checks the
    /// returned genesis against its own (defense in depth).
    HandshakeAck { version: u32, genesis: [u8; 32], accepted: bool },
    /// RPC: read a deployed contract's storage slot `key`. Contract storage is
    /// public by design (e.g. a bonding curve's reserves), so the node returns
    /// the value directly.
    GetContractStorage { contract: [u8; 32], key: u64 },
    /// Reply: the slot value (0 if the contract or slot is unset).
    ContractStorageReply(u64),
    /// RPC: ask whether a contract is deployed at `id`. Replied with `Ack`.
    HasContract([u8; 32]),
    /// T14 finality gossip: an encoded [`Vote`]. Replied with `Ack` (whether
    /// it was newly pooled); newly pooled votes flood on to peers.
    FinalityVote(Vec<u8>),
    /// T14 finality gossip: an encoded [`Certificate`]. Replied with `Ack`
    /// (whether it advanced the watermark); advancing certs flood on.
    FinalityCert(Vec<u8>),
    /// RPC: ask for the node's finality watermark.
    GetFinalized,
    /// Reply: the finalized `(height, block id)`, or `None` if nothing has
    /// been certified yet.
    FinalizedReply(Option<(u64, [u8; 32])>),
    /// RPC: ask for an account's staking state (T13/T16).
    GetStake([u8; 32]),
    /// Reply: `(bonded stake, unbonding entries as (amount, release height))`.
    StakeReply(u64, Vec<(u64, u64)>),
    /// RPC: ask for the DEX pool of `token`.
    GetPool(u32),
    /// Reply: `(lat reserve, token reserve, LP supply)`, or `None` if no pool.
    PoolReply(Option<(u64, u64, u64)>),
    /// RPC: ask for an account's LP shares in the pool of `token`. Replied
    /// with `PublicBalanceReply` (shares are a public u64, same shape).
    GetLpShares { token: u32, id: [u8; 32] },
    /// RPC: ask for the open HTLC with this id.
    GetHtlc([u8; 32]),
    /// Reply: `(token, from, to, amount, hashlock, expiry)`, or `None`.
    HtlcReply(Option<(u32, [u8; 32], [u8; 32], u64, [u8; 32], u64)>),
    /// RPC: ask for every open HTLC (bridge UIs filter client-side; testnet
    /// scale — a paginated form can come later).
    GetHtlcs,
    /// Reply: `(id, token, from, to, amount, hashlock, expiry)` per lock.
    HtlcsReply(Vec<([u8; 32], u32, [u8; 32], [u8; 32], u64, [u8; 32], u64)>),
    /// RPC: ask for `token`'s native bonding curve.
    GetCurve(u32),
    /// Reply: `(vlat, vtok, real_lat, graduated)`, or `None` if no curve.
    CurveReply(Option<(u64, u64, u64, bool)>),
    /// T17 tx gossip: an encoded transaction, flooding node-to-node so a tx
    /// submitted anywhere reaches every miner's mempool. Replied with `Ack`
    /// (whether it was newly added); newly added txs flood on.
    NewTx(Vec<u8>),
    /// T17 compact block announce: `(block id, height)`. The receiver replies
    /// `Ack(true)` iff it does NOT have the block — "send it" — so a ~100-byte
    /// announce replaces re-transmitting whole blocks to peers that already
    /// hold them. The announcer follows up with `NewBlock` on the same
    /// connection when asked.
    BlockAnnounce { id: [u8; 32], height: u64 },
    /// T19 fast sync: ask for the peer's state-sync manifest. The peer
    /// captures its tip anchor + full object-record set atomically (one node
    /// lock) and keeps it FOR THIS CONNECTION, so subsequent chunk requests
    /// see one consistent state even while the peer keeps mining.
    GetStateManifest,
    /// Reply: the anchor block `(height, id)` the records describe, the total
    /// record count, and how many chunks to fetch. `chunk_count == 0` means
    /// the peer can't serve fast sync (fresh chain) — full-sync instead.
    StateManifest { anchor_height: u64, anchor_id: [u8; 32], record_count: u64, chunk_count: u32 },
    /// T19 fast sync: ask for chunk `n` (0-based) of the manifest previously
    /// captured on this connection.
    GetStateChunk(u32),
    /// Reply: that chunk's `(key, value)` object records — raw
    /// `Column::Objects` entries. Empty if out of range or no manifest was
    /// captured on this connection. The records need no per-chunk digests:
    /// the syncing node rebuilds the state commitment from them and accepts
    /// only if the derived root matches the anchor header's PoW-bound
    /// `state_root`, so any tampering is caught wholesale.
    StateChunk(Vec<(Vec<u8>, Vec<u8>)>),
}

/// T19: payload budget per [`Msg::StateChunk`] (sum of key+value bytes).
/// Comfortably under [`MAX_MSG_BYTES`] once per-record length prefixes are
/// added.
const STATE_CHUNK_BYTES: usize = 1024 * 1024;

/// Cap on ring candidates returned by one RPC (bounds the reply size; well
/// above [`lat_chain::MAX_RING_SIZE`] so wallets can still sample freely).
pub const MAX_RING_CANDIDATES: usize = 64;

impl Msg {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        match self {
            Msg::GetTip => v.push(0),
            Msg::Tip(h) => {
                v.push(1);
                v.extend_from_slice(&h.to_le_bytes());
            }
            Msg::GetBlock(h) => {
                v.push(2);
                v.extend_from_slice(&h.to_le_bytes());
            }
            Msg::Block(opt) => {
                v.push(3);
                match opt {
                    Some(b) => {
                        v.push(1);
                        v.extend_from_slice(b);
                    }
                    None => v.push(0),
                }
            }
            Msg::NewBlock(b) => {
                v.push(4);
                v.extend_from_slice(b);
            }
            Msg::Ack(ok) => {
                v.push(5);
                v.push(*ok as u8);
            }
            Msg::SubmitTx(b) => {
                v.push(6);
                v.extend_from_slice(b);
            }
            Msg::GetBalance { id, token } => {
                v.push(7);
                v.extend_from_slice(id);
                v.extend_from_slice(&token.to_le_bytes());
            }
            Msg::BalanceReply(opt) => {
                v.push(8);
                match opt {
                    Some(b) => {
                        v.push(1);
                        v.extend_from_slice(b);
                    }
                    None => v.push(0),
                }
            }
            Msg::GetNonce(id) => {
                v.push(9);
                v.extend_from_slice(id);
            }
            Msg::NonceReply(opt) => {
                v.push(10);
                match opt {
                    Some(n) => {
                        v.push(1);
                        v.extend_from_slice(&n.to_le_bytes());
                    }
                    None => v.push(0),
                }
            }
            Msg::GetPending { id, token } => {
                v.push(11);
                v.extend_from_slice(id);
                v.extend_from_slice(&token.to_le_bytes());
            }
            Msg::Hello(addr) => {
                v.push(12);
                v.extend_from_slice(addr.as_bytes());
            }
            Msg::GetPeers => v.push(13),
            Msg::Peers(list) => {
                v.push(14);
                v.push(list.len().min(MAX_PEERS) as u8);
                for p in list.iter().take(MAX_PEERS) {
                    let b = p.as_bytes();
                    v.push(b.len().min(MAX_PEER_ADDR_LEN) as u8);
                    v.extend_from_slice(&b[..b.len().min(MAX_PEER_ADDR_LEN)]);
                }
            }
            Msg::FindCommon(ids) => {
                v.push(15);
                v.push(ids.len().min(MAX_LOCATOR_IDS) as u8);
                for id in ids.iter().take(MAX_LOCATOR_IDS) {
                    v.extend_from_slice(id);
                }
            }
            Msg::CommonHeight(h) => {
                v.push(16);
                v.extend_from_slice(&h.to_le_bytes());
            }
            Msg::GetPublicBalance { id, token } => {
                v.push(17);
                v.extend_from_slice(id);
                v.extend_from_slice(&token.to_le_bytes());
            }
            Msg::PublicBalanceReply(opt) => {
                v.push(18);
                match opt {
                    Some(n) => {
                        v.push(1);
                        v.extend_from_slice(&n.to_le_bytes());
                    }
                    None => v.push(0),
                }
            }
            Msg::GetRingCandidates { token, max } => {
                v.push(19);
                v.extend_from_slice(&token.to_le_bytes());
                v.extend_from_slice(&max.to_le_bytes());
            }
            Msg::RingCandidates(list) => {
                v.push(20);
                let n = list.len().min(MAX_RING_CANDIDATES);
                v.extend_from_slice(&(n as u32).to_le_bytes());
                for (id, ct) in list.iter().take(n) {
                    v.extend_from_slice(id);
                    v.extend_from_slice(ct);
                }
            }
            Msg::Handshake { version, genesis, addr } => {
                v.push(21);
                v.extend_from_slice(&version.to_le_bytes());
                v.extend_from_slice(genesis);
                let b = addr.as_bytes();
                v.push(b.len().min(MAX_PEER_ADDR_LEN) as u8);
                v.extend_from_slice(&b[..b.len().min(MAX_PEER_ADDR_LEN)]);
            }
            Msg::HandshakeAck { version, genesis, accepted } => {
                v.push(22);
                v.extend_from_slice(&version.to_le_bytes());
                v.extend_from_slice(genesis);
                v.push(*accepted as u8);
            }
            Msg::GetContractStorage { contract, key } => {
                v.push(23);
                v.extend_from_slice(contract);
                v.extend_from_slice(&key.to_le_bytes());
            }
            Msg::ContractStorageReply(val) => {
                v.push(24);
                v.extend_from_slice(&val.to_le_bytes());
            }
            Msg::FinalityVote(b) => {
                v.push(26);
                v.extend_from_slice(b);
            }
            Msg::FinalityCert(b) => {
                v.push(27);
                v.extend_from_slice(b);
            }
            Msg::GetFinalized => v.push(28),
            Msg::FinalizedReply(opt) => {
                v.push(29);
                match opt {
                    Some((h, id)) => {
                        v.push(1);
                        v.extend_from_slice(&h.to_le_bytes());
                        v.extend_from_slice(id);
                    }
                    None => v.push(0),
                }
            }
            Msg::GetStake(id) => {
                v.push(30);
                v.extend_from_slice(id);
            }
            Msg::NewTx(b) => {
                v.push(32);
                v.extend_from_slice(b);
            }
            Msg::BlockAnnounce { id, height } => {
                v.push(33);
                v.extend_from_slice(id);
                v.extend_from_slice(&height.to_le_bytes());
            }
            Msg::StakeReply(staked, unbonding) => {
                v.push(31);
                v.extend_from_slice(&staked.to_le_bytes());
                v.extend_from_slice(&(unbonding.len() as u32).to_le_bytes());
                for (amount, release) in unbonding {
                    v.extend_from_slice(&amount.to_le_bytes());
                    v.extend_from_slice(&release.to_le_bytes());
                }
            }
            Msg::HasContract(id) => {
                v.push(25);
                v.extend_from_slice(id);
            }
            Msg::GetStateManifest => v.push(34),
            Msg::StateManifest { anchor_height, anchor_id, record_count, chunk_count } => {
                v.push(35);
                v.extend_from_slice(&anchor_height.to_le_bytes());
                v.extend_from_slice(anchor_id);
                v.extend_from_slice(&record_count.to_le_bytes());
                v.extend_from_slice(&chunk_count.to_le_bytes());
            }
            Msg::GetStateChunk(n) => {
                v.push(36);
                v.extend_from_slice(&n.to_le_bytes());
            }
            Msg::StateChunk(records) => {
                v.push(37);
                v.extend_from_slice(&(records.len() as u32).to_le_bytes());
                for (key, value) in records {
                    v.extend_from_slice(&(key.len() as u32).to_le_bytes());
                    v.extend_from_slice(key);
                    v.extend_from_slice(&(value.len() as u32).to_le_bytes());
                    v.extend_from_slice(value);
                }
            }
            Msg::GetPool(token) => {
                v.push(38);
                v.extend_from_slice(&token.to_le_bytes());
            }
            Msg::PoolReply(opt) => {
                v.push(39);
                match opt {
                    Some((lat, tok, lp)) => {
                        v.push(1);
                        v.extend_from_slice(&lat.to_le_bytes());
                        v.extend_from_slice(&tok.to_le_bytes());
                        v.extend_from_slice(&lp.to_le_bytes());
                    }
                    None => v.push(0),
                }
            }
            Msg::GetLpShares { token, id } => {
                v.push(40);
                v.extend_from_slice(&token.to_le_bytes());
                v.extend_from_slice(id);
            }
            Msg::GetHtlc(id) => {
                v.push(41);
                v.extend_from_slice(id);
            }
            Msg::HtlcReply(opt) => {
                v.push(42);
                match opt {
                    Some((token, from, to, amount, hashlock, expiry)) => {
                        v.push(1);
                        v.extend_from_slice(&token.to_le_bytes());
                        v.extend_from_slice(from);
                        v.extend_from_slice(to);
                        v.extend_from_slice(&amount.to_le_bytes());
                        v.extend_from_slice(hashlock);
                        v.extend_from_slice(&expiry.to_le_bytes());
                    }
                    None => v.push(0),
                }
            }
            Msg::GetHtlcs => v.push(43),
            Msg::HtlcsReply(locks) => {
                v.push(44);
                v.extend_from_slice(&(locks.len() as u32).to_le_bytes());
                for (id, token, from, to, amount, hashlock, expiry) in locks {
                    v.extend_from_slice(id);
                    v.extend_from_slice(&token.to_le_bytes());
                    v.extend_from_slice(from);
                    v.extend_from_slice(to);
                    v.extend_from_slice(&amount.to_le_bytes());
                    v.extend_from_slice(hashlock);
                    v.extend_from_slice(&expiry.to_le_bytes());
                }
            }
            Msg::GetCurve(token) => {
                v.push(45);
                v.extend_from_slice(&token.to_le_bytes());
            }
            Msg::CurveReply(opt) => {
                v.push(46);
                match opt {
                    Some((vlat, vtok, real_lat, graduated)) => {
                        v.push(1);
                        v.extend_from_slice(&vlat.to_le_bytes());
                        v.extend_from_slice(&vtok.to_le_bytes());
                        v.extend_from_slice(&real_lat.to_le_bytes());
                        v.push(*graduated as u8);
                    }
                    None => v.push(0),
                }
            }
        }
        v
    }

    fn decode(b: &[u8]) -> Option<Msg> {
        let (&tag, rest) = b.split_first()?;
        Some(match tag {
            0 => Msg::GetTip,
            1 => Msg::Tip(u64::from_le_bytes(rest.get(0..8)?.try_into().ok()?)),
            2 => Msg::GetBlock(u64::from_le_bytes(rest.get(0..8)?.try_into().ok()?)),
            3 => match rest.first()? {
                0 => Msg::Block(None),
                1 => Msg::Block(Some(rest.get(1..)?.to_vec())),
                _ => return None,
            },
            4 => Msg::NewBlock(rest.to_vec()),
            5 => Msg::Ack(*rest.first()? != 0),
            6 => Msg::SubmitTx(rest.to_vec()),
            7 => Msg::GetBalance {
                id: rest.get(0..32)?.try_into().ok()?,
                token: u32::from_le_bytes(rest.get(32..36)?.try_into().ok()?),
            },
            8 => match rest.first()? {
                0 => Msg::BalanceReply(None),
                1 => Msg::BalanceReply(Some(rest.get(1..)?.to_vec())),
                _ => return None,
            },
            9 => Msg::GetNonce(rest.get(0..32)?.try_into().ok()?),
            10 => match rest.first()? {
                0 => Msg::NonceReply(None),
                1 => Msg::NonceReply(Some(u64::from_le_bytes(rest.get(1..9)?.try_into().ok()?))),
                _ => return None,
            },
            11 => Msg::GetPending {
                id: rest.get(0..32)?.try_into().ok()?,
                token: u32::from_le_bytes(rest.get(32..36)?.try_into().ok()?),
            },
            12 => {
                if rest.len() > MAX_PEER_ADDR_LEN {
                    return None;
                }
                Msg::Hello(String::from_utf8(rest.to_vec()).ok()?)
            }
            13 => Msg::GetPeers,
            14 => {
                let count = *rest.first()? as usize;
                if count > MAX_PEERS {
                    return None;
                }
                let mut off = 1;
                let mut list = Vec::new();
                for _ in 0..count {
                    let len = *rest.get(off)? as usize;
                    if len > MAX_PEER_ADDR_LEN {
                        return None;
                    }
                    off += 1;
                    let s = String::from_utf8(rest.get(off..off + len)?.to_vec()).ok()?;
                    off += len;
                    list.push(s);
                }
                Msg::Peers(list)
            }
            15 => {
                let count = *rest.first()? as usize;
                if count > MAX_LOCATOR_IDS {
                    return None;
                }
                let mut ids = Vec::new();
                for i in 0..count {
                    ids.push(rest.get(1 + i * 32..1 + (i + 1) * 32)?.try_into().ok()?);
                }
                Msg::FindCommon(ids)
            }
            16 => Msg::CommonHeight(u64::from_le_bytes(rest.get(0..8)?.try_into().ok()?)),
            17 => Msg::GetPublicBalance {
                id: rest.get(0..32)?.try_into().ok()?,
                token: u32::from_le_bytes(rest.get(32..36)?.try_into().ok()?),
            },
            18 => match rest.first()? {
                0 => Msg::PublicBalanceReply(None),
                1 => Msg::PublicBalanceReply(Some(u64::from_le_bytes(rest.get(1..9)?.try_into().ok()?))),
                _ => return None,
            },
            19 => Msg::GetRingCandidates {
                token: u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?),
                max: u32::from_le_bytes(rest.get(4..8)?.try_into().ok()?),
            },
            20 => {
                let count = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?) as usize;
                if count > MAX_RING_CANDIDATES {
                    return None;
                }
                let mut list = Vec::new();
                for i in 0..count {
                    let off = 4 + i * 96;
                    let id: [u8; 32] = rest.get(off..off + 32)?.try_into().ok()?;
                    let ct: [u8; 64] = rest.get(off + 32..off + 96)?.try_into().ok()?;
                    list.push((id, ct));
                }
                Msg::RingCandidates(list)
            }
            21 => {
                let version = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?);
                let genesis: [u8; 32] = rest.get(4..36)?.try_into().ok()?;
                let len = *rest.get(36)? as usize;
                if len > MAX_PEER_ADDR_LEN {
                    return None;
                }
                let addr = String::from_utf8(rest.get(37..37 + len)?.to_vec()).ok()?;
                Msg::Handshake { version, genesis, addr }
            }
            22 => {
                let version = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?);
                let genesis: [u8; 32] = rest.get(4..36)?.try_into().ok()?;
                let accepted = *rest.get(36)? != 0;
                Msg::HandshakeAck { version, genesis, accepted }
            }
            23 => Msg::GetContractStorage {
                contract: rest.get(0..32)?.try_into().ok()?,
                key: u64::from_le_bytes(rest.get(32..40)?.try_into().ok()?),
            },
            24 => Msg::ContractStorageReply(u64::from_le_bytes(rest.get(0..8)?.try_into().ok()?)),
            25 => Msg::HasContract(rest.get(0..32)?.try_into().ok()?),
            26 => Msg::FinalityVote(rest.to_vec()),
            27 => Msg::FinalityCert(rest.to_vec()),
            28 => Msg::GetFinalized,
            30 => Msg::GetStake(rest.get(0..32)?.try_into().ok()?),
            32 => Msg::NewTx(rest.to_vec()),
            33 => {
                if rest.len() != 40 {
                    return None;
                }
                Msg::BlockAnnounce {
                    id: rest.get(0..32)?.try_into().ok()?,
                    height: u64::from_le_bytes(rest.get(32..40)?.try_into().ok()?),
                }
            }
            31 => {
                let staked = u64::from_le_bytes(rest.get(0..8)?.try_into().ok()?);
                let count = u32::from_le_bytes(rest.get(8..12)?.try_into().ok()?) as usize;
                // Cap the record count before looping, like the other arms —
                // the frame cap already bounds it, but reject nonsense early.
                if count > MAX_UNBONDING_ENTRIES {
                    return None;
                }
                let mut unbonding = Vec::new();
                let mut off = 12;
                for _ in 0..count {
                    unbonding.push((
                        u64::from_le_bytes(rest.get(off..off + 8)?.try_into().ok()?),
                        u64::from_le_bytes(rest.get(off + 8..off + 16)?.try_into().ok()?),
                    ));
                    off += 16;
                }
                if off != rest.len() {
                    return None;
                }
                Msg::StakeReply(staked, unbonding)
            }
            29 => match rest.first()? {
                0 => Msg::FinalizedReply(None),
                1 => Msg::FinalizedReply(Some((
                    u64::from_le_bytes(rest.get(1..9)?.try_into().ok()?),
                    rest.get(9..41)?.try_into().ok()?,
                ))),
                _ => return None,
            },
            34 => Msg::GetStateManifest,
            35 => {
                if rest.len() != 52 {
                    return None;
                }
                Msg::StateManifest {
                    anchor_height: u64::from_le_bytes(rest.get(0..8)?.try_into().ok()?),
                    anchor_id: rest.get(8..40)?.try_into().ok()?,
                    record_count: u64::from_le_bytes(rest.get(40..48)?.try_into().ok()?),
                    chunk_count: u32::from_le_bytes(rest.get(48..52)?.try_into().ok()?),
                }
            }
            36 => Msg::GetStateChunk(u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?)),
            37 => {
                let count = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?) as usize;
                let mut records = Vec::with_capacity(count.min(1 << 16));
                let mut off = 4;
                for _ in 0..count {
                    let klen = u32::from_le_bytes(rest.get(off..off + 4)?.try_into().ok()?) as usize;
                    let key = rest.get(off + 4..off + 4 + klen)?.to_vec();
                    off += 4 + klen;
                    let vlen = u32::from_le_bytes(rest.get(off..off + 4)?.try_into().ok()?) as usize;
                    let value = rest.get(off + 4..off + 4 + vlen)?.to_vec();
                    off += 4 + vlen;
                    records.push((key, value));
                }
                if off != rest.len() {
                    return None;
                }
                Msg::StateChunk(records)
            }
            38 => Msg::GetPool(u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?)),
            39 => match rest.first()? {
                0 => Msg::PoolReply(None),
                1 => Msg::PoolReply(Some((
                    u64::from_le_bytes(rest.get(1..9)?.try_into().ok()?),
                    u64::from_le_bytes(rest.get(9..17)?.try_into().ok()?),
                    u64::from_le_bytes(rest.get(17..25)?.try_into().ok()?),
                ))),
                _ => return None,
            },
            40 => Msg::GetLpShares {
                token: u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?),
                id: rest.get(4..36)?.try_into().ok()?,
            },
            41 => Msg::GetHtlc(rest.get(0..32)?.try_into().ok()?),
            42 => match rest.first()? {
                0 => Msg::HtlcReply(None),
                1 => Msg::HtlcReply(Some((
                    u32::from_le_bytes(rest.get(1..5)?.try_into().ok()?),
                    rest.get(5..37)?.try_into().ok()?,
                    rest.get(37..69)?.try_into().ok()?,
                    u64::from_le_bytes(rest.get(69..77)?.try_into().ok()?),
                    rest.get(77..109)?.try_into().ok()?,
                    u64::from_le_bytes(rest.get(109..117)?.try_into().ok()?),
                ))),
                _ => return None,
            },
            43 => Msg::GetHtlcs,
            44 => {
                let count = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?) as usize;
                let mut locks = Vec::with_capacity(count.min(1 << 12));
                let mut off = 4;
                for _ in 0..count {
                    locks.push((
                        rest.get(off..off + 32)?.try_into().ok()?,
                        u32::from_le_bytes(rest.get(off + 32..off + 36)?.try_into().ok()?),
                        rest.get(off + 36..off + 68)?.try_into().ok()?,
                        rest.get(off + 68..off + 100)?.try_into().ok()?,
                        u64::from_le_bytes(rest.get(off + 100..off + 108)?.try_into().ok()?),
                        rest.get(off + 108..off + 140)?.try_into().ok()?,
                        u64::from_le_bytes(rest.get(off + 140..off + 148)?.try_into().ok()?),
                    ));
                    off += 148;
                }
                if off != rest.len() {
                    return None;
                }
                Msg::HtlcsReply(locks)
            }
            45 => Msg::GetCurve(u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?)),
            46 => match rest.first()? {
                0 => Msg::CurveReply(None),
                1 => Msg::CurveReply(Some((
                    u64::from_le_bytes(rest.get(1..9)?.try_into().ok()?),
                    u64::from_le_bytes(rest.get(9..17)?.try_into().ok()?),
                    u64::from_le_bytes(rest.get(17..25)?.try_into().ok()?),
                    match rest.get(25)? {
                        0 => false,
                        1 => true,
                        _ => return None,
                    },
                ))),
                _ => return None,
            },
            _ => return None,
        })
    }
}

fn write_msg(s: &mut impl Write, m: &Msg) -> io::Result<()> {
    let body = m.encode();
    s.write_all(&(body.len() as u32).to_le_bytes())?;
    s.write_all(&body)?;
    s.flush()
}

fn read_msg(s: &mut impl Read) -> io::Result<Msg> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_MSG_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Msg::decode(&buf).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad message"))
}

/// Serve a node to peers/clients on `listener`, spawning a thread per connection.
/// Returns the accept-loop handle. Bind the listener first (e.g. to
/// `127.0.0.1:0`) so you can read the assigned address before serving.
pub fn serve(listener: TcpListener, node: SharedNode) -> JoinHandle<()> {
    thread::spawn(move || {
        // Bound concurrent inbound connections (P-1): a flood of sockets must
        // not spawn unbounded threads. The counter is decremented when each
        // handler returns.
        let conns = Arc::new(AtomicUsize::new(0));
        for stream in listener.incoming().flatten() {
            if conns.fetch_add(1, Ordering::AcqRel) >= MAX_INBOUND_CONNS {
                conns.fetch_sub(1, Ordering::AcqRel);
                continue; // at capacity — drop the stream (closes it)
            }
            let node = Arc::clone(&node);
            let conns = Arc::clone(&conns);
            thread::spawn(move || {
                let _ = handle_conn(stream, node);
                conns.fetch_sub(1, Ordering::AcqRel);
            });
        }
    })
}

fn handle_conn(mut stream: TcpStream, node: SharedNode) -> io::Result<()> {
    // Slowloris / idle-open guard (P-1): a peer that stalls mid-message or holds
    // the socket open without sending is dropped rather than pinning this thread
    // and its buffer indefinitely. Best-effort — a platform that rejects the
    // sockopt just keeps the prior blocking behaviour.
    let _ = stream.set_read_timeout(Some(CONN_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONN_IO_TIMEOUT));
    // T19: state-sync manifest captured for THIS connection — anchor plus the
    // record set pre-split into reply-sized chunks. Kept out of the node lock
    // so serving chunks never blocks mining/RPC, and immune to the tip moving
    // between chunk requests.
    let mut state_sync: Option<Vec<Vec<(Vec<u8>, Vec<u8>)>>> = None;
    loop {
        let msg = match read_msg(&mut stream) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let reply = match msg {
            // --- block sync (peer protocol) ---
            Msg::GetTip => Msg::Tip(lock_node(&node).chain.height()),
            Msg::GetBlock(h) => {
                let bytes = lock_node(&node).chain.block_bytes(h).map(|b| b.to_vec());
                Msg::Block(bytes)
            }
            Msg::NewBlock(bytes) => {
                // Was the block new to us? Only then forward it, so a block
                // floods the network once and gossip loops die out (peers that
                // already have it don't re-announce).
                let header = Block::decode(&bytes).map(|b| (b.header.id(), b.header.height));
                let already_known = header
                    .map(|(id, _)| lock_node(&node).chain.has_block(&id))
                    .unwrap_or(false);
                let ok = lock_node(&node).accept_block_bytes(&bytes);
                if ok && !already_known {
                    // Vote for the newly adopted tip HERE, not on the node's
                    // heartbeat. Gossip is how a non-mining validator learns of
                    // a block, and adopting one used to cast no vote at all —
                    // so its vote waited for latebrad's 15s re-vote tick, which
                    // bounded finality at ~15s no matter how fast blocks came.
                    // The miner already votes on its own block, and the vote
                    // pool dedups, so this only adds the votes that were late.
                    let vote = lock_node(&node).cast_vote();
                    let peers = lock_node(&node).peers();
                    let fwd = bytes.clone();
                    thread::spawn(move || {
                        // T17: forward compactly — peers that already hold the
                        // block cost one 40-byte announce, not a whole block.
                        let (id, height) = header.expect("accepted block decodes");
                        for p in &peers {
                            let _ = announce_block_compact(p.as_str(), &id, height, &fwd);
                        }
                        // Flood the vote (and any certificate it just completed)
                        // the same way, so the quorum converges within the block.
                        if let Some((vote_bytes, cert)) = vote {
                            for p in &peers {
                                let _ = announce_vote(p.as_str(), &vote_bytes);
                            }
                            if let Some(cert) = cert {
                                for p in &peers {
                                    let _ = announce_cert(p.as_str(), &cert);
                                }
                            }
                        }
                    });
                }
                Msg::Ack(ok)
            }
            // --- finality gossip (T14): flood-once, like NewBlock ---
            Msg::FinalityVote(bytes) => {
                let (pooled, cert) = lock_node(&node).add_vote(&bytes);
                if pooled {
                    let peers = lock_node(&node).peers();
                    thread::spawn(move || {
                        for p in &peers {
                            let _ = announce_vote(p.as_str(), &bytes);
                        }
                        if let Some(cert) = cert {
                            for p in &peers {
                                let _ = announce_cert(p.as_str(), &cert);
                            }
                        }
                    });
                    Msg::Ack(true)
                } else {
                    Msg::Ack(false)
                }
            }
            Msg::FinalityCert(bytes) => {
                let advanced = lock_node(&node).accept_cert(&bytes);
                if advanced {
                    let peers = lock_node(&node).peers();
                    thread::spawn(move || {
                        for p in peers {
                            let _ = announce_cert(p.as_str(), &bytes);
                        }
                    });
                }
                Msg::Ack(advanced)
            }
            Msg::GetFinalized => Msg::FinalizedReply(lock_node(&node).chain.finalized()),
            Msg::GetStake(id) => {
                let n = lock_node(&node);
                Msg::StakeReply(n.chain.staked(&id), n.chain.unbonding(&id))
            }
            // --- peer exchange ---
            Msg::Hello(addr) => Msg::Ack(lock_node(&node).add_peer(&addr)),
            Msg::GetPeers => Msg::Peers(lock_node(&node).peers()),
            // --- network handshake: accept a peer only on the same chain ---
            Msg::Handshake { version, genesis, addr } => {
                let mut n = lock_node(&node);
                let ours = n.chain.genesis_id();
                let accepted = version == PROTOCOL_VERSION && genesis == ours;
                if accepted {
                    n.add_peer(&addr);
                }
                Msg::HandshakeAck { version: PROTOCOL_VERSION, genesis: ours, accepted }
            }
            // --- fork sync: find the best block we share with the asker ---
            Msg::FindCommon(ids) => {
                let n = lock_node(&node);
                let common = ids.iter().filter_map(|id| n.chain.active_height_of(id)).max().unwrap_or(0);
                Msg::CommonHeight(common)
            }
            // --- T17 tx gossip: flood-once, like NewBlock ---
            Msg::NewTx(bytes) => {
                let ok = match Transaction::decode(&bytes) {
                    Some(tx) => lock_node(&node).submit_tx(tx),
                    None => false,
                };
                if ok {
                    // Newly added → forward; duplicates return false above,
                    // which is where the gossip loop dies out.
                    let peers = lock_node(&node).peers();
                    thread::spawn(move || {
                        for p in peers {
                            let _ = announce_tx(p.as_str(), &bytes);
                        }
                    });
                    Msg::Ack(true)
                } else {
                    Msg::Ack(false)
                }
            }
            // --- T17 compact announce: "I have block X" → Ack(true) = send it
            Msg::BlockAnnounce { id, .. } => {
                Msg::Ack(!lock_node(&node).chain.has_block(&id))
            }
            // --- T19 fast sync: serve a consistent state snapshot in chunks
            Msg::GetStateManifest => {
                let payload = lock_node(&node).chain.state_sync_payload();
                match payload {
                    Some((anchor_height, anchor_id, records)) => {
                        let record_count = records.len() as u64;
                        // Split into chunks under the payload budget (each
                        // chunk keeps at least one record, so a single
                        // oversized record can't stall the split).
                        let mut chunks: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![Vec::new()];
                        let mut used = 0usize;
                        for (key, value) in records {
                            let cost = key.len() + value.len();
                            if used + cost > STATE_CHUNK_BYTES && !chunks.last().unwrap().is_empty() {
                                chunks.push(Vec::new());
                                used = 0;
                            }
                            used += cost;
                            chunks.last_mut().unwrap().push((key, value));
                        }
                        let chunk_count = chunks.len() as u32;
                        state_sync = Some(chunks);
                        Msg::StateManifest { anchor_height, anchor_id, record_count, chunk_count }
                    }
                    // Fresh chain: nothing to fast-sync from us.
                    None => Msg::StateManifest {
                        anchor_height: 0,
                        anchor_id: [0u8; 32],
                        record_count: 0,
                        chunk_count: 0,
                    },
                }
            }
            Msg::GetStateChunk(n) => Msg::StateChunk(
                state_sync
                    .as_ref()
                    .and_then(|chunks| chunks.get(n as usize).cloned())
                    .unwrap_or_default(),
            ),
            // --- RPC (clients) ---
            Msg::SubmitTx(bytes) => {
                let ok = match Transaction::decode(&bytes) {
                    Some(tx) => lock_node(&node).submit_tx(tx),
                    None => false,
                };
                if ok {
                    // A wallet submitted this tx to US alone (T17): gossip it
                    // on so every miner's mempool sees it, not just ours.
                    let peers = lock_node(&node).peers();
                    let fwd = bytes.clone();
                    thread::spawn(move || {
                        for p in peers {
                            let _ = announce_tx(p.as_str(), &fwd);
                        }
                    });
                }
                Msg::Ack(ok)
            }
            Msg::GetBalance { id, token } => {
                let b = lock_node(&node).chain.balance(&id, token).map(|c| c.to_bytes().to_vec());
                Msg::BalanceReply(b)
            }
            Msg::GetNonce(id) => {
                let n = lock_node(&node).chain.nonce(&id);
                Msg::NonceReply(n)
            }
            Msg::GetPublicBalance { id, token } => {
                let b = lock_node(&node).chain.public_balance(&id, token);
                Msg::PublicBalanceReply(b)
            }
            Msg::GetPool(token) => {
                let p = lock_node(&node).chain.pool(token);
                Msg::PoolReply(p.map(|p| (p.lat, p.tok, p.lp_supply)))
            }
            Msg::GetLpShares { token, id } => {
                let shares = lock_node(&node).chain.lp_shares(token, &id);
                Msg::PublicBalanceReply(Some(shares))
            }
            Msg::GetHtlc(id) => {
                let h = lock_node(&node).chain.htlc(&id);
                Msg::HtlcReply(h.map(|h| (h.token, h.from, h.to, h.amount, h.hashlock, h.expiry)))
            }
            Msg::GetHtlcs => {
                let locks = lock_node(&node)
                    .chain
                    .htlcs()
                    .into_iter()
                    .map(|(id, h)| (id, h.token, h.from, h.to, h.amount, h.hashlock, h.expiry))
                    .collect();
                Msg::HtlcsReply(locks)
            }
            Msg::GetCurve(token) => {
                let c = lock_node(&node).chain.curve(token);
                Msg::CurveReply(c.map(|c| (c.vlat, c.vtok, c.real_lat, c.graduated)))
            }
            Msg::GetPending { id, token } => {
                let b = lock_node(&node).chain.pending(&id, token).map(|c| c.to_bytes().to_vec());
                Msg::BalanceReply(b)
            }
            Msg::GetRingCandidates { token, max } => {
                let all = lock_node(&node).chain.ring_candidates(token);
                let cap = (max as usize).min(MAX_RING_CANDIDATES).min(all.len());
                // If the pool exceeds the cap, take an evenly-strided slice so the
                // reply spans the whole (id-sorted) pool instead of biasing toward
                // low ids. The wallet does the uniform random sampling on top.
                let list: Vec<([u8; 32], [u8; 64])> = if cap == 0 {
                    Vec::new()
                } else {
                    (0..cap)
                        .map(|i| {
                            let (id, ct) = &all[i * all.len() / cap];
                            (*id, ct.to_bytes())
                        })
                        .collect()
                };
                Msg::RingCandidates(list)
            }
            Msg::GetContractStorage { contract, key } => {
                let val = lock_node(&node).chain.contract_storage(&contract, key);
                Msg::ContractStorageReply(val)
            }
            Msg::HasContract(id) => Msg::Ack(lock_node(&node).chain.has_contract(&id)),
            // Replies are not expected inbound; ignore.
            _ => continue,
        };
        write_msg(&mut stream, &reply)?;
    }
}

/// Connect to `addr` and catch `chain` up to that peer, pulling and validating
/// each missing block. Returns the number of blocks adopted.
pub fn sync_from_peer<A: ToSocketAddrs>(chain: &mut Blockchain, addr: A) -> io::Result<usize> {
    let mut stream = connect_timeout(addr)?;
    write_msg(&mut stream, &Msg::GetTip)?;
    let peer_height = match read_msg(&mut stream)? {
        Msg::Tip(h) => h,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "expected tip")),
    };

    let mut adopted = 0;
    while chain.height() < peer_height {
        let next = chain.height() + 1;
        write_msg(&mut stream, &Msg::GetBlock(next))?;
        let bytes = match read_msg(&mut stream)? {
            Msg::Block(Some(b)) => b,
            Msg::Block(None) => break, // peer can't serve it; stop
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "expected block")),
        };
        let block = Block::decode(&bytes)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "undecodable block"))?;
        chain
            .apply_block(&block)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid block: {e:?}")))?;
        adopted += 1;
    }
    Ok(adopted)
}

/// Catch a shared node up to a peer, applying blocks under a brief lock while
/// network reads happen unlocked (so serving/RPC isn't blocked during sync).
///
/// Fork-capable: it sends the peer a block locator, learns the most recent
/// block the two chains share, and pulls the peer's branch from there — so two
/// nodes that mined apart (locally or across the internet) reconcile onto the
/// heavier chain instead of stalling. Returns the number of NEW blocks adopted.
pub fn sync_shared<A: ToSocketAddrs>(node: &SharedNode, addr: A) -> io::Result<usize> {
    let mut stream = connect_timeout(addr)?;
    write_msg(&mut stream, &Msg::GetTip)?;
    let peer_height = match read_msg(&mut stream)? {
        Msg::Tip(h) => h,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "expected tip")),
    };

    // Where do our chains diverge? (Falls back to genesis: same-genesis nodes
    // always share at least that.)
    let locator = lock_node(node).chain.locator();
    write_msg(&mut stream, &Msg::FindCommon(locator))?;
    let common = match read_msg(&mut stream)? {
        Msg::CommonHeight(h) => h,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "expected common height")),
    };

    let mut adopted = 0;
    for h in common + 1..=peer_height {
        write_msg(&mut stream, &Msg::GetBlock(h))?;
        let bytes = match read_msg(&mut stream)? {
            Msg::Block(Some(b)) => b,
            // Peer can't serve it (it reorged mid-sync, or lied about height).
            Msg::Block(None) => break,
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "expected block")),
        };
        let already_known = Block::decode(&bytes)
            .map(|b| lock_node(node).chain.has_block(&b.header.id()))
            .unwrap_or(false);
        if !lock_node(node).accept_block_bytes(&bytes) {
            break; // invalid data from this peer; stop trusting the stream
        }
        if !already_known {
            adopted += 1;
        }
    }
    Ok(adopted)
}

/// T19 fast sync: bootstrap a FRESH node (height 0) from `addr` without
/// replaying historical transactions — download the peer's state records +
/// full header chain, rebuild the state commitment locally, and adopt only if
/// the derived root matches the anchor block's PoW-validated header (see
/// [`Blockchain::fast_sync_adopt`] for the full trust argument).
///
/// `Ok(true)` iff the chain was adopted. `Ok(false)` = not applicable (we're
/// not fresh, the peer can't serve, or verification failed) — the caller
/// falls back to ordinary [`sync_shared`], which is always sound.
pub fn fast_sync_shared<A: ToSocketAddrs>(node: &SharedNode, addr: A) -> io::Result<bool> {
    if lock_node(node).chain.height() != 0 {
        return Ok(false);
    }
    let mut stream = connect_timeout(addr)?;

    write_msg(&mut stream, &Msg::GetStateManifest)?;
    let (anchor_height, anchor_id, chunk_count) = match read_msg(&mut stream)? {
        Msg::StateManifest { anchor_height, anchor_id, chunk_count, .. } => {
            (anchor_height, anchor_id, chunk_count)
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "expected state manifest")),
    };
    if chunk_count == 0 {
        return Ok(false); // peer has nothing to fast-sync
    }

    // The manifest is captured per-connection on the peer, so these chunks
    // are one consistent snapshot even if the peer mines meanwhile.
    let mut records: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for n in 0..chunk_count {
        write_msg(&mut stream, &Msg::GetStateChunk(n))?;
        match read_msg(&mut stream)? {
            Msg::StateChunk(part) if !part.is_empty() => records.extend(part),
            Msg::StateChunk(_) => return Ok(false), // peer lost the snapshot
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "expected state chunk")),
        }
    }

    // The full block list (headers get fully PoW-validated; only the tail
    // after the anchor gets its transactions replayed).
    write_msg(&mut stream, &Msg::GetTip)?;
    let peer_height = match read_msg(&mut stream)? {
        Msg::Tip(h) => h,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "expected tip")),
    };
    if peer_height < anchor_height {
        return Ok(false); // peer reorged below its own anchor mid-sync
    }
    let mut blocks = Vec::with_capacity(peer_height as usize);
    for h in 1..=peer_height {
        write_msg(&mut stream, &Msg::GetBlock(h))?;
        match read_msg(&mut stream)? {
            Msg::Block(Some(b)) => blocks.push(b),
            Msg::Block(None) => return Ok(false), // peer reorged mid-download
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "expected block")),
        }
    }

    Ok(lock_node(node).chain.fast_sync_adopt(&blocks, anchor_height, anchor_id, records))
}

/// Push one encoded block to a peer (gossip). Returns whether the peer adopted it.
pub fn announce_block<A: ToSocketAddrs>(addr: A, block_bytes: &[u8]) -> io::Result<bool> {
    let mut stream = connect_timeout(addr)?;
    write_msg(&mut stream, &Msg::NewBlock(block_bytes.to_vec()))?;
    match read_msg(&mut stream)? {
        Msg::Ack(ok) => Ok(ok),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected ack")),
    }
}

/// Push an encoded finality [`Vote`] to a peer (T14 gossip).
pub fn announce_vote<A: ToSocketAddrs>(addr: A, vote_bytes: &[u8]) -> io::Result<bool> {
    let mut stream = connect_timeout(addr)?;
    write_msg(&mut stream, &Msg::FinalityVote(vote_bytes.to_vec()))?;
    match read_msg(&mut stream)? {
        Msg::Ack(ok) => Ok(ok),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected ack")),
    }
}

/// Push an encoded transaction to a peer's mempool (T17 gossip). `Ok(true)`
/// iff it was newly added there.
pub fn announce_tx<A: ToSocketAddrs>(addr: A, tx_bytes: &[u8]) -> io::Result<bool> {
    let mut stream = connect_timeout(addr)?;
    write_msg(&mut stream, &Msg::NewTx(tx_bytes.to_vec()))?;
    match read_msg(&mut stream)? {
        Msg::Ack(ok) => Ok(ok),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected ack")),
    }
}

/// Announce a block compactly (T17): send `(id, height)` first and the full
/// block only if the peer asks for it. `Ok(true)` iff the peer ended up
/// accepting the block (or already had it — nothing to do).
pub fn announce_block_compact<A: ToSocketAddrs>(
    addr: A,
    id: &[u8; 32],
    height: u64,
    block_bytes: &[u8],
) -> io::Result<bool> {
    let mut stream = connect_timeout(addr)?;
    write_msg(&mut stream, &Msg::BlockAnnounce { id: *id, height })?;
    let wants = match read_msg(&mut stream)? {
        Msg::Ack(wants) => wants,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "expected ack")),
    };
    if !wants {
        return Ok(true); // peer already has it
    }
    write_msg(&mut stream, &Msg::NewBlock(block_bytes.to_vec()))?;
    match read_msg(&mut stream)? {
        Msg::Ack(ok) => Ok(ok),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected ack")),
    }
}

/// Ask a node for an account's staking state: `(bonded stake, unbonding
/// entries as (amount, release height))`.
pub fn get_stake<A: ToSocketAddrs>(addr: A, id: [u8; 32]) -> io::Result<(u64, Vec<(u64, u64)>)> {
    let mut stream = connect_timeout(addr)?;
    write_msg(&mut stream, &Msg::GetStake(id))?;
    match read_msg(&mut stream)? {
        Msg::StakeReply(staked, unbonding) => Ok((staked, unbonding)),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected stake reply")),
    }
}

/// Ask a node for its finality watermark (`None` if nothing certified yet).
pub fn get_finalized<A: ToSocketAddrs>(addr: A) -> io::Result<Option<(u64, [u8; 32])>> {
    let mut stream = connect_timeout(addr)?;
    write_msg(&mut stream, &Msg::GetFinalized)?;
    match read_msg(&mut stream)? {
        Msg::FinalizedReply(f) => Ok(f),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected finalized reply")),
    }
}

/// Push an encoded finality [`Certificate`] to a peer (T14 gossip).
pub fn announce_cert<A: ToSocketAddrs>(addr: A, cert_bytes: &[u8]) -> io::Result<bool> {
    let mut stream = connect_timeout(addr)?;
    write_msg(&mut stream, &Msg::FinalityCert(cert_bytes.to_vec()))?;
    match read_msg(&mut stream)? {
        Msg::Ack(ok) => Ok(ok),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected ack")),
    }
}

// --- Client RPC: how a wallet / tool talks to a node over the network --------

fn rpc<A: ToSocketAddrs>(addr: A, req: &Msg) -> io::Result<Msg> {
    let mut stream = connect_timeout(addr)?;
    write_msg(&mut stream, req)?;
    read_msg(&mut stream)
}

/// Connect to the first resolvable address with a bounded [`CONNECT_TIMEOUT`], so
/// a single unreachable peer can't stall a caller on a slow OS connect.
fn connect_timeout<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::InvalidInput, "no address resolved");
    for sa in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&sa, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Network handshake: tell `addr` who we are (protocol version, our chain's
/// genesis id, the address we advertise) and learn whether we're compatible.
/// Returns `true` only if the peer runs the same protocol version AND is on the
/// same chain (identical genesis) — the guard that keeps a node from wasting
/// effort syncing a foreign or incompatible chain. A compatible peer also
/// records us, so one handshake establishes a two-way link.
pub fn handshake<A: ToSocketAddrs>(
    addr: A,
    my_genesis: [u8; 32],
    my_addr: &str,
) -> io::Result<bool> {
    let req = Msg::Handshake { version: PROTOCOL_VERSION, genesis: my_genesis, addr: my_addr.to_string() };
    match rpc(addr, &req)? {
        // Compatible only if THEY accepted us and we independently confirm their
        // genesis + version match ours (don't trust their `accepted` alone).
        Msg::HandshakeAck { version, genesis, accepted } => {
            Ok(accepted && version == PROTOCOL_VERSION && genesis == my_genesis)
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected handshake ack")),
    }
}

/// RPC: the node's current height.
pub fn get_height<A: ToSocketAddrs>(addr: A) -> io::Result<u64> {
    match rpc(addr, &Msg::GetTip)? {
        Msg::Tip(h) => Ok(h),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected tip")),
    }
}

/// RPC: fetch the encoded block at `height` on the node's active chain.
pub fn get_block<A: ToSocketAddrs>(addr: A, height: u64) -> io::Result<Option<Vec<u8>>> {
    match rpc(addr, &Msg::GetBlock(height))? {
        Msg::Block(opt) => Ok(opt),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected block")),
    }
}

/// RPC: submit an encoded transaction to the node's mempool. Returns whether it
/// was accepted (false = duplicate or malformed).
pub fn submit_tx<A: ToSocketAddrs>(addr: A, tx_bytes: &[u8]) -> io::Result<bool> {
    match rpc(addr, &Msg::SubmitTx(tx_bytes.to_vec()))? {
        Msg::Ack(ok) => Ok(ok),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected ack")),
    }
}

/// RPC: an account's encrypted balance of a token (64 bytes), or `None`. The
/// caller decrypts it locally with their key — the node never sees the amount.
pub fn get_balance<A: ToSocketAddrs>(addr: A, id: [u8; 32], token: u32) -> io::Result<Option<[u8; 64]>> {
    match rpc(addr, &Msg::GetBalance { id, token })? {
        Msg::BalanceReply(opt) => Ok(match opt {
            Some(b) if b.len() == 64 => Some(b.try_into().unwrap()),
            _ => None,
        }),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected balance")),
    }
}

/// RPC: an account's current spend nonce, or `None` if not registered.
pub fn get_nonce<A: ToSocketAddrs>(addr: A, id: [u8; 32]) -> io::Result<Option<u64>> {
    match rpc(addr, &Msg::GetNonce(id))? {
        Msg::NonceReply(n) => Ok(n),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected nonce")),
    }
}

/// RPC: an account's transparent (plaintext) public balance of a token, or
/// `None` if the account isn't registered. Unlike an encrypted balance, this is
/// public by design, so the node can return the amount directly.
pub fn get_public_balance<A: ToSocketAddrs>(addr: A, id: [u8; 32], token: u32) -> io::Result<Option<u64>> {
    match rpc(addr, &Msg::GetPublicBalance { id, token })? {
        Msg::PublicBalanceReply(n) => Ok(n),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected public balance")),
    }
}

/// Peer exchange: tell a node the address we listen on, so it can sync from and
/// gossip to us. Returns whether it recorded us as a new peer.
pub fn hello<A: ToSocketAddrs>(addr: A, my_addr: &str) -> io::Result<bool> {
    match rpc(addr, &Msg::Hello(my_addr.to_string()))? {
        Msg::Ack(ok) => Ok(ok),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected ack")),
    }
}

/// Peer exchange: ask a node for the peer addresses it knows.
pub fn get_peers<A: ToSocketAddrs>(addr: A) -> io::Result<Vec<String>> {
    match rpc(addr, &Msg::GetPeers)? {
        Msg::Peers(list) => Ok(list),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected peers")),
    }
}

/// RPC: up to `max` anonymous-transfer ring candidates for `token` — `(account
/// id, 64-byte encrypted balance)` pairs a wallet samples decoys from (pass
/// them to `Wallet::build_anon_transfer`). Capped at [`MAX_RING_CANDIDATES`].
pub fn get_ring_candidates<A: ToSocketAddrs>(
    addr: A,
    token: u32,
    max: u32,
) -> io::Result<Vec<([u8; 32], [u8; 64])>> {
    match rpc(addr, &Msg::GetRingCandidates { token, max })? {
        Msg::RingCandidates(list) => Ok(list),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected ring candidates")),
    }
}

/// RPC: read a deployed contract's storage slot on the node's active chain
/// (0 if the contract or slot is unset). Contract storage is public by design.
pub fn get_contract_storage<A: ToSocketAddrs>(addr: A, contract: [u8; 32], key: u64) -> io::Result<u64> {
    match rpc(addr, &Msg::GetContractStorage { contract, key })? {
        Msg::ContractStorageReply(val) => Ok(val),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected contract storage")),
    }
}

/// RPC: whether a contract is deployed at `id` on the node's active chain.
pub fn has_contract<A: ToSocketAddrs>(addr: A, id: [u8; 32]) -> io::Result<bool> {
    match rpc(addr, &Msg::HasContract(id))? {
        Msg::Ack(ok) => Ok(ok),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected ack")),
    }
}

/// RPC: the DEX pool of `token` as `(lat reserve, token reserve, LP supply)`,
/// or `None` if no pool exists.
pub fn get_pool<A: ToSocketAddrs>(addr: A, token: u32) -> io::Result<Option<(u64, u64, u64)>> {
    match rpc(addr, &Msg::GetPool(token))? {
        Msg::PoolReply(p) => Ok(p),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected pool")),
    }
}

/// RPC: an account's LP shares in the pool of `token` (0 if none).
pub fn get_lp_shares<A: ToSocketAddrs>(addr: A, token: u32, id: [u8; 32]) -> io::Result<u64> {
    match rpc(addr, &Msg::GetLpShares { token, id })? {
        Msg::PublicBalanceReply(n) => Ok(n.unwrap_or(0)),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected lp shares")),
    }
}

/// RPC: `token`'s native bonding curve as `(vlat, vtok, real_lat, graduated)`,
/// or `None` if none has opened.
pub fn get_curve<A: ToSocketAddrs>(addr: A, token: u32) -> io::Result<Option<(u64, u64, u64, bool)>> {
    match rpc(addr, &Msg::GetCurve(token))? {
        Msg::CurveReply(c) => Ok(c),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected curve")),
    }
}

/// RPC: the open HTLC with this id as `(token, from, to, amount, hashlock,
/// expiry)`, or `None` (never existed, claimed, or refunded).
pub fn get_htlc<A: ToSocketAddrs>(
    addr: A,
    id: [u8; 32],
) -> io::Result<Option<(u32, [u8; 32], [u8; 32], u64, [u8; 32], u64)>> {
    match rpc(addr, &Msg::GetHtlc(id))? {
        Msg::HtlcReply(h) => Ok(h),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected htlc")),
    }
}

/// RPC: every open HTLC as `(id, token, from, to, amount, hashlock, expiry)`.
pub fn get_htlcs<A: ToSocketAddrs>(
    addr: A,
) -> io::Result<Vec<([u8; 32], u32, [u8; 32], [u8; 32], u64, [u8; 32], u64)>> {
    match rpc(addr, &Msg::GetHtlcs)? {
        Msg::HtlcsReply(locks) => Ok(locks),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected htlcs")),
    }
}

/// RPC: an account's pending (received, not yet rolled-over) encrypted balance.
pub fn get_pending<A: ToSocketAddrs>(addr: A, id: [u8; 32], token: u32) -> io::Result<Option<[u8; 64]>> {
    match rpc(addr, &Msg::GetPending { id, token })? {
        Msg::BalanceReply(opt) => Ok(match opt {
            Some(b) if b.len() == 64 => Some(b.try_into().unwrap()),
            _ => None,
        }),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected balance")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lat_chain::DEFAULT_DIFFICULTY;
    use lat_wallet::Wallet;
    use lat_types::Network;
    use rand::rngs::OsRng;

    const PREMINE_ID: [u8; 32] = [7u8; 32];

    #[test]
    fn votes_pool_into_a_certificate_and_finalize() {
        use lat_crypto::SecretKey;
        use lat_chain::MIN_VALIDATOR_STAKE;

        // Three validators staked whale/small/small: the whale alone holds
        // 5/7 of the stake (> 2/3), the two smalls together only 2/7.
        let mut rng = OsRng;
        let sks: Vec<SecretKey> = (0..3).map(|_| SecretKey::random(&mut rng)).collect();
        let ids: Vec<[u8; 32]> = sks.iter().map(|s| s.public_key().to_bytes()).collect();
        let premine: Vec<([u8; 32], u64)> =
            ids.iter().map(|id| (*id, 10 * MIN_VALIDATOR_STAKE)).collect();
        let mut chain =
            Blockchain::genesis_with_public(&[], &premine, DEFAULT_DIFFICULTY);
        let stake = |sk: &SecretKey, amount: u64| {
            let mut tx = Transaction::Stake {
                validator: sk.public_key().to_bytes(),
                amount,
                nonce: 0,
                sig: [0u8; 64],
            };
            let sig = sk.sign(&tx.signing_bytes()).to_bytes();
            if let Transaction::Stake { sig: s, .. } = &mut tx {
                *s = sig;
            }
            tx
        };
        let b1 = chain.mine(vec![
            stake(&sks[0], 5 * MIN_VALIDATOR_STAKE),
            stake(&sks[1], MIN_VALIDATOR_STAKE),
            stake(&sks[2], MIN_VALIDATOR_STAKE),
        ]);
        chain.apply_block(&b1).unwrap();
        let mut node = NodeState::new(chain);

        // A small validator's vote pools but does not certify (1/7 of stake).
        let tip = node.chain.tip();
        let small = Vote::sign(&sks[1], tip, 1);
        assert_eq!(node.add_vote(&small.encode()), (true, None));
        // Re-sending it is not "new" — that's what kills the gossip loop.
        assert_eq!(node.add_vote(&small.encode()), (false, None));
        assert_eq!(node.chain.finalized(), None);

        // The whale votes through cast_vote: 6/7 pooled → certificate forms.
        node.set_validator_key(sks[0].clone());
        let (vote_bytes, cert) = node.cast_vote().expect("whale is a staked validator");
        assert!(!vote_bytes.is_empty());
        let cert = cert.expect("whale's stake crosses 2/3");
        assert_eq!(node.chain.finalized(), Some((1, tip)));

        // A second node adopts the certificate wholesale — and only once.
        let mut chain2 =
            Blockchain::genesis_with_public(&[], &premine, DEFAULT_DIFFICULTY);
        chain2.apply_block(&Block::decode(&b1.encode()).unwrap()).unwrap();
        let mut node2 = NodeState::new(chain2);
        assert!(node2.accept_cert(&cert));
        assert_eq!(node2.chain.finalized(), Some((1, tip)));
        assert!(!node2.accept_cert(&cert), "replays don't re-flood");

        // Votes at or below the watermark are ignored (pool stays clean).
        let late = Vote::sign(&sks[2], tip, 1);
        assert_eq!(node.add_vote(&late.encode()), (false, None));

        // A non-validator (or unstaked) node never casts.
        let mut idle = NodeState::new(Blockchain::genesis_with_public(
            &[],
            &premine,
            DEFAULT_DIFFICULTY,
        ));
        assert!(idle.cast_vote().is_none(), "no key, no vote");
        idle.set_validator_key(SecretKey::random(&mut rng));
        assert!(idle.cast_vote().is_none(), "unstaked key's vote is refused");
    }

    #[test]
    fn tx_gossip_reaches_peer_mempools_over_tcp() {
        // Two serving nodes; B knows A as a peer. A wallet submits one tx to
        // B alone — T17 gossip must carry it into A's mempool too.
        let a = shared(fresh_chain());
        let la = TcpListener::bind("127.0.0.1:0").unwrap();
        let a_addr = la.local_addr().unwrap();
        serve(la, Arc::clone(&a));

        let b = shared(fresh_chain());
        b.lock().unwrap().add_peer(&a_addr.to_string());
        let lb = TcpListener::bind("127.0.0.1:0").unwrap();
        let b_addr = lb.local_addr().unwrap();
        serve(lb, Arc::clone(&b));

        let tx = lat_chain::mine_registration([9u8; 32]);
        assert!(submit_tx(b_addr, &tx.encode()).unwrap(), "B accepts the wallet submission");
        // The forward happens on a background thread — poll briefly.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if lock_node(&a).mempool.len() == 1 {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "tx never reached A's mempool");
            thread::sleep(Duration::from_millis(50));
        }
        // Re-announcing to A is not new (flood dies out).
        assert!(!announce_tx(a_addr, &tx.encode()).unwrap());
    }

    #[test]
    fn compact_announce_transfers_the_body_only_when_missing() {
        // A mined one block; B (same genesis) hasn't seen it.
        let mut chain = fresh_chain();
        let block = chain.mine(vec![]);
        chain.apply_block(&block).unwrap();
        let (id, height, bytes) = (block.header.id(), 1u64, block.encode());

        let b = shared(fresh_chain());
        let lb = TcpListener::bind("127.0.0.1:0").unwrap();
        let b_addr = lb.local_addr().unwrap();
        serve(lb, Arc::clone(&b));

        // Unknown block: B asks for the body and adopts it.
        assert!(announce_block_compact(b_addr, &id, height, &bytes).unwrap());
        assert_eq!(lock_node(&b).chain.height(), 1);

        // Known block: B declines the body — proven by sending GARBAGE as the
        // body, which would be rejected if it were ever transmitted.
        assert!(
            announce_block_compact(b_addr, &id, height, b"garbage").unwrap(),
            "peer that has the block never reads the body"
        );
        // Unknown id with a garbage body: B asks, decode fails, Ack(false).
        assert!(!announce_block_compact(b_addr, &[9u8; 32], 2, b"garbage").unwrap());
    }

    #[test]
    fn vote_gossip_finalizes_over_tcp() {
        use lat_crypto::SecretKey;
        use lat_chain::MIN_VALIDATOR_STAKE;

        // A server node whose sole validator (100% of stake) is staked in
        // block 1; a client pushes the validator's vote over the wire and the
        // server forms the certificate, queryable via GetFinalized.
        let sk = SecretKey::random(&mut OsRng);
        let id = sk.public_key().to_bytes();
        let mut chain = Blockchain::genesis_with_public(
            &[],
            &[(id, 10 * MIN_VALIDATOR_STAKE)],
            DEFAULT_DIFFICULTY,
        );
        let mut tx = Transaction::Stake {
            validator: id,
            amount: MIN_VALIDATOR_STAKE,
            nonce: 0,
            sig: [0u8; 64],
        };
        let sig = sk.sign(&tx.signing_bytes()).to_bytes();
        if let Transaction::Stake { sig: s, .. } = &mut tx {
            *s = sig;
        }
        let b1 = chain.mine(vec![tx]);
        chain.apply_block(&b1).unwrap();
        let tip = chain.tip();

        let server = shared(chain);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&server));

        assert_eq!(get_finalized(addr).unwrap(), None);
        let vote = Vote::sign(&sk, tip, 1);
        assert!(announce_vote(addr, &vote.encode()).unwrap(), "vote newly pooled");
        assert_eq!(get_finalized(addr).unwrap(), Some((1, tip)), "certified over the wire");
        // The same vote again is not new (gossip dies out).
        assert!(!announce_vote(addr, &vote.encode()).unwrap());
    }

    #[test]
    fn adopting_a_gossiped_block_casts_a_vote_immediately() {
        use lat_chain::MIN_VALIDATOR_STAKE;
        use lat_crypto::SecretKey;

        // Finality latency regression. A non-mining validator learns of a block
        // through gossip; if adopting it casts no vote, its vote waits for
        // latebrad's 15s re-vote heartbeat and finality is bounded at ~15s
        // regardless of a 3s block time. Here the server is the only validator
        // (100% of stake), so its own vote alone completes the quorum: if the
        // block is finalized straight after the announce, the vote was cast on
        // adoption and not on a timer. Nobody pushes a vote over the wire.
        let sk = SecretKey::random(&mut OsRng);
        let id = sk.public_key().to_bytes();
        // Blockchain is not Clone, so build two from the same genesis and give
        // both the identical block 1 — the producer then extends the very chain
        // the server is on.
        let build = || {
            Blockchain::genesis_with_public(
                &[],
                &[(id, 10 * MIN_VALIDATOR_STAKE)],
                DEFAULT_DIFFICULTY,
            )
        };
        let mut chain = build();
        let mut producer = build();
        let mut tx = Transaction::Stake {
            validator: id,
            amount: MIN_VALIDATOR_STAKE,
            nonce: 0,
            sig: [0u8; 64],
        };
        let sig = sk.sign(&tx.signing_bytes()).to_bytes();
        if let Transaction::Stake { sig: s, .. } = &mut tx {
            *s = sig;
        }
        let b1 = chain.mine(vec![tx]);
        chain.apply_block(&b1).unwrap();
        producer.apply_block(&b1).unwrap();

        // Block 2 is produced elsewhere and only ever reaches the server as gossip.
        let b2 = producer.mine(vec![]);
        let b2_id = b2.header.id();

        let server = shared(chain);
        lock_node(&server).set_validator_key(sk.clone());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&server));

        assert_eq!(get_finalized(addr).unwrap(), None, "nothing certified yet");
        assert!(announce_block(addr, &b2.encode()).unwrap(), "block accepted");

        // The vote is flooded from a spawned thread, so allow it to land.
        let mut finalized = None;
        for _ in 0..50 {
            finalized = get_finalized(addr).unwrap();
            if finalized.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            finalized,
            Some((2, b2_id)),
            "adopting a gossiped block must vote at once, not on the heartbeat",
        );
    }

    fn fresh_chain() -> Blockchain {
        Blockchain::genesis(&[(PREMINE_ID, 100)], DEFAULT_DIFFICULTY)
    }

    fn shared(chain: Blockchain) -> SharedNode {
        Arc::new(Mutex::new(NodeState::new(chain)))
    }

    #[test]
    fn fast_sync_bootstraps_a_fresh_node_over_tcp() {
        // Node A mines a few blocks (with a real state change) and serves.
        let a = shared(fresh_chain());
        {
            let mut n = lock_node(&a);
            let b1 = n.chain.mine(vec![lat_chain::mine_registration([9u8; 32])]);
            n.chain.apply_block(&b1).unwrap();
            for _ in 0..2 {
                let b = n.chain.mine(Vec::new());
                n.chain.apply_block(&b).unwrap();
            }
        }
        let la = TcpListener::bind("127.0.0.1:0").unwrap();
        let a_addr = la.local_addr().unwrap();
        serve(la, Arc::clone(&a));

        // Fresh node B fast-syncs: same tip + state without replaying.
        let b = shared(fresh_chain());
        assert!(fast_sync_shared(&b, a_addr).unwrap());
        let (na, nb) = (lock_node(&a), lock_node(&b));
        assert_eq!(nb.chain.height(), na.chain.height());
        assert_eq!(nb.chain.tip(), na.chain.tip());
        assert_eq!(nb.chain.state_root(), na.chain.state_root());
        assert!(nb.chain.is_registered(&[9u8; 32]), "synced state is queryable");
        assert_eq!(nb.chain.boot_mode(), lat_chain::BootMode::FastSync);
        drop((na, nb));

        // A node that already has blocks refuses to fast-sync (full sync path).
        assert!(!fast_sync_shared(&b, a_addr).unwrap());

        // And a fresh peer has nothing to serve: manifest says chunk_count 0.
        let empty = shared(fresh_chain());
        let le = TcpListener::bind("127.0.0.1:0").unwrap();
        let e_addr = le.local_addr().unwrap();
        serve(le, empty);
        let c = shared(fresh_chain());
        assert!(!fast_sync_shared(&c, e_addr).unwrap());
        assert_eq!(lock_node(&c).chain.height(), 0);
    }

    #[test]
    fn two_nodes_sync_over_tcp() {
        // Node A mines three blocks and serves.
        let a = shared(fresh_chain());
        for _ in 0..3 {
            a.lock().unwrap().produce_block(8);
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&a));

        // Node B starts empty and syncs over the socket.
        let mut b = fresh_chain();
        let adopted = sync_from_peer(&mut b, addr).unwrap();

        assert_eq!(adopted, 3);
        assert_eq!(b.height(), 3);
        assert_eq!(b.tip(), a.lock().unwrap().chain.tip(), "both agree over the wire");
    }

    #[test]
    fn gossiped_block_is_adopted_over_tcp() {
        let a = shared(fresh_chain());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&a));

        // B mines a block and announces it to A.
        let mut b = fresh_chain();
        let block = b.mine(vec![]);
        b.apply_block(&block).unwrap();

        let adopted = announce_block(addr, b.block_bytes(1).unwrap()).unwrap();
        assert!(adopted);
        assert_eq!(a.lock().unwrap().chain.height(), 1);
    }

    #[test]
    fn rpc_submit_and_query() {
        let a = shared(fresh_chain());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&a));

        // A client registers a wallet via RPC: submit the tx, then the node mines.
        let w = Wallet::generate(Network::Testnet, &mut OsRng);
        let reg = w.registration_tx();
        assert!(submit_tx(addr, &reg.encode()).unwrap(), "tx accepted to mempool");
        assert!(!submit_tx(addr, &reg.encode()).unwrap(), "duplicate rejected");

        // Node produces a block from its mempool, including the registration.
        a.lock().unwrap().produce_block(8);

        // Query over RPC: height advanced, the account is registered (nonce 0),
        // and its encrypted balance is fetchable (and decrypts to 0).
        assert_eq!(get_height(addr).unwrap(), 1);
        assert_eq!(get_nonce(addr, w.id()).unwrap(), Some(0));
        let bal = get_balance(addr, w.id(), 0).unwrap().expect("registered");
        let ct = lat_crypto::Ciphertext::from_bytes(&bal).unwrap();
        assert_eq!(w.decrypt_ciphertext(&ct), Some(0));
    }

    #[test]
    fn networked_wallet_sends_anonymously_over_rpc() {
        let mut rng = OsRng;
        const LAT: u32 = 0;

        // A node whose chain premines four wallets (the decoy pool).
        let wallets: Vec<Wallet> = (0..4).map(|_| Wallet::generate(Network::Testnet, &mut rng)).collect();
        let alice = Wallet::generate(Network::Testnet, &mut rng);
        let premine: Vec<_> = wallets.iter().map(|w| (w.id(), 500_000u64)).collect();
        let a = shared(Blockchain::genesis(&premine, DEFAULT_DIFFICULTY));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&a));

        // The wallet gathers everything over RPC: its balance, the decoy pool,
        // and the epoch of the next block.
        let sender = &wallets[1];
        let bal = get_balance(addr, sender.id(), LAT).unwrap().expect("registered");
        let bal_ct = lat_crypto::Ciphertext::from_bytes(&bal).unwrap();
        let raw = get_ring_candidates(addr, LAT, 32).unwrap();
        assert_eq!(raw.len(), 4, "whole pool fits under the cap");
        let candidates: Vec<([u8; 32], lat_crypto::Ciphertext)> = raw
            .iter()
            .filter_map(|(id, ct)| lat_crypto::Ciphertext::from_bytes(ct).map(|c| (*id, c)))
            .collect();
        let epoch = lat_chain::epoch_of(get_height(addr).unwrap() + 1);

        let tx = sender
            .build_anon_transfer(
                &alice.address(), LAT, 20_000, lat_chain::MIN_TRANSFER_FEE, &bal_ct, &candidates, epoch, 4, &mut rng,
            )
            .expect("builds from RPC data");
        assert!(submit_tx(addr, &tx.encode()).unwrap(), "anon tx accepted to mempool");
        a.lock().unwrap().produce_block(8);
        assert_eq!(get_height(addr).unwrap(), 1);

        // Sender debited; Alice finds her stealth payment by scanning the block.
        let bal_after = get_balance(addr, sender.id(), LAT).unwrap().unwrap();
        let ct_after = lat_crypto::Ciphertext::from_bytes(&bal_after).unwrap();
        assert_eq!(sender.decrypt_ciphertext(&ct_after), Some(500_000 - 20_000 - lat_chain::MIN_TRANSFER_FEE));
        let block_bytes = get_block(addr, 1).unwrap().unwrap();
        let receipts = alice.scan_stealth_bytes(&block_bytes);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].amount, 20_000);

        // A conflicting same-epoch respend is refused by the mempool's
        // nullifier tracking / consensus rules.
        let raw2 = get_ring_candidates(addr, LAT, 32).unwrap();
        let candidates2: Vec<([u8; 32], lat_crypto::Ciphertext)> = raw2
            .iter()
            .filter_map(|(id, ct)| lat_crypto::Ciphertext::from_bytes(ct).map(|c| (*id, c)))
            .collect();
        let respend = sender
            .build_anon_transfer(
                &alice.address(), LAT, 1_000, lat_chain::MIN_TRANSFER_FEE, &ct_after, &candidates2,
                lat_chain::epoch_of(2), 4, &mut rng,
            )
            .expect("builds");
        assert!(submit_tx(addr, &respend.encode()).unwrap(), "mempool can't know yet");
        let before = a.lock().unwrap().chain.height();
        a.lock().unwrap().produce_block(8);
        let n = a.lock().unwrap().chain.height();
        assert_eq!(n, before + 1, "block mined");
        let bal_final = get_balance(addr, sender.id(), LAT).unwrap().unwrap();
        let ct_final = lat_crypto::Ciphertext::from_bytes(&bal_final).unwrap();
        assert_eq!(
            sender.decrypt_ciphertext(&ct_final),
            Some(500_000 - 20_000 - lat_chain::MIN_TRANSFER_FEE),
            "the same-epoch respend was dropped, not applied"
        );
    }

    #[test]
    fn rpc_public_balance_query() {
        // A chain seeded with a transparent public premine.
        let chain = Blockchain::genesis_with_public(&[], &[(PREMINE_ID, 5_000)], DEFAULT_DIFFICULTY);
        let a = shared(chain);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&a));

        // The premined public balance is fetchable directly — no decryption needed.
        assert_eq!(get_public_balance(addr, PREMINE_ID, 0).unwrap(), Some(5_000));
        // An unregistered account returns None.
        assert_eq!(get_public_balance(addr, [1u8; 32], 0).unwrap(), None);
    }

    #[test]
    fn rpc_contract_deploy_and_query() {
        // A counter contract: each call does storage[0] += 1.
        use lat_vm::asm;
        let mut code = asm::push(0);
        code.extend(asm::push(0));
        code.push(asm::SLOAD);
        code.extend(asm::push(1));
        code.push(asm::ADD);
        code.push(asm::SSTORE);
        code.push(asm::STOP);

        // A node whose chain premines (and thus registers) the deployer with
        // PUBLIC LAT to cover the flat deploy + call fees (C-1 — gas is paid in
        // transparent LAT).
        let w = Wallet::generate(Network::Testnet, &mut OsRng);
        let a = shared(Blockchain::genesis_with_public(&[], &[(w.id(), 1_000_000)], DEFAULT_DIFFICULTY));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&a));

        // Before deployment the contract doesn't exist; its storage reads 0.
        let id = lat_vm::contract_id(&w.id(), &code);
        assert!(!has_contract(addr, id).unwrap());
        assert_eq!(get_contract_storage(addr, id, 0).unwrap(), 0);

        // Deploy + one call over RPC, mined into a block.
        assert!(submit_tx(addr, &w.deploy_contract(code).encode()).unwrap());
        assert!(submit_tx(addr, &w.call_contract(id, 0, 0).encode()).unwrap());
        a.lock().unwrap().produce_block(8);

        // The contract now exists and the call incremented slot 0.
        assert!(has_contract(addr, id).unwrap());
        assert_eq!(get_contract_storage(addr, id, 0).unwrap(), 1);
    }

    #[test]
    fn submit_gates_out_consensus_invalid_txs() {
        // A transaction a block could never legally contain must be refused at
        // submit, not merely dropped later at block-build — otherwise it occupies
        // mempool space for free. A transfer paying below the fee floor is one
        // such tx (rejected by the stateless `check_tx` consensus rule).
        let mut node = NodeState::new(fresh_chain());
        let from = lat_crypto::SecretKey::random(&mut OsRng).public_key().to_bytes();
        let to = lat_crypto::SecretKey::random(&mut OsRng).public_key().to_bytes();
        let tx = lat_types::Transaction::PublicTransfer {
            token: 0, from, to, amount: 1, fee: 0, nonce: 0, sig: [0u8; 64],
        };
        assert!(!node.submit_tx(tx), "consensus-invalid tx refused at submit");
        assert_eq!(node.mempool.len(), 0, "and never enters the mempool");
    }

    #[test]
    fn server_survives_hostile_input() {
        let a = shared(fresh_chain());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&a));

        // 1. A length prefix claiming a 4 GiB message must be refused, not
        //    allocated. 2. Garbage bytes must not crash the connection handler.
        // 3. Undecodable "transactions" and "blocks" must be rejected politely.
        {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&u32::MAX.to_le_bytes()).unwrap();
            let _ = s.write_all(&[0u8; 64]); // server closes; ignore write errors
        }
        {
            let mut s = TcpStream::connect(addr).unwrap();
            let _ = s.write_all(&[9u8; 200]); // structured garbage
        }
        assert!(!submit_tx(addr, &[0xEE; 300]).unwrap(), "garbage tx rejected");
        {
            let mut s = TcpStream::connect(addr).unwrap();
            write_msg(&mut s, &Msg::NewBlock(vec![0xAB; 500])).unwrap();
            assert_eq!(read_msg(&mut s).unwrap(), Msg::Ack(false), "garbage block rejected");
        }

        // After all that abuse the node still serves normal requests.
        assert_eq!(get_height(addr).unwrap(), 0);
        assert_eq!(a.lock().unwrap().chain.height(), 0);
    }

    #[test]
    fn forked_peers_reconcile_over_the_network() {
        // A and B mine APART from the same genesis (different miners so their
        // blocks differ): A builds 2 blocks, B builds 3 (heavier).
        let a = shared(fresh_chain());
        let b = shared(fresh_chain());
        {
            let mut n = a.lock().unwrap();
            n.miner = [1u8; 32];
            n.produce_block(8);
            n.produce_block(8);
        }
        {
            let mut n = b.lock().unwrap();
            n.miner = [2u8; 32];
            n.produce_block(8);
            n.produce_block(8);
            n.produce_block(8);
        }
        assert_ne!(a.lock().unwrap().chain.tip(), b.lock().unwrap().chain.tip());

        // Serve B; the old linear sync would stall here (A's height-1 block
        // differs from B's). The locator sync finds genesis as the common
        // ancestor and pulls B's whole branch — A reorgs onto it.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&b));

        let adopted = sync_shared(&a, addr).unwrap();
        assert_eq!(adopted, 3, "pulled B's whole branch");
        assert_eq!(a.lock().unwrap().chain.height(), 3);
        assert_eq!(a.lock().unwrap().chain.tip(), b.lock().unwrap().chain.tip(), "reorged onto the heavier fork");

        // Syncing again is a no-op (already reconciled).
        assert_eq!(sync_shared(&a, addr).unwrap(), 0);
    }

    #[test]
    fn peer_exchange_hello_and_get_peers() {
        let a = shared(fresh_chain());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&a));

        assert!(hello(addr, "10.0.0.5:4040").unwrap(), "new peer recorded");
        assert!(!hello(addr, "10.0.0.5:4040").unwrap(), "duplicate ignored");
        assert!(!hello(addr, "").unwrap(), "empty address refused");
        // An oversized address fails wire decoding — the server drops the
        // connection rather than storing it.
        assert!(hello(addr, &"x".repeat(500)).is_err(), "oversized address refused");
        assert_eq!(get_peers(addr).unwrap(), vec!["10.0.0.5:4040".to_string()]);
    }

    #[test]
    fn gossip_is_forwarded_through_the_network() {
        // Topology A -> B -> C: A only knows B, B only knows C. A block
        // announced to B must reach C via B's re-gossip.
        let b = shared(fresh_chain());
        let c = shared(fresh_chain());
        let lb = TcpListener::bind("127.0.0.1:0").unwrap();
        let lc = TcpListener::bind("127.0.0.1:0").unwrap();
        let (addr_b, addr_c) = (lb.local_addr().unwrap(), lc.local_addr().unwrap());
        serve(lb, Arc::clone(&b));
        serve(lc, Arc::clone(&c));
        b.lock().unwrap().add_peer(&addr_c.to_string());

        let mut a = fresh_chain();
        let block = a.mine(vec![]);
        a.apply_block(&block).unwrap();
        assert!(announce_block(addr_b, a.block_bytes(1).unwrap()).unwrap());

        // B has it immediately; C gets it via the forwarding thread.
        assert_eq!(b.lock().unwrap().chain.height(), 1);
        for _ in 0..100 {
            if c.lock().unwrap().chain.height() == 1 {
                return;
            }
            thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("gossip was not forwarded to C within 2s");
    }

    /// A node with a DIFFERENT genesis (different premine) — a "foreign network".
    fn foreign_chain() -> Blockchain {
        Blockchain::genesis(&[([0xAB; 32], 999)], DEFAULT_DIFFICULTY)
    }

    #[test]
    fn handshake_accepts_same_chain_and_records_peer() {
        let a = shared(fresh_chain());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&a));

        let genesis = a.lock().unwrap().chain.genesis_id();
        assert!(handshake(addr, genesis, "10.0.0.7:4040").unwrap(), "same-chain peer accepted");
        // The compatible peer was recorded (one handshake = a two-way link).
        assert_eq!(a.lock().unwrap().peers(), vec!["10.0.0.7:4040".to_string()]);
    }

    #[test]
    fn handshake_rejects_foreign_genesis_and_bad_version() {
        // The server is on the "real" testnet; the caller pretends a foreign one.
        let server = shared(fresh_chain());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        serve(listener, Arc::clone(&server));

        let foreign_genesis = foreign_chain().genesis_id();
        assert!(!handshake(addr, foreign_genesis, "10.0.0.9:4040").unwrap(), "foreign chain refused");
        assert!(server.lock().unwrap().peers().is_empty(), "foreign peer not recorded");

        // A wrong protocol version is refused even on the right chain.
        let real_genesis = server.lock().unwrap().chain.genesis_id();
        let bad = Msg::Handshake { version: PROTOCOL_VERSION + 1, genesis: real_genesis, addr: "10.0.0.9:4040".into() };
        match rpc(addr, &bad).unwrap() {
            Msg::HandshakeAck { accepted, .. } => assert!(!accepted, "version mismatch refused"),
            _ => panic!("expected ack"),
        }
        assert!(server.lock().unwrap().peers().is_empty(), "still no peer recorded");
    }

    #[test]
    fn peer_set_is_self_guarded_health_tracked_and_persistent() {
        let mut n = NodeState::new(fresh_chain());
        n.set_self_addr("127.0.0.1:4040");

        assert!(!n.add_peer("127.0.0.1:4040"), "never add our own address");
        assert!(n.add_peer("10.0.0.1:4040"));
        assert!(n.add_peer("10.0.0.2:4040"));
        assert!(!n.add_peer("10.0.0.1:4040"), "dedup");
        assert_eq!(n.peer_count(), 2);

        // Health: a peer is evicted only after MAX_PEER_FAILURES in a row; a
        // success in between resets the count.
        for _ in 0..MAX_PEER_FAILURES - 1 {
            assert!(!n.record_peer_failure("10.0.0.1:4040"));
        }
        n.record_peer_ok("10.0.0.1:4040"); // reset
        for _ in 0..MAX_PEER_FAILURES - 1 {
            assert!(!n.record_peer_failure("10.0.0.1:4040"));
        }
        assert!(n.record_peer_failure("10.0.0.1:4040"), "evicted on the Nth straight failure");
        assert_eq!(n.peers(), vec!["10.0.0.2:4040".to_string()]);

        // Persistence: save then load into a fresh node reproduces the set.
        let path = std::env::temp_dir().join(format!("lat-peers-{}.txt", std::process::id()));
        n.save_peers(&path).unwrap();
        let mut m = NodeState::new(fresh_chain());
        assert_eq!(m.load_peers(&path), 1);
        assert_eq!(m.peers(), vec!["10.0.0.2:4040".to_string()]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn three_nodes_join_and_converge_over_tcp() {
        // A fresh node with only ONE seed peer discovers the rest, handshakes
        // onto the right chain, and converges — the "others can join" path.
        let a = shared(fresh_chain());
        let b = shared(fresh_chain());
        let c = shared(fresh_chain());
        let la = TcpListener::bind("127.0.0.1:0").unwrap();
        let lb = TcpListener::bind("127.0.0.1:0").unwrap();
        let lc = TcpListener::bind("127.0.0.1:0").unwrap();
        let (aa, ab, ac) = (la.local_addr().unwrap(), lb.local_addr().unwrap(), lc.local_addr().unwrap());
        for (l, n) in [(la, &a), (lb, &b), (lc, &c)] {
            serve(l, Arc::clone(n));
        }
        let ga = a.lock().unwrap().chain.genesis_id();

        // A mines 4 blocks. B and C each know only A as a seed.
        for _ in 0..4 {
            a.lock().unwrap().produce_block(8);
        }
        b.lock().unwrap().add_peer(&aa.to_string());
        c.lock().unwrap().add_peer(&aa.to_string());

        // B and C handshake with A (learning it as a live, same-chain peer),
        // then pull its peers and sync.
        assert!(handshake(aa, ga, &ab.to_string()).unwrap());
        assert!(handshake(aa, ga, &ac.to_string()).unwrap());
        assert_eq!(sync_shared(&b, aa).unwrap(), 4);
        assert_eq!(sync_shared(&c, aa).unwrap(), 4);

        // A now knows B and C (recorded during their handshakes); C can discover
        // B through A's peer list.
        let a_peers = a.lock().unwrap().peers();
        assert!(a_peers.contains(&ab.to_string()) && a_peers.contains(&ac.to_string()));

        // All three agree on the tip — a converged network from a single seed.
        let tip = a.lock().unwrap().chain.tip();
        assert_eq!(b.lock().unwrap().chain.tip(), tip);
        assert_eq!(c.lock().unwrap().chain.tip(), tip);
    }

    #[test]
    fn one_bad_mempool_tx_cannot_void_a_block() {
        let a = shared(fresh_chain());
        // A valid registration and a tx that fails against state (its receiver —
        // in fact even its sender — was never registered), which the mempool's
        // stateless checks can't catch.
        let w = Wallet::generate(Network::Testnet, &mut OsRng);
        let ghost = Wallet::generate(Network::Testnet, &mut OsRng);
        // Signed rollover for an account that doesn't exist on-chain: passes
        // signature rules, fails at apply (SenderNotRegistered).
        let bad = ghost.rollover_tx(0);
        {
            let mut n = a.lock().unwrap();
            assert!(n.submit_tx(bad));
            assert!(n.submit_tx(w.registration_tx()));
        }
        // The block must still be produced, containing the valid registration.
        let produced = a.lock().unwrap().produce_block(8);
        assert!(produced.is_some(), "bad tx dropped, block still mined");
        let n = a.lock().unwrap();
        assert_eq!(n.chain.height(), 1);
        assert!(n.chain.is_registered(&w.id()), "the good tx made it in");
    }

    // --- T23: decoder robustness (fuzz-style property tests) ---
    //
    // `Msg::decode` is THE untrusted network input surface: every byte a peer
    // sends lands here. It must never panic — only return `None` — for any
    // input, and every valid encoding must round-trip. Deterministic xorshift
    // so failures reproduce exactly.

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

    /// One instance of every wire message variant (keep in sync with `Msg`).
    fn representative_msgs() -> Vec<Msg> {
        vec![
            Msg::GetTip,
            Msg::Tip(7),
            Msg::GetBlock(3),
            Msg::Block(None),
            Msg::Block(Some(vec![1, 2, 3])),
            Msg::NewBlock(vec![4; 60]),
            Msg::Ack(true),
            Msg::SubmitTx(vec![9; 40]),
            Msg::GetBalance { id: [1; 32], token: 2 },
            Msg::BalanceReply(None),
            Msg::BalanceReply(Some(vec![5; 64])),
            Msg::GetNonce([2; 32]),
            Msg::NonceReply(Some(11)),
            Msg::NonceReply(None),
            Msg::GetPending { id: [3; 32], token: 0 },
            Msg::Hello("10.0.0.1:4040".into()),
            Msg::GetPeers,
            Msg::Peers(vec!["a:1".into(), "b:2".into()]),
            Msg::FindCommon(vec![[4; 32], [5; 32]]),
            Msg::CommonHeight(9),
            Msg::GetPublicBalance { id: [6; 32], token: 1 },
            Msg::PublicBalanceReply(Some(1000)),
            Msg::PublicBalanceReply(None),
            Msg::GetRingCandidates { token: 0, max: 8 },
            Msg::RingCandidates(vec![([7; 32], [8; 64])]),
            Msg::Handshake { version: 2, genesis: [9; 32], addr: "x:1".into() },
            Msg::HandshakeAck { version: 2, genesis: [9; 32], accepted: true },
            Msg::GetContractStorage { contract: [10; 32], key: 5 },
            Msg::ContractStorageReply(77),
            Msg::GetPool(3),
            Msg::PoolReply(Some((1_000, 2_000, 1_414))),
            Msg::PoolReply(None),
            Msg::GetLpShares { token: 3, id: [11; 32] },
            Msg::GetHtlc([12; 32]),
            Msg::HtlcReply(Some((0, [1; 32], [2; 32], 777, [13; 32], 99))),
            Msg::HtlcReply(None),
            Msg::GetHtlcs,
            Msg::HtlcsReply(vec![([12; 32], 0, [1; 32], [2; 32], 777, [13; 32], 99)]),
            Msg::GetCurve(7),
            Msg::CurveReply(Some((3_000_000, 1_000_000_000, 500_000, false))),
            Msg::CurveReply(None),
            Msg::HasContract([11; 32]),
            Msg::FinalityVote(vec![12; 80]),
            Msg::FinalityCert(vec![13; 120]),
            Msg::GetFinalized,
            Msg::FinalizedReply(Some((4, [14; 32]))),
            Msg::FinalizedReply(None),
            Msg::GetStake([15; 32]),
            Msg::StakeReply(500, vec![(10, 20), (30, 40)]),
            Msg::NewTx(vec![16; 30]),
            Msg::BlockAnnounce { id: [17; 32], height: 6 },
            Msg::GetStateManifest,
            Msg::StateManifest {
                anchor_height: 42,
                anchor_id: [18; 32],
                record_count: 1000,
                chunk_count: 3,
            },
            Msg::GetStateChunk(2),
            Msg::StateChunk(vec![(vec![b'a'; 33], vec![1; 90]), (vec![b'n'; 33], vec![])]),
        ]
    }

    #[test]
    fn every_msg_variant_round_trips() {
        for msg in representative_msgs() {
            let bytes = msg.encode();
            assert_eq!(Msg::decode(&bytes).as_ref(), Some(&msg), "round-trip failed: {msg:?}");
        }
    }

    #[test]
    fn msg_decode_survives_random_and_mutated_input() {
        let mut rng = XorShift(0x1a7e_b12a_5eed_0001);

        // Pure random buffers across every tag byte and length regime.
        for i in 0..20_000usize {
            let len = rng.below(300) + usize::from(i % 100 == 0) * rng.below(4096);
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                *b = rng.next() as u8;
            }
            if !buf.is_empty() {
                buf[0] = (i % 256) as u8; // sweep tags incl. undefined ones
            }
            let _ = Msg::decode(&buf); // must not panic
        }

        // Valid encodings, damaged: byte flips, truncations, extensions.
        let originals: Vec<Vec<u8>> = representative_msgs().iter().map(Msg::encode).collect();
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
            if let Some(decoded) = Msg::decode(&buf) {
                // Whatever decoded must itself re-encode decodably (no
                // panic-on-echo states reachable from hostile input).
                let _ = Msg::decode(&decoded.encode());
            }
        }
    }
}

//! Authenticated state trie — a compact **Sparse Merkle Tree** (SMT) persisted
//! through [`KVStore`](crate::KVStore).
//!
//! # Why this exists
//!
//! Latebra's original `state_root` rehashed *every* account, token and contract
//! into a fresh Merkle tree on every call — O(n) in the whole state, per block.
//! That does not scale. This SMT commits the same information but updates
//! **incrementally**: changing one key rehashes only the O(log n) nodes on that
//! key's path, and unchanged subtrees are reused straight from storage. It also
//! yields succinct **inclusion and exclusion proofs**, the primitive light
//! clients and snapshot sync are built on.
//!
//! # Structure
//!
//! Keys are fixed 256-bit paths (account ids, contract ids, and other state
//! identifiers are already 32 uniformly-distributed bytes, so the key is used
//! directly as the path — bit 0 is the most-significant bit of byte 0).
//!
//! Conceptually the tree is a full binary tree of depth 256 whose empty
//! subtrees collapse to precomputed *default* hashes. Physically we store only
//! the nodes that actually branch:
//!
//! * **Leaf** — a single key/value occupying an otherwise-empty subtree. Stored
//!   once, under the hash of the subtree it roots (which depends on its depth),
//!   so descent lands on it directly without materializing the skipped levels.
//! * **Internal** — a node with two non-empty children.
//!
//! Nodes are **content-addressed**: a node's storage key is its own hash. That
//! makes the structure immutable and automatically de-duplicated — two states
//! sharing a subtree share its bytes on disk, which is exactly what cheap
//! snapshots and structural pruning need later (tasks T6/T7).
//!
//! # Hashing (domain-separated blake3)
//!
//! ```text
//! leaf(key, value)      = H(0x00 ‖ key ‖ H(value))
//! internal(left, right) = H(0x01 ‖ left ‖ right)
//! empty subtree @ 256   = H("LAT-smt-v1/empty")
//! empty subtree @ d<256 = internal(empty@d+1, empty@d+1)
//! ```
//!
//! The root of a single-leaf subtree rooted at depth `d` is the leaf hash folded
//! upward from depth 256 to `d`, pairing with default hashes on the empty side
//! at each level — see [`single_leaf_subtree_hash`]. This makes roots
//! **insertion-order independent**: a given key/value set always hashes to one
//! root regardless of the order the keys were applied.

use std::sync::OnceLock;

use crate::{Column, KVStore, WriteBatch};

/// Number of bits in a key path (= tree depth).
pub const KEY_BITS: usize = 256;

/// A 32-byte node/subtree hash.
pub type Hash = [u8; 32];

// --- hashing primitives ---------------------------------------------------

fn hash_leaf(key: &[u8; 32], value: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    h.update(key);
    h.update(blake3::hash(value).as_bytes());
    *h.finalize().as_bytes()
}

fn hash_internal(left: &Hash, right: &Hash) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Precomputed default (empty-subtree) hash for every depth `0..=256`.
/// `defaults()[KEY_BITS]` is the empty leaf; `defaults()[0]` is the empty-tree
/// root.
fn defaults() -> &'static [Hash; KEY_BITS + 1] {
    static DEFAULTS: OnceLock<[Hash; KEY_BITS + 1]> = OnceLock::new();
    DEFAULTS.get_or_init(|| {
        let mut d = [[0u8; 32]; KEY_BITS + 1];
        d[KEY_BITS] = *blake3::hash(b"LAT-smt-v1/empty").as_bytes();
        for depth in (0..KEY_BITS).rev() {
            d[depth] = hash_internal(&d[depth + 1], &d[depth + 1]);
        }
        d
    })
}

/// The root of an empty tree — the state root of a ledger with no entries.
/// Callers seed a fresh commitment with this rather than a zero hash.
pub fn empty_root() -> Hash {
    defaults()[0]
}

/// The i-th bit of `key` from the most-significant end (i = 0 → top of tree).
#[inline]
fn bit(key: &[u8; 32], i: usize) -> u8 {
    (key[i / 8] >> (7 - (i % 8))) & 1
}

/// Root hash of the subtree at `depth` that contains exactly the single leaf
/// `(key, leaf_hash)`. Folds the leaf up from the bottom (depth 256) to `depth`,
/// pairing with the default hash on the empty side at each level.
fn single_leaf_subtree_hash(depth: usize, key: &[u8; 32], leaf_hash: Hash) -> Hash {
    let defs = defaults();
    let mut cur = leaf_hash;
    for d in (depth..KEY_BITS).rev() {
        let sib = defs[d + 1];
        cur = if bit(key, d) == 0 { hash_internal(&cur, &sib) } else { hash_internal(&sib, &cur) };
    }
    cur
}

// --- node encoding --------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Leaf { key: [u8; 32], value: Vec<u8> },
    Internal { left: Hash, right: Hash },
}

impl Node {
    fn encode(&self) -> Vec<u8> {
        match self {
            Node::Leaf { key, value } => {
                let mut v = Vec::with_capacity(33 + value.len());
                v.push(0x00);
                v.extend_from_slice(key);
                v.extend_from_slice(value);
                v
            }
            Node::Internal { left, right } => {
                let mut v = Vec::with_capacity(65);
                v.push(0x01);
                v.extend_from_slice(left);
                v.extend_from_slice(right);
                v
            }
        }
    }

    fn decode(b: &[u8]) -> Option<Node> {
        match b.first()? {
            0x00 => Some(Node::Leaf {
                key: b.get(1..33)?.try_into().ok()?,
                value: b.get(33..)?.to_vec(),
            }),
            0x01 => Some(Node::Internal {
                left: b.get(1..33)?.try_into().ok()?,
                right: b.get(33..65)?.try_into().ok()?,
            }),
            _ => None,
        }
    }
}

// --- proofs ---------------------------------------------------------------

/// What sits at the end of a proof path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Terminal {
    /// The queried subtree is empty (basis for a non-membership proof).
    Empty,
    /// A leaf occupies the queried subtree. If `key` equals the queried key this
    /// is an inclusion proof; if it differs it is a non-membership proof (a
    /// *different* key already owns that path prefix).
    Leaf { key: [u8; 32], value: Vec<u8> },
}

/// A Merkle proof: the sibling hash at each descended level (top-down) plus the
/// terminal node. Verified against a root with [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// Sibling hashes from the root downward; `siblings.len()` is the depth at
    /// which descent stopped.
    pub siblings: Vec<Hash>,
    pub terminal: Terminal,
}

impl Proof {
    /// Recompute the root this proof implies for `key`. Compare it to a trusted
    /// root to accept or reject the proof.
    pub fn compute_root(&self, key: &[u8; 32]) -> Hash {
        let depth = self.siblings.len();
        let defs = defaults();
        let mut cur = match &self.terminal {
            Terminal::Empty => defs[depth],
            Terminal::Leaf { key: k, value } => {
                single_leaf_subtree_hash(depth, k, hash_leaf(k, value))
            }
        };
        for d in (0..depth).rev() {
            let sib = self.siblings[d];
            cur = if bit(key, d) == 0 { hash_internal(&cur, &sib) } else { hash_internal(&sib, &cur) };
        }
        cur
    }
}

/// Verify `proof` for `key` against `root`.
///
/// * `expected = Some(v)` — inclusion: the proof must show `key` maps to `v`.
/// * `expected = None` — exclusion: the proof must show `key` is absent (an
///   empty slot, or a different key occupying the path).
///
/// Returns `true` only if the proof both hashes to `root` and matches the
/// claimed membership.
pub fn verify(root: &Hash, key: &[u8; 32], expected: Option<&[u8]>, proof: &Proof) -> bool {
    if proof.siblings.len() > KEY_BITS || proof.compute_root(key) != *root {
        return false;
    }
    match (expected, &proof.terminal) {
        // Inclusion: terminal must be exactly this key with this value.
        (Some(v), Terminal::Leaf { key: k, value }) => k == key && value == v,
        (Some(_), Terminal::Empty) => false,
        // Exclusion: an empty slot, or a *different* key holding the path.
        (None, Terminal::Empty) => true,
        (None, Terminal::Leaf { key: k, .. }) => k != key,
    }
}

// --- the tree ------------------------------------------------------------

/// A sparse Merkle tree over a [`KVStore`]. Nodes live in [`Column::State`];
/// the current [`root`](Smt::root) is held in memory (callers persist it under
/// their own meta key). Reads and proofs are `&self`; mutations are `&mut self`
/// and commit atomically.
pub struct Smt<'a, S: KVStore + ?Sized> {
    store: &'a S,
    root: Hash,
}

impl<'a, S: KVStore + ?Sized> Smt<'a, S> {
    /// An empty tree over `store`.
    pub fn new(store: &'a S) -> Self {
        Smt { store, root: defaults()[0] }
    }

    /// Reopen an existing tree at `root` (e.g. loaded from chain metadata).
    pub fn from_root(store: &'a S, root: Hash) -> Self {
        Smt { store, root }
    }

    /// The current state root. Equal to the empty-tree default when no keys are
    /// present.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// Whether the tree holds no keys.
    pub fn is_empty(&self) -> bool {
        self.root == defaults()[0]
    }

    fn node(&self, hash: &Hash) -> Option<Node> {
        self.store.get(Column::State, hash).and_then(|b| Node::decode(&b))
    }

    /// Value at `key`, or `None`.
    pub fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        let defs = defaults();
        let mut cur = self.root;
        let mut depth = 0;
        loop {
            if cur == defs[depth] {
                return None;
            }
            match self.node(&cur)? {
                Node::Leaf { key: k, value } => return if k == *key { Some(value) } else { None },
                Node::Internal { left, right } => {
                    cur = if bit(key, depth) == 0 { left } else { right };
                    depth += 1;
                }
            }
        }
    }

    /// A proof of `key`'s presence or absence against the current [`root`].
    pub fn prove(&self, key: &[u8; 32]) -> Proof {
        let defs = defaults();
        let mut siblings = Vec::new();
        let mut cur = self.root;
        let mut depth = 0;
        loop {
            if cur == defs[depth] {
                return Proof { siblings, terminal: Terminal::Empty };
            }
            match self.node(&cur).expect("reachable node is stored") {
                Node::Leaf { key: k, value } => {
                    return Proof { siblings, terminal: Terminal::Leaf { key: k, value } };
                }
                Node::Internal { left, right } => {
                    let (next, sib) = if bit(key, depth) == 0 { (left, right) } else { (right, left) };
                    siblings.push(sib);
                    cur = next;
                    depth += 1;
                }
            }
        }
    }

    /// Insert or overwrite `key → value`, returning the new root.
    pub fn update(&mut self, key: &[u8; 32], value: &[u8]) -> Hash {
        let mut batch = WriteBatch::new();
        self.root = self.upsert(&mut batch, self.root, 0, key, value);
        self.store.write(batch);
        self.root
    }

    /// Remove `key` (a no-op if absent), returning the new root.
    pub fn remove(&mut self, key: &[u8; 32]) -> Hash {
        let mut batch = WriteBatch::new();
        self.root = self.delete(&mut batch, self.root, 0, key);
        self.store.write(batch);
        self.root
    }

    /// Recursive upsert. Returns the hash of the (rewritten) subtree rooted at
    /// `depth`. Never re-reads nodes written earlier in the same batch — parents
    /// are built from returned hashes — so buffering the whole update in one
    /// batch stays correct and atomic.
    fn upsert(&self, batch: &mut WriteBatch, node: Hash, depth: usize, key: &[u8; 32], value: &[u8]) -> Hash {
        let defs = defaults();
        if node == defs[depth] {
            return self.place_leaf(batch, depth, key, value);
        }
        match self.node(&node).expect("reachable node is stored") {
            Node::Leaf { key: k, value: v } => {
                if k == *key {
                    self.place_leaf(batch, depth, key, value)
                } else {
                    self.split(batch, depth, key, value, &k, &v)
                }
            }
            Node::Internal { left, right } => {
                if bit(key, depth) == 0 {
                    let left = self.upsert(batch, left, depth + 1, key, value);
                    self.store_internal(batch, left, right)
                } else {
                    let right = self.upsert(batch, right, depth + 1, key, value);
                    self.store_internal(batch, left, right)
                }
            }
        }
    }

    /// Store a leaf as the sole occupant of the subtree at `depth`, returning
    /// that subtree's hash (the leaf's content-address at this depth).
    fn place_leaf(&self, batch: &mut WriteBatch, depth: usize, key: &[u8; 32], value: &[u8]) -> Hash {
        let hash = single_leaf_subtree_hash(depth, key, hash_leaf(key, value));
        batch.put(Column::State, hash.to_vec(), Node::Leaf { key: *key, value: value.to_vec() }.encode());
        hash
    }

    fn store_internal(&self, batch: &mut WriteBatch, left: Hash, right: Hash) -> Hash {
        let hash = hash_internal(&left, &right);
        batch.put(Column::State, hash.to_vec(), Node::Internal { left, right }.encode());
        hash
    }

    /// Two distinct keys collide in the subtree at `depth`: build the internal
    /// spine down to the bit where they diverge, with a single-leaf subtree on
    /// each side below the split.
    fn split(
        &self,
        batch: &mut WriteBatch,
        depth: usize,
        key_a: &[u8; 32],
        val_a: &[u8],
        key_b: &[u8; 32],
        val_b: &[u8],
    ) -> Hash {
        // First bit at/below `depth` where the two keys differ (guaranteed < 256
        // for distinct 32-byte keys).
        let mut m = depth;
        while m < KEY_BITS && bit(key_a, m) == bit(key_b, m) {
            m += 1;
        }
        let ha = self.place_leaf(batch, m + 1, key_a, val_a);
        let hb = self.place_leaf(batch, m + 1, key_b, val_b);
        // At the divergence depth `m`, order the two by key_a's bit.
        let mut cur = if bit(key_a, m) == 0 {
            self.store_internal(batch, ha, hb)
        } else {
            self.store_internal(batch, hb, ha)
        };
        // Wrap upward from m-1 back to `depth`; both keys agree on these bits, so
        // the sibling is always the default (empty) subtree.
        let defs = defaults();
        for d in (depth..m).rev() {
            cur = if bit(key_a, d) == 0 {
                self.store_internal(batch, cur, defs[d + 1])
            } else {
                self.store_internal(batch, defs[d + 1], cur)
            };
        }
        cur
    }

    /// Recursive delete with collapse, keeping roots canonical: removing a key
    /// yields the exact tree as if it had never been inserted.
    fn delete(&self, batch: &mut WriteBatch, node: Hash, depth: usize, key: &[u8; 32]) -> Hash {
        let defs = defaults();
        if node == defs[depth] {
            return node; // absent
        }
        match self.node(&node).expect("reachable node is stored") {
            Node::Leaf { key: k, .. } => {
                if k == *key {
                    defs[depth]
                } else {
                    node
                }
            }
            Node::Internal { left, right } => {
                let (left, right) = if bit(key, depth) == 0 {
                    (self.delete(batch, left, depth + 1, key), right)
                } else {
                    (left, self.delete(batch, right, depth + 1, key))
                };
                self.collapse(batch, depth, left, right)
            }
        }
    }

    /// After a child changed, rebuild the internal node at `depth` — but if one
    /// side is now empty and the other is a lone leaf, pull that leaf up to
    /// `depth` so the tree stays compact and the root stays canonical.
    fn collapse(&self, batch: &mut WriteBatch, depth: usize, left: Hash, right: Hash) -> Hash {
        let defs = defaults();
        let left_empty = left == defs[depth + 1];
        let right_empty = right == defs[depth + 1];
        if left_empty && right_empty {
            return defs[depth];
        }
        if left_empty ^ right_empty {
            let child = if left_empty { right } else { left };
            if let Some(Node::Leaf { key: k, value: v }) = self.node(&child) {
                return self.place_leaf(batch, depth, &k, &v);
            }
        }
        self.store_internal(batch, left, right)
    }
}

// --- pruning (T6) ----------------------------------------------------------

/// Result of a [`prune`] sweep over [`Column::State`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneStats {
    /// Nodes reachable from a retained root (left in place).
    pub kept: usize,
    /// Unreachable nodes deleted by the sweep.
    pub dropped: usize,
}

/// Every node hash reachable from any of `roots` (the mark phase). Default
/// (empty-subtree) hashes are never stored, so a child that doesn't resolve is
/// simply skipped; content-addressing means subtrees shared between roots are
/// visited once.
pub fn reachable_nodes<S: KVStore + ?Sized>(
    store: &S,
    roots: &[Hash],
) -> std::collections::HashSet<Hash> {
    let mut live = std::collections::HashSet::new();
    let mut stack: Vec<Hash> = roots.to_vec();
    while let Some(hash) = stack.pop() {
        if live.contains(&hash) {
            continue;
        }
        let Some(bytes) = store.get(Column::State, &hash) else {
            continue; // default (empty) subtree, or a root not in this store
        };
        live.insert(hash);
        if let Some(Node::Internal { left, right }) = Node::decode(&bytes) {
            stack.push(left);
            stack.push(right);
        }
    }
    live
}

/// Mark-and-sweep prune of the state trie: delete every node in
/// [`Column::State`] not reachable from one of the `retain` roots. Nodes are
/// content-addressed and immutable, so anything unreachable from a retained
/// root can never be referenced again — dropping it is safe by construction,
/// and every retained root remains fully readable and provable afterwards
/// (leaves carry their values).
///
/// Call this on the **committed base** store (after a flush): pruning through
/// an overlay would only accumulate tombstones in its write layer. The caller
/// must retain every root a live reader or speculative clone may still be
/// forked from — the same adopted-state invariant as `flush`. Archive nodes
/// simply never call this.
pub fn prune<S: KVStore + ?Sized>(store: &S, retain: &[Hash]) -> PruneStats {
    let live = reachable_nodes(store, retain);
    let mut batch = WriteBatch::new();
    let mut dropped = 0usize;
    for (key, _) in store.scan_prefix(Column::State, b"") {
        let is_live = key.len() == 32
            && live.contains::<Hash>(&key.as_slice().try_into().expect("checked 32-byte key"));
        if !is_live {
            batch.delete(Column::State, key);
            dropped += 1;
        }
    }
    if dropped > 0 {
        store.write(batch);
    }
    PruneStats { kept: live.len(), dropped }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemStore;

    fn k(bytes: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        key
    }

    // Tiny deterministic PRNG so tests need no rand dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn key(&mut self) -> [u8; 32] {
            let mut key = [0u8; 32];
            for chunk in key.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
            }
            key
        }
    }

    #[test]
    fn empty_tree() {
        let s = MemStore::new();
        let t = Smt::new(&s);
        assert!(t.is_empty());
        assert_eq!(t.root(), defaults()[0]);
        assert!(t.get(&k(b"absent")).is_none());
        // Non-membership proof against the empty root.
        let p = t.prove(&k(b"absent"));
        assert!(verify(&t.root(), &k(b"absent"), None, &p));
    }

    #[test]
    fn insert_get_and_membership_proof() {
        let s = MemStore::new();
        let mut t = Smt::new(&s);
        let key = k(b"alice");
        t.update(&key, b"100");
        assert_eq!(t.get(&key), Some(b"100".to_vec()));
        assert!(!t.is_empty());

        let p = t.prove(&key);
        assert!(verify(&t.root(), &key, Some(b"100"), &p));
        // Wrong value must not verify as inclusion.
        assert!(!verify(&t.root(), &key, Some(b"999"), &p));
    }

    #[test]
    fn two_keys_diverging_early_and_late() {
        let s = MemStore::new();
        let mut t = Smt::new(&s);
        // Diverge in the very first bit.
        let a = {
            let mut x = [0u8; 32];
            x[0] = 0x00;
            x
        };
        let b = {
            let mut x = [0u8; 32];
            x[0] = 0x80;
            x
        };
        // Diverge only in the very last bit.
        let c = [0x11u8; 32];
        let mut d = [0x11u8; 32];
        d[31] ^= 0x01;

        for (key, val) in [(a, "a"), (b, "b"), (c, "c"), (d, "d")] {
            t.update(&key, val.as_bytes());
        }
        for (key, val) in [(a, "a"), (b, "b"), (c, "c"), (d, "d")] {
            assert_eq!(t.get(&key), Some(val.as_bytes().to_vec()));
            assert!(verify(&t.root(), &key, Some(val.as_bytes()), &t.prove(&key)));
        }
    }

    #[test]
    fn root_is_insertion_order_independent() {
        let pairs = [(k(b"x"), b"1".as_ref()), (k(b"yy"), b"2"), (k(b"zzz"), b"3"), (k(b"w"), b"4")];

        let s1 = MemStore::new();
        let mut t1 = Smt::new(&s1);
        for (key, v) in pairs.iter() {
            t1.update(key, v);
        }

        let s2 = MemStore::new();
        let mut t2 = Smt::new(&s2);
        for (key, v) in pairs.iter().rev() {
            t2.update(key, v);
        }
        assert_eq!(t1.root(), t2.root(), "same set ⇒ same root regardless of order");
    }

    #[test]
    fn update_changes_then_reproduces_root() {
        let s = MemStore::new();
        let mut t = Smt::new(&s);
        let key = k(b"acct");
        t.update(&key, b"10");
        let r1 = t.root();
        t.update(&key, b"20");
        assert_ne!(t.root(), r1);
        assert_eq!(t.get(&key), Some(b"20".to_vec()));
        t.update(&key, b"10");
        assert_eq!(t.root(), r1, "reverting the value reverts the root");
    }

    #[test]
    fn delete_is_canonical() {
        let s = MemStore::new();
        let mut t = Smt::new(&s);
        let a = k(b"aaa");
        let b = k(b"bbb");

        t.update(&a, b"1");
        let only_a = t.root();
        t.update(&b, b"2");
        t.remove(&b);
        assert_eq!(t.root(), only_a, "insert+delete leaves the tree unchanged");
        assert_eq!(t.get(&a), Some(b"1".to_vec()));
        assert!(t.get(&b).is_none());

        t.remove(&a);
        assert!(t.is_empty(), "deleting the last key empties the tree");
        assert_eq!(t.root(), defaults()[0]);
    }

    #[test]
    fn non_membership_and_tamper_resistance() {
        let s = MemStore::new();
        let mut t = Smt::new(&s);
        t.update(&k(b"present"), b"v");

        let absent = k(b"absent");
        let p = t.prove(&absent);
        assert!(verify(&t.root(), &absent, None, &p), "genuine non-membership verifies");

        // Tamper: flip a sibling (or fabricate one) → must fail.
        let mut bad = p.clone();
        bad.siblings.push([9u8; 32]);
        assert!(!verify(&t.root(), &absent, None, &bad));

        // A membership claim for an absent key must fail.
        assert!(!verify(&t.root(), &absent, Some(b"v"), &t.prove(&absent)));
    }

    #[test]
    fn persists_and_reopens_by_root() {
        let s = MemStore::new();
        let root = {
            let mut t = Smt::new(&s);
            t.update(&k(b"a"), b"1");
            t.update(&k(b"b"), b"2");
            t.root()
        };
        // Reopen against the same store from just the root hash.
        let t = Smt::from_root(&s, root);
        assert_eq!(t.get(&k(b"a")), Some(b"1".to_vec()));
        assert_eq!(t.get(&k(b"b")), Some(b"2".to_vec()));
        assert!(verify(&t.root(), &k(b"a"), Some(b"1"), &t.prove(&k(b"a"))));
    }

    /// Number of nodes physically present in Column::State.
    fn node_count(s: &MemStore) -> usize {
        s.scan_prefix(Column::State, b"").len()
    }

    #[test]
    fn prune_drops_garbage_keeps_current_root_fully_readable() {
        let s = MemStore::new();
        let mut t = Smt::new(&s);
        let mut rng = Rng(42);
        let mut keys = Vec::new();
        // Churn: every overwrite strands the old path's nodes as garbage.
        for i in 0..64u32 {
            let key = rng.key();
            t.update(&key, &i.to_le_bytes());
            keys.push((key, i));
        }
        for round in 1..=5u32 {
            for (key, i) in &keys {
                t.update(key, &(i + round * 1000).to_le_bytes());
            }
        }
        let before = node_count(&s);
        let stats = prune(&s, &[t.root()]);
        let after = node_count(&s);
        assert!(stats.dropped > 0, "churn must have created garbage");
        assert_eq!(after, stats.kept, "sweep leaves exactly the marked set");
        assert_eq!(before, stats.kept + stats.dropped);

        // The retained root is fully intact: reads and proofs for every key.
        for (key, i) in &keys {
            let val = (i + 5000).to_le_bytes();
            assert_eq!(t.get(key), Some(val.to_vec()));
            assert!(verify(&t.root(), key, Some(&val), &t.prove(key)));
        }
        // Pruning an already-pruned store is a no-op.
        let again = prune(&s, &[t.root()]);
        assert_eq!(again.dropped, 0);
        assert_eq!(again.kept, stats.kept);
    }

    #[test]
    fn prune_retains_historical_roots_on_request() {
        let s = MemStore::new();
        let mut t = Smt::new(&s);
        t.update(&k(b"alice"), b"10");
        t.update(&k(b"bob"), b"20");
        let old_root = t.root();
        t.update(&k(b"alice"), b"99");
        t.update(&k(b"carol"), b"5");
        let new_root = t.root();

        // Retaining both roots keeps the old state queryable (archive window).
        prune(&s, &[new_root, old_root]);
        let old = Smt::from_root(&s, old_root);
        assert_eq!(old.get(&k(b"alice")), Some(b"10".to_vec()));
        assert!(verify(&old_root, &k(b"alice"), Some(b"10"), &old.prove(&k(b"alice"))));
        let new = Smt::from_root(&s, new_root);
        assert_eq!(new.get(&k(b"alice")), Some(b"99".to_vec()));

        // Dropping the old root from the retain set garbage-collects what only
        // it referenced, while the current root stays whole.
        let stats = prune(&s, &[new_root]);
        assert!(stats.dropped > 0, "old-root-only nodes must go");
        assert_eq!(new.get(&k(b"alice")), Some(b"99".to_vec()));
        assert_eq!(new.get(&k(b"bob")), Some(b"20".to_vec()));
        assert_eq!(new.get(&k(b"carol")), Some(b"5".to_vec()));
        assert!(verify(&new_root, &k(b"bob"), Some(b"20"), &new.prove(&k(b"bob"))));
    }

    #[test]
    fn pruned_store_reproduces_a_fresh_rebuild() {
        // Oracle: after churn + prune, the surviving node set is exactly what a
        // from-scratch build of the final key/value set produces.
        let mut rng = Rng(7);
        let s = MemStore::new();
        let mut t = Smt::new(&s);
        let mut model = std::collections::BTreeMap::new();
        let mut keys: Vec<[u8; 32]> = Vec::new();
        for i in 0..300u32 {
            if rng.next() % 10 < 7 || keys.is_empty() {
                let key = rng.key();
                t.update(&key, &i.to_le_bytes());
                model.insert(key, i.to_le_bytes().to_vec());
                keys.push(key);
            } else {
                let key = keys.swap_remove((rng.next() as usize) % keys.len());
                t.remove(&key);
                model.remove(&key);
            }
        }
        prune(&s, &[t.root()]);

        let s2 = MemStore::new();
        let mut fresh = Smt::new(&s2);
        for (key, val) in &model {
            fresh.update(key, val);
        }
        assert_eq!(t.root(), fresh.root());
        // Exactly the reachable set survives. (Counts are NOT comparable across
        // stores: a leaf at depth d shares its content-address with the internal
        // node (leaf@d+1, empty), so a churned store may hold a deeper — equally
        // valid — materialization than a fresh build.)
        assert_eq!(node_count(&s), reachable_nodes(&s, &[t.root()]).len());
        for (key, val) in &model {
            assert_eq!(t.get(key).as_ref(), Some(val));
            assert!(verify(&t.root(), key, Some(val), &t.prove(key)));
        }
    }

    #[test]
    fn matches_reference_over_random_workload() {
        use std::collections::BTreeMap;
        let mut rng = Rng(0x9E3779B97F4A7C15);
        let s = MemStore::new();
        let mut t = Smt::new(&s);
        let mut model: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();

        // Mixed inserts, updates and deletes.
        let mut keys: Vec<[u8; 32]> = Vec::new();
        for i in 0..400u32 {
            let op = rng.next() % 10;
            if op < 7 || keys.is_empty() {
                let key = rng.key();
                let val = i.to_le_bytes().to_vec();
                t.update(&key, &val);
                model.insert(key, val);
                keys.push(key);
            } else {
                let idx = (rng.next() as usize) % keys.len();
                let key = keys.swap_remove(idx);
                t.remove(&key);
                model.remove(&key);
            }
        }

        // Every model entry reads back and proves; absent keys prove absence.
        for (key, val) in &model {
            assert_eq!(t.get(key).as_ref(), Some(val));
            assert!(verify(&t.root(), key, Some(val), &t.prove(key)));
        }
        for _ in 0..50 {
            let key = rng.key();
            if !model.contains_key(&key) {
                assert!(t.get(&key).is_none());
                assert!(verify(&t.root(), &key, None, &t.prove(&key)));
            }
        }

        // Order independence: replaying the final model set fresh reproduces root.
        let s2 = MemStore::new();
        let mut t2 = Smt::new(&s2);
        for (key, val) in &model {
            t2.update(key, val);
        }
        assert_eq!(t.root(), t2.root(), "root depends only on final key/value set");
    }
}

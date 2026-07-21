//! Transaction mempool (clean-room, from `SPEC.md`).
//!
//! A holding area for transactions that have been submitted but not yet mined.
//! The miner drains it to fill a block; when a block is accepted (mined here or
//! received from a peer) its transactions are removed.
//!
//! This is a minimal pool with a fee market: it de-duplicates by transaction
//! hash, refuses transfers paying under the consensus fee floor (they could
//! never be mined), and drains highest-fee-first (FIFO among equal fees, so
//! fee-less types like `Register` keep submission order). It does not yet do
//! expiry or full pre-validation against chain state (a node could add a light
//! validity check before `add`). Those are later refinements.

use std::cmp::Reverse;
use std::collections::HashSet;

use lat_types::Transaction;

use crate::{tx_fee, MAX_CONTRACT_CODE_BYTES, MIN_TRANSFER_FEE};

/// Hard cap on how many transactions the pool holds. Without it, a peer can
/// stream unlimited distinct (fee-floor-passing but never-mineable) transactions
/// and grow a node's memory without bound. When full, the pool keeps its
/// highest-fee transactions and drops the cheapest — so spam can't crowd out a
/// paying transaction (fee-priority admission).
pub const MAX_MEMPOOL_TXS: usize = 8192;

/// Cap on the dedup memory. `seen` remembers hashes so an already-mined or
/// in-flight transaction can't be re-added; over a long-running node that set
/// would otherwise grow forever. When it overflows we clear it — the nonce/
/// solvency checks at mining still prevent any actual double-spend, so the worst
/// case is a stale duplicate that gets dropped at block-build time.
const MAX_SEEN: usize = 1 << 16;

/// Hash of a transaction (BLAKE3 of its canonical encoding) — its mempool id.
pub fn tx_hash(tx: &Transaction) -> [u8; 32] {
    *blake3::hash(&tx.encode()).as_bytes()
}

/// The anonymous-spend nullifier of a transaction, if it has one.
fn tx_nullifier(tx: &Transaction) -> Option<[u8; 32]> {
    match tx {
        Transaction::AnonTransfer { xfer, .. } => Some(xfer.nullifier()),
        _ => None,
    }
}

#[derive(Default)]
pub struct Mempool {
    txs: Vec<Transaction>,
    /// Hashes ever seen, to reject duplicates (including already-mined ones).
    seen: HashSet<[u8; 32]>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool::default()
    }

    /// Add a transaction. Returns `false` if it duplicates one already seen, or
    /// if it's a transfer paying under [`MIN_TRANSFER_FEE`] (consensus would
    /// reject it, so holding or relaying it only wastes space).
    pub fn add(&mut self, tx: Transaction) -> bool {
        if matches!(&tx, Transaction::SolventTransfer { xfer, .. } if xfer.fee < MIN_TRANSFER_FEE) {
            return false;
        }
        if matches!(&tx, Transaction::PublicTransfer { fee, .. } if *fee < MIN_TRANSFER_FEE) {
            return false;
        }
        if matches!(&tx, Transaction::Shield { fee, .. } if *fee < MIN_TRANSFER_FEE) {
            return false;
        }
        if matches!(&tx, Transaction::ShieldStealth { fee, .. } if *fee < MIN_TRANSFER_FEE) {
            return false;
        }
        if matches!(&tx, Transaction::Unshield { xfer, .. } if xfer.fee < MIN_TRANSFER_FEE) {
            return false;
        }
        if matches!(&tx, Transaction::AnonTransfer { xfer, .. } if xfer.fee < MIN_TRANSFER_FEE) {
            return false;
        }
        // DEX + HTLC-lock transactions carry the same public fee floor.
        if matches!(&tx,
            Transaction::AddLiquidity { fee, .. }
            | Transaction::RemoveLiquidity { fee, .. }
            | Transaction::Swap { fee, .. }
            | Transaction::HtlcLock { fee, .. } if *fee < MIN_TRANSFER_FEE)
        {
            return false;
        }
        // Two anonymous spends sharing a nullifier are the same account spending
        // twice in one epoch — only one can ever be mined. Keep the higher-fee
        // one (fee replacement), refuse the other.
        if let Some(nf) = tx_nullifier(&tx) {
            if let Some(idx) = self.txs.iter().position(|t| tx_nullifier(t) == Some(nf)) {
                if tx_fee(&tx) > tx_fee(&self.txs[idx]) {
                    self.txs.swap_remove(idx);
                } else {
                    return false;
                }
            }
        }
        // Same reasoning for oversized contract deploys: consensus caps them.
        if matches!(&tx, Transaction::DeployContract { code, .. } if code.len() > MAX_CONTRACT_CODE_BYTES) {
            return false;
        }
        let h = tx_hash(&tx);
        if self.seen.contains(&h) {
            return false;
        }
        // Size cap with fee-priority admission: when the pool is full, a new tx
        // is only admitted if it outbids the cheapest resident, which it evicts.
        // This bounds memory AND stops zero-value spam from crowding out paying txs.
        if self.txs.len() >= MAX_MEMPOOL_TXS {
            match self.txs.iter().enumerate().map(|(i, t)| (i, tx_fee(t))).min_by_key(|&(_, f)| f) {
                Some((idx, min_fee)) if tx_fee(&tx) > min_fee => {
                    self.txs.swap_remove(idx);
                }
                _ => return false, // doesn't outbid the cheapest — refuse
            }
        }
        if self.seen.len() >= MAX_SEEN {
            self.seen.clear();
        }
        self.seen.insert(h);
        self.txs.push(tx);
        true
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Remove and return up to `max` pending transactions for inclusion in a
    /// block — highest fee first, submission order among equal fees. Their
    /// hashes stay in `seen` so they can't be re-added while in flight.
    pub fn drain(&mut self, max: usize) -> Vec<Transaction> {
        let n = max.min(self.txs.len());
        if n == 0 {
            return Vec::new();
        }
        // Stable sort keeps FIFO order among equal fees.
        let mut order: Vec<usize> = (0..self.txs.len()).collect();
        order.sort_by_key(|&i| Reverse(tx_fee(&self.txs[i])));
        let mut slots: Vec<Option<Transaction>> = self.txs.drain(..).map(Some).collect();
        let picked = order[..n].iter().filter_map(|&i| slots[i].take()).collect();
        self.txs = slots.into_iter().flatten().collect();
        picked
    }

    /// Drop any still-pending transactions that appear in `included` (e.g. after a
    /// block arrives from a peer carrying transactions we also held), plus any
    /// anonymous spend whose nullifier one of them consumed (a conflicting spend
    /// can never be mined once its nullifier is on-chain).
    pub fn remove_included(&mut self, included: &[Transaction]) {
        let ids: HashSet<[u8; 32]> = included.iter().map(tx_hash).collect();
        let nfs: HashSet<[u8; 32]> = included.iter().filter_map(tx_nullifier).collect();
        self.txs.retain(|t| {
            !ids.contains(&tx_hash(t)) && !tx_nullifier(t).is_some_and(|nf| nfs.contains(&nf))
        });
    }

    /// Drop anonymous spends whose epoch is not the one the NEXT block (at
    /// `next_height`) belongs to — their proofs can never be mined now. Call on
    /// every new tip.
    pub fn prune_expired(&mut self, next_height: u64) {
        let epoch = lat_state::epoch_of(next_height);
        self.txs.retain(|t| match t {
            Transaction::AnonTransfer { xfer, .. } => xfer.epoch == epoch,
            _ => true,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lat_crypto::{SecretKey, SolventTransfer};
    use rand::rngs::OsRng;

    fn reg(id: u8) -> Transaction {
        Transaction::Register { pubkey: [id; 32], pow_nonce: 0 }
    }

    /// A valid solvent transfer paying `fee` (fresh random keys each call).
    fn transfer_with_fee(fee: u64) -> Transaction {
        let mut rng = OsRng;
        let sender = SecretKey::random(&mut rng);
        let receiver = SecretKey::random(&mut rng);
        let bal = sender.public_key().encrypt(1_000_000, &mut rng);
        let xfer =
            SolventTransfer::create(&sender, &receiver.public_key(), 0, 1, fee, 1_000_000, &bal, 0, &mut rng)
                .expect("affordable");
        Transaction::SolventTransfer { token: 0, xfer }
    }

    #[test]
    fn dedups_by_hash() {
        let mut mp = Mempool::new();
        assert!(mp.add(reg(1)));
        assert!(!mp.add(reg(1)), "identical tx is a duplicate");
        assert!(mp.add(reg(2)));
        assert_eq!(mp.len(), 2);
    }

    #[test]
    fn drain_returns_in_order_and_empties() {
        let mut mp = Mempool::new();
        mp.add(reg(1));
        mp.add(reg(2));
        mp.add(reg(3));
        let first_two = mp.drain(2);
        assert_eq!(first_two.len(), 2);
        assert_eq!(mp.len(), 1);
        // Drained txs remain "seen" and cannot be re-added.
        assert!(!mp.add(reg(1)));
    }

    #[test]
    fn rejects_transfer_under_the_fee_floor() {
        let mut mp = Mempool::new();
        assert!(!mp.add(transfer_with_fee(MIN_TRANSFER_FEE - 1)), "underpaying tx refused");
        assert!(mp.is_empty());
        assert!(mp.add(transfer_with_fee(MIN_TRANSFER_FEE)), "floor fee accepted");
    }

    #[test]
    fn drain_prefers_higher_fees() {
        let mut mp = Mempool::new();
        let low = transfer_with_fee(MIN_TRANSFER_FEE);
        let high = transfer_with_fee(MIN_TRANSFER_FEE * 10);
        let (low_id, high_id) = (tx_hash(&low), tx_hash(&high));
        mp.add(reg(1)); // fee-less, submitted first
        mp.add(low);
        mp.add(high);

        let picked = mp.drain(2);
        assert_eq!(tx_hash(&picked[0]), high_id, "highest fee mined first");
        assert_eq!(tx_hash(&picked[1]), low_id);
        assert_eq!(mp.len(), 1, "the fee-less registration waits");
    }

    #[test]
    fn rejects_public_transfer_under_the_fee_floor() {
        let mut mp = Mempool::new();
        let sk = SecretKey::random(&mut OsRng);
        let id = sk.public_key().to_bytes();
        let mk = |fee| {
            let mut tx = Transaction::PublicTransfer {
                token: 0, from: id, to: [1u8; 32], amount: 1, fee, nonce: 0, sig: [0u8; 64],
            };
            let sig = sk.sign(&tx.signing_bytes()).to_bytes();
            if let Transaction::PublicTransfer { sig: s, .. } = &mut tx {
                *s = sig;
            }
            tx
        };
        assert!(!mp.add(mk(MIN_TRANSFER_FEE - 1)), "underpaying public transfer refused");
        assert!(mp.is_empty());
        assert!(mp.add(mk(MIN_TRANSFER_FEE)), "floor-fee public transfer accepted");
    }

    #[test]
    fn rejects_shield_under_the_fee_floor() {
        let mut mp = Mempool::new();
        let sk = SecretKey::random(&mut OsRng);
        let id = sk.public_key().to_bytes();
        let mk = |fee| {
            let mut tx = Transaction::Shield {
                token: 0, from: id, to: [1u8; 32], amount: 1, fee, nonce: 0, sig: [0u8; 64],
            };
            let sig = sk.sign(&tx.signing_bytes()).to_bytes();
            if let Transaction::Shield { sig: s, .. } = &mut tx {
                *s = sig;
            }
            tx
        };
        assert!(!mp.add(mk(MIN_TRANSFER_FEE - 1)), "underpaying shield refused");
        assert!(mp.add(mk(MIN_TRANSFER_FEE)), "floor-fee shield accepted");
    }

    #[test]
    fn mempool_is_capped_and_fee_prioritized() {
        // A spam flood can't grow memory without bound, and can't crowd out a
        // paying transaction.
        let mut mp = Mempool::new();
        for i in 0..MAX_MEMPOOL_TXS {
            let mut pk = [0u8; 32];
            pk[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(mp.add(Transaction::Register { pubkey: pk, pow_nonce: 0 }));
        }
        assert_eq!(mp.len(), MAX_MEMPOOL_TXS);

        // Another fee-less (0-fee) tx can't outbid the residents → refused, capped.
        assert!(!mp.add(Transaction::Register { pubkey: [0xFF; 32], pow_nonce: 0 }));
        assert_eq!(mp.len(), MAX_MEMPOOL_TXS, "size stays capped under spam");

        // A fee-paying transfer outbids a 0-fee resident and is admitted.
        assert!(mp.add(transfer_with_fee(MIN_TRANSFER_FEE)), "a paying tx gets in");
        assert_eq!(mp.len(), MAX_MEMPOOL_TXS, "one evicted, one admitted");
    }

    /// An anonymous transfer by `sender` (index 0 of a fresh 3-ring) paying `fee`,
    /// built for `epoch`.
    fn anon_with(sender: &SecretKey, fee: u64, epoch: u64) -> Transaction {
        let mut rng = OsRng;
        let mut sks: Vec<SecretKey> = (0..3).map(|_| SecretKey::random(&mut rng)).collect();
        sks[0] = sender.clone();
        let ring: Vec<_> = sks.iter().map(|s| s.public_key()).collect();
        let balances: Vec<_> = sks.iter().map(|s| s.public_key().encrypt(1_000_000, &mut rng)).collect();
        let receiver = SecretKey::random(&mut rng).public_key();
        let xfer = lat_crypto::AnonTransfer::create(
            &ring, &balances, &sks[0], 0, 1_000_000, &receiver, 0, 1_000, fee, epoch, &mut rng,
        )
        .expect("solvent");
        Transaction::AnonTransfer { token: 0, xfer }
    }

    #[test]
    fn anon_transfer_fee_floor_and_nullifier_replacement() {
        let mut mp = Mempool::new();
        let spender = SecretKey::random(&mut OsRng);

        assert!(!mp.add(anon_with(&spender, MIN_TRANSFER_FEE - 1, 0)), "under the floor refused");

        // Two spends by the same account in the same epoch share a nullifier:
        // only one can be mined, so the pool keeps the higher-fee one.
        let low = anon_with(&spender, MIN_TRANSFER_FEE, 0);
        let high = anon_with(&spender, MIN_TRANSFER_FEE * 5, 0);
        assert!(mp.add(low.clone()));
        assert!(!mp.add(anon_with(&spender, MIN_TRANSFER_FEE, 0)), "equal fee doesn't replace");
        assert_eq!(mp.len(), 1);
        assert!(mp.add(high.clone()), "higher fee replaces the conflicting spend");
        assert_eq!(mp.len(), 1, "the low-fee conflict was evicted");
        assert_eq!(tx_hash(&mp.drain(1)[0]), tx_hash(&high));

        // A DIFFERENT epoch is a different nullifier — no conflict.
        let mut mp = Mempool::new();
        assert!(mp.add(anon_with(&spender, MIN_TRANSFER_FEE, 0)));
        assert!(mp.add(anon_with(&spender, MIN_TRANSFER_FEE, 1)));
        assert_eq!(mp.len(), 2);
    }

    #[test]
    fn confirmed_nullifier_evicts_conflicting_spend_and_expiry_prunes() {
        let mut mp = Mempool::new();
        let spender = SecretKey::random(&mut OsRng);
        let mined = anon_with(&spender, MIN_TRANSFER_FEE, 0);
        let rival = anon_with(&spender, MIN_TRANSFER_FEE, 0); // same nullifier, different tx

        let mut pool2 = Mempool::new();
        assert!(pool2.add(rival));
        // A block carrying `mined` lands: the rival can never be mined now.
        pool2.remove_included(&[mined]);
        assert!(pool2.is_empty(), "conflicting in-flight spend dropped");

        // Epoch expiry: a spend built for epoch 0 dies once the next block is epoch 1.
        assert!(mp.add(anon_with(&spender, MIN_TRANSFER_FEE, 0)));
        mp.prune_expired(lat_state::EPOCH_BLOCKS); // next block is the first of epoch 1
        assert!(mp.is_empty(), "stale-epoch spend pruned");
    }

    #[test]
    fn remove_included_clears_confirmed() {
        let mut mp = Mempool::new();
        mp.add(reg(1));
        mp.add(reg(2));
        let confirmed = vec![reg(1)];
        mp.remove_included(&confirmed);
        assert_eq!(mp.len(), 1);
    }
}

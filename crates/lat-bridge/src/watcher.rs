//! The watcher: the reachable half of swap automation.
//!
//! In a cross-chain swap the counterparty reveals the secret by *claiming* the
//! Latebra HTLC leg — and Latebra, unlike the remote chain, is a chain this
//! process can already read over RPC. So the watcher's job is concrete and
//! fully local: observe a Latebra HTLC by id, and the moment it is claimed,
//! extract the revealed preimage (verifying it against the expected hashlock).
//! That preimage is exactly what [`ChainAdapter::claim`](crate::ChainAdapter)
//! needs to build the spend of the *other* chain's leg — so the watcher closes
//! the loop from "counterparty claimed on Latebra" to "here is your claim
//! payload for BTC/ETH/SOL".
//!
//! The state machine here is pure and testable against a [`LatObserver`] mock.
//! A live node-backed observer lives behind the `node` feature ([`node`]).

use crate::{sha256, Hash};

/// What an observer can learn about a Latebra HTLC leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LatLegState {
    /// No lock with this id is on-chain (not created yet, or unreachable).
    Absent,
    /// The lock is open and funded — not yet claimed or refunded.
    Open,
    /// The lock was claimed; the preimage was revealed on-chain.
    Claimed(Hash),
    /// The lock is gone, but no claim was seen — refunded, or the claim is
    /// outside the observer's scan window.
    GoneUnclaimed,
}

/// A source of Latebra HTLC observations: a live node, or a test mock.
pub trait LatObserver {
    /// The current on-chain state of the Latebra HTLC with this id.
    fn lat_leg(&self, id: &Hash) -> LatLegState;
    /// The current chain height, for expiry checks.
    fn height(&self) -> u64;
}

/// What the local party should do next, from polling the Latebra leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchResult {
    /// The lock is open and not yet past expiry — keep watching.
    Pending,
    /// The lock was claimed and the revealed preimage checks out against the
    /// hashlock. Feed it to the remote chain's `ChainAdapter::claim`.
    Revealed(Hash),
    /// The local party should refund: the lock is open but past expiry, or it
    /// vanished without an observable claim.
    RefundReady,
    /// A claim was observed but its preimage did NOT hash to the expected
    /// hashlock — never act on it (a malformed or unrelated record).
    BadPreimage,
}

/// Watches one Latebra HTLC leg for the revealed preimage.
#[derive(Clone, Debug)]
pub struct PreimageWatch {
    /// The Latebra HTLC id to watch (see [`lat_types::htlc_id`] when `node`).
    pub htlc_id: Hash,
    /// The hashlock every leg of the swap commits to.
    pub hashlock: Hash,
    /// The Latebra lock's expiry height; past it, the funder can refund.
    pub expiry: u64,
}

impl PreimageWatch {
    pub fn new(htlc_id: Hash, hashlock: Hash, expiry: u64) -> Self {
        PreimageWatch { htlc_id, hashlock, expiry }
    }

    /// Evaluate one observation into the next action.
    pub fn poll(&self, obs: &impl LatObserver) -> WatchResult {
        match obs.lat_leg(&self.htlc_id) {
            LatLegState::Claimed(preimage) => {
                if sha256(&preimage) == self.hashlock {
                    WatchResult::Revealed(preimage)
                } else {
                    WatchResult::BadPreimage
                }
            }
            LatLegState::GoneUnclaimed => WatchResult::RefundReady,
            LatLegState::Open => {
                if obs.height() >= self.expiry {
                    WatchResult::RefundReady
                } else {
                    WatchResult::Pending
                }
            }
            // Not on-chain yet (or node unreachable): nothing to refund, wait.
            LatLegState::Absent => WatchResult::Pending,
        }
    }
}

#[cfg(feature = "node")]
pub mod node {
    //! A [`LatObserver`] backed by a live `latebrad` node over RPC. Reads the
    //! open-HTLC set directly, and recovers a revealed preimage by scanning the
    //! most recent blocks for the `HtlcClaim` transaction that spent the lock.

    use super::{LatLegState, LatObserver};
    use crate::Hash;

    pub struct NodeObserver {
        addr: String,
        /// How many recent blocks to scan for a claim before giving up.
        scan_window: u64,
    }

    impl NodeObserver {
        pub fn new(addr: impl Into<String>) -> Self {
            NodeObserver { addr: addr.into(), scan_window: 1024 }
        }

        pub fn with_scan_window(mut self, blocks: u64) -> Self {
            self.scan_window = blocks;
            self
        }

        /// Scan recent blocks (newest first) for the `HtlcClaim` of `id`,
        /// returning the preimage it revealed.
        fn find_claim(&self, id: &Hash, height: u64) -> Option<Hash> {
            let start = height.saturating_sub(self.scan_window);
            for h in (start..=height).rev() {
                let Ok(Some(bytes)) = lat_p2p::get_block(&self.addr, h) else { continue };
                let Some(block) = lat_chain::Block::decode(&bytes) else { continue };
                for tx in &block.txs {
                    if let lat_types::Transaction::HtlcClaim { id: cid, preimage } = tx {
                        if cid == id {
                            return Some(*preimage);
                        }
                    }
                }
            }
            None
        }
    }

    impl LatObserver for NodeObserver {
        fn height(&self) -> u64 {
            lat_p2p::get_height(&self.addr).unwrap_or(0)
        }

        fn lat_leg(&self, id: &Hash) -> LatLegState {
            match lat_p2p::get_htlc(&self.addr, *id) {
                Ok(Some(_)) => LatLegState::Open,
                Ok(None) => {
                    let h = self.height();
                    match self.find_claim(id, h) {
                        Some(pre) => LatLegState::Claimed(pre),
                        None => LatLegState::GoneUnclaimed,
                    }
                }
                Err(_) => LatLegState::Absent, // unreachable → treat as not-yet-visible
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;
    use std::cell::Cell;

    struct Mock {
        state: LatLegState,
        height: Cell<u64>,
    }
    impl LatObserver for Mock {
        fn lat_leg(&self, _id: &Hash) -> LatLegState {
            self.state.clone()
        }
        fn height(&self) -> u64 {
            self.height.get()
        }
    }

    fn watch() -> (PreimageWatch, Secret) {
        let secret = Secret::from_bytes([9u8; 32]);
        (PreimageWatch::new([1u8; 32], secret.hashlock(), 1000), secret)
    }

    #[test]
    fn open_before_expiry_is_pending() {
        let (w, _) = watch();
        let m = Mock { state: LatLegState::Open, height: Cell::new(500) };
        assert_eq!(w.poll(&m), WatchResult::Pending);
    }

    #[test]
    fn open_past_expiry_is_refund_ready() {
        let (w, _) = watch();
        let m = Mock { state: LatLegState::Open, height: Cell::new(1000) };
        assert_eq!(w.poll(&m), WatchResult::RefundReady);
    }

    #[test]
    fn valid_claim_reveals_preimage() {
        let (w, secret) = watch();
        let m = Mock { state: LatLegState::Claimed(secret.reveal()), height: Cell::new(500) };
        assert_eq!(w.poll(&m), WatchResult::Revealed(secret.reveal()));
    }

    #[test]
    fn mismatched_preimage_is_rejected() {
        let (w, _) = watch();
        let m = Mock { state: LatLegState::Claimed([0xff; 32]), height: Cell::new(500) };
        assert_eq!(w.poll(&m), WatchResult::BadPreimage);
    }

    #[test]
    fn vanished_lock_is_refund_ready() {
        let (w, _) = watch();
        let m = Mock { state: LatLegState::GoneUnclaimed, height: Cell::new(500) };
        assert_eq!(w.poll(&m), WatchResult::RefundReady);
    }

    #[test]
    fn absent_lock_waits() {
        let (w, _) = watch();
        let m = Mock { state: LatLegState::Absent, height: Cell::new(500) };
        assert_eq!(w.poll(&m), WatchResult::Pending);
    }
}

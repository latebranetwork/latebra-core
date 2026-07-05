//! Latebra peer synchronization (clean-room, from `SPEC.md`).
//!
//! This is the **transport-agnostic** core of networking: the logic by which one
//! node catches up to another and accepts gossiped blocks, expressed purely over
//! the block wire-codec (`Block::encode`/`decode`). It carries no sockets — a
//! [`Node`] exchanges `&[u8]` block messages, so it can sit on top of any
//! transport (libp2p, raw TCP, an in-process channel, a test harness).
//!
//! Wiring this to real sockets (libp2p gossipsub for propagation + a
//! request/response protocol for catch-up) is the next, mechanical layer. The
//! correctness that matters — that a peer *independently re-validates* every block
//! it receives (PoW, proofs, tx-root, linkage) before adopting it — lives here and
//! is exercised by the tests.

use lat_chain::{Block, Blockchain, ChainError};

/// A network participant: a local chain plus the sync protocol over it.
pub struct Node {
    /// The node's blockchain. Public so callers can mine, inspect balances, etc.
    pub chain: Blockchain,
}

/// Why an incoming block was not adopted.
#[derive(Debug, PartialEq, Eq)]
pub enum SyncError {
    /// The bytes did not decode into a well-formed block.
    Malformed,
    /// The block decoded but failed consensus validation.
    Invalid(ChainError),
}

impl Node {
    /// Create a node whose chain starts from the given genesis premine. All nodes
    /// on a network must use the SAME premine + difficulty, or their genesis
    /// hashes differ and they will never agree.
    pub fn genesis(premine: &[([u8; 32], u64)], difficulty: u64) -> Node {
        Node {
            chain: Blockchain::genesis(premine, difficulty),
        }
    }

    pub fn height(&self) -> u64 {
        self.chain.height()
    }

    pub fn tip(&self) -> [u8; 32] {
        self.chain.tip()
    }

    /// Handle a single gossiped block. The node adopts it only if it cleanly
    /// extends the tip AND passes full consensus validation — exactly what stops a
    /// peer from feeding us an invalid or out-of-order block.
    pub fn receive_block(&mut self, bytes: &[u8]) -> Result<(), SyncError> {
        let block = Block::decode(bytes).ok_or(SyncError::Malformed)?;
        if block.header.height != self.chain.height() + 1 {
            // Not the next block — ignore (a real node would buffer / request gaps).
            return Err(SyncError::Invalid(ChainError::BadHeight));
        }
        self.chain.apply_block(&block).map_err(SyncError::Invalid)
    }

    /// Catch up to `peer` by pulling and validating each block above our tip.
    /// Returns the number of blocks adopted. Every block is re-validated locally —
    /// we trust no peer.
    pub fn sync_from(&mut self, peer: &Node) -> Result<usize, SyncError> {
        let mut adopted = 0;
        loop {
            let next = self.chain.height() + 1;
            let Some(bytes) = peer.chain.block_bytes(next) else {
                break; // caught up
            };
            // Copy out of the borrow before mutating self.
            let owned = bytes.to_vec();
            self.receive_block(&owned)?;
            adopted += 1;
        }
        Ok(adopted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lat_chain::DEFAULT_DIFFICULTY;
    use lat_state::LAT_TOKEN;
    use lat_wallet::Wallet;
    use lat_types::Network;
    use rand::rngs::OsRng;

    fn premine_for(id: [u8; 32]) -> Vec<([u8; 32], u64)> {
        vec![(id, 1_000_000)]
    }

    #[test]
    fn peer_syncs_full_chain() {
        let mut rng = OsRng;
        let genesis = Wallet::from_seed(Network::Testnet, [9u8; 32]);
        let alice = Wallet::generate(Network::Testnet, &mut rng);

        // Node A mines a few blocks.
        let mut a = Node::genesis(&premine_for(genesis.id()), DEFAULT_DIFFICULTY);
        let b1 = a.chain.mine(vec![alice.registration_tx()]);
        a.chain.apply_block(&b1).unwrap();
        let tx = genesis
            .create_solvent_transfer(&a.chain, &alice.address(), LAT_TOKEN, 400_000, lat_wallet::MIN_TRANSFER_FEE, &mut rng)
            .unwrap();
        let b2 = a.chain.mine(vec![tx]);
        a.chain.apply_block(&b2).unwrap();
        assert_eq!(a.height(), 2);

        // Node B starts fresh from the same genesis and syncs from A.
        let mut b = Node::genesis(&premine_for(genesis.id()), DEFAULT_DIFFICULTY);
        let adopted = b.sync_from(&a).unwrap();

        assert_eq!(adopted, 2);
        assert_eq!(b.height(), a.height());
        assert_eq!(b.tip(), a.tip(), "both nodes agree on the chain");

        // B independently reconstructed the (encrypted) state: Alice's received
        // funds (which land in her pending pool until she rolls them over).
        assert_eq!(alice.pending(&b.chain, LAT_TOKEN), Some(400_000));
    }

    #[test]
    fn gossiped_block_is_adopted() {
        let genesis = Wallet::from_seed(Network::Testnet, [1u8; 32]);
        let mut a = Node::genesis(&premine_for(genesis.id()), DEFAULT_DIFFICULTY);
        let mut b = Node::genesis(&premine_for(genesis.id()), DEFAULT_DIFFICULTY);

        let block = a.chain.mine(vec![]);
        a.chain.apply_block(&block).unwrap();

        // A gossips the raw block bytes to B.
        b.receive_block(a.chain.block_bytes(1).unwrap()).unwrap();
        assert_eq!(b.tip(), a.tip());
    }

    #[test]
    fn rejects_malformed_and_out_of_order() {
        let genesis = Wallet::from_seed(Network::Testnet, [2u8; 32]);
        let mut a = Node::genesis(&premine_for(genesis.id()), DEFAULT_DIFFICULTY);
        let mut b = Node::genesis(&premine_for(genesis.id()), DEFAULT_DIFFICULTY);

        assert_eq!(b.receive_block(&[0xde, 0xad]), Err(SyncError::Malformed));

        // Build height-2 before B has height-1: out of order, rejected.
        let b1 = a.chain.mine(vec![]);
        a.chain.apply_block(&b1).unwrap();
        let b2 = a.chain.mine(vec![]);
        a.chain.apply_block(&b2).unwrap();
        assert_eq!(
            b.receive_block(a.chain.block_bytes(2).unwrap()),
            Err(SyncError::Invalid(ChainError::BadHeight))
        );
    }
}

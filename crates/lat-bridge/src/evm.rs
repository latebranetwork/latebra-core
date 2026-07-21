//! EVM leg (Ethereum and any EVM chain): a `HashedTimelock` contract.
//!
//! Funds are locked by calling `lock(hashlock, recipient, timelock)` with the
//! ETH value attached; the recipient claims with `withdraw(hashlock, preimage)`
//! (the contract checks `sha256(preimage) == hashlock`); the funder reclaims
//! with `refund(hashlock)` once `block.timestamp >= timelock`. The reference
//! contract source is [`HASHED_TIMELOCK_SOL`].

use crate::adapter::{Action, BridgeTx, ChainAdapter, HtlcArtifact, HtlcParams};
use crate::encoding::{abi_word, eip55, selector};
use crate::{BridgeError, Chain, Network, Result};

/// The reference HTLC contract this adapter targets. Deploy it once per chain;
/// the deployed address is what [`EvmAdapter::new`] takes. It commits to
/// `sha256` (not `keccak256`) precisely so the same secret works on Bitcoin,
/// Solana, and Latebra.
pub const HASHED_TIMELOCK_SOL: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Cross-chain-swap HTLC. Hashlock is sha256(preimage) so one secret unlocks
/// the matching lock on Bitcoin, Solana, and Latebra.
contract HashedTimelock {
    struct Lock {
        address funder;
        address recipient;
        uint256 amount;
        uint256 timelock; // unix seconds; refundable at or after
        bool claimed;
        bool refunded;
    }
    mapping(bytes32 => Lock) public locks; // keyed by hashlock

    event Locked(bytes32 indexed hashlock, address recipient, uint256 amount, uint256 timelock);
    event Withdrawn(bytes32 indexed hashlock, bytes32 preimage);
    event Refunded(bytes32 indexed hashlock);

    function lock(bytes32 hashlock, address recipient, uint256 timelock) external payable {
        require(msg.value > 0, "no value");
        require(locks[hashlock].funder == address(0), "exists");
        require(timelock > block.timestamp, "timelock past");
        locks[hashlock] = Lock(msg.sender, recipient, msg.value, timelock, false, false);
        emit Locked(hashlock, recipient, msg.value, timelock);
    }

    function withdraw(bytes32 hashlock, bytes32 preimage) external {
        Lock storage l = locks[hashlock];
        require(l.recipient == msg.sender, "not recipient");
        require(!l.claimed && !l.refunded, "closed");
        require(sha256(abi.encodePacked(preimage)) == hashlock, "bad preimage");
        l.claimed = true;
        payable(l.recipient).transfer(l.amount);
        emit Withdrawn(hashlock, preimage);
    }

    function refund(bytes32 hashlock) external {
        Lock storage l = locks[hashlock];
        require(l.funder == msg.sender, "not funder");
        require(!l.claimed && !l.refunded, "closed");
        require(block.timestamp >= l.timelock, "not expired");
        l.refunded = true;
        payable(l.funder).transfer(l.amount);
        emit Refunded(hashlock);
    }
}
"#;

pub struct EvmAdapter {
    contract: [u8; 20],
    chain_id: u64,
    network: Network,
}

impl EvmAdapter {
    /// `contract` is the deployed [`HASHED_TIMELOCK_SOL`] address; `chain_id` is
    /// the EVM network id (1 = Ethereum mainnet, 11155111 = Sepolia, …).
    pub fn new(contract: [u8; 20], chain_id: u64, network: Network) -> Self {
        EvmAdapter { contract, chain_id, network }
    }

    fn recipient_word(p: &HtlcParams) -> Result<[u8; 32]> {
        if p.recipient.len() != 20 {
            return Err(BridgeError::BadParam(
                "EVM recipient must be a 20-byte address".into(),
            ));
        }
        Ok(abi_word(&p.recipient))
    }

    /// Calldata for `lock(hashlock, recipient, timelock)`, sent with
    /// `value = amount` wei.
    pub fn lock_calldata(&self, p: &HtlcParams) -> Result<Vec<u8>> {
        let mut d = selector("lock(bytes32,address,uint256)").to_vec();
        d.extend_from_slice(&p.hashlock);
        d.extend_from_slice(&Self::recipient_word(p)?);
        d.extend_from_slice(&abi_word(&p.timelock.to_be_bytes()));
        Ok(d)
    }
}

impl ChainAdapter for EvmAdapter {
    fn chain(&self) -> Chain {
        Chain::Ethereum
    }

    fn network(&self) -> Network {
        self.network
    }

    fn lock_artifact(&self, p: &HtlcParams) -> Result<HtlcArtifact> {
        let calldata = self.lock_calldata(p)?;
        let addr = eip55(&self.contract);
        Ok(HtlcArtifact {
            chain: Chain::Ethereum,
            deposit_address: addr.clone(),
            script_hex: hex::encode(&calldata),
            instructions: format!(
                "On chain id {}, send a transaction to the HashedTimelock contract \
                 {} with value {} wei and the payload hex as calldata (calls \
                 lock(hashlock, recipient, timelock)).",
                self.chain_id, addr, p.amount
            ),
        })
    }

    fn claim(&self, p: &HtlcParams, preimage: &[u8; 32]) -> Result<BridgeTx> {
        let mut d = selector("withdraw(bytes32,bytes32)").to_vec();
        d.extend_from_slice(&p.hashlock);
        d.extend_from_slice(preimage);
        Ok(BridgeTx {
            chain: Chain::Ethereum,
            action: Action::Claim,
            payload_hex: hex::encode(&d),
            describe: format!(
                "Call withdraw(hashlock, preimage) on {} — reveals the preimage and \
                 pays the recipient.",
                eip55(&self.contract)
            ),
        })
    }

    fn refund(&self, p: &HtlcParams) -> Result<BridgeTx> {
        let mut d = selector("refund(bytes32)").to_vec();
        d.extend_from_slice(&p.hashlock);
        Ok(BridgeTx {
            chain: Chain::Ethereum,
            action: Action::Refund,
            payload_hex: hex::encode(&d),
            describe: format!(
                "After unix time {}, call refund(hashlock) on {} to reclaim the \
                 locked value.",
                p.timelock,
                eip55(&self.contract)
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    fn adapter() -> EvmAdapter {
        EvmAdapter::new([0x11; 20], 1, Network::Mainnet)
    }

    fn params() -> HtlcParams {
        HtlcParams {
            hashlock: sha256(b"secret"),
            recipient: vec![0xab; 20],
            refund: vec![0xcd; 20],
            amount: 1_000_000_000_000_000_000, // 1 ETH in wei
            timelock: 1_800_000_000,
        }
    }

    #[test]
    fn lock_calldata_layout() {
        let d = adapter().lock_calldata(&params()).unwrap();
        // selector(4) + 3 ABI words(32 each) = 100 bytes.
        assert_eq!(d.len(), 4 + 32 * 3);
        // Correct selector for lock(bytes32,address,uint256).
        assert_eq!(&d[0..4], &selector("lock(bytes32,address,uint256)"));
        // hashlock occupies the first word verbatim.
        assert_eq!(&d[4..36], &sha256(b"secret"));
        // recipient address is right-aligned in its word (12 zero bytes first).
        assert_eq!(&d[36..48], &[0u8; 12]);
        assert_eq!(&d[48..68], &[0xab; 20]);
    }

    #[test]
    fn withdraw_reveals_preimage() {
        let pre = [9u8; 32];
        let tx = adapter().claim(&params(), &pre).unwrap();
        let bytes = hex::decode(&tx.payload_hex).unwrap();
        assert_eq!(&bytes[0..4], &selector("withdraw(bytes32,bytes32)"));
        assert_eq!(&bytes[36..68], &pre); // preimage is the second word
    }

    #[test]
    fn rejects_bad_recipient() {
        let mut p = params();
        p.recipient = vec![0xab; 33];
        assert!(adapter().lock_calldata(&p).is_err());
    }
}

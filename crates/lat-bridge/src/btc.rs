//! Bitcoin leg: a P2WSH hash time-locked contract.
//!
//! The redeem script is the classic cross-chain-swap HTLC:
//!
//! ```text
//! OP_IF
//!     OP_SHA256 <hashlock> OP_EQUALVERIFY <recipient_pubkey> OP_CHECKSIG
//! OP_ELSE
//!     <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <refund_pubkey> OP_CHECKSIG
//! OP_ENDIF
//! ```
//!
//! The claimer spends the `OP_IF` branch by revealing the preimage; the funder
//! reclaims via the `OP_ELSE` branch after block height `locktime`. The deposit
//! address is the witness-v0 program `SHA-256(redeemScript)`, bech32-encoded.

use crate::adapter::{Action, BridgeTx, ChainAdapter, HtlcArtifact, HtlcParams};
use crate::encoding::{push_data, script_num};
use crate::{sha256, BridgeError, Chain, Network, Result};
use bech32::Hrp;

// Script opcodes used by the HTLC.
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_DROP: u8 = 0x75;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_SHA256: u8 = 0xa8;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;

pub struct BtcAdapter {
    network: Network,
}

impl BtcAdapter {
    pub fn new(network: Network) -> Self {
        BtcAdapter { network }
    }

    fn hrp(&self) -> Hrp {
        match self.network {
            Network::Mainnet => Hrp::parse("bc").unwrap(),
            Network::Testnet => Hrp::parse("tb").unwrap(),
        }
    }

    /// Build the HTLC redeem (witness) script from the params. `recipient` and
    /// `refund` must be 33-byte compressed secp256k1 public keys.
    pub fn redeem_script(&self, p: &HtlcParams) -> Result<Vec<u8>> {
        if p.recipient.len() != 33 {
            return Err(BridgeError::BadParam(
                "BTC recipient must be a 33-byte compressed pubkey".into(),
            ));
        }
        if p.refund.len() != 33 {
            return Err(BridgeError::BadParam(
                "BTC refund must be a 33-byte compressed pubkey".into(),
            ));
        }
        let mut s = Vec::with_capacity(128);
        s.push(OP_IF);
        s.push(OP_SHA256);
        push_data(&mut s, &p.hashlock);
        s.push(OP_EQUALVERIFY);
        push_data(&mut s, &p.recipient);
        s.push(OP_CHECKSIG);
        s.push(OP_ELSE);
        push_data(&mut s, &script_num(p.timelock as i64));
        s.push(OP_CHECKLOCKTIMEVERIFY);
        s.push(OP_DROP);
        push_data(&mut s, &p.refund);
        s.push(OP_CHECKSIG);
        s.push(OP_ENDIF);
        Ok(s)
    }

    /// The bech32 P2WSH deposit address for a given redeem script.
    pub fn p2wsh_address(&self, redeem_script: &[u8]) -> String {
        let program = sha256(redeem_script); // witness v0 program (32 bytes)
        bech32::segwit::encode_v0(self.hrp(), &program).expect("valid witness program")
    }
}

impl ChainAdapter for BtcAdapter {
    fn chain(&self) -> Chain {
        Chain::Bitcoin
    }

    fn network(&self) -> Network {
        self.network
    }

    fn lock_artifact(&self, p: &HtlcParams) -> Result<HtlcArtifact> {
        let script = self.redeem_script(p)?;
        let address = self.p2wsh_address(&script);
        Ok(HtlcArtifact {
            chain: Chain::Bitcoin,
            deposit_address: address.clone(),
            script_hex: hex::encode(&script),
            instructions: format!(
                "Send {} sat to the P2WSH address {}. It becomes claimable by the \
                 recipient with the preimage, or refundable to you after block {}.",
                p.amount, address, p.timelock
            ),
        })
    }

    fn claim(&self, p: &HtlcParams, preimage: &[u8; 32]) -> Result<BridgeTx> {
        let script = self.redeem_script(p)?;
        Ok(BridgeTx {
            chain: Chain::Bitcoin,
            action: Action::Claim,
            payload_hex: hex::encode(&script),
            describe: format!(
                "Spend the P2WSH output with witness stack \
                 [<signature> {} 0x01 <redeemScript>] (the 0x01 selects the OP_IF \
                 branch). redeemScript = the payload hex.",
                hex::encode(preimage)
            ),
        })
    }

    fn refund(&self, p: &HtlcParams) -> Result<BridgeTx> {
        let script = self.redeem_script(p)?;
        Ok(BridgeTx {
            chain: Chain::Bitcoin,
            action: Action::Refund,
            payload_hex: hex::encode(&script),
            describe: format!(
                "After block {}, spend the P2WSH output with witness stack \
                 [<signature> <empty> <redeemScript>], the transaction's nLockTime \
                 set to at least {} and the input's nSequence below 0xffffffff.",
                p.timelock, p.timelock
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> HtlcParams {
        HtlcParams {
            hashlock: sha256(b"secret"),
            recipient: vec![0x02; 33],
            refund: vec![0x03; 33],
            amount: 100_000,
            timelock: 800_000,
        }
    }

    #[test]
    fn redeem_script_has_expected_shape() {
        let a = BtcAdapter::new(Network::Mainnet);
        let s = a.redeem_script(&params()).unwrap();
        assert_eq!(s[0], OP_IF);
        assert_eq!(s[1], OP_SHA256);
        assert_eq!(s[2], 32); // push 32-byte hashlock
        assert_eq!(*s.last().unwrap(), OP_ENDIF);
        // Both branches end in OP_CHECKSIG, and the else branch uses CLTV+DROP.
        assert!(s.contains(&OP_CHECKLOCKTIMEVERIFY));
        assert!(s.contains(&OP_DROP));
    }

    #[test]
    fn address_is_bech32_p2wsh() {
        let a = BtcAdapter::new(Network::Mainnet);
        let art = a.lock_artifact(&params()).unwrap();
        // Mainnet P2WSH addresses are bech32 "bc1q…", 62 chars long.
        assert!(art.deposit_address.starts_with("bc1q"));
        assert_eq!(art.deposit_address.len(), 62);

        let t = BtcAdapter::new(Network::Testnet);
        assert!(t.lock_artifact(&params()).unwrap().deposit_address.starts_with("tb1q"));
    }

    #[test]
    fn rejects_bad_pubkey_length() {
        let a = BtcAdapter::new(Network::Mainnet);
        let mut p = params();
        p.recipient = vec![0x02; 20];
        assert!(a.redeem_script(&p).is_err());
    }

    #[test]
    fn address_is_deterministic() {
        let a = BtcAdapter::new(Network::Mainnet);
        assert_eq!(
            a.lock_artifact(&params()).unwrap().deposit_address,
            a.lock_artifact(&params()).unwrap().deposit_address
        );
    }
}

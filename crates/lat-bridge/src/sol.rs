//! Solana leg: an HTLC program whose escrow is a program-derived account (PDA).
//!
//! `initialize` moves lamports into the PDA under a hashlock + timelock;
//! `redeem` releases them to the recipient on a preimage whose `sha256` matches;
//! `refund` returns them to the funder after the timelock. Discriminators follow
//! the Anchor convention `sha256("global:<ix>")[..8]`, so the reference program
//! ([`HTLC_PROGRAM_RS`]) can be built with Anchor unchanged.

use crate::adapter::{Action, BridgeTx, ChainAdapter, HtlcArtifact, HtlcParams};
use crate::encoding::base58;
use crate::{BridgeError, Chain, Network, Result};
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

/// Reference Anchor program the adapter's instruction data targets.
pub const HTLC_PROGRAM_RS: &str = r#"// Anchor HTLC program (reference). Hashlock is sha256(preimage) so one secret
// unlocks the matching lock on Bitcoin, EVM chains, and Latebra.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;

#[program]
pub mod htlc {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, hashlock: [u8; 32],
                      timelock: i64, recipient: Pubkey, amount: u64) -> Result<()> {
        let e = &mut ctx.accounts.escrow;
        e.funder = ctx.accounts.funder.key();
        e.recipient = recipient;
        e.hashlock = hashlock;
        e.timelock = timelock;
        e.amount = amount;
        // move `amount` lamports from funder into the escrow PDA
        Ok(())
    }

    pub fn redeem(ctx: Context<Redeem>, preimage: [u8; 32]) -> Result<()> {
        let e = &ctx.accounts.escrow;
        require!(hashv(&[&preimage]).to_bytes() == e.hashlock, Err::BadPreimage);
        // pay escrow lamports to e.recipient
        Ok(())
    }

    pub fn refund(ctx: Context<Refund>) -> Result<()> {
        let e = &ctx.accounts.escrow;
        require!(Clock::get()?.unix_timestamp >= e.timelock, Err::NotExpired);
        // return escrow lamports to e.funder
        Ok(())
    }
}
"#;

/// The Anchor instruction discriminator: `sha256("global:<name>")[..8]`.
fn discriminator(ix: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(format!("global:{ix}").as_bytes());
    let d: [u8; 32] = h.finalize().into();
    d[..8].try_into().unwrap()
}

/// True if `bytes` is a valid ed25519 curve point — i.e. NOT a valid PDA. A PDA
/// must be off-curve so no private key can control it.
fn is_on_curve(bytes: &[u8; 32]) -> bool {
    match CompressedEdwardsY::from_slice(bytes) {
        Ok(c) => c.decompress().is_some(),
        Err(_) => false,
    }
}

pub struct SolAdapter {
    program_id: [u8; 32],
    network: Network,
}

impl SolAdapter {
    pub fn new(program_id: [u8; 32], network: Network) -> Self {
        SolAdapter { program_id, network }
    }

    /// Derive the escrow PDA and its bump for a hashlock, exactly as Solana's
    /// `find_program_address(&[b"htlc", hashlock], program_id)` does.
    pub fn escrow_pda(&self, hashlock: &[u8; 32]) -> ([u8; 32], u8) {
        for bump in (0u8..=255).rev() {
            let mut h = Sha256::new();
            h.update(b"htlc");
            h.update(hashlock);
            h.update([bump]);
            h.update(self.program_id);
            h.update(b"ProgramDerivedAddress");
            let cand: [u8; 32] = h.finalize().into();
            if !is_on_curve(&cand) {
                return (cand, bump);
            }
        }
        unreachable!("a bump seed yielding an off-curve address always exists")
    }

    /// `initialize` instruction data: discriminator ++ hashlock ++ timelock(i64
    /// LE) ++ recipient(32) ++ amount(u64 LE).
    pub fn initialize_data(&self, p: &HtlcParams) -> Result<Vec<u8>> {
        if p.recipient.len() != 32 {
            return Err(BridgeError::BadParam(
                "SOL recipient must be a 32-byte pubkey".into(),
            ));
        }
        let amount: u64 = p
            .amount
            .try_into()
            .map_err(|_| BridgeError::BadParam("SOL amount exceeds u64 lamports".into()))?;
        let mut d = discriminator("initialize").to_vec();
        d.extend_from_slice(&p.hashlock);
        d.extend_from_slice(&(p.timelock as i64).to_le_bytes());
        d.extend_from_slice(&p.recipient);
        d.extend_from_slice(&amount.to_le_bytes());
        Ok(d)
    }
}

impl ChainAdapter for SolAdapter {
    fn chain(&self) -> Chain {
        Chain::Solana
    }

    fn network(&self) -> Network {
        self.network
    }

    fn lock_artifact(&self, p: &HtlcParams) -> Result<HtlcArtifact> {
        let data = self.initialize_data(p)?;
        let (pda, bump) = self.escrow_pda(&p.hashlock);
        Ok(HtlcArtifact {
            chain: Chain::Solana,
            deposit_address: base58(&pda),
            script_hex: hex::encode(&data),
            instructions: format!(
                "Invoke program {} instruction `initialize` (payload hex) with the \
                 escrow PDA {} (bump {}); it locks {} lamports under the hashlock.",
                base58(&self.program_id),
                base58(&pda),
                bump,
                p.amount
            ),
        })
    }

    fn claim(&self, p: &HtlcParams, preimage: &[u8; 32]) -> Result<BridgeTx> {
        let mut d = discriminator("redeem").to_vec();
        d.extend_from_slice(preimage);
        Ok(BridgeTx {
            chain: Chain::Solana,
            action: Action::Claim,
            payload_hex: hex::encode(&d),
            describe: format!(
                "Invoke `redeem` on program {} with the escrow PDA {} — reveals the \
                 preimage and pays the recipient.",
                base58(&self.program_id),
                base58(&self.escrow_pda(&p.hashlock).0)
            ),
        })
    }

    fn refund(&self, p: &HtlcParams) -> Result<BridgeTx> {
        let d = discriminator("refund").to_vec();
        Ok(BridgeTx {
            chain: Chain::Solana,
            action: Action::Refund,
            payload_hex: hex::encode(&d),
            describe: format!(
                "After unix time {}, invoke `refund` on program {} with the escrow \
                 PDA {} to return the lamports to the funder.",
                p.timelock,
                base58(&self.program_id),
                base58(&self.escrow_pda(&p.hashlock).0)
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    fn adapter() -> SolAdapter {
        SolAdapter::new([0x05; 32], Network::Mainnet)
    }

    fn params() -> HtlcParams {
        HtlcParams {
            hashlock: sha256(b"secret"),
            recipient: vec![0x07; 32],
            refund: vec![0x08; 32],
            amount: 1_000_000_000, // 1 SOL in lamports
            timelock: 1_800_000_000,
        }
    }

    #[test]
    fn initialize_data_layout() {
        let d = adapter().initialize_data(&params()).unwrap();
        // 8 (disc) + 32 (hashlock) + 8 (timelock) + 32 (recipient) + 8 (amount).
        assert_eq!(d.len(), 8 + 32 + 8 + 32 + 8);
        assert_eq!(&d[0..8], &discriminator("initialize"));
        assert_eq!(&d[8..40], &sha256(b"secret"));
    }

    #[test]
    fn pda_is_off_curve_and_deterministic() {
        let a = adapter();
        let (pda, _bump) = a.escrow_pda(&params().hashlock);
        assert!(!is_on_curve(&pda), "a PDA must not be a valid curve point");
        assert_eq!(pda, a.escrow_pda(&params().hashlock).0);
    }

    #[test]
    fn pda_base58_looks_like_a_pubkey() {
        let art = adapter().lock_artifact(&params()).unwrap();
        // Base58 of 32 bytes is 32–44 chars.
        assert!((32..=44).contains(&art.deposit_address.len()));
    }

    #[test]
    fn rejects_bad_recipient() {
        let mut p = params();
        p.recipient = vec![0x07; 20];
        assert!(adapter().initialize_data(&p).is_err());
    }
}

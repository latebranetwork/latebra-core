//! T14 — stake-weighted **finality certificates** (the first half of BFT-PoS).
//!
//! # Model (hybrid, honest about its guarantees)
//!
//! Proof-of-work keeps *producing* blocks exactly as before; finality rides on
//! top. Validators (accounts bonded via T13's `Stake`) sign a [`Vote`] for a
//! block they have adopted as their tip. Votes for one block whose stake sums
//! to **more than 2/3** of the validator set's total form a [`Certificate`],
//! and a certified block becomes the chain's **finalized watermark**: fork
//! choice (T15, in `Blockchain::apply_block`) refuses any reorganization that
//! does not descend from it, however much cumulative work the rival carries.
//!
//! With more than 2/3 of bonded stake honest, two conflicting certificates
//! cannot form (any two >2/3 quorums intersect in >1/3, which would require
//! that overlap to sign two blocks at one height). What this v1 does NOT yet
//! provide: slashing for exactly that equivocation (T16), round-based
//! liveness (a height may simply never certify — PoW continues regardless),
//! and proposer rotation (PoW is the producer). An **empty validator set
//! disables finality entirely** — the chain behaves as pure PoW, which keeps
//! single-node dev and the current testnet semantics unchanged.
//!
//! # Which validator set judges a certificate?
//!
//! The set committed by the voted block itself (recorded by the chain when it
//! adopts the block, from `Ledger::validator_set()` — T13). The header's
//! PoW-bound `state_root` commits that set, so it is not the verifier's
//! opinion, it is chain state. Nodes keep the recent window of sets in memory
//! ([`crate::FINALITY_SET_WINDOW`]); certificates older than the window can no
//! longer be verified live and are simply ignored — finality is a *recent*
//! anti-reorg guarantee, deep history is already secured by accumulated work.

use lat_crypto::{PublicKey, SecretKey, Signature};

/// The bytes a finality vote signs — defined in lat-types so the ledger can
/// verify `SlashEvidence` (T16) without a dependency cycle.
pub use lat_types::finality_vote_signing_bytes as vote_signing_bytes;

/// One validator's signed attestation: "the block `block_id` at `height` is
/// on my adopted chain".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    pub block_id: [u8; 32],
    pub height: u64,
    /// The validator's account key (must be in the block's validator set).
    pub validator: [u8; 32],
    /// Schnorr signature by `validator` over [`vote_signing_bytes`].
    pub sig: [u8; 64],
}

impl Vote {
    /// Sign a vote for (`block_id`, `height`) with the validator key `sk`.
    pub fn sign(sk: &SecretKey, block_id: [u8; 32], height: u64) -> Vote {
        let sig = sk.sign(&vote_signing_bytes(&block_id, height)).to_bytes();
        Vote { block_id, height, validator: sk.public_key().to_bytes(), sig }
    }

    /// Whether `sig` is a valid signature by `validator` over this vote.
    pub fn verify(&self) -> bool {
        let Some(pk) = PublicKey::from_bytes(&self.validator) else { return false };
        let Some(sig) = Signature::from_bytes(&self.sig) else { return false };
        pk.verify(&vote_signing_bytes(&self.block_id, self.height), &sig)
    }

    /// Fixed 136-byte wire encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(136);
        v.extend_from_slice(&self.block_id);
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(&self.validator);
        v.extend_from_slice(&self.sig);
        v
    }

    pub fn decode(b: &[u8]) -> Option<Vote> {
        if b.len() != 136 {
            return None;
        }
        Some(Vote {
            block_id: b[0..32].try_into().ok()?,
            height: u64::from_le_bytes(b[32..40].try_into().ok()?),
            validator: b[40..72].try_into().ok()?,
            sig: b[72..136].try_into().ok()?,
        })
    }
}

/// A quorum of votes for one block: the object that finalizes it. Compact and
/// self-contained — anyone holding the block's validator set can verify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub block_id: [u8; 32],
    pub height: u64,
    /// `(validator, signature)` pairs, one per distinct validator.
    pub votes: Vec<([u8; 32], [u8; 64])>,
}

impl Certificate {
    /// Verify against the voted block's validator `set` (id → stake):
    /// every signer is a distinct set member with a valid signature, and the
    /// signers' stake is **strictly more than 2/3** of the set's total.
    pub fn verify(&self, set: &[([u8; 32], u64)]) -> bool {
        if self.votes.is_empty() || set.is_empty() {
            return false;
        }
        let total: u128 = set.iter().map(|(_, s)| *s as u128).sum();
        let mut seen = std::collections::HashSet::new();
        let mut voted: u128 = 0;
        for (validator, sig) in &self.votes {
            if !seen.insert(*validator) {
                return false; // duplicate signer
            }
            let Some((_, stake)) = set.iter().find(|(id, _)| id == validator) else {
                return false; // not in the set that judges this block
            };
            let vote = Vote {
                block_id: self.block_id,
                height: self.height,
                validator: *validator,
                sig: *sig,
            };
            if !vote.verify() {
                return false;
            }
            voted += *stake as u128;
        }
        3 * voted > 2 * total
    }

    /// Wire encoding: block id ‖ height ‖ count ‖ (validator ‖ sig)*.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 8 + 4 + self.votes.len() * 96);
        v.extend_from_slice(&self.block_id);
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(&(self.votes.len() as u32).to_le_bytes());
        for (validator, sig) in &self.votes {
            v.extend_from_slice(validator);
            v.extend_from_slice(sig);
        }
        v
    }

    pub fn decode(b: &[u8]) -> Option<Certificate> {
        let block_id: [u8; 32] = b.get(0..32)?.try_into().ok()?;
        let height = u64::from_le_bytes(b.get(32..40)?.try_into().ok()?);
        let count = u32::from_le_bytes(b.get(40..44)?.try_into().ok()?) as usize;
        let mut votes = Vec::new();
        let mut off = 44;
        for _ in 0..count {
            let validator: [u8; 32] = b.get(off..off + 32)?.try_into().ok()?;
            let sig: [u8; 64] = b.get(off + 32..off + 96)?.try_into().ok()?;
            votes.push((validator, sig));
            off += 96;
        }
        (off == b.len()).then_some(Certificate { block_id, height, votes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn vote_sign_verify_and_wire_roundtrip() {
        let sk = SecretKey::random(&mut OsRng);
        let vote = Vote::sign(&sk, [7u8; 32], 42);
        assert!(vote.verify());
        assert_eq!(Vote::decode(&vote.encode()), Some(vote.clone()));

        // Any field change breaks the signature.
        let mut bad = vote.clone();
        bad.height = 43;
        assert!(!bad.verify());
        let mut bad = vote;
        bad.block_id[0] ^= 1;
        assert!(!bad.verify());
    }

    #[test]
    fn certificate_threshold_is_strictly_two_thirds_of_stake() {
        let sks: Vec<SecretKey> = (0..3).map(|_| SecretKey::random(&mut OsRng)).collect();
        let ids: Vec<[u8; 32]> = sks.iter().map(|s| s.public_key().to_bytes()).collect();
        // Equal stakes: 2 of 3 = exactly 2/3 — NOT enough (strict); 3 of 3 is.
        let set: Vec<([u8; 32], u64)> = ids.iter().map(|id| (*id, 100)).collect();
        let block = [9u8; 32];
        let vote = |i: usize| {
            let v = Vote::sign(&sks[i], block, 5);
            (v.validator, v.sig)
        };
        let two = Certificate { block_id: block, height: 5, votes: vec![vote(0), vote(1)] };
        assert!(!two.verify(&set), "exactly 2/3 must not certify");
        let three =
            Certificate { block_id: block, height: 5, votes: vec![vote(0), vote(1), vote(2)] };
        assert!(three.verify(&set));
        assert_eq!(Certificate::decode(&three.encode()), Some(three.clone()));

        // Stake-weighted: one whale with 500 of 700 total is > 2/3 alone
        // (400 of 600 would be exactly 2/3 — not enough).
        let set = vec![(ids[0], 500u64), (ids[1], 100), (ids[2], 100)];
        let whale = Certificate { block_id: block, height: 5, votes: vec![vote(0)] };
        assert!(whale.verify(&set));

        // Rejections: duplicate signer, outsider, empty set/cert.
        let dup = Certificate { block_id: block, height: 5, votes: vec![vote(0), vote(0)] };
        assert!(!dup.verify(&set));
        let outsider_sk = SecretKey::random(&mut OsRng);
        let ov = Vote::sign(&outsider_sk, block, 5);
        let outsider =
            Certificate { block_id: block, height: 5, votes: vec![vote(0), (ov.validator, ov.sig)] };
        assert!(!outsider.verify(&set));
        assert!(!three.verify(&[]));
        assert!(!Certificate { block_id: block, height: 5, votes: vec![] }.verify(&set));
    }
}

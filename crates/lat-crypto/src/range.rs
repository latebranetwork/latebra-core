//! Range proofs for confidential amounts (clean-room, from `SPEC.md`).
//!
//! The transfer proof in `transfer.rs` shows value is *conserved* (same hidden
//! amount debited and credited) but NOT that amounts are non-negative. Without
//! that, a sender could transfer a "negative" amount and mint coins. This module
//! closes the gap.
//!
//! For a secret value `v` that appears on-chain as `Cv = v·G + rho·P` (e.g. the
//! transfer amount inside `C_sender = t·G + r·Y_sender`, or a sender's remaining
//! balance), we produce:
//!
//!   1. a **Bulletproofs** range proof that `v ∈ [0, 2^64)` — built on a Pedersen
//!      commitment `V = v·G + s·H` using the audited `bulletproofs` crate; and
//!   2. a small **linking sigma proof** that the `v` inside `V` is the *same* `v`
//!      inside the public `Cv`.
//!
//! Together: the value committed in the on-chain point is provably in range,
//! without revealing it. We do not implement Bulletproofs ourselves — that is the
//! audited library's job. We only write the linking proof.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript as MerlinTranscript;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

/// Amounts and balances are proven to fit in 64 bits (the full `u64` range).
pub const RANGE_BITS: usize = 64;

/// A range proof for one confidential value, plus the sigma proof linking it to
/// the on-chain commitment `Cv`.
#[derive(Clone)]
pub struct RangeComponent {
    /// Bulletproofs Pedersen commitment `V = v·G + s·H`.
    commitment: CompressedRistretto,
    /// Bulletproofs range proof that `V` commits to a value in `[0, 2^64)`.
    range_proof: RangeProof,
    // Linking sigma proof (knowledge of v, rho, s s.t. Cv = v·G + rho·P and V = v·G + s·H):
    a_cv: RistrettoPoint,
    a_v: RistrettoPoint,
    z_v: Scalar,
    z_rho: Scalar,
    z_s: Scalar,
}

/// Fiat–Shamir challenge for the linking proof. Same append order in prove/verify.
fn link_challenge(
    blinding_base: &RistrettoPoint,
    h: &RistrettoPoint,
    cv: &RistrettoPoint,
    v_commit: &RistrettoPoint,
    a_cv: &RistrettoPoint,
    a_v: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"Latebra.RangeLink.v1");
    for p in [blinding_base, h, cv, v_commit, a_cv, a_v] {
        hasher.update(p.compress().as_bytes());
    }
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

impl RangeComponent {
    /// Prove that the value `v`, committed publicly as `cv = v·G + rho·P`, lies in
    /// `[0, 2^64)`. `blinding_base` is `P` and `rho` is the public commitment's
    /// blinding. Returns `None` only on internal proof-gen failure.
    pub fn prove<R: RngCore + CryptoRng>(
        value: u64,
        blinding_base: &RistrettoPoint,
        rho: &Scalar,
        cv: &RistrettoPoint,
        rng: &mut R,
    ) -> Option<RangeComponent> {
        let pc_gens = PedersenGens::default(); // B = G, B_blinding = H
        let bp_gens = BulletproofGens::new(RANGE_BITS, 1);
        let h = pc_gens.B_blinding;

        // Bulletproofs commitment blinding.
        let s = Scalar::random(rng);

        let mut t = MerlinTranscript::new(b"Latebra.Range.v1");
        let (range_proof, commitment) =
            RangeProof::prove_single(&bp_gens, &pc_gens, &mut t, value, &s, RANGE_BITS).ok()?;

        let v_commit = commitment.decompress()?; // V = v·G + s·H

        // Linking sigma: prove cv and V share the same v.
        let v = Scalar::from(value);
        let k_v = Scalar::random(rng);
        let k_rho = Scalar::random(rng);
        let k_s = Scalar::random(rng);

        let a_cv = G * k_v + blinding_base * k_rho;
        let a_v = G * k_v + h * k_s;

        let e = link_challenge(blinding_base, &h, cv, &v_commit, &a_cv, &a_v);

        let z_v = k_v + e * v;
        let z_rho = k_rho + e * rho;
        let z_s = k_s + e * s;

        Some(RangeComponent {
            commitment,
            range_proof,
            a_cv,
            a_v,
            z_v,
            z_rho,
            z_s,
        })
    }

    /// Verify the range proof and the link to `cv = v·G + rho·P` (with `P =
    /// blinding_base`). Returns `true` iff the value in `cv` is provably in range.
    pub fn verify(&self, blinding_base: &RistrettoPoint, cv: &RistrettoPoint) -> bool {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(RANGE_BITS, 1);
        let h = pc_gens.B_blinding;

        // 1) Bulletproofs range proof on the committed value.
        let mut t = MerlinTranscript::new(b"Latebra.Range.v1");
        if self
            .range_proof
            .verify_single(&bp_gens, &pc_gens, &mut t, &self.commitment, RANGE_BITS)
            .is_err()
        {
            return false;
        }

        let v_commit = match self.commitment.decompress() {
            Some(p) => p,
            None => return false,
        };

        // 2) Linking sigma proof: cv and V commit to the same value.
        let e = link_challenge(blinding_base, &h, cv, &v_commit, &self.a_cv, &self.a_v);
        let check_cv = G * self.z_v + blinding_base * self.z_rho == self.a_cv + cv * e;
        let check_v = G * self.z_v + h * self.z_s == self.a_v + v_commit * e;

        check_cv && check_v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// Build a public commitment `cv = v·G + rho·P` the way the transfer ciphertext
    /// commits to an amount (P = a public key point).
    fn commit(value: u64, base: &RistrettoPoint, rho: &Scalar) -> RistrettoPoint {
        G * Scalar::from(value) + base * rho
    }

    #[test]
    fn in_range_value_verifies() {
        let mut rng = OsRng;
        let base = RistrettoPoint::random(&mut rng); // stand-in for a public key
        let rho = Scalar::random(&mut rng);
        let value = 1_234_567u64;

        let cv = commit(value, &base, &rho);
        let proof = RangeComponent::prove(value, &base, &rho, &cv, &mut rng).unwrap();
        assert!(proof.verify(&base, &cv), "valid in-range amount must verify");
    }

    #[test]
    fn max_u64_value_verifies() {
        let mut rng = OsRng;
        let base = RistrettoPoint::random(&mut rng);
        let rho = Scalar::random(&mut rng);
        let value = u64::MAX;

        let cv = commit(value, &base, &rho);
        let proof = RangeComponent::prove(value, &base, &rho, &cv, &mut rng).unwrap();
        assert!(proof.verify(&base, &cv));
    }

    #[test]
    fn wrong_commitment_fails_linking() {
        // A proof made for one cv must not verify against a different cv.
        let mut rng = OsRng;
        let base = RistrettoPoint::random(&mut rng);
        let rho = Scalar::random(&mut rng);
        let value = 500u64;

        let cv = commit(value, &base, &rho);
        let proof = RangeComponent::prove(value, &base, &rho, &cv, &mut rng).unwrap();

        let other_cv = commit(501, &base, &rho);
        assert!(!proof.verify(&base, &other_cv), "linking must bind to cv");
    }

    #[test]
    fn tampered_linking_response_fails() {
        let mut rng = OsRng;
        let base = RistrettoPoint::random(&mut rng);
        let rho = Scalar::random(&mut rng);
        let value = 42u64;

        let cv = commit(value, &base, &rho);
        let mut proof = RangeComponent::prove(value, &base, &rho, &cv, &mut rng).unwrap();
        proof.z_v += Scalar::from(1u64);
        assert!(!proof.verify(&base, &cv));
    }
}

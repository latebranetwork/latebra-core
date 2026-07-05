//! Balance-conservation proof over a ring of committed deltas (clean-room, from
//! `SPEC.md`).
//!
//! In a DERO/Zether anonymous transfer, every account in the ring receives an
//! encrypted balance *delta*: `−amount` for the (hidden) sender, `+amount` for the
//! (hidden) receiver, and `0` for the decoys. For the ledger to be sound, those
//! deltas must **net to exactly zero** — no money created or destroyed — and this
//! must be verifiable without revealing the individual deltas.
//!
//! This module proves exactly that. Each delta `vᵢ` is a Pedersen commitment
//! `Cᵢ = vᵢ·G + sᵢ·H` (with `H` independent of `G`, shared with the range proofs).
//! Their sum `ΣCᵢ = (Σvᵢ)·G + (Σsᵢ)·H` lies in the subgroup `⟨H⟩` **iff** `Σvᵢ = 0`.
//! So a single Schnorr proof that `ΣCᵢ = s·H` for a known `s` proves conservation.
//!
//! ## Honest scope
//! This proves conservation (`Σvᵢ = 0`) — the no-inflation core. The full
//! many-out-of-many transfer additionally needs: each `vᵢ` restricted to `{0, ±t}`
//! (not arbitrary values that merely cancel), the two nonzero deltas bound to the
//! ring's real sender/receiver (via the linkable ring signature), amount/solvency
//! range proofs, and index-hiding. Those compose on top and must be audited.

use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

fn scalar_from_i64(v: i64) -> Scalar {
    if v >= 0 {
        Scalar::from(v as u64)
    } else {
        -Scalar::from(v.unsigned_abs())
    }
}

fn challenge(commitments: &[RistrettoPoint], agg: &RistrettoPoint, a: &RistrettoPoint) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.Conservation.v1");
    h.update((commitments.len() as u64).to_le_bytes());
    for c in commitments {
        h.update(c.compress().as_bytes());
    }
    h.update(agg.compress().as_bytes());
    h.update(a.compress().as_bytes());
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A set of committed balance deltas plus a proof that they sum to zero.
#[derive(Clone, Debug)]
pub struct ConservedDeltas {
    /// The public Pedersen commitments `Cᵢ = vᵢ·G + sᵢ·H`.
    pub commitments: Vec<RistrettoPoint>,
    /// Schnorr proof that `ΣCᵢ = z·H − e·(…)` i.e. the aggregate is a commitment to 0.
    a: RistrettoPoint,
    z: Scalar,
}

impl ConservedDeltas {
    /// Commit to the signed `values` and prove they sum to zero. Returns `None` if
    /// the caller-supplied values do not actually net to zero (a programming error
    /// — no valid conservation proof exists for them).
    pub fn create<R: RngCore + CryptoRng>(values: &[i64], rng: &mut R) -> Option<ConservedDeltas> {
        if values.iter().try_fold(0i128, |acc, &v| Some(acc + v as i128))? != 0 {
            return None;
        }
        let pc = PedersenGens::default(); // B = G, B_blinding = H
        let g = pc.B;
        let h = pc.B_blinding;

        let mut commitments = Vec::with_capacity(values.len());
        let mut blinding_sum = Scalar::ZERO;
        for &v in values {
            let s = Scalar::random(rng);
            commitments.push(g * scalar_from_i64(v) + h * s);
            blinding_sum += s;
        }

        // Aggregate = (Σvᵢ)·G + blinding_sum·H = blinding_sum·H (since Σvᵢ = 0).
        let agg: RistrettoPoint = commitments.iter().sum();

        // Schnorr proof of knowledge of `blinding_sum` with `agg = blinding_sum·H`.
        let k = Scalar::random(rng);
        let a = h * k;
        let e = challenge(&commitments, &agg, &a);
        let z = k + e * blinding_sum;

        Some(ConservedDeltas { commitments, a, z })
    }

    /// Verify the deltas provably sum to zero (no value created or destroyed).
    pub fn verify(&self) -> bool {
        let h = PedersenGens::default().B_blinding;
        let agg: RistrettoPoint = self.commitments.iter().sum();
        let e = challenge(&self.commitments, &agg, &self.a);
        // h·z == a + e·agg   (holds iff agg ∈ ⟨H⟩, i.e. Σvᵢ = 0)
        h * self.z == self.a + agg * e
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn balanced_deltas_verify() {
        // A transfer of 5 from one member to another, with two decoys.
        let d = ConservedDeltas::create(&[-5, 0, 5, 0], &mut OsRng).expect("balanced");
        assert!(d.verify());
        assert_eq!(d.commitments.len(), 4);
    }

    #[test]
    fn unbalanced_values_have_no_proof() {
        // Values that don't net to zero can't be proven (would create/destroy money).
        assert!(ConservedDeltas::create(&[5, -3, 0], &mut OsRng).is_none());
    }

    #[test]
    fn all_zero_deltas_verify() {
        let d = ConservedDeltas::create(&[0, 0, 0], &mut OsRng).unwrap();
        assert!(d.verify());
    }

    #[test]
    fn tampering_a_commitment_breaks_conservation() {
        let mut d = ConservedDeltas::create(&[-8, 8], &mut OsRng).unwrap();
        // Nudging one commitment makes the set no longer sum to zero; the proof,
        // bound to the original aggregate, must fail.
        d.commitments[0] += PedersenGens::default().B; // add 1·G of value
        assert!(!d.verify());
    }
}

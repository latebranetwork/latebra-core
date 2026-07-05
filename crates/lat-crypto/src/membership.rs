//! Set-membership proof for a committed value (clean-room, from `SPEC.md`).
//!
//! Proves that a Pedersen commitment `C = v·G + s·H` hides a value `v` drawn from
//! a public set `{a₀, …, a_{m-1}}`, without revealing which one. This is the tool
//! that bounds each ring member's balance delta to an allowed value (e.g. a decoy
//! `0` vs. a real transfer amount) — so a sender cannot slip an arbitrary theft
//! amount onto a decoy.
//!
//! It is the same Cramer–Damgård–Schoenmakers OR-composition used by the ring
//! signature, but over the statements "`C − aⱼ·G ∈ ⟨H⟩`" (i.e. `C` commits to
//! `aⱼ`). Exactly one branch is true; the prover proves that one honestly and
//! simulates the rest.
//!
//! ## Honest scope
//! The set here is **public**. A fully private transfer hides the amount itself,
//! which needs the value committed rather than public — the extra step (and the
//! index-binding that ties the nonzero deltas to the ring's real sender/receiver)
//! is the remaining many-out-of-many work, and must be audited.

use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

fn scalar_from_i64(v: i64) -> Scalar {
    if v >= 0 {
        Scalar::from(v as u64)
    } else {
        -Scalar::from(v.unsigned_abs())
    }
}

fn challenge(commitment: &RistrettoPoint, allowed: &[i64], a: &[RistrettoPoint]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.ValueInSet.v1");
    h.update(commitment.compress().as_bytes());
    h.update((allowed.len() as u64).to_le_bytes());
    for v in allowed {
        h.update(v.to_le_bytes());
    }
    for p in a {
        h.update(p.compress().as_bytes());
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A proof that a commitment's hidden value lies in a public set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueInSetProof {
    e: Vec<Scalar>,
    z: Vec<Scalar>,
}

impl ValueInSetProof {
    /// Commit to `value` (with the given `blinding`) and prove it is one of
    /// `allowed`. Returns the commitment and proof, or `None` if `value` is not in
    /// `allowed` (no valid proof exists).
    pub fn prove<R: RngCore + CryptoRng>(
        value: i64,
        blinding: &Scalar,
        allowed: &[i64],
        rng: &mut R,
    ) -> Option<(RistrettoPoint, ValueInSetProof)> {
        let real = allowed.iter().position(|&a| a == value)?;
        let pc = PedersenGens::default();
        let (g, h) = (pc.B, pc.B_blinding);
        let commitment = g * scalar_from_i64(value) + h * blinding;

        let m = allowed.len();
        let mut e = vec![Scalar::ZERO; m];
        let mut z = vec![Scalar::ZERO; m];
        let mut a = vec![RistrettoPoint::identity(); m];

        let mut sum_other = Scalar::ZERO;
        for j in 0..m {
            if j == real {
                continue;
            }
            e[j] = Scalar::random(rng);
            z[j] = Scalar::random(rng);
            let p_j = commitment - g * scalar_from_i64(allowed[j]);
            a[j] = h * z[j] - p_j * e[j];
            sum_other += e[j];
        }

        // True branch: P_real = C − value·G = s·H, witness is the blinding.
        let k = Scalar::random(rng);
        a[real] = h * k;
        let c = challenge(&commitment, allowed, &a);
        e[real] = c - sum_other;
        z[real] = k + e[real] * blinding;

        Some((commitment, ValueInSetProof { e, z }))
    }

    /// Verify that `commitment` hides a value in `allowed`.
    pub fn verify(&self, commitment: &RistrettoPoint, allowed: &[i64]) -> bool {
        let m = allowed.len();
        if self.e.len() != m || self.z.len() != m {
            return false;
        }
        let pc = PedersenGens::default();
        let (g, h) = (pc.B, pc.B_blinding);

        let mut a = vec![RistrettoPoint::identity(); m];
        let mut sum = Scalar::ZERO;
        for j in 0..m {
            let p_j = commitment - g * scalar_from_i64(allowed[j]);
            a[j] = h * self.z[j] - p_j * self.e[j];
            sum += self.e[j];
        }
        challenge(commitment, allowed, &a) == sum
    }

    /// Self-describing byte encoding: a `u32` branch count `m`, then `m` challenge
    /// scalars and `m` response scalars. (`m` equals the `allowed` set's length.)
    pub fn to_bytes(&self) -> Vec<u8> {
        let m = self.e.len();
        let mut v = Vec::with_capacity(4 + m * 64);
        v.extend_from_slice(&(m as u32).to_le_bytes());
        for s in &self.e {
            v.extend_from_slice(s.as_bytes());
        }
        for s in &self.z {
            v.extend_from_slice(s.as_bytes());
        }
        v
    }

    /// Decode from [`to_bytes`](Self::to_bytes). `None` on malformed input or any
    /// trailing bytes (an encoding is exactly its contents). Only checks the bytes
    /// are canonical scalars — soundness is still `verify`'s job.
    pub fn from_bytes(b: &[u8]) -> Option<ValueInSetProof> {
        let m = u32::from_le_bytes(b.get(0..4)?.try_into().ok()?) as usize;
        if b.len() != 4 + m * 64 {
            return None;
        }
        let rd = |i: usize| -> Option<Scalar> {
            let off = 4 + i * 32;
            let arr: [u8; 32] = b.get(off..off + 32)?.try_into().ok()?;
            Option::from(Scalar::from_canonical_bytes(arr))
        };
        let mut e = Vec::with_capacity(m);
        let mut z = Vec::with_capacity(m);
        for i in 0..m {
            e.push(rd(i)?);
        }
        for i in 0..m {
            z.push(rd(m + i)?);
        }
        Some(ValueInSetProof { e, z })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn value_in_set_verifies() {
        let mut rng = OsRng;
        let s = Scalar::random(&mut rng);
        let (c, proof) = ValueInSetProof::prove(5, &s, &[0, 5, 10], &mut rng).unwrap();
        assert!(proof.verify(&c, &[0, 5, 10]));
    }

    #[test]
    fn decoy_zero_and_real_amount_both_prove() {
        // The two cases used for a ring delta — a decoy 0 and a real amount — both
        // verify against the same allowed set, hiding which is which.
        let mut rng = OsRng;
        let s0 = Scalar::random(&mut rng);
        let s1 = Scalar::random(&mut rng);
        let (c0, p0) = ValueInSetProof::prove(0, &s0, &[0, 7], &mut rng).unwrap();
        let (c1, p1) = ValueInSetProof::prove(7, &s1, &[0, 7], &mut rng).unwrap();
        assert!(p0.verify(&c0, &[0, 7]));
        assert!(p1.verify(&c1, &[0, 7]));
    }

    #[test]
    fn value_outside_set_has_no_proof() {
        let mut rng = OsRng;
        let s = Scalar::random(&mut rng);
        assert!(ValueInSetProof::prove(9, &s, &[0, 5, 10], &mut rng).is_none());
    }

    #[test]
    fn proof_does_not_verify_against_wrong_commitment() {
        let mut rng = OsRng;
        let s = Scalar::random(&mut rng);
        let (c, proof) = ValueInSetProof::prove(5, &s, &[0, 5, 10], &mut rng).unwrap();
        let wrong = c + PedersenGens::default().B; // commitment to 6, not in a valid opening
        assert!(!proof.verify(&wrong, &[0, 5, 10]));
    }

    #[test]
    fn tampered_proof_fails() {
        let mut rng = OsRng;
        let s = Scalar::random(&mut rng);
        let (c, mut proof) = ValueInSetProof::prove(0, &s, &[0, 5], &mut rng).unwrap();
        proof.z[0] += Scalar::ONE;
        assert!(!proof.verify(&c, &[0, 5]));
    }
}

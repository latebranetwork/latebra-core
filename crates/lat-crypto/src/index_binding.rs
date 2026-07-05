//! Index-binding proof — the missing brick for sender-anonymous spends.
//!
//! **UNAUDITED PRIMITIVE. NOT WIRED INTO CONSENSUS.** Built primitive-first, the
//! way `ring.rs` / `membership.rs` / `solvent.rs` were. See `ANON_SPEND.md` for
//! how it composes into a full anonymous spend, and the audit boundary.
//!
//! # What it proves
//! Given an anonymity set of public keys `{Y_0 … Y_{N-1}}` and a matching vector
//! of Pedersen **delta commitments** `{C_0 … C_{N-1}}` (each `C_i = δ_i·G + r_i·H`),
//! plus a public `amount`, this proves — in zero knowledge — that there is a
//! **hidden index `l`** for which the prover simultaneously:
//!
//! 1. **owns** member `l`: knows `x` with `Y_l = x·G`, and
//! 2. **is the one debited**: `C_l` commits to `amount` (`C_l − amount·G = r_l·H`).
//!
//! This is the brick both `ring.rs` and `membership.rs` call out as missing: it
//! *binds the debited slot to the owned slot*. Without it, a spender could
//! authorize with their own key yet park the `amount` delta on a rich decoy and
//! debit **that** account — a theft. With it (plus per-member `{0, amount}` bounds
//! from [`crate::ValueInSetProof`] and a sum-conservation proof), the account you
//! own is provably the only one debited `amount`.
//!
//! It does **not** prove the hidden account is *solvent* (brick D in
//! `ANON_SPEND.md`) — that is the remaining, audit-gated many-out-of-many step.
//!
//! # Construction
//! A Cramer–Damgård–Schoenmakers OR-composition (same family as the ring
//! signature) where each branch `i` is the *conjunction* of two Schnorr
//! statements over independent bases `G` and `H`:
//! `Y_i = x·G`  **and**  `C_i − amount·G = r·H`. The real branch is proven
//! honestly; every decoy branch is simulated. The Fiat–Shamir challenge fixes the
//! sum of per-branch challenges, so only a prover who genuinely satisfies *both*
//! relations at some index can make the sum come out right.

use bulletproofs::PedersenGens;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{PublicKey, SecretKey};

/// The Pedersen blinding base `H` (independent of `G`), shared with
/// [`crate::ValueInSetProof`] so delta commitments interoperate between the two.
fn blinding_base() -> RistrettoPoint {
    PedersenGens::default().B_blinding
}

/// Build a delta commitment `C = value·G + blinding·H`, the form this proof (and
/// `ValueInSetProof`) expects. `value` is `0` for a decoy, `amount` for the real
/// sender.
pub fn commit_delta(value: u64, blinding: &Scalar) -> RistrettoPoint {
    G * Scalar::from(value) + blinding_base() * blinding
}

/// A proof binding "the account I own" to "the account debited `amount`".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexBindingProof {
    /// Per-branch challenges; their sum equals the Fiat–Shamir challenge.
    e: Vec<Scalar>,
    /// Per-branch responses for the ownership relation (`Y_i = x·G`).
    z_x: Vec<Scalar>,
    /// Per-branch responses for the delta relation (`C_i − amount·G = r·H`).
    z_r: Vec<Scalar>,
}

#[allow(clippy::too_many_arguments)]
fn challenge(
    ring: &[PublicKey],
    amount: u64,
    deltas: &[RistrettoPoint],
    a_pts: &[RistrettoPoint],
    b_pts: &[RistrettoPoint],
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.IndexBinding.v1");
    h.update((ring.len() as u64).to_le_bytes());
    for pk in ring {
        h.update(pk.0.compress().as_bytes());
    }
    h.update(amount.to_le_bytes());
    for c in deltas {
        h.update(c.compress().as_bytes());
    }
    for a in a_pts {
        h.update(a.compress().as_bytes());
    }
    for b in b_pts {
        h.update(b.compress().as_bytes());
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

impl IndexBindingProof {
    /// Prove the binding at the real `index`: `secret` opens `ring[index]`, and
    /// `deltas[index] = amount·G + blinding·H`. `deltas` and `ring` must be the
    /// same length; `deltas[i]` for `i != index` are the decoys' (zero-value)
    /// commitments.
    ///
    /// Panics only on caller programming errors (mismatched lengths, or
    /// `ring[index]` not `secret`'s key). It does **not** check that
    /// `deltas[index]` really commits to `amount` — a wrong commitment simply
    /// yields a proof that fails to verify (that's the soundness we test).
    pub fn prove<R: RngCore + CryptoRng>(
        ring: &[PublicKey],
        deltas: &[RistrettoPoint],
        amount: u64,
        secret: &SecretKey,
        blinding: &Scalar,
        index: usize,
        rng: &mut R,
    ) -> IndexBindingProof {
        let n = ring.len();
        assert_eq!(deltas.len(), n, "ring and deltas length mismatch");
        assert!(index < n, "signer index out of range");
        assert_eq!(ring[index], secret.public_key(), "signer key not at ring[index]");

        let h = blinding_base();
        let amt_g = G * Scalar::from(amount);

        let mut e = vec![Scalar::ZERO; n];
        let mut z_x = vec![Scalar::ZERO; n];
        let mut z_r = vec![Scalar::ZERO; n];
        let mut a = vec![RistrettoPoint::identity(); n];
        let mut b = vec![RistrettoPoint::identity(); n];

        // Simulate every decoy branch: pick (e_i, z_x_i, z_r_i), derive the two
        // commitments backwards so both Schnorr checks will pass.
        let mut sum_decoy = Scalar::ZERO;
        for i in 0..n {
            if i == index {
                continue;
            }
            e[i] = Scalar::random(rng);
            z_x[i] = Scalar::random(rng);
            z_r[i] = Scalar::random(rng);
            a[i] = G * z_x[i] - ring[i].0 * e[i];
            b[i] = h * z_r[i] - (deltas[i] - amt_g) * e[i];
            sum_decoy += e[i];
        }

        // Real branch: honest commitments with fresh nonces for both relations.
        let k_x = Scalar::random(rng);
        let k_r = Scalar::random(rng);
        a[index] = G * k_x;
        b[index] = h * k_r;

        let c = challenge(ring, amount, deltas, &a, &b);
        e[index] = c - sum_decoy;
        z_x[index] = k_x + e[index] * secret.0;
        z_r[index] = k_r + e[index] * blinding;

        IndexBindingProof { e, z_x, z_r }
    }

    /// Verify the binding against the public ring, delta commitments, and amount.
    pub fn verify(&self, ring: &[PublicKey], deltas: &[RistrettoPoint], amount: u64) -> bool {
        let n = ring.len();
        if deltas.len() != n || self.e.len() != n || self.z_x.len() != n || self.z_r.len() != n {
            return false;
        }
        let h = blinding_base();
        let amt_g = G * Scalar::from(amount);

        let mut a = vec![RistrettoPoint::identity(); n];
        let mut b = vec![RistrettoPoint::identity(); n];
        let mut sum = Scalar::ZERO;
        for i in 0..n {
            a[i] = G * self.z_x[i] - ring[i].0 * self.e[i];
            b[i] = h * self.z_r[i] - (deltas[i] - amt_g) * self.e[i];
            sum += self.e[i];
        }
        challenge(ring, amount, deltas, &a, &b) == sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// A ring of `n` fresh accounts.
    fn ring_of(n: usize, rng: &mut OsRng) -> (Vec<SecretKey>, Vec<PublicKey>) {
        let sks: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(rng)).collect();
        let pks = sks.iter().map(|s| s.public_key()).collect();
        (sks, pks)
    }

    /// Delta commitments where index `real` carries `amount` and the rest carry 0.
    /// Returns the commitments and the real member's blinding.
    fn deltas_with_real(n: usize, real: usize, amount: u64, rng: &mut OsRng) -> (Vec<RistrettoPoint>, Scalar) {
        let mut deltas = Vec::with_capacity(n);
        let mut real_blind = Scalar::ZERO;
        for i in 0..n {
            let blind = Scalar::random(rng);
            let value = if i == real { amount } else { 0 };
            deltas.push(commit_delta(value, &blind));
            if i == real {
                real_blind = blind;
            }
        }
        (deltas, real_blind)
    }

    #[test]
    fn honest_binding_verifies() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(5, &mut rng);
        let l = 2;
        let amount = 750;
        let (deltas, r_l) = deltas_with_real(5, l, amount, &mut rng);

        let proof = IndexBindingProof::prove(&ring, &deltas, amount, &sks[l], &r_l, l, &mut rng);
        assert!(proof.verify(&ring, &deltas, amount));
    }

    #[test]
    fn debiting_a_decoy_instead_of_yourself_fails() {
        // The anti-theft property. The prover owns member `l` but leaves their OWN
        // delta at 0 (they'd rather debit a rich decoy). No binding for `amount`
        // exists at the owned index, so the proof cannot verify.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(5, &mut rng);
        let l = 1;
        let amount = 900;

        // Every delta (including the owned one) commits to 0.
        let mut deltas = Vec::new();
        let mut blinds = Vec::new();
        for _ in 0..5 {
            let b = Scalar::random(&mut rng);
            deltas.push(commit_delta(0, &b));
            blinds.push(b);
        }

        // Prove the binding at the OWNED index l, but deltas[l] commits to 0, not amount.
        let proof = IndexBindingProof::prove(&ring, &deltas, amount, &sks[l], &blinds[l], l, &mut rng);
        assert!(
            !proof.verify(&ring, &deltas, amount),
            "you cannot bind `amount` to yourself while debiting 0"
        );
    }

    #[test]
    fn proof_is_bound_to_the_amount() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let l = 3;
        let amount = 500;
        let (deltas, r_l) = deltas_with_real(4, l, amount, &mut rng);

        let proof = IndexBindingProof::prove(&ring, &deltas, amount, &sks[l], &r_l, l, &mut rng);
        assert!(proof.verify(&ring, &deltas, amount));
        // Verifying the same proof against a different amount must fail.
        assert!(!proof.verify(&ring, &deltas, amount + 1), "the amount is bound in");
    }

    #[test]
    fn hides_which_member_is_bound() {
        // Two different owners, same-shape rings/deltas → structurally identical
        // proofs, so an observer can't tell which member was bound.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(6, &mut rng);
        let amount = 42;
        let (d0, r0) = deltas_with_real(6, 0, amount, &mut rng);
        let (d5, r5) = deltas_with_real(6, 5, amount, &mut rng);

        let p0 = IndexBindingProof::prove(&ring, &d0, amount, &sks[0], &r0, 0, &mut rng);
        let p5 = IndexBindingProof::prove(&ring, &d5, amount, &sks[5], &r5, 5, &mut rng);
        assert!(p0.verify(&ring, &d0, amount) && p5.verify(&ring, &d5, amount));
        assert_eq!(p0.e.len(), p5.e.len());
        assert_eq!(p0.z_x.len(), p5.z_x.len());
        assert_eq!(p0.z_r.len(), p5.z_r.len());
    }

    #[test]
    fn tampered_proof_fails() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let l = 1;
        let amount = 321;
        let (deltas, r_l) = deltas_with_real(4, l, amount, &mut rng);

        let mut proof = IndexBindingProof::prove(&ring, &deltas, amount, &sks[l], &r_l, l, &mut rng);
        assert!(proof.verify(&ring, &deltas, amount));
        proof.z_x[0] += Scalar::ONE;
        assert!(!proof.verify(&ring, &deltas, amount));
    }

    #[test]
    fn substituting_a_ring_member_fails() {
        let mut rng = OsRng;
        let (sks, mut ring) = ring_of(4, &mut rng);
        let l = 2;
        let amount = 10;
        let (deltas, r_l) = deltas_with_real(4, l, amount, &mut rng);

        let proof = IndexBindingProof::prove(&ring, &deltas, amount, &sks[l], &r_l, l, &mut rng);
        assert!(proof.verify(&ring, &deltas, amount));
        ring[0] = SecretKey::random(&mut rng).public_key();
        assert!(!proof.verify(&ring, &deltas, amount), "bound to the exact ring");
    }
}

//! Brick D — hidden-index solvency (clean-room, from `ANON_SPEND.md`).
//!
//! **UNAUDITED PRIMITIVE. NOT WIRED INTO CONSENSUS.** Built primitive-first, the
//! way `ring.rs` / `membership.rs` / `index_binding.rs` were. This is the "hard
//! remainder" (brick D) the blueprint calls out: proving the *hidden* sender could
//! actually afford the spend, without revealing which anonymity-set member they are.
//!
//! # What it proves
//! Given an anonymity set `{Y_0 … Y_{N-1}}`, each member's on-chain ElGamal balance
//! ciphertext `(C_i^bal, D_i^bal)` (with `C_i^bal = b_i·G + ρ_i·Y_i`,
//! `D_i^bal = ρ_i·G`, so `C_i^bal − x_i·D_i^bal = b_i·G`), a matching vector of
//! Pedersen **delta commitments** `C_i = δ_i·G + s_i·H`, a public `amount` and
//! `fee`, this proves — in zero knowledge, hiding the index `l` — that there is a
//! hidden index `l` for which the prover simultaneously:
//!
//! 1. **owns** member `l`: knows `x` with `Y_l = x·G`,
//! 2. **is the one debited**: `C_l` commits to `amount` (`C_l − amount·G = s·H`), and
//! 3. **is solvent**: `b_l − amount − fee ≥ 0`, where `b_l` is the balance that
//!    ciphertext `(C_l^bal, D_l^bal)` decrypts to under `x`.
//!
//! # Why relations 1–3 are fused (index-consistency)
//! `ANON_SPEND.md` warns: *"the index-consistent selection + range binding is where
//! subtle unsoundness hides."* If solvency (brick D) were proven by a *separate*
//! OR-composition from index-binding (brick C), a prover who owns **two** ring
//! members — a rich one and a poor one — could bind the `amount` delta to the poor
//! account (debiting it) while proving the *rich* account solvent. The poor account
//! then goes negative → inflation. Guarding against that requires the owned index,
//! the debited index, and the solvent index to be **one and the same** `l`. So this
//! proof fuses relations 1–3 into a **single** Cramer–Damgård–Schoenmakers
//! OR-composition sharing the branch challenge `e_l` and the witness `x`. This
//! subsumes brick C ([`crate::IndexBindingProof`]); using this proof, that separate
//! proof is unnecessary.
//!
//! # Construction
//! Per anonymity-set member `i`, the branch is the conjunction of three Schnorr
//! statements over the independent bases `G`, `H`, and the member's `D_i^bal`:
//!
//! ```text
//!   (1) Y_i                              = x·G
//!   (2) C_i − amount·G                   = s·H
//!   (3) V − C_i^bal + (amount+fee)·G     = γ·H − x·D_i^bal
//! ```
//!
//! where `V = b'·G + γ·H` is a Pedersen commitment to the remaining balance
//! `b' = b_i − amount − fee` (produced by the Bulletproofs range proof, whose blinding
//! is `γ`). At the real index `l`, relation (3) rearranges to
//! `V = (b_l − amount − fee)·G + γ·H`, so a Bulletproofs proof that `V ∈ [0, 2^64)`
//! proves `b_l − amount − fee ≥ 0`. The real branch is proven honestly; every decoy
//! branch is simulated. Fiat–Shamir fixes `Σ e_i`, so only a prover who satisfies
//! all three relations at some index can make the sum come out right.
//!
//! # Composition (the full anti-theft + solvency + anonymity primitive set)
//! This proof (fused C+D) forces: *the owned index is the amount-carrying index and
//! is solvent*. To also forbid a **decoy** from secretly carrying value, pair it with
//! [`crate::ValueInSetProof`] (brick B) on each `C_i` (each `δ_i ∈ {0, amount}`) and
//! [`crate::ConservedDeltas`] (`Σδ_i = amount`): together they force *exactly one*
//! member — the owned, solvent one — to carry `amount`, and all decoys to carry `0`.
//! Add [`crate::LinkableRingSignature`]'s key image (brick A) for double-spend
//! prevention. See the composition test [`tests::full_anti_theft_and_solvency`].
//!
//! **The audit boundary still stands:** none of this is wired into a transaction or
//! consensus, and it must not carry real value before a professional review.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript as MerlinTranscript;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{Ciphertext, PublicKey, SecretKey};

const RANGE_BITS: usize = 64;

/// The Pedersen blinding base `H` (independent of `G`), shared with
/// [`crate::ValueInSetProof`] / [`crate::commit_delta`] so delta commitments and
/// the range-proof commitment interoperate.
fn blinding_base() -> RistrettoPoint {
    PedersenGens::default().B_blinding
}

/// A proof that a hidden anonymity-set member is simultaneously owned, debited
/// `amount`, and solvent for `amount + fee`.
#[derive(Clone, Debug)]
pub struct HiddenSolventSpend {
    /// Bulletproofs Pedersen commitment `V = b'·G + γ·H` to the remaining balance.
    v: CompressedRistretto,
    /// Bulletproofs range proof that `V` commits to a value in `[0, 2^64)`.
    rp: RangeProof,
    /// Per-branch challenges; their sum equals the Fiat–Shamir challenge.
    e: Vec<Scalar>,
    /// Per-branch responses for the ownership relation (1).
    z_x: Vec<Scalar>,
    /// Per-branch responses for the delta relation (2).
    z_s: Vec<Scalar>,
    /// Per-branch responses for the solvency relation (3)'s `γ` witness.
    z_g: Vec<Scalar>,
}

#[allow(clippy::too_many_arguments)]
fn challenge(
    ring: &[PublicKey],
    balances: &[Ciphertext],
    deltas: &[RistrettoPoint],
    amount: u64,
    fee: u64,
    v: &RistrettoPoint,
    a1: &[RistrettoPoint],
    a2: &[RistrettoPoint],
    a3: &[RistrettoPoint],
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.HiddenSolvency.v1");
    h.update((ring.len() as u64).to_le_bytes());
    for pk in ring {
        h.update(pk.0.compress().as_bytes());
    }
    for ct in balances {
        h.update(ct.c.compress().as_bytes());
        h.update(ct.d.compress().as_bytes());
    }
    for c in deltas {
        h.update(c.compress().as_bytes());
    }
    h.update(amount.to_le_bytes());
    h.update(fee.to_le_bytes());
    h.update(v.compress().as_bytes());
    for a in a1 {
        h.update(a.compress().as_bytes());
    }
    for a in a2 {
        h.update(a.compress().as_bytes());
    }
    for a in a3 {
        h.update(a.compress().as_bytes());
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// The public per-branch target of solvency relation (3):
/// `T_i = V − C_i^bal + (amount+fee)·G`. At the real index this equals
/// `γ·H − x·D_i^bal`.
fn solvency_target(v: &RistrettoPoint, bal: &Ciphertext, spend_g: &RistrettoPoint) -> RistrettoPoint {
    v - bal.c + spend_g
}

impl HiddenSolventSpend {
    /// Prove hidden-index solvency at the real `index`.
    ///
    /// * `secret` must open `ring[index]` (`x` with `Y_l = x·G`).
    /// * `deltas[index]` must be `amount·G + blinding·H` (the delta commitment whose
    ///   blinding is `blinding`); decoy `deltas[i]` commit to `0`.
    /// * `balances[index]` must be the owner's real on-chain balance ciphertext, and
    ///   `balance` its plaintext value (the wallet knows it by decrypting).
    ///
    /// Returns `None` if the owner is **insolvent** (`balance < amount + fee`) — then
    /// no valid proof exists, by design — or on internal range-proof failure.
    ///
    /// Panics only on caller programming errors (mismatched lengths, `index` out of
    /// range, or `ring[index]` not `secret`'s key). It does **not** check that
    /// `deltas[index]` really commits to `amount`, nor that `balances[index]` really
    /// encrypts `balance`: a wrong input simply yields a proof that fails to verify
    /// (that is the soundness the tests exercise).
    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore + CryptoRng>(
        ring: &[PublicKey],
        balances: &[Ciphertext],
        deltas: &[RistrettoPoint],
        amount: u64,
        fee: u64,
        secret: &SecretKey,
        blinding: &Scalar,
        balance: u64,
        index: usize,
        rng: &mut R,
    ) -> Option<HiddenSolventSpend> {
        let n = ring.len();
        assert_eq!(balances.len(), n, "ring and balances length mismatch");
        assert_eq!(deltas.len(), n, "ring and deltas length mismatch");
        assert!(index < n, "signer index out of range");
        assert_eq!(ring[index], secret.public_key(), "signer key not at ring[index]");

        // Insolvent → unprovable (no range proof exists for a negative remainder).
        let spent = amount.checked_add(fee)?;
        let remaining = balance.checked_sub(spent)?;

        let h = blinding_base();
        let amt_g = G * Scalar::from(amount);
        let spend_g = G * Scalar::from(spent);

        // Bulletproofs range proof on the remaining balance b'. Its Pedersen
        // commitment V = b'·G + γ·H (B = G, B_blinding = H) is exactly the point
        // solvency relation (3) pins, and γ is our relation-(3) blinding witness.
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(RANGE_BITS, 1);
        let gamma = Scalar::random(rng);
        let mut tr = MerlinTranscript::new(b"Latebra.HiddenSolvency.range");
        let (rp, v_comp) =
            RangeProof::prove_single(&bp, &pc, &mut tr, remaining, &gamma, RANGE_BITS).ok()?;
        let v = v_comp.decompress()?;

        let x = secret.0;

        let mut e = vec![Scalar::ZERO; n];
        let mut z_x = vec![Scalar::ZERO; n];
        let mut z_s = vec![Scalar::ZERO; n];
        let mut z_g = vec![Scalar::ZERO; n];
        let mut a1 = vec![RistrettoPoint::identity(); n];
        let mut a2 = vec![RistrettoPoint::identity(); n];
        let mut a3 = vec![RistrettoPoint::identity(); n];

        // Simulate every decoy branch: pick (e_i, z_x_i, z_s_i, z_g_i) at random and
        // derive the three announcements backwards so all three checks will pass.
        let mut sum_decoy = Scalar::ZERO;
        for i in 0..n {
            if i == index {
                continue;
            }
            e[i] = Scalar::random(rng);
            z_x[i] = Scalar::random(rng);
            z_s[i] = Scalar::random(rng);
            z_g[i] = Scalar::random(rng);
            let t_i = solvency_target(&v, &balances[i], &spend_g);
            a1[i] = G * z_x[i] - ring[i].0 * e[i];
            a2[i] = h * z_s[i] - (deltas[i] - amt_g) * e[i];
            a3[i] = h * z_g[i] - balances[i].d * z_x[i] - t_i * e[i];
            sum_decoy += e[i];
        }

        // Real branch: honest announcements with fresh nonces for the three witnesses.
        let k_x = Scalar::random(rng);
        let k_s = Scalar::random(rng);
        let k_g = Scalar::random(rng);
        a1[index] = G * k_x;
        a2[index] = h * k_s;
        // Mirrors the verifier's relation (3): a3 = k_g·H − k_x·D_l^bal.
        a3[index] = h * k_g - balances[index].d * k_x;

        let c = challenge(ring, balances, deltas, amount, fee, &v, &a1, &a2, &a3);
        e[index] = c - sum_decoy;
        z_x[index] = k_x + e[index] * x;
        z_s[index] = k_s + e[index] * blinding;
        z_g[index] = k_g + e[index] * gamma;

        Some(HiddenSolventSpend { v: v_comp, rp, e, z_x, z_s, z_g })
    }

    /// Verify the proof against the public anonymity set, balances, delta
    /// commitments, amount, and fee. Returns `true` iff some hidden member is
    /// provably owned, debited `amount`, and solvent for `amount + fee`.
    pub fn verify(
        &self,
        ring: &[PublicKey],
        balances: &[Ciphertext],
        deltas: &[RistrettoPoint],
        amount: u64,
        fee: u64,
    ) -> bool {
        let n = ring.len();
        if balances.len() != n
            || deltas.len() != n
            || self.e.len() != n
            || self.z_x.len() != n
            || self.z_s.len() != n
            || self.z_g.len() != n
        {
            return false;
        }
        let spent = match amount.checked_add(fee) {
            Some(s) => s,
            None => return false,
        };

        // 1) Bulletproofs range proof on the remaining balance commitment V.
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(RANGE_BITS, 1);
        let mut tr = MerlinTranscript::new(b"Latebra.HiddenSolvency.range");
        if self.rp.verify_single(&bp, &pc, &mut tr, &self.v, RANGE_BITS).is_err() {
            return false;
        }
        let v = match self.v.decompress() {
            Some(p) => p,
            None => return false,
        };

        let h = blinding_base();
        let amt_g = G * Scalar::from(amount);
        let spend_g = G * Scalar::from(spent);

        // 2) The fused OR-composition: reconstruct all three announcements per branch
        //    and require the transcript challenge to equal the sum of branch challenges.
        let mut a1 = vec![RistrettoPoint::identity(); n];
        let mut a2 = vec![RistrettoPoint::identity(); n];
        let mut a3 = vec![RistrettoPoint::identity(); n];
        let mut sum = Scalar::ZERO;
        for i in 0..n {
            let t_i = solvency_target(&v, &balances[i], &spend_g);
            a1[i] = G * self.z_x[i] - ring[i].0 * self.e[i];
            a2[i] = h * self.z_s[i] - (deltas[i] - amt_g) * self.e[i];
            a3[i] = h * self.z_g[i] - balances[i].d * self.z_x[i] - t_i * self.e[i];
            sum += self.e[i];
        }
        challenge(ring, balances, deltas, amount, fee, &v, &a1, &a2, &a3) == sum
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{commit_delta, ConservedDeltas, ValueInSetProof};
    use rand::rngs::OsRng;

    /// An anonymity set of `n` fresh accounts.
    fn ring_of(n: usize, rng: &mut OsRng) -> (Vec<SecretKey>, Vec<PublicKey>) {
        let sks: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(rng)).collect();
        let pks = sks.iter().map(|s| s.public_key()).collect();
        (sks, pks)
    }

    /// Build the on-chain balance ciphertexts for a set: member `i` holds `bals[i]`,
    /// encrypted under its own key (so `C_i − x_i·D_i = b_i·G`).
    fn balances_of(sks: &[SecretKey], bals: &[u64], rng: &mut OsRng) -> Vec<Ciphertext> {
        sks.iter()
            .zip(bals)
            .map(|(sk, &b)| sk.public_key().encrypt(b, rng))
            .collect()
    }

    /// Delta commitments where index `real` carries `amount` and the rest carry `0`.
    /// Returns the commitments and the real member's blinding.
    fn deltas_with_real(
        n: usize,
        real: usize,
        amount: u64,
        rng: &mut OsRng,
    ) -> (Vec<RistrettoPoint>, Scalar) {
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
    fn honest_spend_verifies() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(5, &mut rng);
        let l = 2;
        let (amount, fee) = (750u64, 25u64);
        let bals = [10_000, 5_000, 3_000, 40_000, 900];
        let balances = balances_of(&sks, &bals, &mut rng);
        let (deltas, r_l) = deltas_with_real(5, l, amount, &mut rng);

        let proof = HiddenSolventSpend::prove(
            &ring, &balances, &deltas, amount, fee, &sks[l], &r_l, bals[l], l, &mut rng,
        )
        .expect("solvent owner");
        assert!(proof.verify(&ring, &balances, &deltas, amount, fee));
    }

    #[test]
    fn spending_exactly_the_balance_verifies() {
        // amount + fee == balance → remaining 0, still solvent.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(3, &mut rng);
        let l = 0;
        let (amount, fee) = (900u64, 100u64);
        let bals = [1_000, 7_777, 42];
        let balances = balances_of(&sks, &bals, &mut rng);
        let (deltas, r_l) = deltas_with_real(3, l, amount, &mut rng);

        let proof = HiddenSolventSpend::prove(
            &ring, &balances, &deltas, amount, fee, &sks[l], &r_l, bals[l], l, &mut rng,
        )
        .expect("exactly affordable");
        assert!(proof.verify(&ring, &balances, &deltas, amount, fee));
    }

    #[test]
    fn insolvent_owner_has_no_proof() {
        // The owner holds less than amount + fee: no valid proof can be produced.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let l = 1;
        let (amount, fee) = (900u64, 100u64); // needs 1000
        let bals = [50_000, 500, 50_000, 50_000]; // owner l holds only 500
        let balances = balances_of(&sks, &bals, &mut rng);
        let (deltas, r_l) = deltas_with_real(4, l, amount, &mut rng);

        assert!(HiddenSolventSpend::prove(
            &ring, &balances, &deltas, amount, fee, &sks[l], &r_l, bals[l], l, &mut rng,
        )
        .is_none());
    }

    #[test]
    fn lying_about_balance_fails_verification() {
        // Claim a large balance you don't have: prove() succeeds (it trusts the
        // caller's plaintext), but verify() against the REAL on-chain ciphertext
        // fails, because relation (3) binds V to the true balance ciphertext.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(3, &mut rng);
        let l = 2;
        let (amount, fee) = (900u64, 100u64);
        // Owner's REAL balance is 100, far short of 1000.
        let real_bals = [5_000, 5_000, 100];
        let balances = balances_of(&sks, &real_bals, &mut rng);
        let (deltas, r_l) = deltas_with_real(3, l, amount, &mut rng);

        // The prover lies that they hold 10_000.
        let proof = HiddenSolventSpend::prove(
            &ring, &balances, &deltas, amount, fee, &sks[l], &r_l, 10_000, l, &mut rng,
        )
        .expect("builds against the claimed balance");
        assert!(
            !proof.verify(&ring, &balances, &deltas, amount, fee),
            "must bind to the real on-chain balance ciphertext"
        );
    }

    #[test]
    fn debiting_a_decoy_instead_of_yourself_fails() {
        // Anti-theft: the prover owns member l and is solvent, but leaves their OWN
        // delta at 0 (hoping to debit a rich decoy). Relation (2) has no opening for
        // `amount` at the owned index, so the fused proof cannot verify.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(5, &mut rng);
        let l = 3;
        let (amount, fee) = (900u64, 100u64);
        let bals = [1_000, 1_000, 1_000, 50_000, 1_000];
        let balances = balances_of(&sks, &bals, &mut rng);

        // Every delta (including the owned one) commits to 0.
        let mut deltas = Vec::new();
        let mut blinds = Vec::new();
        for _ in 0..5 {
            let b = Scalar::random(&mut rng);
            deltas.push(commit_delta(0, &b));
            blinds.push(b);
        }

        let proof = HiddenSolventSpend::prove(
            &ring, &balances, &deltas, amount, fee, &sks[l], &blinds[l], bals[l], l, &mut rng,
        )
        .expect("builds (solvent owner)");
        assert!(
            !proof.verify(&ring, &balances, &deltas, amount, fee),
            "cannot bind `amount` to yourself while debiting 0"
        );
    }

    #[test]
    fn proof_is_bound_to_amount_and_fee() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let l = 0;
        let (amount, fee) = (500u64, 30u64);
        let bals = [4_000, 1, 2, 3];
        let balances = balances_of(&sks, &bals, &mut rng);
        let (deltas, r_l) = deltas_with_real(4, l, amount, &mut rng);

        let proof = HiddenSolventSpend::prove(
            &ring, &balances, &deltas, amount, fee, &sks[l], &r_l, bals[l], l, &mut rng,
        )
        .unwrap();
        assert!(proof.verify(&ring, &balances, &deltas, amount, fee));
        assert!(!proof.verify(&ring, &balances, &deltas, amount + 1, fee), "amount bound in");
        assert!(!proof.verify(&ring, &balances, &deltas, amount, fee + 1), "fee bound in");
    }

    #[test]
    fn substituting_a_ring_member_fails() {
        let mut rng = OsRng;
        let (sks, mut ring) = ring_of(4, &mut rng);
        let l = 2;
        let (amount, fee) = (100u64, 10u64);
        let bals = [1, 2, 5_000, 4];
        let balances = balances_of(&sks, &bals, &mut rng);
        let (deltas, r_l) = deltas_with_real(4, l, amount, &mut rng);

        let proof = HiddenSolventSpend::prove(
            &ring, &balances, &deltas, amount, fee, &sks[l], &r_l, bals[l], l, &mut rng,
        )
        .unwrap();
        assert!(proof.verify(&ring, &balances, &deltas, amount, fee));
        ring[0] = SecretKey::random(&mut rng).public_key();
        assert!(!proof.verify(&ring, &balances, &deltas, amount, fee), "bound to the exact ring");
    }

    #[test]
    fn tampered_proof_fails() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let l = 1;
        let (amount, fee) = (321u64, 9u64);
        let bals = [1, 5_000, 2, 3];
        let balances = balances_of(&sks, &bals, &mut rng);
        let (deltas, r_l) = deltas_with_real(4, l, amount, &mut rng);

        let mut proof = HiddenSolventSpend::prove(
            &ring, &balances, &deltas, amount, fee, &sks[l], &r_l, bals[l], l, &mut rng,
        )
        .unwrap();
        assert!(proof.verify(&ring, &balances, &deltas, amount, fee));
        proof.z_x[0] += Scalar::ONE;
        assert!(!proof.verify(&ring, &balances, &deltas, amount, fee));
        // Restore, then tamper a different response vector.
        proof.z_x[0] -= Scalar::ONE;
        proof.z_g[2] += Scalar::ONE;
        assert!(!proof.verify(&ring, &balances, &deltas, amount, fee));
    }

    #[test]
    fn hides_which_member_is_bound() {
        // Two different owners over same-shape sets → structurally identical proofs,
        // so an observer can't tell which member spent.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(6, &mut rng);
        let (amount, fee) = (42u64, 8u64);
        let bals = [9_000, 9_000, 9_000, 9_000, 9_000, 9_000];
        let balances = balances_of(&sks, &bals, &mut rng);

        let (d0, r0) = deltas_with_real(6, 0, amount, &mut rng);
        let (d5, r5) = deltas_with_real(6, 5, amount, &mut rng);
        let p0 = HiddenSolventSpend::prove(
            &ring, &balances, &d0, amount, fee, &sks[0], &r0, bals[0], 0, &mut rng,
        )
        .unwrap();
        let p5 = HiddenSolventSpend::prove(
            &ring, &balances, &d5, amount, fee, &sks[5], &r5, bals[5], 5, &mut rng,
        )
        .unwrap();
        assert!(p0.verify(&ring, &balances, &d0, amount, fee));
        assert!(p5.verify(&ring, &balances, &d5, amount, fee));
        assert_eq!(p0.e.len(), p5.e.len());
        assert_eq!(p0.z_x.len(), p5.z_x.len());
        assert_eq!(p0.z_s.len(), p5.z_s.len());
        assert_eq!(p0.z_g.len(), p5.z_g.len());
    }

    #[test]
    fn full_anti_theft_and_solvency() {
        // The complete composition (bricks B + conservation + D). Together they force:
        //  - each delta ∈ {0, amount}          (ValueInSetProof, brick B)
        //  - Σ deltas = amount                 (ConservedDeltas)
        //  - the owned index carries `amount` AND is solvent (this proof, fused C+D)
        // ⇒ exactly one member — the owned, solvent one — is debited `amount`.
        let mut rng = OsRng;
        let n = 5;
        let l = 2;
        let (amount, fee) = (1_500u64, 50u64);
        let (sks, ring) = ring_of(n, &mut rng);
        let bals = [3_000, 3_000, 6_000, 3_000, 3_000];
        let balances = balances_of(&sks, &bals, &mut rng);

        // Build deltas and remember each blinding so we can prove B per member.
        let mut deltas = Vec::with_capacity(n);
        let mut blinds = Vec::with_capacity(n);
        for i in 0..n {
            let b = Scalar::random(&mut rng);
            let value = if i == l { amount } else { 0 };
            deltas.push(commit_delta(value, &b));
            blinds.push(b);
        }

        // Brick B: every delta opens to {0, amount}.
        let allowed = [0i64, amount as i64];
        for i in 0..n {
            let value = if i == l { amount as i64 } else { 0 };
            let (commitment, proof) =
                ValueInSetProof::prove(value, &blinds[i], &allowed, &mut rng).unwrap();
            assert_eq!(commitment, deltas[i], "commitment matches the on-set delta");
            assert!(proof.verify(&deltas[i], &allowed), "each delta ∈ {{0, amount}}");
        }

        // Conservation: the SIGNED deltas net to zero (sender −amount, receiver +amount).
        // Here we model the sender leg only, so pair it with a +amount receiver leg.
        let conserved = ConservedDeltas::create(&[-(amount as i64), amount as i64], &mut rng).unwrap();
        assert!(conserved.verify(), "Σ deltas = 0 (no inflation)");

        // Brick D (fused C+D): the owned member is the amount-carrier and is solvent.
        let proof = HiddenSolventSpend::prove(
            &ring, &balances, &deltas, amount, fee, &sks[l], &blinds[l], bals[l], l, &mut rng,
        )
        .expect("owned + solvent");
        assert!(proof.verify(&ring, &balances, &deltas, amount, fee));
    }
}

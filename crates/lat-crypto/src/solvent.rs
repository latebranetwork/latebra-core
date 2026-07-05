//! Solvent confidential transfer — the integrated proof that closes the minting
//! gap (clean-room, from `SPEC.md`).
//!
//! The simple transfer in `transfer.rs` proves value conservation + ownership but
//! NOT that amounts/balances are non-negative. A naive bolt-on range proof is
//! UNSOUND here: linking a range commitment to `c_sender = t·G + r·Y_s` alone
//! leaves `r` free, so any `t` could be faked (every blinding base lives in ⟨G⟩).
//!
//! This module fixes that with ONE integrated Σ-protocol whose relations share
//! witnesses, plus two Bulletproofs range proofs. Proving knowledge of
//! `(x, t, r, b', s_t, s_b)`:
//!
//! ```text
//!   1. Y_s        = x·G                  (sender owns the account)
//!   2. c_sender   = t·G + r·Y_s          (amount debited)
//!   3. c_receiver = t·G + r·Y_r          (same amount credited)
//!   4. d          = r·G                  (pins r)
//!   5. V_t        = t·G + s_t·H          (amount range commitment)
//!   6. C_rem      = b'·G + x·D_rem       (b' = remaining sender balance)
//!   7. V_b        = b'·G + s_b·H         (remaining-balance range commitment)
//! ```
//! with Bulletproofs proving `V_t` and `V_b` each commit to a value in `[0,2^64)`.
//!
//! Soundness: (4) pins `r`; then (2) pins `t`; (5) ties the in-range value to that
//! `t`. (1) pins `x`; then (6) — with `C_rem`, `D_rem` public — pins `b'`; (7) ties
//! the in-range value to that `b'`. Since `C_rem = (b_s − t)·G + r'·Y_s` and
//! `D_rem = r'·G`, relation (6) forces `b' = b_s − t`. Proving `b' ≥ 0` therefore
//! proves the sender could afford the transfer. H is independent of G (a
//! Pedersen blinding generator), so values in `V_t`/`V_b` cannot be shifted.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript as MerlinTranscript;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{Ciphertext, PublicKey, SecretKey};

const RANGE_BITS: usize = 64;

// --- wire-decode helpers ---------------------------------------------------
fn rd_point(b: &[u8], off: &mut usize) -> Option<RistrettoPoint> {
    let s = b.get(*off..*off + 32)?;
    *off += 32;
    CompressedRistretto::from_slice(s).ok()?.decompress()
}
fn rd_comp(b: &[u8], off: &mut usize) -> Option<CompressedRistretto> {
    let s = b.get(*off..*off + 32)?;
    *off += 32;
    CompressedRistretto::from_slice(s).ok()
}
fn rd_scalar(b: &[u8], off: &mut usize) -> Option<Scalar> {
    let arr: [u8; 32] = b.get(*off..*off + 32)?.try_into().ok()?;
    *off += 32;
    Option::from(Scalar::from_canonical_bytes(arr))
}
fn rd_u32(b: &[u8], off: &mut usize) -> Option<u32> {
    let arr: [u8; 4] = b.get(*off..*off + 4)?.try_into().ok()?;
    *off += 4;
    Some(u32::from_le_bytes(arr))
}

/// A confidential transfer that also proves the sender is solvent.
#[derive(Clone)]
pub struct SolventTransfer {
    pub sender: PublicKey,
    pub receiver: PublicKey,
    /// The sender's account nonce this transfer spends at. Bound into the proof
    /// (so it can't be edited) and checked by the ledger to prevent replay.
    pub nonce: u64,
    /// Public transaction fee (paid to the block's miner). Public by necessity —
    /// miners must see it — and bound into the proof so it can't be altered. The
    /// solvency proof covers `balance − amount − fee ≥ 0`.
    pub fee: u64,
    pub c_sender: RistrettoPoint,
    pub c_receiver: RistrettoPoint,
    pub d: RistrettoPoint,

    // Range-proof commitments and proofs (amount `t`, remaining balance `b'`).
    v_t: CompressedRistretto,
    v_b: CompressedRistretto,
    rp_t: RangeProof,
    rp_b: RangeProof,

    // Integrated Σ-protocol: announcements A1..A7 and responses.
    a1: RistrettoPoint,
    a2: RistrettoPoint,
    a3: RistrettoPoint,
    a4: RistrettoPoint,
    a5: RistrettoPoint,
    a6: RistrettoPoint,
    a7: RistrettoPoint,
    z_x: Scalar,
    z_t: Scalar,
    z_r: Scalar,
    z_b: Scalar,
    z_st: Scalar,
    z_sb: Scalar,
}

#[allow(clippy::too_many_arguments)]
fn challenge(nonce: u64, fee: u64, points: &[&RistrettoPoint]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.SolventTransfer.v1");
    h.update(nonce.to_le_bytes());
    h.update(fee.to_le_bytes());
    for p in points {
        h.update(p.compress().as_bytes());
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

impl SolventTransfer {
    /// Build a solvent transfer of `amount` from `sender_sk` to `receiver_pk`.
    ///
    /// `current_balance` is the sender's plaintext balance (the wallet knows it by
    /// decrypting), and `current_balance_ct` is the sender's on-chain encrypted
    /// balance `(C_s, D_s)`. Returns `None` if the sender cannot afford the amount
    /// (then no valid proof exists, by design).
    pub fn create<R: RngCore + CryptoRng>(
        sender_sk: &SecretKey,
        receiver_pk: &PublicKey,
        amount: u64,
        fee: u64,
        current_balance: u64,
        current_balance_ct: &Ciphertext,
        nonce: u64,
        rng: &mut R,
    ) -> Option<SolventTransfer> {
        // Must cover both the amount and the fee.
        let spent = amount.checked_add(fee)?;
        if spent > current_balance {
            return None; // insolvent — unprovable
        }
        let sender = sender_sk.public_key();
        let x = sender_sk.0;
        let t_val = amount;
        let b_val = current_balance - spent;
        let t = Scalar::from(t_val);
        let b = Scalar::from(b_val);
        let r = Scalar::random(rng);

        let c_sender = G * t + sender.0 * r;
        let c_receiver = G * t + receiver_pk.0 * r;
        let d = G * r;

        // Remaining balance also loses the public fee (fee·G is public).
        let c_rem = current_balance_ct.c - c_sender - G * Scalar::from(fee);
        let d_rem = current_balance_ct.d - d;

        let pc = PedersenGens::default(); // B = G, B_blinding = H
        let bp = BulletproofGens::new(RANGE_BITS, 1);
        let h = pc.B_blinding;

        let s_t = Scalar::random(rng);
        let s_b = Scalar::random(rng);

        let mut tr_t = MerlinTranscript::new(b"Latebra.Range.amount");
        let (rp_t, v_t) = RangeProof::prove_single(&bp, &pc, &mut tr_t, t_val, &s_t, RANGE_BITS).ok()?;
        let mut tr_b = MerlinTranscript::new(b"Latebra.Range.balance");
        let (rp_b, v_b) = RangeProof::prove_single(&bp, &pc, &mut tr_b, b_val, &s_b, RANGE_BITS).ok()?;

        let big_vt = v_t.decompress()?;
        let big_vb = v_b.decompress()?;

        // Σ nonces.
        let k_x = Scalar::random(rng);
        let k_t = Scalar::random(rng);
        let k_r = Scalar::random(rng);
        let k_b = Scalar::random(rng);
        let k_st = Scalar::random(rng);
        let k_sb = Scalar::random(rng);

        let a1 = G * k_x;
        let a2 = G * k_t + sender.0 * k_r;
        let a3 = G * k_t + receiver_pk.0 * k_r;
        let a4 = G * k_r;
        let a5 = G * k_t + h * k_st;
        let a6 = G * k_b + d_rem * k_x;
        let a7 = G * k_b + h * k_sb;

        let e = challenge(nonce, fee, &[
            &sender.0, &receiver_pk.0, &c_sender, &c_receiver, &d, &c_rem, &d_rem, &big_vt,
            &big_vb, &a1, &a2, &a3, &a4, &a5, &a6, &a7,
        ]);

        Some(SolventTransfer {
            sender,
            receiver: *receiver_pk,
            nonce,
            fee,
            c_sender,
            c_receiver,
            d,
            v_t,
            v_b,
            rp_t,
            rp_b,
            a1,
            a2,
            a3,
            a4,
            a5,
            a6,
            a7,
            z_x: k_x + e * x,
            z_t: k_t + e * t,
            z_r: k_r + e * r,
            z_b: k_b + e * b,
            z_st: k_st + e * s_t,
            z_sb: k_sb + e * s_b,
        })
    }

    /// Canonical wire encoding (fixed 640-byte prefix + two length-prefixed
    /// Bulletproofs range proofs).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(700);
        for p in [
            &self.sender.0,
            &self.receiver.0,
            &self.c_sender,
            &self.c_receiver,
            &self.d,
        ] {
            v.extend_from_slice(p.compress().as_bytes());
        }
        v.extend_from_slice(self.v_t.as_bytes());
        v.extend_from_slice(self.v_b.as_bytes());
        for p in [
            &self.a1, &self.a2, &self.a3, &self.a4, &self.a5, &self.a6, &self.a7,
        ] {
            v.extend_from_slice(p.compress().as_bytes());
        }
        for s in [
            &self.z_x, &self.z_t, &self.z_r, &self.z_b, &self.z_st, &self.z_sb,
        ] {
            v.extend_from_slice(s.as_bytes());
        }
        for rp in [&self.rp_t, &self.rp_b] {
            let bytes = rp.to_bytes();
            v.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            v.extend_from_slice(&bytes);
        }
        v.extend_from_slice(&self.nonce.to_le_bytes());
        v.extend_from_slice(&self.fee.to_le_bytes());
        v
    }

    /// Decode from [`to_bytes`](Self::to_bytes). `None` on malformed input.
    pub fn from_bytes(b: &[u8]) -> Option<SolventTransfer> {
        let mut off = 0usize;
        let sender = PublicKey(rd_point(b, &mut off)?);
        let receiver = PublicKey(rd_point(b, &mut off)?);
        let c_sender = rd_point(b, &mut off)?;
        let c_receiver = rd_point(b, &mut off)?;
        let d = rd_point(b, &mut off)?;
        let v_t = rd_comp(b, &mut off)?;
        let v_b = rd_comp(b, &mut off)?;
        let a1 = rd_point(b, &mut off)?;
        let a2 = rd_point(b, &mut off)?;
        let a3 = rd_point(b, &mut off)?;
        let a4 = rd_point(b, &mut off)?;
        let a5 = rd_point(b, &mut off)?;
        let a6 = rd_point(b, &mut off)?;
        let a7 = rd_point(b, &mut off)?;
        let z_x = rd_scalar(b, &mut off)?;
        let z_t = rd_scalar(b, &mut off)?;
        let z_r = rd_scalar(b, &mut off)?;
        let z_b = rd_scalar(b, &mut off)?;
        let z_st = rd_scalar(b, &mut off)?;
        let z_sb = rd_scalar(b, &mut off)?;
        let rt_len = rd_u32(b, &mut off)? as usize;
        let rp_t = RangeProof::from_bytes(b.get(off..off + rt_len)?).ok()?;
        off += rt_len;
        let rb_len = rd_u32(b, &mut off)? as usize;
        let rp_b = RangeProof::from_bytes(b.get(off..off + rb_len)?).ok()?;
        off += rb_len;
        let nonce = u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?);
        off += 8;
        let fee = u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?);
        off += 8;
        if off != b.len() {
            return None;
        }
        Some(SolventTransfer {
            sender, receiver, nonce, fee, c_sender, c_receiver, d, v_t, v_b, rp_t, rp_b,
            a1, a2, a3, a4, a5, a6, a7, z_x, z_t, z_r, z_b, z_st, z_sb,
        })
    }

    /// The ciphertext to homomorphically SUBTRACT from the sender's balance.
    pub fn sender_ciphertext(&self) -> Ciphertext {
        Ciphertext { c: self.c_sender, d: self.d }
    }

    /// The ciphertext to homomorphically ADD to the receiver's balance.
    pub fn receiver_ciphertext(&self) -> Ciphertext {
        Ciphertext { c: self.c_receiver, d: self.d }
    }

    /// Verify the transfer against the sender's current on-chain balance
    /// `(C_s, D_s)`. Returns `true` iff value is conserved, the sender owns the
    /// account, the amount is non-negative, AND the sender's remaining balance is
    /// non-negative (solvency).
    pub fn verify(&self, current_balance_ct: &Ciphertext) -> bool {
        let c_rem = current_balance_ct.c - self.c_sender - G * Scalar::from(self.fee);
        let d_rem = current_balance_ct.d - self.d;

        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(RANGE_BITS, 1);
        let h = pc.B_blinding;

        // Bulletproofs range proofs.
        let mut tr_t = MerlinTranscript::new(b"Latebra.Range.amount");
        if self.rp_t.verify_single(&bp, &pc, &mut tr_t, &self.v_t, RANGE_BITS).is_err() {
            return false;
        }
        let mut tr_b = MerlinTranscript::new(b"Latebra.Range.balance");
        if self.rp_b.verify_single(&bp, &pc, &mut tr_b, &self.v_b, RANGE_BITS).is_err() {
            return false;
        }

        let (big_vt, big_vb) = match (self.v_t.decompress(), self.v_b.decompress()) {
            (Some(a), Some(b)) => (a, b),
            _ => return false,
        };

        let e = challenge(self.nonce, self.fee, &[
            &self.sender.0, &self.receiver.0, &self.c_sender, &self.c_receiver, &self.d, &c_rem,
            &d_rem, &big_vt, &big_vb, &self.a1, &self.a2, &self.a3, &self.a4, &self.a5, &self.a6,
            &self.a7,
        ]);

        // The 7 Σ relations.
        let c1 = G * self.z_x == self.a1 + self.sender.0 * e;
        let c2 = G * self.z_t + self.sender.0 * self.z_r == self.a2 + self.c_sender * e;
        let c3 = G * self.z_t + self.receiver.0 * self.z_r == self.a3 + self.c_receiver * e;
        let c4 = G * self.z_r == self.a4 + self.d * e;
        let c5 = G * self.z_t + h * self.z_st == self.a5 + big_vt * e;
        let c6 = G * self.z_b + d_rem * self.z_x == self.a6 + c_rem * e;
        let c7 = G * self.z_b + h * self.z_sb == self.a7 + big_vb * e;

        c1 && c2 && c3 && c4 && c5 && c6 && c7
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// A sender's on-chain balance ciphertext encrypting `amount` under their key.
    fn balance_ct(sk: &SecretKey, amount: u64, rng: &mut OsRng) -> Ciphertext {
        sk.public_key().encrypt(amount, rng)
    }

    #[test]
    fn solvent_transfer_verifies_and_pays_receiver() {
        let mut rng = OsRng;
        let sender = SecretKey::random(&mut rng);
        let receiver = SecretKey::random(&mut rng);
        let bal = balance_ct(&sender, 1_000, &mut rng);

        let xfer = SolventTransfer::create(&sender, &receiver.public_key(), 300, 0, 1_000, &bal, 0, &mut rng)
            .expect("solvent");
        assert!(xfer.verify(&bal), "honest solvent transfer must verify");

        // Receiver can recover the hidden amount.
        let got = receiver.decrypt(&xfer.receiver_ciphertext(), 20);
        assert_eq!(got, Some(300));
    }

    #[test]
    fn transfer_with_fee_verifies_and_covers_amount_plus_fee() {
        let mut rng = OsRng;
        let sender = SecretKey::random(&mut rng);
        let receiver = SecretKey::random(&mut rng);
        let bal = balance_ct(&sender, 1_000, &mut rng);

        // amount 700 + fee 250 = 950 <= 1000: OK, remaining 50 proven >= 0.
        let xfer = SolventTransfer::create(&sender, &receiver.public_key(), 700, 250, 1_000, &bal, 0, &mut rng)
            .expect("affordable with fee");
        assert_eq!(xfer.fee, 250);
        assert!(xfer.verify(&bal));

        // amount 800 + fee 300 = 1100 > 1000: unprovable.
        assert!(SolventTransfer::create(&sender, &receiver.public_key(), 800, 300, 1_000, &bal, 0, &mut rng).is_none());
    }

    #[test]
    fn editing_the_fee_breaks_the_proof() {
        let mut rng = OsRng;
        let sender = SecretKey::random(&mut rng);
        let receiver = SecretKey::random(&mut rng);
        let bal = balance_ct(&sender, 1_000, &mut rng);
        let mut xfer = SolventTransfer::create(&sender, &receiver.public_key(), 300, 10, 1_000, &bal, 0, &mut rng).unwrap();
        assert!(xfer.verify(&bal));
        xfer.fee = 0; // try to dodge the fee
        assert!(!xfer.verify(&bal), "the fee is bound into the proof");
    }

    #[test]
    fn overspend_is_unprovable() {
        let mut rng = OsRng;
        let sender = SecretKey::random(&mut rng);
        let receiver = SecretKey::random(&mut rng);
        let bal = balance_ct(&sender, 100, &mut rng);

        // Trying to send more than you hold yields no proof at all.
        assert!(SolventTransfer::create(&sender, &receiver.public_key(), 500, 0, 100, &bal, 0, &mut rng).is_none());
    }

    #[test]
    fn lying_about_balance_fails_verification() {
        let mut rng = OsRng;
        let sender = SecretKey::random(&mut rng);
        let receiver = SecretKey::random(&mut rng);

        // Build an honest-looking proof claiming a balance of 1000...
        let claimed = balance_ct(&sender, 1_000, &mut rng);
        let xfer = SolventTransfer::create(&sender, &receiver.public_key(), 900, 0, 1_000, &claimed, 0, &mut rng)
            .expect("builds");

        // ...but the sender's ACTUAL on-chain balance is only 100. Verification
        // against the real balance must fail (the solvency relation won't hold).
        let actual = balance_ct(&sender, 100, &mut rng);
        assert!(!xfer.verify(&actual), "proof must bind to the real balance");
    }

    #[test]
    fn wire_roundtrip_preserves_validity() {
        let mut rng = OsRng;
        let sender = SecretKey::random(&mut rng);
        let receiver = SecretKey::random(&mut rng);
        let bal = balance_ct(&sender, 1_000, &mut rng);

        let xfer = SolventTransfer::create(&sender, &receiver.public_key(), 300, 0, 1_000, &bal, 0, &mut rng)
            .unwrap();
        let bytes = xfer.to_bytes();
        let decoded = SolventTransfer::from_bytes(&bytes).expect("decodes");
        assert_eq!(decoded.to_bytes(), bytes);
        assert!(decoded.verify(&bal), "decoded solvent transfer still verifies");
    }

    #[test]
    fn tampered_proof_fails() {
        let mut rng = OsRng;
        let sender = SecretKey::random(&mut rng);
        let receiver = SecretKey::random(&mut rng);
        let bal = balance_ct(&sender, 1_000, &mut rng);

        let mut xfer = SolventTransfer::create(&sender, &receiver.public_key(), 300, 0, 1_000, &bal, 0, &mut rng)
            .unwrap();
        xfer.z_b += Scalar::from(1u64);
        assert!(!xfer.verify(&bal));
    }

    #[test]
    fn editing_nonce_breaks_proof() {
        // The nonce is bound into the proof, so an attacker can't change it (e.g.
        // to match a later account state) and still have it verify.
        let mut rng = OsRng;
        let sender = SecretKey::random(&mut rng);
        let receiver = SecretKey::random(&mut rng);
        let bal = balance_ct(&sender, 1_000, &mut rng);

        let mut xfer = SolventTransfer::create(&sender, &receiver.public_key(), 300, 0, 1_000, &bal, 7, &mut rng)
            .unwrap();
        assert!(xfer.verify(&bal));
        xfer.nonce = 8;
        assert!(!xfer.verify(&bal), "tampering the nonce must invalidate the proof");
    }
}

//! Confidential transfer proof (clean-room, from `SPEC.md`).
//!
//! A transfer moves a hidden amount `t` from a sender to a receiver. It publishes
//! a "transfer ciphertext" that encrypts the SAME `t` under both parties' keys,
//! plus a zero-knowledge proof. The proof convinces verifiers — without revealing
//! `t` — that:
//!
//!   1. `C_sender   = t·G + r·Y_sender`     (amount debited from sender)
//!   2. `C_receiver = t·G + r·Y_receiver`   (same amount credited to receiver)
//!   3. `D          = r·G`                   (shared randomness)
//!   4. `Y_sender   = x·G`                   (sender knows their secret key)
//!
//! Because relations 1–3 share the same witnesses `(t, r)`, the proof guarantees
//! the sender cannot encrypt one amount to themselves and a different amount to
//! the receiver — i.e. value is conserved. This is a standard generalized-Schnorr
//! sigma protocol made non-interactive with Fiat–Shamir.
//!
//! NOTE (soundness scope): this proof does NOT yet enforce `t ≥ 0` or
//! `sender_balance − t ≥ 0`. Those are the Bulletproofs *range proofs*, the next
//! step in Milestone 1. Until they land, this type must not guard real value.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{PublicKey, SecretKey};

/// Fiat–Shamir transcript: absorbs the public statement + announcements, then
/// squeezes a single challenge scalar. Domain-separated so proofs for one context
/// can never be replayed in another.
struct Transcript {
    hasher: Sha512,
}

impl Transcript {
    fn new() -> Self {
        let mut hasher = Sha512::new();
        hasher.update(b"Latebra.ConfidentialTransfer.v1");
        Transcript { hasher }
    }

    fn append(&mut self, label: &[u8], point: &RistrettoPoint) {
        self.hasher.update(label);
        self.hasher.update(point.compress().as_bytes());
    }

    fn challenge(self) -> Scalar {
        let digest = self.hasher.finalize(); // 64 bytes
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&digest);
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

/// The non-interactive proof: announcements `A_*` and responses `z_*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferProof {
    a_cs: RistrettoPoint,
    a_cr: RistrettoPoint,
    a_d: RistrettoPoint,
    a_ys: RistrettoPoint,
    z_t: Scalar,
    z_r: Scalar,
    z_x: Scalar,
}

/// A complete confidential transfer: the public statement plus its proof.
/// The amount `t` and randomness `r` are NOT stored — they stay secret.
#[derive(Clone, Debug)]
pub struct ConfidentialTransfer {
    pub sender: PublicKey,
    pub receiver: PublicKey,
    /// `C_sender = t·G + r·Y_sender`
    pub c_sender: RistrettoPoint,
    /// `C_receiver = t·G + r·Y_receiver`
    pub c_receiver: RistrettoPoint,
    /// `D = r·G`
    pub d: RistrettoPoint,
    pub proof: TransferProof,
}

/// Build the Fiat–Shamir challenge from the public statement and announcements.
/// Must append in the exact same order during proving and verifying.
fn challenge(
    sender: &PublicKey,
    receiver: &PublicKey,
    c_sender: &RistrettoPoint,
    c_receiver: &RistrettoPoint,
    d: &RistrettoPoint,
    a_cs: &RistrettoPoint,
    a_cr: &RistrettoPoint,
    a_d: &RistrettoPoint,
    a_ys: &RistrettoPoint,
) -> Scalar {
    let mut t = Transcript::new();
    t.append(b"Ys", &sender.0);
    t.append(b"Yr", &receiver.0);
    t.append(b"Cs", c_sender);
    t.append(b"Cr", c_receiver);
    t.append(b"D", d);
    t.append(b"A_Cs", a_cs);
    t.append(b"A_Cr", a_cr);
    t.append(b"A_D", a_d);
    t.append(b"A_Ys", a_ys);
    t.challenge()
}

impl ConfidentialTransfer {
    /// Create a confidential transfer of `amount` from `sender_sk` to
    /// `receiver_pk`, together with its zero-knowledge proof.
    pub fn create<R: RngCore + CryptoRng>(
        sender_sk: &SecretKey,
        receiver_pk: &PublicKey,
        amount: u64,
        rng: &mut R,
    ) -> Self {
        let sender = sender_sk.public_key();
        let x = sender_sk.0;
        let t = Scalar::from(amount);
        let r = Scalar::random(rng);

        // Public transfer ciphertext.
        let c_sender = G * t + sender.0 * r;
        let c_receiver = G * t + receiver_pk.0 * r;
        let d = G * r;

        // Sigma protocol: random nonces for each witness (t, r, x).
        let k_t = Scalar::random(rng);
        let k_r = Scalar::random(rng);
        let k_x = Scalar::random(rng);

        // Announcements mirror the four relations.
        let a_cs = G * k_t + sender.0 * k_r;
        let a_cr = G * k_t + receiver_pk.0 * k_r;
        let a_d = G * k_r;
        let a_ys = G * k_x;

        let e = challenge(
            &sender,
            receiver_pk,
            &c_sender,
            &c_receiver,
            &d,
            &a_cs,
            &a_cr,
            &a_d,
            &a_ys,
        );

        // Responses: z = nonce + e·witness.
        let z_t = k_t + e * t;
        let z_r = k_r + e * r;
        let z_x = k_x + e * x;

        ConfidentialTransfer {
            sender,
            receiver: *receiver_pk,
            c_sender,
            c_receiver,
            d,
            proof: TransferProof {
                a_cs,
                a_cr,
                a_d,
                a_ys,
                z_t,
                z_r,
                z_x,
            },
        }
    }

    /// Canonical byte encoding (compressed points + scalar bytes), for hashing
    /// into transaction ids and block commitments. 12 × 32 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(12 * 32);
        for p in [
            &self.sender.0,
            &self.receiver.0,
            &self.c_sender,
            &self.c_receiver,
            &self.d,
            &self.proof.a_cs,
            &self.proof.a_cr,
            &self.proof.a_d,
            &self.proof.a_ys,
        ] {
            v.extend_from_slice(p.compress().as_bytes());
        }
        for s in [&self.proof.z_t, &self.proof.z_r, &self.proof.z_x] {
            v.extend_from_slice(s.as_bytes());
        }
        v
    }

    /// Decode a transfer from its canonical 384-byte encoding (the inverse of
    /// [`to_bytes`](Self::to_bytes)). Returns `None` on malformed input (bad
    /// point/scalar encodings). The proof still needs `verify()` — decoding only
    /// checks the bytes are well-formed group elements.
    pub fn from_bytes(b: &[u8]) -> Option<ConfidentialTransfer> {
        if b.len() != 12 * 32 {
            return None;
        }
        let pt = |i: usize| -> Option<RistrettoPoint> {
            CompressedRistretto::from_slice(&b[i * 32..i * 32 + 32])
                .ok()?
                .decompress()
        };
        let sc = |i: usize| -> Option<Scalar> {
            let arr: [u8; 32] = b[i * 32..i * 32 + 32].try_into().ok()?;
            Option::from(Scalar::from_canonical_bytes(arr))
        };
        Some(ConfidentialTransfer {
            sender: PublicKey(pt(0)?),
            receiver: PublicKey(pt(1)?),
            c_sender: pt(2)?,
            c_receiver: pt(3)?,
            d: pt(4)?,
            proof: TransferProof {
                a_cs: pt(5)?,
                a_cr: pt(6)?,
                a_d: pt(7)?,
                a_ys: pt(8)?,
                z_t: sc(9)?,
                z_r: sc(10)?,
                z_x: sc(11)?,
            },
        })
    }

    /// The ciphertext to homomorphically SUBTRACT from the sender's balance.
    pub fn sender_ciphertext(&self) -> crate::Ciphertext {
        crate::Ciphertext {
            c: self.c_sender,
            d: self.d,
        }
    }

    /// The ciphertext to homomorphically ADD to the receiver's balance.
    pub fn receiver_ciphertext(&self) -> crate::Ciphertext {
        crate::Ciphertext {
            c: self.c_receiver,
            d: self.d,
        }
    }

    /// Verify the proof. Returns `true` iff all four relations hold for some
    /// witnesses the prover demonstrably knew — without learning the amount.
    pub fn verify(&self) -> bool {
        let p = &self.proof;
        let e = challenge(
            &self.sender,
            &self.receiver,
            &self.c_sender,
            &self.c_receiver,
            &self.d,
            &p.a_cs,
            &p.a_cr,
            &p.a_d,
            &p.a_ys,
        );

        // Each check: z_t·G + z_r·Y == A + e·C
        let check_cs = G * p.z_t + self.sender.0 * p.z_r == p.a_cs + self.c_sender * e;
        let check_cr = G * p.z_t + self.receiver.0 * p.z_r == p.a_cr + self.c_receiver * e;
        let check_d = G * p.z_r == p.a_d + self.d * e;
        let check_ys = G * p.z_x == p.a_ys + self.sender.0 * e;

        check_cs && check_cr && check_d && check_ys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ciphertext;
    use rand::rngs::OsRng;

    #[test]
    fn honest_transfer_verifies() {
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let receiver_sk = SecretKey::random(&mut rng);
        let receiver_pk = receiver_sk.public_key();

        let xfer = ConfidentialTransfer::create(&sender_sk, &receiver_pk, 4_200, &mut rng);
        assert!(xfer.verify(), "honest transfer must verify");
    }

    #[test]
    fn receiver_recovers_hidden_amount() {
        // End-to-end: the proof verifies AND the receiver (only) can decrypt the
        // amount from (C_receiver, D) using their key.
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let receiver_sk = SecretKey::random(&mut rng);
        let receiver_pk = receiver_sk.public_key();

        let amount = 9_999u64;
        let xfer = ConfidentialTransfer::create(&sender_sk, &receiver_pk, amount, &mut rng);
        assert!(xfer.verify());

        let ct = Ciphertext {
            c: xfer.c_receiver,
            d: xfer.d,
        };
        assert_eq!(receiver_sk.decrypt(&ct, 20), Some(amount));
    }

    #[test]
    fn tampered_amount_fails() {
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let receiver_pk = SecretKey::random(&mut rng).public_key();

        let mut xfer = ConfidentialTransfer::create(&sender_sk, &receiver_pk, 100, &mut rng);
        // Forge a different credited amount on the receiver side.
        xfer.c_receiver += G * Scalar::from(1u64);
        assert!(!xfer.verify(), "tampered ciphertext must not verify");
    }

    #[test]
    fn forged_response_fails() {
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let receiver_pk = SecretKey::random(&mut rng).public_key();

        let mut xfer = ConfidentialTransfer::create(&sender_sk, &receiver_pk, 100, &mut rng);
        xfer.proof.z_t += Scalar::from(1u64);
        assert!(!xfer.verify(), "forged response must not verify");
    }

    #[test]
    fn wire_roundtrip_preserves_validity() {
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let receiver_pk = SecretKey::random(&mut rng).public_key();

        let xfer = ConfidentialTransfer::create(&sender_sk, &receiver_pk, 1234, &mut rng);
        let bytes = xfer.to_bytes();
        let decoded = ConfidentialTransfer::from_bytes(&bytes).expect("decodes");

        assert_eq!(decoded.to_bytes(), bytes);
        assert!(decoded.verify(), "decoded transfer still verifies");
    }

    #[test]
    fn proof_does_not_leak_amount() {
        // Two transfers of different amounts must have independent-looking proofs;
        // at minimum the public statement must not equal the amount in the clear.
        // (Sanity check, not a formal ZK test.)
        let mut rng = OsRng;
        let sender_sk = SecretKey::random(&mut rng);
        let receiver_pk = SecretKey::random(&mut rng).public_key();

        let a = ConfidentialTransfer::create(&sender_sk, &receiver_pk, 1, &mut rng);
        let b = ConfidentialTransfer::create(&sender_sk, &receiver_pk, 1, &mut rng);
        // Same amount, fresh randomness -> different ciphertexts (semantic security).
        assert_ne!(a.c_sender, b.c_sender);
        assert_ne!(a.d, b.d);
    }
}

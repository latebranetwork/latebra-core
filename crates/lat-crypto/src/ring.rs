//! Ring signatures — the one-of-many anonymity primitive (clean-room, `SPEC.md`).
//!
//! This is the cryptographic heart of sender/receiver anonymity (the DERO / Zether
//! idea of an *anonymity set*): prove you control the key of *one* account among a
//! ring of `N`, without revealing which one. It is a Cramer–Damgård–Schoenmakers
//! OR-composition of Schnorr proofs, made non-interactive with Fiat–Shamir.
//!
//! For the real member the prover runs Schnorr honestly; for every other member it
//! *simulates* a transcript (pick the response and challenge, derive the
//! commitment backwards). The Fiat–Shamir challenge fixes the sum of the per-member
//! challenges, and only someone holding at least one real secret key can make the
//! sum come out right — so the proof is unforgeable, yet every member looks equally
//! likely to be the signer.
//!
//! ## Honest scope
//! This is the FOUNDATION, not the finished feature. Real DERO-style private
//! transfers additionally need: (1) balance conservation across the ring (encrypted
//! +0 deltas for the decoys, ±amount for the real pair) — the Anonymous-Zether
//! "many-out-of-many" construction; (2) a **key image** for linkability so a coin
//! can't be double-spent; and (3) a log-size proof for efficiency. Those build on
//! top of this primitive and must be audited before real value. Proof size here is
//! O(N).

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{PublicKey, SecretKey};

/// A ring signature over a set of public keys and a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingSignature {
    /// Per-member challenges; their sum equals the Fiat–Shamir challenge.
    e: Vec<Scalar>,
    /// Per-member Schnorr responses.
    z: Vec<Scalar>,
}

fn challenge(ring: &[PublicKey], msg: &[u8], commitments: &[RistrettoPoint]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.RingSig.v1");
    h.update((ring.len() as u64).to_le_bytes());
    for pk in ring {
        h.update(pk.0.compress().as_bytes());
    }
    h.update(msg);
    for c in commitments {
        h.update(c.compress().as_bytes());
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

impl RingSignature {
    /// Sign `msg` on behalf of the ring, where `secret` is the key of `ring[index]`.
    /// The resulting signature hides which member signed.
    ///
    /// Panics if `index` is out of range or `ring[index]` is not `secret`'s public
    /// key (a programming error — the caller must place their own key in the ring).
    pub fn sign<R: RngCore + CryptoRng>(
        ring: &[PublicKey],
        secret: &SecretKey,
        index: usize,
        msg: &[u8],
        rng: &mut R,
    ) -> RingSignature {
        let n = ring.len();
        assert!(index < n, "signer index out of range");
        assert_eq!(ring[index], secret.public_key(), "signer key not at ring[index]");

        let mut e = vec![Scalar::ZERO; n];
        let mut z = vec![Scalar::ZERO; n];
        let mut commitments = vec![RistrettoPoint::identity(); n];

        // Simulate every decoy member: choose (e_i, z_i) at random, derive the
        // commitment A_i = z_i·G − e_i·Y_i so the Schnorr check will pass.
        let mut sum_decoy = Scalar::ZERO;
        for i in 0..n {
            if i == index {
                continue;
            }
            e[i] = Scalar::random(rng);
            z[i] = Scalar::random(rng);
            commitments[i] = G * z[i] - ring[i].0 * e[i];
            sum_decoy += e[i];
        }

        // Real member: a genuine Schnorr commitment with a fresh nonce.
        let k = Scalar::random(rng);
        commitments[index] = G * k;

        // Fiat–Shamir: the total challenge fixes the real member's share.
        let c = challenge(ring, msg, &commitments);
        e[index] = c - sum_decoy;
        z[index] = k + e[index] * secret.0;

        RingSignature { e, z }
    }

    /// Verify the signature against the ring and message. Returns `true` iff it was
    /// produced by someone holding a secret key for one of the ring members.
    pub fn verify(&self, ring: &[PublicKey], msg: &[u8]) -> bool {
        let n = ring.len();
        if self.e.len() != n || self.z.len() != n {
            return false;
        }
        // Reconstruct each commitment and sum the challenges.
        let mut commitments = vec![RistrettoPoint::identity(); n];
        let mut sum = Scalar::ZERO;
        for i in 0..n {
            commitments[i] = G * self.z[i] - ring[i].0 * self.e[i];
            sum += self.e[i];
        }
        // The transcript's challenge must equal the sum of per-member challenges.
        challenge(ring, msg, &commitments) == sum
    }
}

/// Hash a public key to an independent curve point `H_p(Y)` (for key images).
fn hash_to_point(pk: &RistrettoPoint) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(b"Latebra.RingHp.v1");
    h.update(pk.compress().as_bytes());
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    RistrettoPoint::from_uniform_bytes(&wide)
}

fn lsag_challenge(
    ring: &[PublicKey],
    image: &RistrettoPoint,
    msg: &[u8],
    l: &RistrettoPoint,
    r: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.LSAG.v1");
    h.update((ring.len() as u64).to_le_bytes());
    for pk in ring {
        h.update(pk.0.compress().as_bytes());
    }
    h.update(image.compress().as_bytes());
    h.update(msg);
    h.update(l.compress().as_bytes());
    h.update(r.compress().as_bytes());
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A **linkable** ring signature (LSAG, Liu–Wei–Wong / Monero-style). Like a ring
/// signature, but it also publishes a *key image* `I = x·H_p(Y)` that is:
/// deterministic for the signer's key (so two spends by the same key share it →
/// double-spend detectable), yet unlinkable to which public key produced it. The
/// chain rejects a transaction whose key image was already seen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkableRingSignature {
    image: RistrettoPoint,
    c0: Scalar,
    s: Vec<Scalar>,
}

impl LinkableRingSignature {
    /// Sign `msg` on behalf of the ring; `secret` is the key of `ring[index]`.
    pub fn sign<R: RngCore + CryptoRng>(
        ring: &[PublicKey],
        secret: &SecretKey,
        index: usize,
        msg: &[u8],
        rng: &mut R,
    ) -> LinkableRingSignature {
        let n = ring.len();
        assert!(index < n, "signer index out of range");
        assert_eq!(ring[index], secret.public_key(), "signer key not at ring[index]");

        let hp: Vec<RistrettoPoint> = ring.iter().map(|pk| hash_to_point(&pk.0)).collect();
        let x = secret.0;
        let image = hp[index] * x;

        let mut c = vec![Scalar::ZERO; n];
        let mut s = vec![Scalar::ZERO; n];

        // Start the ring at the real member with a fresh nonce.
        let k = Scalar::random(rng);
        let l_real = G * k;
        let r_real = hp[index] * k;
        c[(index + 1) % n] = lsag_challenge(ring, &image, msg, &l_real, &r_real);

        // Walk the decoys around the ring, simulating each link.
        let mut i = (index + 1) % n;
        while i != index {
            s[i] = Scalar::random(rng);
            let l_i = G * s[i] + ring[i].0 * c[i];
            let r_i = hp[i] * s[i] + image * c[i];
            c[(i + 1) % n] = lsag_challenge(ring, &image, msg, &l_i, &r_i);
            i = (i + 1) % n;
        }

        // Close the ring at the real member.
        s[index] = k - c[index] * x;

        LinkableRingSignature { image, c0: c[0], s }
    }

    /// The key image, as 32 bytes — the chain tracks these to prevent double-spends.
    pub fn key_image(&self) -> [u8; 32] {
        self.image.compress().to_bytes()
    }

    /// Verify the signature against the ring and message.
    pub fn verify(&self, ring: &[PublicKey], msg: &[u8]) -> bool {
        let n = ring.len();
        if self.s.len() != n {
            return false;
        }
        let hp: Vec<RistrettoPoint> = ring.iter().map(|pk| hash_to_point(&pk.0)).collect();
        let mut c = self.c0;
        for i in 0..n {
            let l_i = G * self.s[i] + ring[i].0 * c;
            let r_i = hp[i] * self.s[i] + self.image * c;
            c = lsag_challenge(ring, &self.image, msg, &l_i, &r_i);
        }
        c == self.c0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn ring_of(n: usize, rng: &mut OsRng) -> (Vec<SecretKey>, Vec<PublicKey>) {
        let sks: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(rng)).collect();
        let pks = sks.iter().map(|s| s.public_key()).collect();
        (sks, pks)
    }

    #[test]
    fn honest_signer_verifies() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(5, &mut rng);
        let sig = RingSignature::sign(&ring, &sks[2], 2, b"pay alice", &mut rng);
        assert!(sig.verify(&ring, b"pay alice"));
    }

    #[test]
    fn hides_which_member_signed() {
        // Two different real signers over the SAME ring both verify, and the
        // signatures are structurally identical (same size) — an observer can't
        // tell which member produced either.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(6, &mut rng);
        let sig0 = RingSignature::sign(&ring, &sks[0], 0, b"m", &mut rng);
        let sig4 = RingSignature::sign(&ring, &sks[4], 4, b"m", &mut rng);
        assert!(sig0.verify(&ring, b"m"));
        assert!(sig4.verify(&ring, b"m"));
        assert_eq!(sig0.e.len(), sig4.e.len());
    }

    #[test]
    fn wrong_message_fails() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let sig = RingSignature::sign(&ring, &sks[1], 1, b"send 5", &mut rng);
        assert!(!sig.verify(&ring, b"send 50"));
    }

    #[test]
    fn tampered_response_fails() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let mut sig = RingSignature::sign(&ring, &sks[1], 1, b"m", &mut rng);
        sig.z[0] += Scalar::ONE;
        assert!(!sig.verify(&ring, b"m"));
    }

    #[test]
    fn substituting_a_ring_member_fails() {
        // A signature is bound to the exact ring; swapping in another key breaks it.
        let mut rng = OsRng;
        let (sks, mut ring) = ring_of(4, &mut rng);
        let sig = RingSignature::sign(&ring, &sks[3], 3, b"m", &mut rng);
        assert!(sig.verify(&ring, b"m"));
        ring[0] = SecretKey::random(&mut rng).public_key();
        assert!(!sig.verify(&ring, b"m"));
    }

    #[test]
    fn outsider_key_not_in_ring_is_useless() {
        // An attacker's key that isn't in the ring can't sign for a member slot:
        // the reconstructed commitment won't match, so verification fails.
        let mut rng = OsRng;
        let (_sks, ring) = ring_of(4, &mut rng);
        let outsider = SecretKey::random(&mut rng);
        // Forge attempt: run the honest algorithm as if the outsider were ring[1],
        // but ring[1] is someone else's key. Build the signature manually to skip
        // the sanity assert, then verify — it must fail.
        let n = ring.len();
        let mut e = vec![Scalar::ZERO; n];
        let mut z = vec![Scalar::ZERO; n];
        let mut commitments = vec![RistrettoPoint::identity(); n];
        let mut sum_decoy = Scalar::ZERO;
        for i in 0..n {
            if i == 1 {
                continue;
            }
            e[i] = Scalar::random(&mut rng);
            z[i] = Scalar::random(&mut rng);
            commitments[i] = G * z[i] - ring[i].0 * e[i];
            sum_decoy += e[i];
        }
        let k = Scalar::random(&mut rng);
        commitments[1] = G * k;
        let c = challenge(&ring, b"m", &commitments);
        e[1] = c - sum_decoy;
        z[1] = k + e[1] * outsider.0; // wrong secret for ring[1]
        let sig = RingSignature { e, z };
        assert!(!sig.verify(&ring, b"m"), "outsider must not be able to sign");
    }

    // --- linkable ring signatures (key images) ---

    #[test]
    fn lsag_honest_signer_verifies() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(5, &mut rng);
        let sig = LinkableRingSignature::sign(&ring, &sks[3], 3, b"spend", &mut rng);
        assert!(sig.verify(&ring, b"spend"));
    }

    #[test]
    fn lsag_key_image_is_stable_and_links_double_spends() {
        // The SAME key produces the SAME key image every time — even in a different
        // ring and over a different message — so a double-spend is detectable, while
        // two DIFFERENT keys produce different images.
        let mut rng = OsRng;
        let (sks, ring1) = ring_of(4, &mut rng);
        let (_o, ring2) = ring_of(6, &mut rng);
        let mut ring2 = ring2;
        ring2[2] = sks[0].public_key(); // put signer 0 into a second, different ring

        let a = LinkableRingSignature::sign(&ring1, &sks[0], 0, b"tx-a", &mut rng);
        let b = LinkableRingSignature::sign(&ring2, &sks[0], 2, b"tx-b", &mut rng);
        assert_eq!(a.key_image(), b.key_image(), "same key → same image (linkable)");

        let other = LinkableRingSignature::sign(&ring1, &sks[1], 1, b"tx-a", &mut rng);
        assert_ne!(a.key_image(), other.key_image(), "different keys → different images");
    }

    #[test]
    fn lsag_hides_which_member_signed() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(6, &mut rng);
        let s1 = LinkableRingSignature::sign(&ring, &sks[1], 1, b"m", &mut rng);
        let s5 = LinkableRingSignature::sign(&ring, &sks[5], 5, b"m", &mut rng);
        assert!(s1.verify(&ring, b"m") && s5.verify(&ring, b"m"));
        assert_eq!(s1.s.len(), s5.s.len());
    }

    #[test]
    fn lsag_tampering_and_wrong_message_fail() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let sig = LinkableRingSignature::sign(&ring, &sks[2], 2, b"m", &mut rng);
        assert!(!sig.verify(&ring, b"other message"));
        let mut t = sig.clone();
        t.s[0] += Scalar::ONE;
        assert!(!t.verify(&ring, b"m"));
        let mut forged_image = sig.clone();
        forged_image.image += G;
        assert!(!forged_image.verify(&ring, b"m"), "a swapped key image must not verify");
    }
}

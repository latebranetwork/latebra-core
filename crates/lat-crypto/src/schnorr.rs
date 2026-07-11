//! Schnorr signatures over ristretto255 (clean-room, from `SPEC.md`).
//!
//! Used to authenticate the *transparent* transaction types (`CreateToken`,
//! `Rollover`, `DeployContract`, `CallContract`) — the confidential transfer
//! carries its own integrated Σ-proof of ownership instead.
//!
//! The signing nonce is derived deterministically from the secret key and the
//! message (EdDSA-style), so signing needs no RNG and can never leak the key
//! through nonce reuse.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use crate::{PublicKey, SecretKey};

/// A Schnorr signature `(R, s)` with `s = k + e·x`, `e = H(R ‖ Y ‖ msg)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature {
    r: CompressedRistretto,
    s: Scalar,
}

fn wide_hash(h: Sha512) -> Scalar {
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn challenge(r: &CompressedRistretto, pk: &PublicKey, msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.Schnorr.v1");
    h.update(r.as_bytes());
    h.update(pk.0.compress().as_bytes());
    h.update(msg);
    wide_hash(h)
}

impl Signature {
    /// Fixed 64-byte wire encoding: `R` (compressed point) then `s` (scalar).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.r.as_bytes());
        out[32..].copy_from_slice(self.s.as_bytes());
        out
    }

    /// Decode from 64 bytes. `None` on wrong length or a non-canonical scalar
    /// (point validity is checked at verification time, where it decompresses).
    pub fn from_bytes(b: &[u8]) -> Option<Signature> {
        if b.len() != 64 {
            return None;
        }
        let r = CompressedRistretto::from_slice(&b[..32]).ok()?;
        let s_arr: [u8; 32] = b[32..].try_into().ok()?;
        let s = Option::from(Scalar::from_canonical_bytes(s_arr))?;
        Some(Signature { r, s })
    }
}

impl SecretKey {
    /// Sign `msg` with this key (deterministic nonce, no RNG needed).
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let mut h = Sha512::new();
        h.update(b"Latebra.Schnorr.nonce.v1");
        h.update(self.0.as_bytes());
        h.update(msg);
        let k = wide_hash(h);

        let r = (G * k).compress();
        let e = challenge(&r, &self.public_key(), msg);
        Signature { r, s: k + e * self.0 }
    }
}

impl PublicKey {
    /// Verify a signature on `msg`: `s·G == R + e·Y`.
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        let Some(r) = sig.r.decompress() else {
            return false;
        };
        let e = challenge(&sig.r, self, msg);
        G * sig.s == r + self.0 * e
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SecretKey::random(&mut OsRng);
        let sig = sk.sign(b"hello latebra");
        assert!(sk.public_key().verify(b"hello latebra", &sig));
    }

    #[test]
    fn wrong_message_or_key_fails() {
        let sk = SecretKey::random(&mut OsRng);
        let other = SecretKey::random(&mut OsRng);
        let sig = sk.sign(b"msg");
        assert!(!sk.public_key().verify(b"other msg", &sig));
        assert!(!other.public_key().verify(b"msg", &sig));
    }

    #[test]
    fn wire_roundtrip_and_tamper() {
        let sk = SecretKey::random(&mut OsRng);
        let sig = sk.sign(b"payload");
        let bytes = sig.to_bytes();
        let decoded = Signature::from_bytes(&bytes).expect("decodes");
        assert!(sk.public_key().verify(b"payload", &decoded));

        let mut bad = bytes;
        bad[40] ^= 1; // corrupt s
        // A non-canonical scalar failing to decode at all is also a fine rejection.
        if let Some(s) = Signature::from_bytes(&bad) {
            assert!(!sk.public_key().verify(b"payload", &s));
        }
        assert!(Signature::from_bytes(&bytes[..63]).is_none(), "wrong length");
    }

    #[test]
    fn deterministic_signatures() {
        let sk = SecretKey::from_seed(&[1u8; 32]);
        assert_eq!(sk.sign(b"m").to_bytes(), sk.sign(b"m").to_bytes());
    }
}

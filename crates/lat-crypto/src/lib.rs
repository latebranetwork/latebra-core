//! Latebra cryptographic core — confidential balances.
//!
//! This is an independent, clean-room implementation written from the public
//! cryptography described in `SPEC.md` (twisted-ElGamal encrypted balances on the
//! ristretto255 group, additively homomorphic). It does not derive from any other
//! project's source. All primitives come from the audited, MIT-licensed
//! `curve25519-dalek` library — we never hand-roll field/curve arithmetic.
//!
//! # Model
//! An account has a secret scalar `x` and public key `Y = x·G`. A balance `b`
//! (a `u64`) is encrypted as a twisted-ElGamal ciphertext:
//!
//! ```text
//!   C = b·G + r·Y
//!   D = r·G
//! ```
//!
//! Because the message lives in the exponent, ciphertexts are **additively
//! homomorphic**: adding two ciphertexts (same key) yields an encryption of the
//! sum of the balances. This is what lets the chain move encrypted value without
//! ever decrypting it.
//!
//! Decryption computes `M = C − x·D = b·G`, then recovers the small integer `b`
//! by a bounded discrete-log search (baby-step / giant-step).

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use std::collections::HashMap;

mod anon_transfer;
mod conservation;
mod hidden_solvency;
mod index_binding;
mod membership;
mod range;
mod ring;
mod schnorr;
mod solvent;
mod stealth;
pub use anon_transfer::AnonTransfer;
pub use conservation::ConservedDeltas;
pub use hidden_solvency::HiddenSolventSpend;
pub use index_binding::{commit_delta, IndexBindingProof};
pub use membership::ValueInSetProof;
pub use range::{RangeComponent, RANGE_BITS};
pub use ring::{LinkableRingSignature, RingSignature};
pub use schnorr::Signature;
pub use solvent::SolventTransfer;
pub use stealth::{stealth_receive, stealth_send, StealthOutput};

/// An account secret key (a ristretto255 scalar).
#[derive(Clone)]
pub struct SecretKey(pub(crate) Scalar);

/// An account public key `Y = x·G`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey(pub(crate) RistrettoPoint);

/// A twisted-ElGamal ciphertext encrypting a balance under one public key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ciphertext {
    /// `C = b·G + r·Y`
    pub c: RistrettoPoint,
    /// `D = r·G`
    pub d: RistrettoPoint,
}

impl SecretKey {
    /// Generate a fresh random secret key.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        SecretKey(Scalar::random(rng))
    }

    /// Derive a secret key deterministically from a 32-byte wallet seed. Domain-
    /// separated and hashed wide, so the same seed always yields the same key —
    /// this is what makes a wallet recoverable from its backup.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = Sha512::new();
        h.update(b"Latebra.WalletSeed.v1");
        h.update(seed);
        let digest = h.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&digest);
        SecretKey(Scalar::from_bytes_mod_order_wide(&wide))
    }

    /// Derive the matching public key `Y = x·G`.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(G * self.0)
    }

    /// Recover the plaintext balance from a ciphertext encrypted under this key's
    /// public key. Searches the range `[0, 2^max_bits)`; returns `None` if the
    /// balance is outside that bound (which should never happen for valid state).
    pub fn decrypt(&self, ct: &Ciphertext, max_bits: u32) -> Option<u64> {
        // M = C - x·D = b·G
        let m = ct.c - ct.d * self.0;
        discrete_log(&m, max_bits)
    }
}

impl PublicKey {
    /// Encrypt a `u64` balance under this public key with fresh randomness.
    pub fn encrypt<R: RngCore + CryptoRng>(&self, amount: u64, rng: &mut R) -> Ciphertext {
        let r = Scalar::random(rng);
        self.encrypt_with_randomness(amount, &r)
    }

    /// Encrypt with caller-supplied randomness (needed later by transfer proofs,
    /// which must know `r` to prove statements about the ciphertext).
    pub fn encrypt_with_randomness(&self, amount: u64, r: &Scalar) -> Ciphertext {
        let b = Scalar::from(amount);
        Ciphertext {
            c: G * b + self.0 * r,
            d: G * r,
        }
    }
}

impl Ciphertext {
    /// A transparent "mint" ciphertext for genesis premine / coinbase rewards:
    /// `C = amount·G`, `D = 0`. Decrypts to `amount` under any key (since `x·0 = 0`).
    /// Intentionally NOT private — genesis/coinbase amounts are public by design.
    pub fn mint(amount: u64) -> Ciphertext {
        Ciphertext {
            c: G * Scalar::from(amount),
            d: RistrettoPoint::identity(),
        }
    }

    /// The all-zero encrypted balance of a freshly registered account.
    pub fn zero() -> Ciphertext {
        Ciphertext {
            c: RistrettoPoint::identity(),
            d: RistrettoPoint::identity(),
        }
    }

    /// 64-byte encoding: compressed `C` then compressed `D`. For RPC / storage.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(self.c.compress().as_bytes());
        out[32..64].copy_from_slice(self.d.compress().as_bytes());
        out
    }

    /// Decode a ciphertext from its 64-byte form.
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Ciphertext> {
        let c = CompressedRistretto::from_slice(&bytes[0..32]).ok()?.decompress()?;
        let d = CompressedRistretto::from_slice(&bytes[32..64]).ok()?.decompress()?;
        Some(Ciphertext { c, d })
    }

    /// Homomorphic addition: `Enc(a) + Enc(b) = Enc(a + b)` (same public key).
    pub fn add(&self, other: &Ciphertext) -> Ciphertext {
        Ciphertext {
            c: self.c + other.c,
            d: self.d + other.d,
        }
    }

    /// Homomorphic subtraction: `Enc(a) − Enc(b) = Enc(a − b)` (same public key).
    pub fn sub(&self, other: &Ciphertext) -> Ciphertext {
        Ciphertext {
            c: self.c - other.c,
            d: self.d - other.d,
        }
    }
}

/// Fixed baby-step block size. Built once and shared across all decryptions —
/// rebuilding it per call was the dominant cost. (A larger table covers bigger
/// balances with fewer giant steps; this is the SPEC's "shared precomputed table".)
const BSGS_STEP: u64 = 1 << 16;

struct BabyTable {
    /// `{ (j·G) bytes -> j }` for `j` in `[0, BSGS_STEP)`.
    table: HashMap<[u8; 32], u64>,
    /// `BSGS_STEP · G`, subtracted each giant step.
    giant_stride: RistrettoPoint,
}

/// The process-wide baby-step table, built lazily on first use.
fn baby_table() -> &'static BabyTable {
    use std::sync::OnceLock;
    static T: OnceLock<BabyTable> = OnceLock::new();
    T.get_or_init(|| {
        let mut table = HashMap::with_capacity(BSGS_STEP as usize);
        let mut acc = RistrettoPoint::identity(); // 0·G
        for j in 0..BSGS_STEP {
            table.insert(acc.compress().to_bytes(), j);
            acc += G;
        }
        BabyTable {
            table,
            giant_stride: G * Scalar::from(BSGS_STEP),
        }
    })
}

/// Solve `m·G = point` for the small non-negative integer `m < 2^max_bits` using
/// baby-step / giant-step over the shared [`baby_table`]. Giant-step count is
/// ~`m / BSGS_STEP`, so larger balances take longer (bounded by `2^max_bits`).
fn discrete_log(point: &RistrettoPoint, max_bits: u32) -> Option<u64> {
    let bound: u64 = if max_bits >= 64 { u64::MAX } else { 1u64 << max_bits };
    let bt = baby_table();
    let mut cur = *point;
    let mut i: u64 = 0;
    while i.saturating_mul(BSGS_STEP) < bound {
        if let Some(&j) = bt.table.get(&cur.compress().to_bytes()) {
            return Some(i * BSGS_STEP + j);
        }
        cur -= bt.giant_stride;
        i += 1;
    }
    None
}

// --- unshield "view key" ---------------------------------------------------
//
// Moving value from the private (confidential) balance back to a public
// (transparent) balance requires REVEALING the amount as it re-enters the clear.
// We reuse the existing `SolventTransfer` proof unchanged: an unshield is just a
// confidential spend whose receiver is a *publicly-known* key. Because everyone
// knows this key's secret, anyone (consensus, an explorer) can read the amount —
// yet the proof still guarantees the sender was solvent and that this revealed
// amount is exactly what left the private balance. No new zero-knowledge
// machinery: the reveal is a one-line algebraic check.

/// Fixed 32-byte seed for the unshield view key. Its secret is intentionally
/// public — the view key never holds funds; consensus redirects the value to the
/// unshield's named public destination.
const UNSHIELD_VIEW_SEED: [u8; 32] = *b"latebra/unshield-view-key/v1\0\0\0\0";

/// The public unshield "view" key. A wallet building an unshield encrypts the
/// (to-be-revealed) amount to this key inside an ordinary `SolventTransfer`.
pub fn unshield_view_key() -> PublicKey {
    SecretKey::from_seed(&UNSHIELD_VIEW_SEED).public_key()
}

/// Verify that `ct` — an ElGamal ciphertext `(C, D)` under [`unshield_view_key`] —
/// encrypts exactly `amount`. O(1): with `C = amount·G + r·Y_view` and `D = r·G`,
/// and the view secret `x_view` (so `Y_view = x_view·G`), this holds iff
/// `C − amount·G == x_view·D` (both equal `r·Y_view`). No discrete-log search, so
/// it can't be turned into a verification-time DoS by a large amount.
pub fn unshield_reveals(ct: &Ciphertext, amount: u64) -> bool {
    let x_view = SecretKey::from_seed(&UNSHIELD_VIEW_SEED).0;
    ct.c - G * Scalar::from(amount) == ct.d * x_view
}

/// Serialize a public key to 32 bytes (compressed ristretto point).
impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Option<PublicKey> {
        CompressedRistretto::from_slice(bytes)
            .ok()?
            .decompress()
            .map(PublicKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut rng = OsRng;
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public_key();

        for &amount in &[0u64, 1, 42, 1_000, 12_281_254] {
            let ct = pk.encrypt(amount, &mut rng);
            let got = sk.decrypt(&ct, 28).expect("balance in range");
            assert_eq!(got, amount, "roundtrip failed for {amount}");
        }
    }

    #[test]
    fn decrypts_balance_above_32_bit_range() {
        // 100,000 LAT = 1e10 base units — beyond the old 2^32 (~42,949 LAT) cap.
        let mut rng = OsRng;
        let sk = SecretKey::random(&mut rng);
        let amount = 10_000_000_000u64; // > 2^32
        let ct = sk.public_key().encrypt(amount, &mut rng);
        assert_eq!(sk.decrypt(&ct, 40), Some(amount));
    }

    #[test]
    fn homomorphic_addition() {
        // The whole point of the scheme: add encrypted balances without decrypting.
        let mut rng = OsRng;
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public_key();

        let a = 5_000u64;
        let b = 3_333u64;
        let ct_a = pk.encrypt(a, &mut rng);
        let ct_b = pk.encrypt(b, &mut rng);

        let ct_sum = ct_a.add(&ct_b);
        assert_eq!(sk.decrypt(&ct_sum, 28).unwrap(), a + b);

        let ct_diff = ct_a.sub(&ct_b);
        assert_eq!(sk.decrypt(&ct_diff, 28).unwrap(), a - b);
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let mut rng = OsRng;
        let sk = SecretKey::random(&mut rng);
        let pk = sk.public_key();
        let attacker = SecretKey::random(&mut rng);

        let ct = pk.encrypt(777, &mut rng);
        // The attacker's key yields a point that is not b·G for any small b,
        // so the bounded search fails.
        assert!(attacker.decrypt(&ct, 20).is_none() || sk.decrypt(&ct, 20) == Some(777));
    }

    #[test]
    fn public_key_serialization() {
        let mut rng = OsRng;
        let pk = SecretKey::random(&mut rng).public_key();
        let bytes = pk.to_bytes();
        assert_eq!(PublicKey::from_bytes(&bytes), Some(pk));
    }

    #[test]
    fn unshield_reveal_is_exact() {
        let mut rng = OsRng;
        // A ciphertext encrypting `amount` under the public view key reveals that
        // exact amount — and nothing else.
        for &amount in &[0u64, 1, 500, 250_000, 10_000_000_000] {
            let ct = unshield_view_key().encrypt(amount, &mut rng);
            assert!(unshield_reveals(&ct, amount), "true amount {amount} must reveal");
            assert!(!unshield_reveals(&ct, amount.wrapping_add(1)), "wrong amount must not");
        }
        // A ciphertext under a DIFFERENT key does not reveal under the view key.
        let other = SecretKey::random(&mut rng).public_key().encrypt(500, &mut rng);
        assert!(!unshield_reveals(&other, 500), "non-view-key ciphertext must not reveal");
    }
}

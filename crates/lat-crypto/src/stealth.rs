//! Stealth one-time addresses (clean-room, from `SPEC.md` / `PRIVACY_ARCHITECTURE.md`).
//!
//! This is the **receiver-unlinkability** primitive: a payment names a fresh
//! *one-time* account `P` that only the intended recipient can recognize as
//! theirs and derive the spend key for. An on-chain observer sees `P` and an
//! ephemeral point `R`, but cannot link `P` to the recipient's long-term
//! address — so "who received the shielded output" stays hidden.
//!
//! It is the standard CryptoNote construction, on ristretto255, using only ECDH
//! and hashing — no zero-knowledge machinery. In Latebra's account model the
//! recipient's ordinary account key doubles as their stealth address, so no new
//! address format is needed.
//!
//! ```text
//!   sender picks r,           R = r·G
//!   shared  s = H( r·A )     ( = H( a·R ) for the recipient, since r·A = a·R )
//!   one-time P = s·G + A
//!   spend key p = s + a       ( p·G = s·G + a·G = s·G + A = P )
//! ```
//!
//! **Scope (honest):** this hides the *recipient*. Hiding the *sender/origin* of
//! a value-carrying spend is a different, harder problem (a one-of-many solvency
//! proof / Anonymous-Zether), tracked separately and audit-bound.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{PublicKey, SecretKey};

/// Hash the ECDH shared point to a scalar (domain-separated, hashed wide).
fn shared_scalar(shared: &curve25519_dalek::ristretto::RistrettoPoint) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.Stealth.v1");
    h.update(shared.compress().as_bytes());
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// A one-time stealth output paying some recipient: the public `ephemeral` point
/// `R` and the derived one-time account key `one_time` (`P`). Both go on-chain;
/// neither reveals the recipient without their secret.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StealthOutput {
    /// `R = r·G` — the sender's ephemeral public key.
    pub ephemeral: PublicKey,
    /// `P = H(r·A)·G + A` — the one-time account the payment credits.
    pub one_time: PublicKey,
}

/// Sender side: derive a fresh one-time output paying `recipient` (their normal
/// account public key). Each call uses new randomness, so two payments to the
/// same recipient are unlinkable on-chain.
pub fn stealth_send<R: RngCore + CryptoRng>(recipient: &PublicKey, rng: &mut R) -> StealthOutput {
    let r = Scalar::random(rng);
    let shared = recipient.0 * r; // r·A
    let s = shared_scalar(&shared);
    StealthOutput {
        ephemeral: PublicKey(G * r),
        one_time: PublicKey(G * s + recipient.0), // s·G + A
    }
}

/// Recipient side: test whether `(ephemeral, one_time)` pays this key. Returns
/// the one-time **spend key** `p` if so (with `p·G == one_time`), else `None`.
/// A wallet runs this over every stealth output to find the ones it owns.
pub fn stealth_receive(
    secret: &SecretKey,
    ephemeral: &PublicKey,
    one_time: &PublicKey,
) -> Option<SecretKey> {
    let shared = ephemeral.0 * secret.0; // a·R  (== r·A)
    let s = shared_scalar(&shared);
    let expected = G * s + secret.public_key().0; // s·G + A
    if expected == one_time.0 {
        Some(SecretKey(s + secret.0)) // p = s + a
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn recipient_recognizes_and_can_spend_its_output() {
        let mut rng = OsRng;
        let recipient = SecretKey::random(&mut rng);
        let out = stealth_send(&recipient.public_key(), &mut rng);

        // The recipient recognizes the output and derives its one-time spend key.
        let p = stealth_receive(&recipient, &out.ephemeral, &out.one_time)
            .expect("recipient must recognize its own output");
        // The derived key really controls the one-time account: p·G == P.
        assert_eq!(p.public_key(), out.one_time, "one-time key must open the account");
    }

    #[test]
    fn stranger_cannot_recognize_the_output() {
        let mut rng = OsRng;
        let recipient = SecretKey::random(&mut rng);
        let stranger = SecretKey::random(&mut rng);
        let out = stealth_send(&recipient.public_key(), &mut rng);

        assert!(
            stealth_receive(&stranger, &out.ephemeral, &out.one_time).is_none(),
            "a non-recipient must not detect the output"
        );
    }

    #[test]
    fn two_payments_to_same_recipient_are_distinct() {
        let mut rng = OsRng;
        let recipient = SecretKey::random(&mut rng);
        let a = stealth_send(&recipient.public_key(), &mut rng);
        let b = stealth_send(&recipient.public_key(), &mut rng);
        // Unlinkable on-chain: different one-time accounts and ephemerals...
        assert_ne!(a.one_time, b.one_time);
        assert_ne!(a.ephemeral, b.ephemeral);
        // ...yet the recipient can claim both.
        assert!(stealth_receive(&recipient, &a.ephemeral, &a.one_time).is_some());
        assert!(stealth_receive(&recipient, &b.ephemeral, &b.one_time).is_some());
    }
}

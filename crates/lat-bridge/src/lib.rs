//! # lat-bridge — trustless cross-chain atomic swaps for Latebra
//!
//! Latebra already has a native hash time-locked contract (HTLC): see
//! [`lat_types::Transaction::HtlcLock`]. It escrows LAT (or a Latebra token)
//! under the SHA-256 hashlock of a secret, releasing it to whoever reveals the
//! preimage before an expiry height. That is *one leg* of a cross-chain swap.
//!
//! This crate builds the **other leg** on Bitcoin, any EVM chain, and Solana,
//! and the [`coordinator`] that drives both legs to completion (or refund). The
//! same secret unlocks every chain, because they all commit to `SHA-256(secret)`
//! — so no custodian, no wrapped token, and no trusted relayer ever holds funds.
//!
//! ## The swap (BTC → Latebra, as an example)
//!
//! Alice has BTC and wants LAT; Bob (a liquidity provider) has LAT and wants BTC.
//!
//! 1. Alice picks a random secret `S` and publishes `H = SHA-256(S)`.
//! 2. Alice locks her BTC to a P2WSH HTLC ([`btc`]) that pays Bob on reveal of
//!    `S`, refundable to Alice after height `T₁`.
//! 3. Bob sees Alice's funded lock and locks LAT on Latebra's HTLC to Alice,
//!    with a **shorter** expiry `T₂ < T₁`.
//! 4. Alice claims the LAT by revealing `S` on Latebra ([`lat_types::Transaction::HtlcClaim`]).
//! 5. Bob reads `S` from the Latebra chain and claims the BTC with it.
//!
//! Either both legs settle or, past the timeouts, both refund. Because Bob's
//! timelock is shorter, Bob can never be left having paid without a claim path.
//!
//! ## What this crate does and does not do
//!
//! It produces the **real, verifiable on-chain artifacts** — the exact witness
//! script and deposit address on Bitcoin, the exact ABI calldata on EVM, the
//! exact instruction data and program-derived escrow on Solana — plus the
//! coordination state machine ([`coordinator`]). Broadcasting those to a live
//! Bitcoin / Ethereum / Solana network is a signing+RPC step that needs that
//! chain's node and the spender's own keys; this crate stops at correct payloads.

use sha2::{Digest, Sha256};

pub mod adapter;
pub mod btc;
pub mod coordinator;
pub mod encoding;
pub mod evm;
pub mod sol;
pub mod watcher;

pub use adapter::{Action, BridgeTx, ChainAdapter, HtlcArtifact, HtlcParams};
pub use btc::BtcAdapter;
pub use coordinator::{Swap, SwapCoordinator, SwapState};
pub use evm::EvmAdapter;
pub use sol::SolAdapter;
pub use watcher::{LatLegState, LatObserver, PreimageWatch, WatchResult};

/// A 32-byte hash (a hashlock, a swap id, a secret's image).
pub type Hash = [u8; 32];

/// The chains this crate can build an HTLC leg on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Bitcoin,
    Ethereum,
    Solana,
    /// Latebra itself — handled natively (account-based HTLC), not via a
    /// [`ChainAdapter`]; present so a [`coordinator::Swap`] can name both legs.
    Latebra,
}

impl Chain {
    pub fn ticker(self) -> &'static str {
        match self {
            Chain::Bitcoin => "BTC",
            Chain::Ethereum => "ETH",
            Chain::Solana => "SOL",
            Chain::Latebra => "LAT",
        }
    }
}

/// Mainnet vs. testnet — changes address human-readable prefixes and, for the
/// caller, which node the artifact is broadcast to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

/// The secret that unlocks every leg of a swap. Its SHA-256 image is the
/// hashlock all chains commit to.
#[derive(Clone)]
pub struct Secret([u8; 32]);

impl Secret {
    /// A fresh, cryptographically random secret. The initiator of a swap holds
    /// this and reveals it only once the counterparty's lock is confirmed.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        Secret(b)
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Secret(b)
    }

    /// `SHA-256(secret)` — the hashlock every chain in the swap commits to.
    pub fn hashlock(&self) -> Hash {
        sha256(&self.0)
    }

    /// The raw preimage, to be revealed on-chain to claim.
    pub fn reveal(&self) -> [u8; 32] {
        self.0
    }
}

/// SHA-256, the hash all HTLC legs share (Bitcoin's `OP_SHA256`, an EVM
/// `sha256(preimage)`, and Latebra's own HTLC all agree on this).
pub fn sha256(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Everything that can go wrong building or coordinating a swap leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// A parameter was the wrong length or shape for the target chain
    /// (e.g. a Bitcoin pubkey that is not 33 compressed bytes).
    BadParam(String),
    /// The swap state machine was asked to do something out of order.
    BadState(String),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::BadParam(s) => write!(f, "bad parameter: {s}"),
            BridgeError::BadState(s) => write!(f, "bad swap state: {s}"),
        }
    }
}

impl std::error::Error for BridgeError {}

pub type Result<T> = std::result::Result<T, BridgeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashlock_is_sha256_of_secret() {
        let s = Secret::from_bytes([7u8; 32]);
        assert_eq!(s.hashlock(), sha256(&[7u8; 32]));
    }

    #[test]
    fn random_secrets_differ() {
        assert_ne!(Secret::random().reveal(), Secret::random().reveal());
    }
}

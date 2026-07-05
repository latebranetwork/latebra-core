//! Standard on-chain contracts for Latebra, compiled to `lat-vm` bytecode.
//!
//! Right now this is the **bonding curve** that powers the latfun launchpad's
//! pricing. Previously latfun ran the curve as off-chain `f64` accounting in a
//! JSON file — anyone running the server could edit it. Here the curve's *state*
//! (virtual reserves, collected LAT, per-buyer holdings, graduation) lives in a
//! deployed contract's storage, so every buy/sell is recomputed and validated by
//! consensus with deterministic integer math. No node can fake a price.
//!
//! ## Honest boundary (v1 VM)
//! The `lat-vm` cannot move LAT itself — it only reads/writes `u64` storage. So
//! this contract is the *pricing and accounting* half: it decides how many tokens
//! a buy yields (and how much LAT a sell returns) and tracks holdings. The actual
//! LAT settlement is a separate transparent transfer to the curve's treasury
//! account (latfun orchestrates both). Binding the two atomically needs a
//! VM-native token-transfer opcode — a future VM upgrade, documented as such.

pub mod bonding_curve;

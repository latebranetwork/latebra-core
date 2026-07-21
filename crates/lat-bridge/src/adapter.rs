//! The chain-agnostic HTLC interface. Each supported chain implements
//! [`ChainAdapter`] to turn a set of [`HtlcParams`] into the concrete artifacts
//! a user broadcasts: the deposit address/script to *lock* funds, and the
//! encoded *claim* (reveal-preimage) and *refund* (after-timeout) actions.

use crate::{Chain, Hash, Network, Result};

/// The identifying parameters of one HTLC leg, in chain-native units.
///
/// `recipient` and `refund` are the target chain's native public keys or
/// addresses (a 33-byte compressed pubkey on Bitcoin, a 20-byte address on EVM,
/// a 32-byte pubkey on Solana). `amount` is the smallest unit of that chain
/// (satoshi, wei, lamport). `timelock` is absolute — a block height on Bitcoin,
/// a Unix timestamp on EVM/Solana.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcParams {
    /// `SHA-256(secret)` — shared by every leg of the swap.
    pub hashlock: Hash,
    /// Who can claim by revealing the preimage.
    pub recipient: Vec<u8>,
    /// Who gets the funds back after `timelock` (the original funder).
    pub refund: Vec<u8>,
    /// Amount in the chain's smallest unit.
    pub amount: u128,
    /// Absolute timeout: block height (BTC) or Unix seconds (EVM/SOL).
    pub timelock: u64,
}

/// The deposit artifact: where and how a funder locks the asset to open this
/// HTLC. Every field here is derived deterministically from [`HtlcParams`], so
/// both parties compute the identical address and can verify it independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtlcArtifact {
    pub chain: Chain,
    /// The address the funder sends the asset to (a P2WSH bech32 address, an
    /// EVM contract address, or a Solana program-derived escrow account).
    pub deposit_address: String,
    /// The redeem script (BTC), lock calldata (EVM), or initialize instruction
    /// data (SOL), hex-encoded — the bytes that make the deposit an HTLC.
    pub script_hex: String,
    /// Human-readable instructions for completing the deposit.
    pub instructions: String,
}

/// Which spend path a [`BridgeTx`] takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Claim by revealing the preimage (the happy path).
    Claim,
    /// Refund to the funder after the timelock elapses.
    Refund,
}

/// An encoded spend of an open HTLC — the calldata / witness / instruction the
/// spender's own wallet signs and broadcasts. Signing needs that chain's keys
/// and the funding UTXO/account, which live in the user's wallet, not here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeTx {
    pub chain: Chain,
    pub action: Action,
    /// The action's payload, hex-encoded (EVM calldata, BTC witness script +
    /// stack layout, or SOL instruction data).
    pub payload_hex: String,
    /// Human-readable description of how the spender uses this payload.
    pub describe: String,
}

/// A chain that can host one leg of a Latebra atomic swap.
pub trait ChainAdapter {
    fn chain(&self) -> Chain;
    fn network(&self) -> Network;

    /// The deposit address + script a counterparty funds to open the HTLC.
    fn lock_artifact(&self, p: &HtlcParams) -> Result<HtlcArtifact>;

    /// The encoded claim (reveal `preimage`) spend of an open HTLC.
    fn claim(&self, p: &HtlcParams, preimage: &[u8; 32]) -> Result<BridgeTx>;

    /// The encoded refund spend, valid once `p.timelock` has elapsed.
    fn refund(&self, p: &HtlcParams) -> Result<BridgeTx>;
}

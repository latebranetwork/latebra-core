//! The swap coordinator: the state machine a watcher runs to drive both legs of
//! a cross-chain atomic swap to completion, and the security invariants that
//! keep it trustless.
//!
//! A swap has two legs. The **initiator** holds the secret, *sells* the asset on
//! one chain and *buys* on the other. The critical rule that makes the swap safe
//! is the timelock ordering: the initiator's own lock (the sell leg) must expire
//! *later* than the counterparty's lock (the buy leg). The initiator redeems the
//! buy leg first — revealing the secret — which leaves the counterparty enough
//! time to redeem the sell leg before it can be refunded. [`SwapCoordinator`]
//! refuses to propose a swap that violates this ordering.

use crate::adapter::HtlcParams;
use crate::{sha256, BridgeError, Chain, Hash, Result};

/// One leg of a swap: the chain it settles on and its HTLC parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    pub chain: Chain,
    pub params: HtlcParams,
}

/// The lifecycle of a swap, from the initiator's point of view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapState {
    /// Proposed; no funds locked yet.
    Proposed,
    /// The initiator has funded the sell leg.
    SellLocked,
    /// Both legs are funded; safe for the initiator to redeem.
    BothLocked,
    /// The initiator redeemed the buy leg, revealing the secret on-chain.
    Redeemed,
    /// The counterparty redeemed the sell leg with the revealed secret. Done.
    Settled,
    /// Timed out; the legs were refunded to their funders.
    Refunded,
}

/// A cross-chain atomic swap and its live state.
#[derive(Clone, Debug)]
pub struct Swap {
    pub id: Hash,
    pub hashlock: Hash,
    /// What the initiator gives (funded first, longer timelock).
    pub sell: Leg,
    /// What the initiator receives (funded by the counterparty, shorter timelock).
    pub buy: Leg,
    pub state: SwapState,
    /// The preimage, once revealed on-chain by the buy-leg redemption.
    pub revealed: Option<[u8; 32]>,
}

/// Builds and advances [`Swap`]s, enforcing the timelock-ordering invariant.
pub struct SwapCoordinator;

impl SwapCoordinator {
    /// Propose a swap. Fails unless the sell leg's timelock is strictly greater
    /// than the buy leg's — the ordering that guarantees the counterparty can
    /// always claim after the secret is revealed.
    pub fn propose(id: Hash, hashlock: Hash, sell: Leg, buy: Leg) -> Result<Swap> {
        if sell.params.hashlock != hashlock || buy.params.hashlock != hashlock {
            return Err(BridgeError::BadParam(
                "both legs must commit to the swap's hashlock".into(),
            ));
        }
        if sell.params.timelock <= buy.params.timelock {
            return Err(BridgeError::BadState(
                "sell-leg timelock must be strictly later than buy-leg timelock".into(),
            ));
        }
        Ok(Swap {
            id,
            hashlock,
            sell,
            buy,
            state: SwapState::Proposed,
            revealed: None,
        })
    }

    /// Record that the initiator funded the sell leg.
    pub fn sell_funded(swap: &mut Swap) -> Result<()> {
        expect(swap, SwapState::Proposed)?;
        swap.state = SwapState::SellLocked;
        Ok(())
    }

    /// Record that the counterparty funded the buy leg.
    pub fn buy_funded(swap: &mut Swap) -> Result<()> {
        expect(swap, SwapState::SellLocked)?;
        swap.state = SwapState::BothLocked;
        Ok(())
    }

    /// The initiator redeems the buy leg by revealing `preimage`. Verifies the
    /// preimage against the hashlock and stores it (now public on that chain).
    pub fn redeem_buy(swap: &mut Swap, preimage: [u8; 32]) -> Result<()> {
        expect(swap, SwapState::BothLocked)?;
        if sha256(&preimage) != swap.hashlock {
            return Err(BridgeError::BadParam("preimage does not match hashlock".into()));
        }
        swap.revealed = Some(preimage);
        swap.state = SwapState::Redeemed;
        Ok(())
    }

    /// The counterparty redeems the sell leg with the now-revealed preimage.
    pub fn redeem_sell(swap: &mut Swap) -> Result<[u8; 32]> {
        expect(swap, SwapState::Redeemed)?;
        let pre = swap
            .revealed
            .ok_or_else(|| BridgeError::BadState("secret not yet revealed".into()))?;
        swap.state = SwapState::Settled;
        Ok(pre)
    }

    /// Abandon a swap that never completed: valid only once both legs are past
    /// their timelocks (`now` in the legs' own units) and nothing was redeemed.
    pub fn refund(swap: &mut Swap, now: u64) -> Result<()> {
        match swap.state {
            SwapState::Proposed | SwapState::SellLocked | SwapState::BothLocked => {}
            _ => {
                return Err(BridgeError::BadState(
                    "can only refund a swap with no redemption".into(),
                ))
            }
        }
        // The sell leg has the later timelock; if it is refundable, so is the buy.
        if now < swap.sell.params.timelock {
            return Err(BridgeError::BadState("sell-leg timelock not yet reached".into()));
        }
        swap.state = SwapState::Refunded;
        Ok(())
    }
}

fn expect(swap: &Swap, want: SwapState) -> Result<()> {
    if swap.state != want {
        return Err(BridgeError::BadState(format!(
            "expected state {:?}, was {:?}",
            want, swap.state
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    fn legs(sell_tl: u64, buy_tl: u64) -> (Hash, Leg, Leg, Secret) {
        let secret = Secret::from_bytes([42u8; 32]);
        let h = secret.hashlock();
        let sell = Leg {
            chain: Chain::Bitcoin,
            params: HtlcParams {
                hashlock: h,
                recipient: vec![2u8; 33],
                refund: vec![3u8; 33],
                amount: 100_000,
                timelock: sell_tl,
            },
        };
        let buy = Leg {
            chain: Chain::Latebra,
            params: HtlcParams {
                hashlock: h,
                recipient: vec![1u8; 32],
                refund: vec![4u8; 32],
                amount: 250_000,
                timelock: buy_tl,
            },
        };
        (h, sell, buy, secret)
    }

    #[test]
    fn rejects_bad_timelock_ordering() {
        let (h, sell, buy, _) = legs(500, 500);
        assert!(SwapCoordinator::propose([0; 32], h, sell, buy).is_err());
    }

    #[test]
    fn happy_path_settles() {
        let (h, sell, buy, secret) = legs(1000, 500);
        let mut swap = SwapCoordinator::propose([1; 32], h, sell, buy).unwrap();
        SwapCoordinator::sell_funded(&mut swap).unwrap();
        SwapCoordinator::buy_funded(&mut swap).unwrap();
        // Initiator reveals the secret claiming the buy leg.
        SwapCoordinator::redeem_buy(&mut swap, secret.reveal()).unwrap();
        assert_eq!(swap.revealed, Some(secret.reveal()));
        // Counterparty uses the revealed secret to claim the sell leg.
        let learned = SwapCoordinator::redeem_sell(&mut swap).unwrap();
        assert_eq!(learned, secret.reveal());
        assert_eq!(swap.state, SwapState::Settled);
    }

    #[test]
    fn wrong_preimage_is_rejected() {
        let (h, sell, buy, _) = legs(1000, 500);
        let mut swap = SwapCoordinator::propose([2; 32], h, sell, buy).unwrap();
        SwapCoordinator::sell_funded(&mut swap).unwrap();
        SwapCoordinator::buy_funded(&mut swap).unwrap();
        assert!(SwapCoordinator::redeem_buy(&mut swap, [0u8; 32]).is_err());
        assert_eq!(swap.state, SwapState::BothLocked);
    }

    #[test]
    fn refund_only_after_sell_timelock() {
        let (h, sell, buy, _) = legs(1000, 500);
        let mut swap = SwapCoordinator::propose([3; 32], h, sell, buy).unwrap();
        SwapCoordinator::sell_funded(&mut swap).unwrap();
        // Too early — sell leg expires at 1000.
        assert!(SwapCoordinator::refund(&mut swap, 999).is_err());
        SwapCoordinator::refund(&mut swap, 1000).unwrap();
        assert_eq!(swap.state, SwapState::Refunded);
    }

    #[test]
    fn cannot_refund_after_reveal() {
        let (h, sell, buy, secret) = legs(1000, 500);
        let mut swap = SwapCoordinator::propose([4; 32], h, sell, buy).unwrap();
        SwapCoordinator::sell_funded(&mut swap).unwrap();
        SwapCoordinator::buy_funded(&mut swap).unwrap();
        SwapCoordinator::redeem_buy(&mut swap, secret.reveal()).unwrap();
        // Once the secret is public the swap must settle, never refund.
        assert!(SwapCoordinator::refund(&mut swap, 100_000).is_err());
    }
}

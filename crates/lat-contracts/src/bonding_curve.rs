//! Constant-product bonding curve, as a `lat-vm` contract.
//!
//! A classic `x·y = k` virtual AMM: the pool holds virtual LAT (`vlat`) and
//! virtual tokens (`vtok`). Buying adds (fee-adjusted) LAT and removes tokens;
//! selling does the reverse. `real_lat` tracks the actual LAT collected; once it
//! reaches [`GRADUATE_LAT`] the token "graduates" and the curve locks (further
//! trades revert — trading moves to a DEX). Everything is **integer** math (the
//! VM has no floats) with overflow-safe bounds.
//!
//! ## Call ABI
//! One `CallContract` per trade. The 64-bit `input` word encodes the trade:
//! bit 63 is the side (`1` = buy, `0` = sell), the low 63 bits are the amount in
//! base units (LAT in for a buy, tokens in for a sell). Build it with
//! [`encode_trade`]. The caller's holdings are keyed by the first 8 bytes of its
//! account id (see [`holdings_key`]).
//!
//! ## Storage layout (`u64 → u64`)
//! | slot | meaning |
//! |------|---------|
//! | 0 | `vlat` — virtual LAT reserve (base units) |
//! | 1 | `vtok` — virtual token reserve (base units) |
//! | 2 | `real_lat` — cumulative real LAT collected |
//! | 3 | `graduated` — 0/1 |
//! | 4 | `initialized` — 0/1 (set on first call) |
//! | 10–17 | scratch (per-call temporaries) |
//! | `id \| 2^63` | that account's token holdings |
//!
//! A failed trade (graduated, zero/oversize amount, oversell) makes the VM error,
//! and the ledger discards the call's storage changes — an atomic revert.

use lat_vm::assembler::{Asm, Instr::*};

// -- curve parameters (base units; 1 LAT = 100_000 base units, 5 decimals) -----

/// Virtual LAT reserve at genesis: 30 LAT.
pub const VLAT0: u64 = 30 * 100_000;
/// Virtual token reserve at genesis: 1,000,000,000 tokens (0 decimals).
pub const VTOK0: u64 = 1_000_000_000;
/// Real LAT collected at which the token graduates: 500 LAT.
pub const GRADUATE_LAT: u64 = 500 * 100_000;
/// Trading fee, as a divisor: `fee = amount / FEE_DIVISOR` (100 ⇒ 1%). Charged on
/// **both sides**, as pump.fun does — withheld from the input on a buy, from the
/// payout on a sell. Only the buy side is consensus-enforced; see [`Fill`].
pub const FEE_DIVISOR: u64 = 100;
/// Largest single-trade amount accepted (base units). Keeps every intermediate
/// product below `u64::MAX`: with `vtok ≤ VTOK0 = 1e9`, `vtok · amount ≤ 5e18`,
/// well under `1.84e19`. Far above any realistic pre-graduation trade.
pub const MAX_TRADE: u64 = 5_000_000_000;

// -- storage slots -------------------------------------------------------------

/// Storage slot: virtual LAT reserve.
pub const SLOT_VLAT: u64 = 0;
/// Storage slot: virtual token reserve.
pub const SLOT_VTOK: u64 = 1;
/// Storage slot: cumulative real LAT collected.
pub const SLOT_REAL_LAT: u64 = 2;
/// Storage slot: graduation flag (0/1).
pub const SLOT_GRADUATED: u64 = 3;
/// Storage slot: initialization flag (0/1).
pub const SLOT_INIT: u64 = 4;

// Scratch slots (overwritten every call).
const S_SIDE: u64 = 10;
const S_AMOUNT: u64 = 11;
const S_KEY: u64 = 12;
const S_HOLD: u64 = 13;
const S_FEE: u64 = 14;
const S_NET: u64 = 15;
const S_DENOM: u64 = 16;
const S_OUT: u64 = 17;

const BIT63: u64 = 1 << 63;
const MASK63: u64 = BIT63 - 1;

/// The storage key an account's token holdings live under: the first 8 bytes of
/// its id (as this contract sees via `CALLER`), with bit 63 forced set so the
/// holdings keyspace `[2^63, 2^64)` can never collide with the low fixed slots.
pub fn holdings_key(caller: &[u8; 32]) -> u64 {
    let c = u64::from_le_bytes(caller[0..8].try_into().expect("32 >= 8"));
    (c & MASK63) | BIT63
}

/// Encode a trade into the `CallContract` input word: bit 63 = side (buy=1),
/// low 63 bits = amount in base units.
pub fn encode_trade(is_buy: bool, amount: u64) -> u64 {
    debug_assert!(amount <= MASK63, "amount must fit in 63 bits");
    ((is_buy as u64) << 63) | (amount & MASK63)
}

/// Inverse of [`encode_trade`]: recover `(is_buy, amount)` from a call's input
/// word. An indexer reading mined `CallContract` transactions uses this to see
/// what each trade actually was.
pub fn decode_trade(input: u64) -> (bool, u64) {
    (input >> 63 == 1, input & MASK63)
}

/// `[Push(slot), Sload]` — push `storage[slot]`.
fn load(slot: u64) -> Vec<lat_vm::assembler::Instr> {
    vec![Push(slot), Sload]
}

/// Store the stack top into `storage[slot]` (consumes it).
fn save(slot: u64) -> Vec<lat_vm::assembler::Instr> {
    // stack: [val] -> [val, slot] -> [slot, val] -> Sstore(key=slot, value=val)
    vec![Push(slot), Swap, Sstore]
}

/// The compiled bonding-curve contract bytecode. Deterministic — the same bytes
/// every time, so its `contract_id` (hash of deployer+code) is stable.
///
/// NB: *because* it is stable, one deployer can hold only ONE unsalted curve —
/// a second `DeployContract` with these bytes hits `LedgerError::ContractExists`.
/// A launchpad needs a distinct curve per token: use [`bytecode_for`].
pub fn bytecode() -> Vec<u8> {
    program(None)
}

/// The curve bytecode salted for one token, so every token gets its own curve
/// instance under one deployer.
///
/// `contract_id` is `hash(deployer ‖ code)` and `DeployContract` carries no salt
/// field, so distinct instances require distinct *code*. This prepends a dead
/// `Push(salt); Pop` — 10 bytes, 2 gas, no effect on the stack the program then
/// builds — which is enough to move the hash. The id stays deterministic: anyone
/// who knows `(deployer, salt)` can recompute it and verify they are trading
/// against the real curve rather than a look-alike.
///
/// Pass [`ticker_salt`] of the token's normalized ticker: the chain enforces
/// ticker uniqueness, so curve ids inherit it — and unlike the sequential
/// `token_id`, a ticker is known *before* the `CreateToken` is mined, so the
/// curve can be deployed in the same breath as the token.
pub fn bytecode_for(salt: u64) -> Vec<u8> {
    program(Some(salt))
}

/// The contract id of `creator`'s curve for `normalized_ticker` — the whole
/// derivation in one place, so a caller never has to reassemble it.
///
/// Every input is public, which is the point: a trader can recompute this from
/// the token's creator and ticker and check that the curve they are about to
/// trade against is the real one, not a look-alike the operator points them at.
pub fn curve_id(creator: &[u8; 32], normalized_ticker: &str) -> [u8; 32] {
    lat_vm::contract_id(creator, &bytecode_for(ticker_salt(normalized_ticker)))
}

/// The curve salt for a normalized ticker: the first 8 bytes of a domain-tagged
/// BLAKE3 of it. Deterministic and collision-free in practice — and a collision
/// could only ever strand *one creator's own* second token (the deployer is part
/// of `contract_id`), never let one token hijack another's curve.
pub fn ticker_salt(normalized_ticker: &str) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(b"LAT-curve-salt");
    h.update(normalized_ticker.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.finalize().as_bytes()[..8]);
    u64::from_le_bytes(b)
}

/// Shared program body. `salt = None` reproduces the original unsalted bytes
/// exactly, so [`bytecode`]'s contract id is unchanged.
fn program(salt: Option<u64>) -> Vec<u8> {
    let mut a = Asm::new();

    // --- salt: unique contract_id per token; dead code, never read ----------
    if let Some(s) = salt {
        a = a.extend([Push(s), Pop]);
    }

    // --- prologue: initialize on first call ---------------------------------
    a = a.extend(load(SLOT_INIT)).ins(PushLabel("post_init")).ins(JumpI); // init!=0 -> skip
    a = a
        .extend([Push(SLOT_VLAT), Push(VLAT0), Sstore])
        .extend([Push(SLOT_VTOK), Push(VTOK0), Sstore])
        .extend([Push(SLOT_REAL_LAT), Push(0), Sstore])
        .extend([Push(SLOT_GRADUATED), Push(0), Sstore])
        .extend([Push(SLOT_INIT), Push(1), Sstore]);
    a = a.ins(Label("post_init"));

    // --- reject trades once graduated ---------------------------------------
    a = a.extend(load(SLOT_GRADUATED)).ins(PushLabel("rev")).ins(JumpI);

    // --- decode input: side, amount; derive caller key ----------------------
    a = a.extend([Input, Push(BIT63), Div]).extend(save(S_SIDE)); // side = input >> 63
    a = a.extend([Input, Push(MASK63), And]).extend(save(S_AMOUNT)); // amount = input & mask
    a = a
        .extend([Caller, Push(MASK63), And, Push(BIT63), Add])
        .extend(save(S_KEY)); // key = (caller & mask) | 2^63

    // --- validate amount: reject 0 or > MAX_TRADE ---------------------------
    a = a.extend(load(S_AMOUNT)).extend([Push(0), Eq]).ins(PushLabel("rev")).ins(JumpI);
    a = a.extend(load(S_AMOUNT)).extend([Push(MAX_TRADE), Gt]).ins(PushLabel("rev")).ins(JumpI);

    // --- dispatch on side ---------------------------------------------------
    a = a.extend(load(S_SIDE)).ins(PushLabel("buy")).ins(JumpI); // side!=0 -> buy; else sell

    // ===================== SELL =============================================
    a = a.ins(Label("sell"));
    // hold = storage[key]
    a = a.extend(load(S_KEY)).ins(Sload).extend(save(S_HOLD));
    // if amount > hold: revert (can't sell more than you hold)
    a = a.extend(load(S_AMOUNT)).extend(load(S_HOLD)).ins(Gt).ins(PushLabel("rev")).ins(JumpI);
    // denom = vtok + amount
    a = a.extend(load(SLOT_VTOK)).extend(load(S_AMOUNT)).ins(Add).extend(save(S_DENOM));
    // out(lat) = vlat * amount / denom
    a = a
        .extend(load(SLOT_VLAT))
        .extend(load(S_AMOUNT))
        .ins(Mul)
        .extend(load(S_DENOM))
        .ins(Div)
        .extend(save(S_OUT));
    // vtok += amount ; vlat -= lat
    a = a.extend(load(SLOT_VTOK)).extend(load(S_AMOUNT)).ins(Add).extend(save(SLOT_VTOK));
    a = a.extend(load(SLOT_VLAT)).extend(load(S_OUT)).ins(Sub).extend(save(SLOT_VLAT));
    // real_lat = real_lat < lat ? 0 : real_lat - lat
    a = a.extend(load(SLOT_REAL_LAT)).extend(load(S_OUT)).ins(Lt).ins(PushLabel("rl_zero")).ins(JumpI);
    a = a
        .extend(load(SLOT_REAL_LAT))
        .extend(load(S_OUT))
        .ins(Sub)
        .extend(save(SLOT_REAL_LAT))
        .ins(PushLabel("rl_done"))
        .ins(Jump);
    a = a.ins(Label("rl_zero")).extend([Push(0)]).extend(save(SLOT_REAL_LAT)).ins(Label("rl_done"));
    // holding[key] = hold - amount
    a = a
        .extend(load(S_HOLD))
        .extend(load(S_AMOUNT))
        .ins(Sub)
        .extend(load(S_KEY))
        .ins(Swap)
        .ins(Sstore);
    a = a.ins(PushLabel("grad")).ins(Jump);

    // ===================== BUY ==============================================
    a = a.ins(Label("buy"));
    // fee = amount / FEE_DIVISOR ; net = amount - fee
    a = a.extend(load(S_AMOUNT)).extend([Push(FEE_DIVISOR), Div]).extend(save(S_FEE));
    a = a.extend(load(S_AMOUNT)).extend(load(S_FEE)).ins(Sub).extend(save(S_NET));
    // denom = vlat + net
    a = a.extend(load(SLOT_VLAT)).extend(load(S_NET)).ins(Add).extend(save(S_DENOM));
    // out(tok) = vtok * net / denom
    a = a
        .extend(load(SLOT_VTOK))
        .extend(load(S_NET))
        .ins(Mul)
        .extend(load(S_DENOM))
        .ins(Div)
        .extend(save(S_OUT));
    // vlat += net ; vtok -= tok ; real_lat += net
    a = a.extend(load(SLOT_VLAT)).extend(load(S_NET)).ins(Add).extend(save(SLOT_VLAT));
    a = a.extend(load(SLOT_VTOK)).extend(load(S_OUT)).ins(Sub).extend(save(SLOT_VTOK));
    a = a.extend(load(SLOT_REAL_LAT)).extend(load(S_NET)).ins(Add).extend(save(SLOT_REAL_LAT));
    // holding[key] = holding[key] + tok
    a = a
        .extend(load(S_KEY))
        .ins(Sload)
        .extend(load(S_OUT))
        .ins(Add)
        .extend(load(S_KEY))
        .ins(Swap)
        .ins(Sstore);
    a = a.ins(PushLabel("grad")).ins(Jump);

    // ===================== graduation + exits ===============================
    a = a.ins(Label("grad"));
    // if real_lat < GRADUATE_LAT skip; else graduated = 1
    a = a.extend(load(SLOT_REAL_LAT)).extend([Push(GRADUATE_LAT), Lt]).ins(PushLabel("end")).ins(JumpI);
    a = a.extend([Push(SLOT_GRADUATED), Push(1), Sstore]);
    a = a.ins(Label("end")).ins(Stop);
    a = a.ins(Label("rev")).ins(Revert);

    a.assemble().expect("bonding-curve assembles")
}

// -- Rust reference (the source of truth for tests + off-chain quote display) --

/// A pure-integer mirror of the on-chain curve state, so latfun can render exact
/// quotes/prices from the state it reads over RPC and tests can check the
/// contract against a trusted implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Curve {
    pub vlat: u64,
    pub vtok: u64,
    pub real_lat: u64,
    pub graduated: bool,
}

impl Default for Curve {
    fn default() -> Self {
        Curve { vlat: VLAT0, vtok: VTOK0, real_lat: 0, graduated: false }
    }
}

/// What a fill produced: `out` to the trader, `fee` retained by the platform.
///
/// The two fees are **not equally enforced**, and callers must not pretend
/// otherwise:
///
/// * A **buy** fee is enforced by consensus. The contract adds only `amount −
///   fee` to the reserves, so the pool provably never received the fee — that is
///   a fact on-chain, checkable by anyone.
/// * A **sell** fee is bookkeeping. The contract debits the reserves by the full
///   gross (it has no value-transfer opcode, so it cannot pay anyone), and the
///   payout happens off-chain. Nothing on-chain forces the payer to withhold
///   exactly `fee` — or to pay at all. pump.fun can enforce both sides because
///   its Solana program moves the SOL itself; Latebra cannot until D4 is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fill {
    /// Tokens (buy) or LAT (sell) owed to the trader, net of fee.
    pub out: u64,
    /// LAT retained by the platform.
    pub fee: u64,
}

impl Curve {
    /// Apply a buy of `amount` LAT (base units). `None` if the trade would revert
    /// on-chain (graduated / zero / oversize). Mutates the reserves exactly as the
    /// contract does.
    pub fn apply_buy(&mut self, amount: u64) -> Option<Fill> {
        if self.graduated || amount == 0 || amount > MAX_TRADE {
            return None;
        }
        let fee = amount / FEE_DIVISOR;
        let net = amount - fee;
        let denom = self.vlat + net;
        let tok = ((self.vtok as u128 * net as u128) / denom as u128) as u64;
        self.vlat += net;
        self.vtok -= tok;
        self.real_lat += net;
        if self.real_lat >= GRADUATE_LAT {
            self.graduated = true;
        }
        Some(Fill { out: tok, fee })
    }

    /// Apply a sell of `amount` tokens by a holder currently holding `hold`.
    /// `None` if it would revert (graduated / zero / oversize / more than held).
    ///
    /// The 1% is taken from the *payout*, matching pump.fun's fee on both sides:
    /// the reserves fall by the full gross, the seller receives `gross − fee`.
    /// Note the reserve move is identical either way, which is exactly why this
    /// needed no bytecode change — and why it is not consensus-enforced. See
    /// [`Fill`].
    pub fn apply_sell(&mut self, amount: u64, hold: u64) -> Option<Fill> {
        if self.graduated || amount == 0 || amount > MAX_TRADE || amount > hold {
            return None;
        }
        let denom = self.vtok + amount;
        let gross = ((self.vlat as u128 * amount as u128) / denom as u128) as u64;
        let fee = gross / FEE_DIVISOR;
        self.vtok += amount;
        self.vlat -= gross;
        self.real_lat = self.real_lat.saturating_sub(gross);
        // Selling never triggers graduation (real_lat only falls), matching the
        // contract, which checks the threshold with the same `<` after every trade.
        Some(Fill { out: gross - fee, fee })
    }

    /// Current spot price in LAT-base-units per token, scaled by 1e9 for display
    /// precision (`vlat / vtok` is otherwise sub-integer). latfun divides by 1e9.
    pub fn price_scaled(&self) -> u64 {
        ((self.vlat as u128 * 1_000_000_000u128) / self.vtok as u128) as u64
    }

    /// Progress toward graduation, in basis points (0..=10000).
    pub fn graduation_bps(&self) -> u64 {
        ((self.real_lat as u128 * 10_000u128) / GRADUATE_LAT as u128).min(10_000) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lat_vm::{execute, Storage, VmError, DEFAULT_GAS};

    fn caller(n: u8) -> [u8; 32] {
        let mut c = [0u8; 32];
        c[0] = n;
        c[7] = 0xAA; // ensure a non-trivial 8-byte prefix
        c
    }

    /// Run one trade against `storage` as the ledger would (fresh clone, commit
    /// only on success). Returns whether it succeeded.
    fn trade(storage: &mut Storage, who: &[u8; 32], is_buy: bool, amount: u64) -> bool {
        let mut next = storage.clone();
        let input = encode_trade(is_buy, amount);
        match execute(&bytecode(), &mut next, who, input, DEFAULT_GAS) {
            Ok(()) => {
                *storage = next;
                true
            }
            Err(_) => false, // reverted: storage unchanged
        }
    }

    fn view(storage: &Storage) -> Curve {
        Curve {
            vlat: *storage.get(&SLOT_VLAT).unwrap_or(&0),
            vtok: *storage.get(&SLOT_VTOK).unwrap_or(&0),
            real_lat: *storage.get(&SLOT_REAL_LAT).unwrap_or(&0),
            graduated: *storage.get(&SLOT_GRADUATED).unwrap_or(&0) != 0,
        }
    }

    #[test]
    fn bytecode_is_deterministic() {
        assert_eq!(bytecode(), bytecode(), "same bytes every build (stable contract id)");
        assert!(bytecode().len() < DEFAULT_GAS as usize, "fits the gas budget comfortably");
    }

    /// A launchpad deploys one curve per token from ONE wallet. `contract_id` is
    /// `hash(deployer ‖ code)` and `DeployContract` has no salt field, so the
    /// salt must live in the code or the second token's deploy is rejected as
    /// `ContractExists` and every token would share one curve.
    #[test]
    fn salted_bytecode_gives_each_token_its_own_contract_id() {
        let deployer = caller(9);
        let id = |code: &[u8]| lat_vm::contract_id(&deployer, code);

        assert_eq!(bytecode_for(7), bytecode_for(7), "same salt -> same bytes (stable id)");
        assert_ne!(id(&bytecode_for(1)), id(&bytecode_for(2)), "distinct tokens must not collide");
        assert_ne!(id(&bytecode_for(1)), id(&bytecode()), "salted differs from unsalted");
        assert_eq!(bytecode_for(1).len(), bytecode().len() + 10, "salt costs Push8+Pop = 10 bytes");
    }

    /// pump.fun charges 1% on BOTH sides. Pin that, and pin where each fee comes
    /// from: a buy fee is withheld from the input (so the pool never receives it —
    /// consensus-visible), a sell fee is withheld from the payout (so the reserves
    /// still fall by the full gross — off-chain, see `Fill`).
    #[test]
    fn one_percent_is_charged_on_both_sides() {
        let mut c = Curve::default();
        let buy = 10 * 100_000u64;
        let bought = c.apply_buy(buy).unwrap();
        assert_eq!(bought.fee, buy / 100, "buy fee is 1% of the input");

        // The pool only ever saw the net: real_lat is the fee-adjusted input.
        assert_eq!(c.real_lat, buy - bought.fee, "fee never entered the reserves");

        let before = c;
        let sold = c.apply_sell(bought.out, bought.out).unwrap();
        let gross = sold.out + sold.fee;
        assert_eq!(sold.fee, gross / 100, "sell fee is 1% of the gross payout");
        assert!(sold.out < gross, "seller receives the payout net of fee");
        assert_eq!(before.vlat - c.vlat, gross, "reserves fall by the GROSS, not the net");
    }

    #[test]
    fn decode_trade_inverts_encode_trade() {
        for (is_buy, amount) in [(true, 0u64), (false, 1), (true, MAX_TRADE), (false, MASK63)] {
            assert_eq!(decode_trade(encode_trade(is_buy, amount)), (is_buy, amount));
        }
    }

    #[test]
    fn ticker_salt_is_deterministic_and_separates_tickers() {
        assert_eq!(ticker_salt("DOGE"), ticker_salt("DOGE"), "same ticker -> same curve id");
        assert_ne!(ticker_salt("DOGE"), ticker_salt("PEPE"), "distinct tickers -> distinct curves");
        // Normalization is the caller's job (lat_types::normalize_ticker); the
        // salt is over the *normalized* form, so raw case must not sneak past.
        assert_ne!(ticker_salt("DOGE"), ticker_salt("doge"), "salt is over normalized input only");

        let deployer = caller(9);
        let id = |t: &str| lat_vm::contract_id(&deployer, &bytecode_for(ticker_salt(t)));
        assert_ne!(id("DOGE"), id("PEPE"), "one creator's two tokens get two curves");
    }

    /// The salt is dead code: it must not perturb the curve it prefixes.
    #[test]
    fn salt_does_not_change_behaviour() {
        let alice = caller(1);
        let run = |code: &[u8]| {
            let mut s = Storage::new();
            let mut ok = true;
            for amt in [10 * 100_000u64, 3 * 100_000, 25 * 100_000] {
                let input = encode_trade(true, amt);
                ok &= execute(code, &mut s, &alice, input, DEFAULT_GAS).is_ok();
            }
            (ok, view(&s), *s.get(&holdings_key(&alice)).unwrap_or(&0))
        };

        let plain = run(&bytecode());
        assert!(plain.0, "unsalted curve accepted the trades");
        for salt in [1u64, 42, u64::MAX] {
            assert_eq!(run(&bytecode_for(salt)), plain, "salt {salt} altered the curve");
        }
    }

    #[test]
    fn first_buy_initializes_and_matches_reference() {
        let mut storage = Storage::new();
        let alice = caller(1);
        assert!(trade(&mut storage, &alice, true, 10 * 100_000)); // buy 10 LAT

        let mut reference = Curve::default();
        let tok = reference.apply_buy(10 * 100_000).unwrap().out;

        assert_eq!(view(&storage), reference, "on-chain curve matches the reference");
        assert_eq!(*storage.get(&holdings_key(&alice)).unwrap(), tok, "holdings credited");
        assert!(tok > 0);
    }

    #[test]
    fn buy_then_sell_round_trips_through_the_curve() {
        let mut storage = Storage::new();
        let bob = caller(2);
        let mut reference = Curve::default();

        // Bob buys 50 LAT worth.
        assert!(trade(&mut storage, &bob, true, 50 * 100_000));
        let bought = reference.apply_buy(50 * 100_000).unwrap().out;
        assert_eq!(*storage.get(&holdings_key(&bob)).unwrap(), bought);

        // Bob sells half of them back.
        let sell = bought / 2;
        assert!(trade(&mut storage, &bob, false, sell));
        reference.apply_sell(sell, bought).unwrap();
        assert_eq!(view(&storage), reference);
        assert_eq!(*storage.get(&holdings_key(&bob)).unwrap(), bought - sell);
    }

    #[test]
    fn many_traders_track_independent_holdings() {
        // A scripted sequence of buys/sells by several callers; the on-chain curve
        // and per-caller holdings must match a parallel reference simulation.
        let mut storage = Storage::new();
        let mut reference = Curve::default();
        let mut holds = std::collections::HashMap::<u64, u64>::new();

        let script: &[(u8, bool, u64)] = &[
            (1, true, 5 * 100_000),
            (2, true, 12 * 100_000),
            (1, true, 3 * 100_000),
            (3, true, 40 * 100_000),
            (2, false, 100_000), // sell some tokens
            (1, false, 50_000),
            (3, true, 20 * 100_000),
        ];

        for &(who, is_buy, amount) in script {
            let c = caller(who);
            let key = holdings_key(&c);
            let hold = *holds.get(&key).unwrap_or(&0);
            let expect = if is_buy {
                reference.apply_buy(amount)
            } else {
                reference.apply_sell(amount, hold)
            };
            let ok = trade(&mut storage, &c, is_buy, amount);
            assert_eq!(ok, expect.is_some(), "success matches reference for {who} {is_buy} {amount}");
            if let Some(fill) = expect {
                let new_hold = if is_buy { hold + fill.out } else { hold - amount };
                holds.insert(key, new_hold);
                assert_eq!(*storage.get(&key).unwrap_or(&0), new_hold, "holdings match");
            }
        }
        assert_eq!(view(&storage), reference, "final curve state matches the reference");
    }

    #[test]
    fn reverts_leave_state_untouched() {
        let mut storage = Storage::new();
        let carol = caller(4);
        // Seed the curve with a real buy.
        assert!(trade(&mut storage, &carol, true, 10 * 100_000));
        let before = storage.clone();

        // Zero amount, oversize amount, and overselling all revert with no change.
        assert!(!trade(&mut storage, &carol, true, 0), "zero-amount buy reverts");
        assert!(!trade(&mut storage, &carol, true, MAX_TRADE + 1), "oversize buy reverts");
        assert!(!trade(&mut storage, &carol, false, MASK63), "oversell reverts");
        let stranger = caller(9);
        assert!(!trade(&mut storage, &stranger, false, 1), "selling with no holdings reverts");

        assert_eq!(storage, before, "no reverted trade mutated storage");
    }

    #[test]
    fn graduation_locks_the_curve() {
        let mut storage = Storage::new();
        let whale = caller(5);
        let mut reference = Curve::default();

        // Buy in chunks until graduation (real_lat >= GRADUATE_LAT = 500 LAT).
        // Each chunk is 90 LAT gross (net ~89.1), so ~6 buys cross 500.
        let chunk = 90 * 100_000;
        let mut graduated = false;
        for _ in 0..8 {
            let expect = reference.apply_buy(chunk).map(|f| f.out);
            let ok = trade(&mut storage, &whale, true, chunk);
            match expect {
                Some(_) => assert!(ok),
                None => {
                    assert!(!ok, "post-graduation buy reverts");
                    graduated = true;
                    break;
                }
            }
        }
        assert!(graduated, "curve graduated and then locked");
        assert!(view(&storage).graduated, "graduated flag set on-chain");
        assert_eq!(view(&storage), reference);

        // Direct wire check via the VM error type on a graduated curve.
        let input = encode_trade(true, 100_000);
        let mut next = storage.clone();
        assert_eq!(
            execute(&bytecode(), &mut next, &whale, input, DEFAULT_GAS),
            Err(VmError::DivByZero),
            "graduated curve reverts (via the Revert primitive)"
        );
    }

    #[test]
    fn holdings_key_is_disjoint_from_curve_slots() {
        // The holdings keyspace must never collide with the fixed low slots, even
        // for an adversary who grinds a low 8-byte id prefix.
        let mut zero = [0u8; 32]; // 8-byte prefix = 0
        zero[0] = 0;
        assert!(holdings_key(&zero) >= BIT63, "holdings live in the high keyspace");
        assert_ne!(holdings_key(&zero), SLOT_VLAT);
        assert_ne!(holdings_key(&zero), SLOT_GRADUATED);
    }
}

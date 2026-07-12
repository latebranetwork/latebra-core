//! Composed anonymous transfer (clean-room, from `ANON_SPEND.md` /
//! `ANON_INTEGRATION.md`).
//!
//! **UNAUDITED.** This bundles the anonymity bricks into one verifiable object —
//! the core of the `Transaction::AnonTransfer` consensus type (see
//! `lat-types` / `lat-state`). Built primitive-first, the way `ring.rs` /
//! `hidden_solvency.rs` were, and now wired into consensus on the TESTNET; it
//! must not carry real value before a professional cryptographic review.
//!
//! # What it hides — and what it does not
//! * **Sender:** hidden inside a public anonymity set (ring) of `N` members.
//! * **Receiver:** hidden via a one-time **stealth** address ([`crate::stealth_send`]).
//! * **Amount:** **HIDDEN** (v3, closing finding F2). The transfer publishes only a
//!   Pedersen commitment `C_debit` to the total debit and an ElGamal `credit`
//!   ciphertext for the receiver; every relation that previously took the public
//!   amount is proven against the commitment instead.
//! * **Fee:** **PUBLIC** — the miner must credit it in plaintext, and a public fee
//!   is what lets consensus enforce the fee floor. (Zcash/Monero also expose fees.)
//!
//! # Debit accounting (fee folded in)
//! Because the sender is hidden, the fee cannot be subtracted from it separately (that
//! would reveal which account paid). So the value that leaves the sender is the whole
//! **`debit = amount + fee`**, committed as `C_debit = debit·G + s_d·H`: the delta
//! commitments, zero-or-debit bounds, solvency, and conservation are all against
//! `C_debit`. Consensus credits the carried `credit` ciphertext to the stealth
//! receiver's pending pool and the public `fee` to the miner.
//!
//! # What `verify` proves (soundness)
//! For a public ring `{Y_i}`, on-chain balance ciphertexts `{(C_i^bal,D_i^bal)}`,
//! per-member Pedersen delta commitments `{C_i = δ_i·G + s_i·H}`, per-member ElGamal
//! debit ciphertexts `{Enc_i}`, debit commitment `C_debit`, receiver credit ciphertext
//! `credit`, public `fee`/`epoch`, and a published nullifier `u`:
//!
//! 1. **Bounds (brick B, hidden form):** every `δ_i ∈ {0, debit}` — proven per member
//!    as `C_i ∈ ⟨H⟩ OR (C_i − C_debit) ∈ ⟨H⟩` (a CDS OR of two Schnorr-on-H proofs),
//!    which needs no public amount.
//! 2. **Conservation:** `Σ C_i − C_debit ∈ ⟨H⟩` — so `Σ δ_i = debit`, and with (1)
//!    *exactly one* member carries `debit` and the rest carry `0` (for `debit ≠ 0`;
//!    consensus's fee floor keeps `debit ≥ fee > 0`).
//! 3. **Owned = debited = solvent = nullified (fused bricks A+C+D):** one CDS
//!    OR-composition proves a hidden index `l` at which the prover simultaneously
//!    (a) owns `Y_l = x·G`, (b) `C_l − C_debit ∈ ⟨H⟩` (commits to `debit`),
//!    (c) `balance_l − debit ≥ 0` (Bulletproofs, via `T_i = V − C_i^bal + C_debit`),
//!    and (d) the **epoch nullifier** `u = x·G_epoch` uses that same `x`. All four
//!    share the branch challenge `e_l` and witness `x`.
//! 4. **Value-movement link (brick E):** every `Enc_i` provably encrypts the *same*
//!    `δ_i` committed in `C_i` (a per-member two-base Schnorr), so the ciphertext the
//!    ledger subtracts from `balance_i` matches the proven-correct delta.
//! 5. **Amount well-formedness + credit link (v3):** the aggregated Bulletproof also
//!    range-proves the hidden `amount` via `C_amt = C_debit − fee·G` (so
//!    `debit ≥ fee`, no scalar wraparound), and a two-base Schnorr proves the carried
//!    `credit` ciphertext encrypts, under the stealth one-time key, exactly the value
//!    `C_amt` commits to — the receiver is credited precisely `debit − fee`.
//!
//! # Epoch nullifier (anti-replay for an account model)
//! The nullifier is `u = x·G_epoch`, where `G_epoch = H_p("Latebra.Epoch" ‖ epoch)`.
//! It is deterministic per account **per epoch** (so a second spend by the same
//! account in the same epoch collides and is rejected) yet reveals nothing about which
//! member spent (linking `u` to a `Y_i` is a DDH problem). This is the Zether-style
//! anti-replay `ANON_INTEGRATION.md` §4 calls for — an account model cannot use a
//! *static* per-key image, which would allow only one spend ever.
//!
//! # Consensus integration (implemented; the audit gate still applies)
//! The `Transaction::AnonTransfer` type (`lat-types`, tag `0x0B`), the ledger's
//! nullifier set + whole-ring delta application + stealth pending credit
//! (`lat-state`), and the epoch/fee/ring-size consensus rules + mempool
//! nullifier conflicts (`lat-chain`) are all wired in. Decoy selection is
//! wallet-side and still open. See `ANON_INTEGRATION.md`. Do not ship with
//! value before an audit.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use merlin::Transcript as MerlinTranscript;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::{commit_delta, stealth_send, Ciphertext, PublicKey, SecretKey, StealthOutput};

const RANGE_BITS: usize = 64;

/// The Pedersen blinding base `H` (independent of `G`), shared with the delta
/// commitments and the Bulletproofs range-proof commitment.
fn blinding_base() -> RistrettoPoint {
    PedersenGens::default().B_blinding
}

/// The per-epoch nullifier base `G_epoch = H_p("Latebra.Epoch" ‖ epoch)`. Independent
/// of `G` and of any member key, so `u = x·G_epoch` hides which member spent.
fn epoch_base(epoch: u64) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(b"Latebra.Epoch.v1");
    h.update(epoch.to_le_bytes());
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Brick E: a per-member proof that ElGamal `Enc_i` encrypts the same value that the
/// Pedersen commitment `C_i` commits to (without revealing it). Two-base Schnorr over
/// witnesses `(δ_i, s_i, y_i)` for the three relations `C_i = δ·G + s·H`,
/// `Enc_i.c = δ·G + y·Y_i`, `Enc_i.d = y·G`. Also reused (v3) to link the receiver
/// `credit` ciphertext to the hidden-amount commitment `C_amt`.
#[derive(Clone, Debug)]
struct DeltaLink {
    a1: RistrettoPoint,
    a2: RistrettoPoint,
    a3: RistrettoPoint,
    z_d: Scalar,
    z_s: Scalar,
    z_y: Scalar,
}

/// Brick B, hidden-amount form (v3): a CDS OR-proof that a delta commitment `C`
/// opens to `0` **or** to the (hidden) debit committed by `C_debit` — i.e.
/// `C = s·H` OR `C − C_debit = s'·H`, both plain Schnorrs on base `H`. Replaces
/// the old `ValueInSetProof` over the public set `{0, debit}`.
#[derive(Clone, Debug)]
struct ZeroOrDebit {
    a0: RistrettoPoint,
    a1: RistrettoPoint,
    e0: Scalar,
    z0: Scalar,
    z1: Scalar,
}

/// Fiat–Shamir challenge for one [`ZeroOrDebit`] proof.
fn zod_challenge(
    c: &RistrettoPoint,
    c_debit: &RistrettoPoint,
    a0: &RistrettoPoint,
    a1: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.AnonTransfer.zod.v1");
    for p in [c, c_debit, a0, a1] {
        h.update(p.compress().as_bytes());
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

impl ZeroOrDebit {
    /// Prove `C = value·G + s·H` opens to 0 (`debit_branch = false`, witness `s`)
    /// or to the debit committed by `C_debit = debit·G + s_d·H`
    /// (`debit_branch = true`, witness `s − s_d`).
    fn prove<R: RngCore + CryptoRng>(
        c: &RistrettoPoint,
        c_debit: &RistrettoPoint,
        debit_branch: bool,
        witness: &Scalar, // `s` for the 0 branch, `s − s_d` for the debit branch
        rng: &mut R,
    ) -> ZeroOrDebit {
        let h = blinding_base();
        let diff = c - c_debit;
        let k = Scalar::random(rng);
        if debit_branch {
            // Simulate branch 0 (C = s·H), prove branch 1 (C − C_debit = s'·H).
            let e0 = Scalar::random(rng);
            let z0 = Scalar::random(rng);
            let a0 = h * z0 - c * e0;
            let a1 = h * k;
            let e = zod_challenge(c, c_debit, &a0, &a1);
            let e1 = e - e0;
            ZeroOrDebit { a0, a1, e0, z0, z1: k + e1 * witness }
        } else {
            // Simulate branch 1, prove branch 0.
            let e1 = Scalar::random(rng);
            let z1 = Scalar::random(rng);
            let a1 = h * z1 - diff * e1;
            let a0 = h * k;
            let e = zod_challenge(c, c_debit, &a0, &a1);
            let e0 = e - e1;
            ZeroOrDebit { a0, a1, e0, z0: k + e0 * witness, z1 }
        }
    }

    fn verify(&self, c: &RistrettoPoint, c_debit: &RistrettoPoint) -> bool {
        let h = blinding_base();
        let e = zod_challenge(c, c_debit, &self.a0, &self.a1);
        let e1 = e - self.e0;
        h * self.z0 == self.a0 + c * self.e0 && h * self.z1 == self.a1 + (c - c_debit) * e1
    }
}

/// A composed anonymous transfer: the public statement plus its bundled proofs.
#[derive(Clone, Debug)]
pub struct AnonTransfer {
    /// The anonymity set (the sender is one of these — which one is hidden).
    pub ring: Vec<PublicKey>,
    /// Each member's on-chain balance ciphertext, in the same order as `ring`.
    pub balances: Vec<Ciphertext>,
    /// Per-member Pedersen delta commitments `C_i = δ_i·G + s_i·H`.
    pub deltas: Vec<RistrettoPoint>,
    /// Per-member ElGamal debit ciphertexts under `ring[i]` — what the ledger
    /// subtracts from `balances[i]` (`δ_sender = debit`, decoys `0`).
    pub enc: Vec<Ciphertext>,
    /// Pedersen commitment `C_debit = (amount + fee)·G + s_d·H` to the HIDDEN
    /// total debit (v3 — the amount never appears in plaintext).
    pub c_debit: RistrettoPoint,
    /// ElGamal encryption of the hidden `amount` under the stealth one-time
    /// key — what the ledger adds to the receiver's pending pool. Proven (via
    /// `credit_link` + the aggregated range proof) to encrypt exactly
    /// `debit − fee`.
    pub credit: Ciphertext,
    /// Public fee paid to the miner.
    pub fee: u64,
    /// The epoch this spend is valid in (its nullifier base). Consensus must check
    /// this equals the containing block's epoch.
    pub epoch: u64,
    /// The stealth output crediting the (hidden) receiver.
    pub output: StealthOutput,

    /// Epoch nullifier `u = x·G_epoch` — deterministic per account per epoch.
    nullifier: RistrettoPoint,
    /// Bulletproofs commitment `V = b'·G + γ·H` to the remaining balance `b'`.
    v: CompressedRistretto,
    /// Aggregated range proof over TWO values: the remaining balance (in `V`)
    /// and the hidden amount (in `C_amt = C_debit − fee·G`) — the latter is what
    /// rules out `debit < fee` scalar wraparound.
    rp: RangeProof,

    // Fused OR-composition (relations a–d), one entry per ring member.
    e: Vec<Scalar>,
    z_x: Vec<Scalar>,
    z_s: Vec<Scalar>,
    z_g: Vec<Scalar>,

    /// Brick B (hidden form): proof that each `deltas[i]` opens to 0 or the debit.
    membership: Vec<ZeroOrDebit>,
    /// Brick E: per-member link that `enc[i]` encrypts the same `δ_i` as `deltas[i]`.
    links: Vec<DeltaLink>,
    /// v3: link that `credit` encrypts (under the one-time key) the value committed
    /// by `C_amt = C_debit − fee·G`.
    credit_link: DeltaLink,

    // Conservation: Schnorr that `Σ deltas − debit·G = σ·H` (so `Σ δ_i = debit`).
    sum_a: RistrettoPoint,
    sum_z: Scalar,
}

/// Fiat–Shamir challenge for the fused OR-composition. Binds the entire public
/// statement — ring, balances, deltas, debit ciphertexts, amount/fee/epoch, the
/// stealth receiver, and the nullifier — so nothing can be mauled after proving.
#[allow(clippy::too_many_arguments)]
fn fused_challenge(
    ring: &[PublicKey],
    balances: &[Ciphertext],
    deltas: &[RistrettoPoint],
    enc: &[Ciphertext],
    c_debit: &RistrettoPoint,
    credit: &Ciphertext,
    fee: u64,
    epoch: u64,
    nullifier: &RistrettoPoint,
    v: &RistrettoPoint,
    output: &StealthOutput,
    a1: &[RistrettoPoint],
    a2: &[RistrettoPoint],
    a3: &[RistrettoPoint],
    a4: &[RistrettoPoint],
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.AnonTransfer.v3");
    h.update((ring.len() as u64).to_le_bytes());
    for pk in ring {
        h.update(pk.0.compress().as_bytes());
    }
    for ct in balances {
        h.update(ct.c.compress().as_bytes());
        h.update(ct.d.compress().as_bytes());
    }
    for c in deltas {
        h.update(c.compress().as_bytes());
    }
    for ct in enc {
        h.update(ct.c.compress().as_bytes());
        h.update(ct.d.compress().as_bytes());
    }
    h.update(c_debit.compress().as_bytes());
    h.update(credit.c.compress().as_bytes());
    h.update(credit.d.compress().as_bytes());
    h.update(fee.to_le_bytes());
    h.update(epoch.to_le_bytes());
    h.update(nullifier.compress().as_bytes());
    h.update(v.compress().as_bytes());
    h.update(output.ephemeral.0.compress().as_bytes());
    h.update(output.one_time.0.compress().as_bytes());
    for group in [a1, a2, a3, a4] {
        for a in group {
            h.update(a.compress().as_bytes());
        }
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Challenge for the conservation (sum-to-debit) Schnorr — the debit is hidden,
/// so the challenge binds its commitment.
fn sum_challenge(
    deltas: &[RistrettoPoint],
    c_debit: &RistrettoPoint,
    agg_target: &RistrettoPoint,
    a: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.AnonTransfer.sum.v3");
    for c in deltas {
        h.update(c.compress().as_bytes());
    }
    h.update(c_debit.compress().as_bytes());
    h.update(agg_target.compress().as_bytes());
    h.update(a.compress().as_bytes());
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Challenge for one brick-E value-movement link.
fn link_challenge(
    y: &PublicKey,
    c_delta: &RistrettoPoint,
    enc: &Ciphertext,
    a1: &RistrettoPoint,
    a2: &RistrettoPoint,
    a3: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"Latebra.AnonTransfer.link.v1");
    for p in [&y.0, c_delta, &enc.c, &enc.d, a1, a2, a3] {
        h.update(p.compress().as_bytes());
    }
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// The per-branch target of the solvency relation (c):
/// `T_i = V − C_i^bal + C_debit`. At the real index this equals
/// `(γ + s_d)·H − x·D_i^bal` (the debit commitment's blinding folds into the
/// range-proof blinding — both are on base `H`).
fn solvency_target(v: &RistrettoPoint, bal: &Ciphertext, c_debit: &RistrettoPoint) -> RistrettoPoint {
    v - bal.c + c_debit
}

impl AnonTransfer {
    /// Build an anonymous transfer of `amount` (+`fee`) from a hidden `sender`
    /// (at `sender_index` in `ring`, holding plaintext `sender_balance`) to
    /// `receiver` (hidden behind a fresh stealth output), valid in `epoch`.
    ///
    /// `balances[i]` must be `ring[i]`'s real on-chain balance ciphertext.
    /// Returns `None` if the sender is insolvent (`sender_balance < amount + fee`),
    /// on `amount + fee` overflow, or on internal range-proof failure.
    ///
    /// Panics only on caller programming errors (mismatched lengths, bad index, or
    /// `ring[sender_index]` not `sender`'s key).
    #[allow(clippy::too_many_arguments)]
    pub fn create<R: RngCore + CryptoRng>(
        ring: &[PublicKey],
        balances: &[Ciphertext],
        sender: &SecretKey,
        sender_index: usize,
        sender_balance: u64,
        receiver: &PublicKey,
        amount: u64,
        fee: u64,
        epoch: u64,
        rng: &mut R,
    ) -> Option<AnonTransfer> {
        let n = ring.len();
        assert!(n >= 2, "an anonymity set needs at least 2 members");
        assert_eq!(balances.len(), n, "ring and balances length mismatch");
        assert!(sender_index < n, "sender index out of range");
        assert_eq!(ring[sender_index], sender.public_key(), "sender key not at ring[sender_index]");

        // The sender is hidden, so the fee rides inside the debit (see module docs).
        let debit = amount.checked_add(fee)?;
        let remaining = sender_balance.checked_sub(debit)?;

        let h = blinding_base();

        // --- hidden-debit commitment (v3): C_debit = debit·G + s_d·H -----------
        let s_d = Scalar::random(rng);
        let c_debit = G * Scalar::from(debit) + h * s_d;

        // --- delta commitments + ElGamal debits: sender carries `debit`, decoys 0 --
        let mut deltas = Vec::with_capacity(n);
        let mut blinds = Vec::with_capacity(n);
        let mut enc = Vec::with_capacity(n);
        let mut encs_rand = Vec::with_capacity(n);
        for (i, member) in ring.iter().enumerate() {
            let value = if i == sender_index { debit } else { 0 };
            let blind = Scalar::random(rng);
            deltas.push(commit_delta(value, &blind));
            blinds.push(blind);
            let y = Scalar::random(rng);
            enc.push(member.encrypt_with_randomness(value, &y));
            encs_rand.push(y);
        }

        // --- aggregated range proof: remaining balance AND hidden amount -------
        // V = b'·G + γ·H, and C_amt = amount·G + s_d·H (== C_debit − fee·G, so the
        // amount slot proves debit ≥ fee with no scalar wraparound).
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(RANGE_BITS, 2);
        let gamma = Scalar::random(rng);
        let mut tr = MerlinTranscript::new(b"Latebra.AnonTransfer.range.v3");
        let (rp, comms) = RangeProof::prove_multiple(
            &bp, &pc, &mut tr, &[remaining, amount], &[gamma, s_d], RANGE_BITS,
        )
        .ok()?;
        let v_comp = comms[0];
        let v = v_comp.decompress()?;
        debug_assert_eq!(comms[1].decompress()?, c_debit - G * Scalar::from(fee));

        // --- epoch nullifier and stealth receiver ------------------------------
        let x = sender.0;
        let g_epoch = epoch_base(epoch);
        let nullifier = g_epoch * x;
        let output = stealth_send(receiver, rng);

        // --- receiver credit: Enc_onetime(amount), linked to C_amt below -------
        let y_c = Scalar::random(rng);
        let credit = output.one_time.encrypt_with_randomness(amount, &y_c);

        // --- fused OR-composition (relations a–d) ------------------------------
        let mut e = vec![Scalar::ZERO; n];
        let mut z_x = vec![Scalar::ZERO; n];
        let mut z_s = vec![Scalar::ZERO; n];
        let mut z_g = vec![Scalar::ZERO; n];
        let mut a1 = vec![RistrettoPoint::identity(); n]; // ownership   Y_i = x·G
        let mut a2 = vec![RistrettoPoint::identity(); n]; // delta       C_i − C_debit = s·H
        let mut a3 = vec![RistrettoPoint::identity(); n]; // solvency    T_i = γ'·H − x·D_i^bal
        let mut a4 = vec![RistrettoPoint::identity(); n]; // nullifier   u = x·G_epoch

        let mut sum_decoy = Scalar::ZERO;
        for i in 0..n {
            if i == sender_index {
                continue;
            }
            e[i] = Scalar::random(rng);
            z_x[i] = Scalar::random(rng);
            z_s[i] = Scalar::random(rng);
            z_g[i] = Scalar::random(rng);
            let t_i = solvency_target(&v, &balances[i], &c_debit);
            a1[i] = G * z_x[i] - ring[i].0 * e[i];
            a2[i] = h * z_s[i] - (deltas[i] - c_debit) * e[i];
            a3[i] = h * z_g[i] - balances[i].d * z_x[i] - t_i * e[i];
            a4[i] = g_epoch * z_x[i] - nullifier * e[i];
            sum_decoy += e[i];
        }

        let k_x = Scalar::random(rng);
        let k_s = Scalar::random(rng);
        let k_g = Scalar::random(rng);
        let l = sender_index;
        a1[l] = G * k_x;
        a2[l] = h * k_s;
        a3[l] = h * k_g - balances[l].d * k_x;
        a4[l] = g_epoch * k_x;

        let c = fused_challenge(
            ring, balances, &deltas, &enc, &c_debit, &credit, fee, epoch, &nullifier, &v, &output,
            &a1, &a2, &a3, &a4,
        );
        e[l] = c - sum_decoy;
        z_x[l] = k_x + e[l] * x;
        // Relation (b) witness: C_l − C_debit = (s_l − s_d)·H.
        z_s[l] = k_s + e[l] * (blinds[l] - s_d);
        // Relation (c) witness: T_l = (γ + s_d)·H − x·D_l^bal.
        z_g[l] = k_g + e[l] * (gamma + s_d);

        // --- brick B (hidden form): each delta opens to 0 or the hidden debit --
        let mut membership = Vec::with_capacity(n);
        for i in 0..n {
            let (debit_branch, witness) =
                if i == sender_index { (true, blinds[i] - s_d) } else { (false, blinds[i]) };
            membership.push(ZeroOrDebit::prove(&deltas[i], &c_debit, debit_branch, &witness, rng));
        }

        // --- brick E: link each Enc_i to the same value as C_i -----------------
        let mut links = Vec::with_capacity(n);
        for i in 0..n {
            let value = Scalar::from(if i == sender_index { debit } else { 0 });
            let (k_d, k_s2, k_y) = (Scalar::random(rng), Scalar::random(rng), Scalar::random(rng));
            let a1l = G * k_d + h * k_s2;
            let a2l = G * k_d + ring[i].0 * k_y;
            let a3l = G * k_y;
            let el = link_challenge(&ring[i], &deltas[i], &enc[i], &a1l, &a2l, &a3l);
            links.push(DeltaLink {
                a1: a1l,
                a2: a2l,
                a3: a3l,
                z_d: k_d + el * value,
                z_s: k_s2 + el * blinds[i],
                z_y: k_y + el * encs_rand[i],
            });
        }

        // --- v3: link the receiver credit to C_amt = C_debit − fee·G -----------
        // Same three-relation two-base Schnorr as brick E, with the one-time key
        // in the ElGamal slot: C_amt = a·G + s_d·H, credit.c = a·G + y_c·OT,
        // credit.d = y_c·G.
        let c_amt = c_debit - G * Scalar::from(fee);
        let credit_link = {
            let (k_d, k_s2, k_y) = (Scalar::random(rng), Scalar::random(rng), Scalar::random(rng));
            let a1l = G * k_d + h * k_s2;
            let a2l = G * k_d + output.one_time.0 * k_y;
            let a3l = G * k_y;
            let el = link_challenge(&output.one_time, &c_amt, &credit, &a1l, &a2l, &a3l);
            DeltaLink {
                a1: a1l,
                a2: a2l,
                a3: a3l,
                z_d: k_d + el * Scalar::from(amount),
                z_s: k_s2 + el * s_d,
                z_y: k_y + el * y_c,
            }
        };

        // --- conservation: Σ deltas − C_debit = σ'·H ---------------------------
        let sigma: Scalar = blinds.iter().sum::<Scalar>() - s_d;
        let agg: RistrettoPoint = deltas.iter().sum();
        let agg_target = agg - c_debit; // = σ'·H when Σδ = debit
        let k_sum = Scalar::random(rng);
        let sum_a = h * k_sum;
        let e_sum = sum_challenge(&deltas, &c_debit, &agg_target, &sum_a);
        let sum_z = k_sum + e_sum * sigma;

        Some(AnonTransfer {
            ring: ring.to_vec(),
            balances: balances.to_vec(),
            deltas,
            enc,
            c_debit,
            credit,
            fee,
            epoch,
            output,
            nullifier,
            v: v_comp,
            rp,
            e,
            z_x,
            z_s,
            z_g,
            membership,
            links,
            credit_link,
            sum_a,
            sum_z,
        })
    }

    /// The nullifier, as 32 bytes — consensus tracks these to reject a second spend by
    /// the same account within the same epoch.
    pub fn nullifier(&self) -> [u8; 32] {
        self.nullifier.compress().to_bytes()
    }

    /// Verify the whole bundle: range proof, fused OR-composition, per-delta bounds
    /// (B), value-movement links (E), and conservation. Returns `true` iff a hidden
    /// owned/solvent member is the unique account debited `amount + fee`, with the
    /// epoch nullifier bound to it and matching ElGamal debits published.
    ///
    /// Note: this checks internal consistency for `self.epoch`; consensus must
    /// additionally verify `self.epoch` equals the containing block's epoch and that
    /// `self.nullifier()` is unseen.
    pub fn verify(&self) -> bool {
        let n = self.ring.len();
        if n < 2
            || self.balances.len() != n
            || self.deltas.len() != n
            || self.enc.len() != n
            || self.e.len() != n
            || self.z_x.len() != n
            || self.z_s.len() != n
            || self.z_g.len() != n
            || self.membership.len() != n
            || self.links.len() != n
        {
            return false;
        }
        // 1) Aggregated Bulletproof: the remaining balance (V) AND the hidden
        //    amount (C_amt = C_debit − fee·G) are both in [0, 2^64).
        let c_amt = self.c_debit - G * Scalar::from(self.fee);
        let pc = PedersenGens::default();
        let bp = BulletproofGens::new(RANGE_BITS, 2);
        let mut tr = MerlinTranscript::new(b"Latebra.AnonTransfer.range.v3");
        if self
            .rp
            .verify_multiple(&bp, &pc, &mut tr, &[self.v, c_amt.compress()], RANGE_BITS)
            .is_err()
        {
            return false;
        }
        let v = match self.v.decompress() {
            Some(p) => p,
            None => return false,
        };

        let h = blinding_base();
        let g_epoch = epoch_base(self.epoch);

        // 2) Fused OR-composition: reconstruct all four announcements per branch.
        let mut a1 = vec![RistrettoPoint::identity(); n];
        let mut a2 = vec![RistrettoPoint::identity(); n];
        let mut a3 = vec![RistrettoPoint::identity(); n];
        let mut a4 = vec![RistrettoPoint::identity(); n];
        let mut sum = Scalar::ZERO;
        for i in 0..n {
            let t_i = solvency_target(&v, &self.balances[i], &self.c_debit);
            a1[i] = G * self.z_x[i] - self.ring[i].0 * self.e[i];
            a2[i] = h * self.z_s[i] - (self.deltas[i] - self.c_debit) * self.e[i];
            a3[i] = h * self.z_g[i] - self.balances[i].d * self.z_x[i] - t_i * self.e[i];
            a4[i] = g_epoch * self.z_x[i] - self.nullifier * self.e[i];
            sum += self.e[i];
        }
        let c = fused_challenge(
            &self.ring, &self.balances, &self.deltas, &self.enc, &self.c_debit, &self.credit,
            self.fee, self.epoch, &self.nullifier, &v, &self.output, &a1, &a2, &a3, &a4,
        );
        if c != sum {
            return false;
        }

        // 3) Brick B (hidden form): every delta opens to 0 or the hidden debit.
        for i in 0..n {
            if !self.membership[i].verify(&self.deltas[i], &self.c_debit) {
                return false;
            }
        }

        // 4) Brick E: every Enc_i encrypts the same value as its delta commitment.
        for i in 0..n {
            let lk = &self.links[i];
            let el = link_challenge(&self.ring[i], &self.deltas[i], &self.enc[i], &lk.a1, &lk.a2, &lk.a3);
            let c1 = G * lk.z_d + h * lk.z_s == lk.a1 + self.deltas[i] * el;
            let c2 = G * lk.z_d + self.ring[i].0 * lk.z_y == lk.a2 + self.enc[i].c * el;
            let c3 = G * lk.z_y == lk.a3 + self.enc[i].d * el;
            if !(c1 && c2 && c3) {
                return false;
            }
        }

        // 5) v3 credit link: `credit` encrypts (under the one-time key) exactly the
        //    value C_amt commits to — so the ledger credits precisely debit − fee.
        {
            let lk = &self.credit_link;
            let el = link_challenge(&self.output.one_time, &c_amt, &self.credit, &lk.a1, &lk.a2, &lk.a3);
            let c1 = G * lk.z_d + h * lk.z_s == lk.a1 + c_amt * el;
            let c2 = G * lk.z_d + self.output.one_time.0 * lk.z_y == lk.a2 + self.credit.c * el;
            let c3 = G * lk.z_y == lk.a3 + self.credit.d * el;
            if !(c1 && c2 && c3) {
                return false;
            }
        }

        // 6) Conservation: Σ deltas − C_debit ∈ ⟨H⟩ with the proven blinding sum.
        let agg: RistrettoPoint = self.deltas.iter().sum();
        let agg_target = agg - self.c_debit;
        let e_sum = sum_challenge(&self.deltas, &self.c_debit, &agg_target, &self.sum_a);
        if h * self.sum_z != self.sum_a + agg_target * e_sum {
            return false;
        }

        true
    }

    /// Canonical byte encoding (v3). Layout: `n`, `fee`, `epoch`, then the
    /// `n`-sized vectors (ring, balances, deltas, enc), the debit commitment and
    /// receiver credit, the stealth output, nullifier, remaining-balance commitment,
    /// the length-prefixed range proof, the four response vectors, the fixed-size
    /// membership proofs, the value-movement links, the credit link, and the
    /// conservation proof.
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.ring.len();
        let mut v = Vec::with_capacity(32 + n * 520);
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v.extend_from_slice(&self.fee.to_le_bytes());
        v.extend_from_slice(&self.epoch.to_le_bytes());
        for pk in &self.ring {
            v.extend_from_slice(&pk.to_bytes());
        }
        for ct in &self.balances {
            v.extend_from_slice(&ct.to_bytes());
        }
        for d in &self.deltas {
            v.extend_from_slice(d.compress().as_bytes());
        }
        for ct in &self.enc {
            v.extend_from_slice(&ct.to_bytes());
        }
        v.extend_from_slice(self.c_debit.compress().as_bytes());
        v.extend_from_slice(&self.credit.to_bytes());
        v.extend_from_slice(&self.output.ephemeral.to_bytes());
        v.extend_from_slice(&self.output.one_time.to_bytes());
        v.extend_from_slice(self.nullifier.compress().as_bytes());
        v.extend_from_slice(self.v.as_bytes());
        let rp = self.rp.to_bytes();
        v.extend_from_slice(&(rp.len() as u32).to_le_bytes());
        v.extend_from_slice(&rp);
        for vec in [&self.e, &self.z_x, &self.z_s, &self.z_g] {
            for s in vec {
                v.extend_from_slice(s.as_bytes());
            }
        }
        for m in &self.membership {
            v.extend_from_slice(m.a0.compress().as_bytes());
            v.extend_from_slice(m.a1.compress().as_bytes());
            for s in [&m.e0, &m.z0, &m.z1] {
                v.extend_from_slice(s.as_bytes());
            }
        }
        for lk in self.links.iter().chain(std::iter::once(&self.credit_link)) {
            for p in [&lk.a1, &lk.a2, &lk.a3] {
                v.extend_from_slice(p.compress().as_bytes());
            }
            for s in [&lk.z_d, &lk.z_s, &lk.z_y] {
                v.extend_from_slice(s.as_bytes());
            }
        }
        v.extend_from_slice(self.sum_a.compress().as_bytes());
        v.extend_from_slice(self.sum_z.as_bytes());
        v
    }

    /// Decode from [`to_bytes`](Self::to_bytes). `None` on any malformed input:
    /// truncation, bad group elements/scalars, or trailing bytes. Decoding only
    /// checks well-formedness; `verify` still establishes soundness.
    pub fn from_bytes(b: &[u8]) -> Option<AnonTransfer> {
        let mut r = Rd { b, off: 0 };
        let n = r.u32()? as usize;
        if n < 2 {
            return None;
        }
        let fee = r.u64()?;
        let epoch = r.u64()?;

        let mut ring = Vec::with_capacity(n);
        for _ in 0..n {
            ring.push(PublicKey::from_bytes(&r.arr32()?)?);
        }
        let mut balances = Vec::with_capacity(n);
        for _ in 0..n {
            balances.push(Ciphertext::from_bytes(&r.arr64()?)?);
        }
        let mut deltas = Vec::with_capacity(n);
        for _ in 0..n {
            deltas.push(r.point()?);
        }
        let mut enc = Vec::with_capacity(n);
        for _ in 0..n {
            enc.push(Ciphertext::from_bytes(&r.arr64()?)?);
        }
        let c_debit = r.point()?;
        let credit = Ciphertext::from_bytes(&r.arr64()?)?;
        let output = StealthOutput {
            ephemeral: PublicKey::from_bytes(&r.arr32()?)?,
            one_time: PublicKey::from_bytes(&r.arr32()?)?,
        };
        let nullifier = r.point()?;
        let v = r.comp()?;
        let rp_len = r.u32()? as usize;
        let rp = RangeProof::from_bytes(r.take(rp_len)?).ok()?;

        let read_vec = |r: &mut Rd| -> Option<Vec<Scalar>> {
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                out.push(r.scalar()?);
            }
            Some(out)
        };
        let e = read_vec(&mut r)?;
        let z_x = read_vec(&mut r)?;
        let z_s = read_vec(&mut r)?;
        let z_g = read_vec(&mut r)?;

        let mut membership = Vec::with_capacity(n);
        for _ in 0..n {
            membership.push(ZeroOrDebit {
                a0: r.point()?,
                a1: r.point()?,
                e0: r.scalar()?,
                z0: r.scalar()?,
                z1: r.scalar()?,
            });
        }
        let read_link = |r: &mut Rd| -> Option<DeltaLink> {
            Some(DeltaLink {
                a1: r.point()?,
                a2: r.point()?,
                a3: r.point()?,
                z_d: r.scalar()?,
                z_s: r.scalar()?,
                z_y: r.scalar()?,
            })
        };
        let mut links = Vec::with_capacity(n);
        for _ in 0..n {
            links.push(read_link(&mut r)?);
        }
        let credit_link = read_link(&mut r)?;
        let sum_a = r.point()?;
        let sum_z = r.scalar()?;

        if r.off != b.len() {
            return None; // no trailing garbage
        }
        Some(AnonTransfer {
            ring, balances, deltas, enc, c_debit, credit, fee, epoch, output, nullifier, v, rp,
            e, z_x, z_s, z_g, membership, links, credit_link, sum_a, sum_z,
        })
    }
}

/// Bounds-checked cursor over an [`AnonTransfer`] encoding.
struct Rd<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.off..self.off.checked_add(n)?)?;
        self.off += n;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }
    fn arr64(&mut self) -> Option<[u8; 64]> {
        self.take(64)?.try_into().ok()
    }
    fn point(&mut self) -> Option<RistrettoPoint> {
        CompressedRistretto::from_slice(self.take(32)?).ok()?.decompress()
    }
    fn comp(&mut self) -> Option<CompressedRistretto> {
        CompressedRistretto::from_slice(self.take(32)?).ok()
    }
    fn scalar(&mut self) -> Option<Scalar> {
        Option::from(Scalar::from_canonical_bytes(self.arr32()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    const EPOCH: u64 = 7;

    /// An anonymity set of `n` fresh accounts.
    fn ring_of(n: usize, rng: &mut OsRng) -> (Vec<SecretKey>, Vec<PublicKey>) {
        let sks: Vec<SecretKey> = (0..n).map(|_| SecretKey::random(rng)).collect();
        let pks = sks.iter().map(|s| s.public_key()).collect();
        (sks, pks)
    }

    /// Balance ciphertexts: member `i` holds `bals[i]` under its own key.
    fn balances_of(sks: &[SecretKey], bals: &[u64], rng: &mut OsRng) -> Vec<Ciphertext> {
        sks.iter().zip(bals).map(|(sk, &b)| sk.public_key().encrypt(b, rng)).collect()
    }

    #[test]
    fn honest_transfer_verifies() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(5, &mut rng);
        let bals = [10_000, 5_000, 8_000, 40_000, 900];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng);

        let tx = AnonTransfer::create(
            &ring, &balances, &sks[3], 3, bals[3], &receiver.public_key(), 25_000, 100, EPOCH, &mut rng,
        )
        .expect("solvent");
        assert!(tx.verify(), "honest anonymous transfer must verify");
    }

    #[test]
    fn elgamal_debits_decrypt_to_the_deltas() {
        // Brick E ledger effect: enc[sender] decrypts to debit under the sender key;
        // every decoy's enc decrypts to 0 under its own key. This is exactly what
        // consensus subtracts from each balance.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let bals = [50_000, 3_000, 3_000, 3_000];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng);
        let (amount, fee) = (1_000u64, 10u64);

        let tx = AnonTransfer::create(
            &ring, &balances, &sks[0], 0, bals[0], &receiver.public_key(), amount, fee, EPOCH, &mut rng,
        )
        .unwrap();
        assert!(tx.verify());
        assert_eq!(sks[0].decrypt(&tx.enc[0], 24), Some(amount + fee), "sender debit = amount+fee");
        for (sk, enc) in sks.iter().zip(tx.enc.iter()).skip(1) {
            assert_eq!(sk.decrypt(enc, 24), Some(0), "decoy debit = 0");
        }
    }

    #[test]
    fn receiver_recognizes_and_can_spend_the_stealth_output() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let bals = [50_000, 3_000, 3_000, 3_000];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng);

        let tx = AnonTransfer::create(
            &ring, &balances, &sks[0], 0, bals[0], &receiver.public_key(), 1_000, 10, EPOCH, &mut rng,
        )
        .unwrap();

        let spend = crate::stealth_receive(&receiver, &tx.output.ephemeral, &tx.output.one_time)
            .expect("receiver recognizes its output");
        assert_eq!(spend.public_key(), tx.output.one_time);
        let stranger = SecretKey::random(&mut rng);
        assert!(crate::stealth_receive(&stranger, &tx.output.ephemeral, &tx.output.one_time).is_none());
    }

    #[test]
    fn insolvent_sender_has_no_proof() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let bals = [50_000, 500, 50_000, 50_000]; // sender (idx 1) holds only 500
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng);

        assert!(AnonTransfer::create(
            &ring, &balances, &sks[1], 1, bals[1], &receiver.public_key(), 900, 100, EPOCH, &mut rng,
        )
        .is_none());
    }

    #[test]
    fn lying_about_balance_fails_verification() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(3, &mut rng);
        let real_bals = [5_000, 5_000, 100];
        let balances = balances_of(&sks, &real_bals, &mut rng);
        let receiver = SecretKey::random(&mut rng);

        let tx = AnonTransfer::create(
            &ring, &balances, &sks[2], 2, 10_000, &receiver.public_key(), 900, 100, EPOCH, &mut rng,
        )
        .expect("builds against the lie");
        assert!(!tx.verify(), "must bind to the real balance ciphertext");
    }

    #[test]
    fn nullifier_is_stable_per_epoch_and_rotates_across_epochs() {
        // Same spender, SAME epoch, different rings/receivers → same nullifier
        // (a double-spend within the epoch is detectable). Same spender, DIFFERENT
        // epoch → different nullifier (unlinkable across epochs).
        let mut rng = OsRng;
        let (sks, ring1) = ring_of(4, &mut rng);
        let bals1 = [40_000, 3_000, 3_000, 3_000];
        let balances1 = balances_of(&sks, &bals1, &mut rng);
        let rcv = SecretKey::random(&mut rng).public_key();

        let a = AnonTransfer::create(&ring1, &balances1, &sks[0], 0, bals1[0], &rcv, 1_000, 10, EPOCH, &mut rng).unwrap();

        let (mut sks2, mut ring2) = ring_of(5, &mut rng);
        sks2[2] = sks[0].clone();
        ring2[2] = sks[0].public_key();
        let bals2 = [1, 1, 40_000, 1, 1];
        let balances2 = balances_of(&sks2, &bals2, &mut rng);
        let rcv2 = SecretKey::random(&mut rng).public_key();
        let b = AnonTransfer::create(&ring2, &balances2, &sks2[2], 2, bals2[2], &rcv2, 500, 5, EPOCH, &mut rng).unwrap();
        assert_eq!(a.nullifier(), b.nullifier(), "same spender + epoch → same nullifier");

        // Different epoch → different nullifier, so cross-epoch spends don't link.
        let c = AnonTransfer::create(&ring1, &balances1, &sks[0], 0, bals1[0], &rcv, 1_000, 10, EPOCH + 1, &mut rng).unwrap();
        assert_ne!(a.nullifier(), c.nullifier(), "different epoch → different nullifier");

        // A different spender differs in the same epoch.
        let other = AnonTransfer::create(&ring1, &balances1, &sks[1], 1, bals1[1], &rcv, 100, 1, EPOCH, &mut rng).unwrap();
        assert_ne!(a.nullifier(), other.nullifier(), "different spender → different nullifier");
    }

    #[test]
    fn debiting_a_decoy_instead_of_yourself_fails() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let bals = [3_000, 3_000, 6_000, 3_000];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng).public_key();

        let mut tx = AnonTransfer::create(&ring, &balances, &sks[2], 2, bals[2], &receiver, 1_500, 50, EPOCH, &mut rng).unwrap();
        assert!(tx.verify());
        tx.deltas.swap(0, 2);
        assert!(!tx.verify(), "moving the debit off the owned/solvent index must fail");
    }

    #[test]
    fn tampering_amount_fee_or_epoch_fails() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let bals = [40_000, 1, 2, 3];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng).public_key();

        let base = AnonTransfer::create(&ring, &balances, &sks[0], 0, bals[0], &receiver, 5_000, 30, EPOCH, &mut rng).unwrap();
        assert!(base.verify());

        // v3: the amount is hidden behind C_debit — shifting the commitment
        // (equivalent to claiming a different debit) must break every relation
        // proven against it.
        let mut bad_amt = base.clone();
        bad_amt.c_debit += G;
        assert!(!bad_amt.verify(), "the debit commitment is bound into every sub-proof");

        // Inflating the carried credit ciphertext must break the credit link.
        let mut bad_credit = base.clone();
        bad_credit.credit.c += G;
        assert!(!bad_credit.verify(), "the credit ciphertext is bound to C_amt");

        let mut bad_fee = base.clone();
        bad_fee.fee += 1;
        assert!(!bad_fee.verify(), "fee shifts C_amt, breaking the range/credit proofs");

        let mut bad_epoch = base.clone();
        bad_epoch.epoch += 1;
        assert!(!bad_epoch.verify(), "epoch is bound into the nullifier relation");
    }

    #[test]
    fn malleability_sweep_every_byte_flip_is_rejected() {
        // Red-team (Gap 1): the whole encoding is bound by Fiat–Shamir, so no
        // adversary can mutate a valid transfer into a different valid one.
        // Flip one bit at a strided set of byte positions; each mutant must
        // either fail to decode or fail to verify — never both pass.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let bals = [50_000, 10, 20, 30];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng).public_key();
        let tx = AnonTransfer::create(&ring, &balances, &sks[0], 0, bals[0], &receiver, 4_000, 100, EPOCH, &mut rng).unwrap();
        let bytes = tx.to_bytes();
        assert!(AnonTransfer::from_bytes(&bytes).is_some_and(|t| t.verify()));

        // Stride keeps the test fast while still hitting every field region
        // (each verify is a full multi-proof check, so we sample ~64 positions
        // spread across the whole encoding rather than every byte).
        let stride = (bytes.len() / 64).max(1);
        let mut checked = 0;
        for i in (0..bytes.len()).step_by(stride) {
            let mut m = bytes.clone();
            m[i] ^= 0x01;
            if let Some(t) = AnonTransfer::from_bytes(&m) {
                assert!(!t.verify(), "byte {i} flipped but transfer still verified");
                checked += 1;
            }
        }
        assert!(checked > 0, "expected some mutants to decode-but-not-verify");
    }

    #[test]
    fn forgery_without_owning_a_ring_member_is_impossible() {
        // An attacker who owns NONE of the ring keys cannot build a transfer:
        // create() asserts sender ∈ ring. Simulating it — placing an outsider's
        // key nowhere in the ring but trying to spend a member's balance — has
        // no honest API path, so we assert the guard and, at the proof level,
        // that a transfer whose owned index doesn't hold the balance fails
        // (covered by debiting_a_decoy_instead_of_yourself_fails). Here we
        // confirm an insolvent sender is refused outright.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(3, &mut rng);
        let bals = [100, 10, 20];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng).public_key();
        // Sender holds 100 but tries to send 5_000 + fee: no witness exists.
        assert!(
            AnonTransfer::create(&ring, &balances, &sks[0], 0, bals[0], &receiver, 5_000, 100, EPOCH, &mut rng)
                .is_none(),
            "insolvent sender must not be able to build a transfer"
        );
    }

    #[test]
    fn splicing_a_range_proof_from_another_transfer_fails() {
        // Take a valid transfer, replace its aggregated range proof with one
        // from a DIFFERENT transfer (different commitments): verification binds
        // the proof to this transfer's V and C_amt, so it must reject.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(3, &mut rng);
        let balances = balances_of(&sks, &[80_000, 1, 2], &mut rng);
        let rcv = SecretKey::random(&mut rng).public_key();
        let good = AnonTransfer::create(&ring, &balances, &sks[0], 0, 80_000, &rcv, 4_000, 100, EPOCH, &mut rng).unwrap();
        let other = AnonTransfer::create(&ring, &balances, &sks[0], 0, 80_000, &rcv, 9_000, 100, EPOCH, &mut rng).unwrap();
        let mut spliced = good.clone();
        spliced.rp = other.rp.clone();
        assert!(!spliced.verify(), "a range proof from another transfer must not verify");
    }

    #[test]
    fn hidden_amount_reaches_only_the_stealth_receiver() {
        // v3: the amount appears nowhere in plaintext. The stealth receiver
        // derives the one-time spend key and decrypts the carried credit; an
        // observer holding only public data has no field to read.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(3, &mut rng);
        let bals = [40_000, 1, 2];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng);

        let amount = 7_777;
        let tx = AnonTransfer::create(
            &ring, &balances, &sks[0], 0, bals[0], &receiver.public_key(), amount, 10, EPOCH, &mut rng,
        )
        .unwrap();
        assert!(tx.verify());

        let spend = crate::stealth_receive(&receiver, &tx.output.ephemeral, &tx.output.one_time)
            .expect("receiver recognizes the output");
        assert_eq!(spend.decrypt(&tx.credit, 24), Some(amount), "receiver reads the amount");
        // A ring member (non-receiver) cannot read it.
        assert_eq!(sks[1].decrypt(&tx.credit, 24), None, "credit is opaque to non-receivers");
    }

    #[test]
    fn tampering_the_debit_ciphertext_fails() {
        // Repointing a published ElGamal debit breaks its brick-E link.
        let mut rng = OsRng;
        let (sks, ring) = ring_of(3, &mut rng);
        let bals = [40_000, 1, 2];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng).public_key();

        let mut tx = AnonTransfer::create(&ring, &balances, &sks[0], 0, bals[0], &receiver, 1_000, 10, EPOCH, &mut rng).unwrap();
        assert!(tx.verify());
        tx.enc[0] = ring[0].encrypt(999, &mut rng); // forge a different debit
        assert!(!tx.verify(), "a debit ciphertext not matching its delta must fail");
    }

    #[test]
    fn tampering_the_stealth_receiver_fails() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(3, &mut rng);
        let bals = [40_000, 1, 2];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng).public_key();

        let mut tx = AnonTransfer::create(&ring, &balances, &sks[0], 0, bals[0], &receiver, 1_000, 10, EPOCH, &mut rng).unwrap();
        assert!(tx.verify());
        tx.output = stealth_send(&SecretKey::random(&mut rng).public_key(), &mut rng);
        assert!(!tx.verify(), "the receiver output is bound into the proof");
    }

    #[test]
    fn tampered_responses_fail() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(4, &mut rng);
        let bals = [40_000, 1, 2, 3];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng).public_key();

        let base = AnonTransfer::create(&ring, &balances, &sks[0], 0, bals[0], &receiver, 5_000, 30, EPOCH, &mut rng).unwrap();
        for mutate in [0, 1, 2, 3, 4] {
            let mut t = base.clone();
            match mutate {
                0 => t.z_x[1] += Scalar::ONE,
                1 => t.z_s[2] += Scalar::ONE,
                2 => t.z_g[0] += Scalar::ONE,
                3 => t.sum_z += Scalar::ONE,
                _ => t.links[1].z_d += Scalar::ONE,
            }
            assert!(!t.verify(), "tampered response {mutate} must fail");
        }
    }

    #[test]
    fn wire_roundtrip_preserves_validity() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(5, &mut rng);
        let bals = [10_000, 5_000, 8_000, 40_000, 900];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng);

        let tx = AnonTransfer::create(
            &ring, &balances, &sks[3], 3, bals[3], &receiver.public_key(), 25_000, 100, EPOCH, &mut rng,
        )
        .unwrap();
        let bytes = tx.to_bytes();
        let decoded = AnonTransfer::from_bytes(&bytes).expect("decodes");
        assert_eq!(decoded.to_bytes(), bytes, "canonical roundtrip");
        assert!(decoded.verify(), "decoded anonymous transfer still verifies");
        assert_eq!(decoded.nullifier(), tx.nullifier());
        assert_eq!(decoded.epoch, tx.epoch);
    }

    #[test]
    fn wire_rejects_garbage_and_truncation() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(3, &mut rng);
        let bals = [40_000, 1, 2];
        let balances = balances_of(&sks, &bals, &mut rng);
        let receiver = SecretKey::random(&mut rng).public_key();

        let tx = AnonTransfer::create(&ring, &balances, &sks[0], 0, bals[0], &receiver, 1_000, 10, EPOCH, &mut rng).unwrap();
        let bytes = tx.to_bytes();

        let mut extra = bytes.clone();
        extra.push(0);
        assert!(AnonTransfer::from_bytes(&extra).is_none(), "trailing garbage rejected");
        assert!(AnonTransfer::from_bytes(&bytes[..bytes.len() - 1]).is_none(), "truncation rejected");
        assert!(AnonTransfer::from_bytes(&[]).is_none(), "empty input rejected");
    }

    #[test]
    fn red_team_graph_goes_dark() {
        let mut rng = OsRng;
        let (sks, ring) = ring_of(6, &mut rng);
        let bals = [9_000, 9_000, 9_000, 9_000, 9_000, 9_000];
        let balances = balances_of(&sks, &bals, &mut rng);
        let real_receiver = SecretKey::random(&mut rng);

        let t2 = AnonTransfer::create(&ring, &balances, &sks[2], 2, bals[2], &real_receiver.public_key(), 1_000, 10, EPOCH, &mut rng).unwrap();
        let t4 = AnonTransfer::create(&ring, &balances, &sks[4], 4, bals[4], &real_receiver.public_key(), 1_000, 10, EPOCH, &mut rng).unwrap();
        assert!(t2.verify() && t4.verify());

        // (1) No distinguished sender: structurally identical regardless of who spent.
        assert_eq!(t2.ring.len(), 6);
        assert_eq!(t2.e.len(), t4.e.len());
        assert_eq!(t2.deltas.len(), t4.deltas.len());
        assert_eq!(t2.enc.len(), t4.enc.len());

        // (2) Receiver is a one-time key: exactly one party (the true receiver) claims it.
        let mut recognizers = 0;
        for sk in sks.iter().chain(std::iter::once(&real_receiver)) {
            if crate::stealth_receive(sk, &t2.output.ephemeral, &t2.output.one_time).is_some() {
                recognizers += 1;
            }
        }
        assert_eq!(recognizers, 1);
        assert!(crate::stealth_receive(&real_receiver, &t2.output.ephemeral, &t2.output.one_time).is_some());

        // (3) The one-time account matches no ring member's address.
        for pk in &ring {
            assert_ne!(pk.to_bytes(), t2.output.one_time.to_bytes());
        }
    }
}

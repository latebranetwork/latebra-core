# Anonymous Spend — construction blueprint (Phase 3b)

> **Status: DESIGN + partial primitives. UNAUDITED. Not wired into consensus.**
>
> This document specifies how Latebra will hide the **sender/origin** of a
> value-carrying spend (the private→public unshield, and later private→private
> transfers). It is the blueprint for a multi-session, **audit-gated** effort — no
> transaction type described here is live, and none must carry real value before a
> professional cryptographic audit. See [`PRIVACY_ARCHITECTURE.md`](PRIVACY_ARCHITECTURE.md)
> Phase 3b.

---

## The problem, precisely

Today a confidential spend (`SolventTransfer`, and the `Unshield` built on it)
names `sender` in the clear. Phase 3b must let a spender prove:

1. **Ownership (anonymous):** they control *one* account in a public anonymity
   set `{Y_0 … Y_{N-1}}`, without revealing which.
2. **Solvency of that hidden account:** the *same* hidden account holds at least
   `amount + fee`, i.e. its balance minus the spend stays `≥ 0`.
3. **No double-spend:** a key image / nullifier that is deterministic per account
   but unlinkable to which one, so the same authorization can't be replayed.
4. **Conservation:** exactly `amount` leaves the (hidden) sender — decoys are
   untouched.

The trap this avoids: an "authorize with a ring, debit whoever you like" scheme
is **money-stealing** — you'd ring yourself with a rich decoy and debit the
decoy. Soundness *requires* binding the debited account to the owned account and
proving *that* account solvent.

## The four bricks

| # | Brick | Statement | Status |
|---|---|---|---|
| A | **Ownership + key image** | know `x` with `Y_l = x·G`; publish `I = x·H_p(Y_l)` | ✅ `ring.rs` `LinkableRingSignature` (LSAG) |
| B | **Decoy bounds** | each delta commitment `C_i` opens to a value in `{0, amount}` | ✅ `membership.rs` `ValueInSetProof` |
| C | **Index binding** | ∃ hidden `l`: prover owns `Y_l` **and** `C_l` commits to `amount` | ✅ `index_binding.rs` `IndexBindingProof` (unaudited) |
| D | **Hidden-index solvency** | the balance of the hidden `Y_l`, after `−amount−fee`, is `≥ 0` | ✅ *this turn* — `hidden_solvency.rs` `HiddenSolventSpend` (unaudited); **fuses C+D**, see below |

Bricks A + B + C together already force: *the account you own is the (only)
account debited `amount`, and decoys are debited `0`* — the anti-theft property.
Brick **D** adds the last missing guarantee — that the hidden owner could *afford*
it — implemented as a linear-size (`O(N)`) CDS one-of-many tied to a Bulletproofs
range proof on the remaining balance.

### Why D fuses ownership + delta-binding (brick C) rather than standing alone

Solvency must hold at the **same** hidden index that is debited. If D were a
*separate* OR-composition from C, a prover owning **two** ring members — one rich,
one poor — could bind the `amount` delta to the poor account (debiting it) while
proving the *rich* account solvent; the poor account then goes negative → inflation.
So `HiddenSolventSpend` proves, in **one** OR-composition sharing the branch
challenge and the witness `x`, all three per-branch relations:

```text
  (1) Y_i                            = x·G                    (ownership)
  (2) C_i − amount·G                 = s·H                    (debited = amount)
  (3) V − C_i^bal + (amount+fee)·G   = γ·H − x·D_i^bal        (solvency)
```

with `V = b'·G + γ·H` the Bulletproofs commitment to `b' = b_i − amount − fee`; the
range proof `V ∈ [0,2^64)` gives `b' ≥ 0`. This is the *index-consistent selection +
range binding* the section below flags as where unsoundness hides — hence the fusion.
Because it subsumes C, an integration using `HiddenSolventSpend` does not also need a
separate `IndexBindingProof`.

## How A + B + C compose (sound today, as primitives)

Let each anonymity-set member `i` carry a Pedersen delta commitment
`C_i = δ_i·G + r_i·H`, where `δ_l = amount` for the real sender and `δ_i = 0` for
every decoy.

- **B (per member):** a `ValueInSetProof` that `C_i` opens to `{0, amount}` — a
  decoy can't be assigned a secret theft amount.
- **Conservation:** the homomorphic sum `ΣC_i = amount·G + (Σr_i)·H`; a Schnorr
  proof of knowledge of `Σr_i` over `ΣC_i − amount·G ∈ ⟨H⟩` shows *exactly one*
  member carries `amount` (given each is in `{0, amount}`).
- **C (index binding):** an `IndexBindingProof` OR-composition whose real branch
  proves, for the *owned* index `l`, both `Y_l = x·G` **and**
  `C_l − amount·G = r_l·H`. This nails the `amount` delta to the account the
  prover actually owns.
- **A (LSAG):** the key image `I` prevents replay/double-spend.

## Brick D (built as a primitive — why it's still audit-gated)

Solvency must be proven for the balance at the **hidden** index. Each member's
on-chain balance is an ElGamal ciphertext `(C_i^{bal}, D_i^{bal})` under `Y_i`.
The spender must show that `balance_l − amount − fee ≥ 0` *without revealing `l`*.
This is the **Anonymous-Zether "many-out-of-many"** step: a one-of-many selection
of the balance ciphertext tied (at the same secret `l`) to a Bulletproofs range
proof on the resulting remaining balance. `hidden_solvency.rs` implements the
linear-size (`O(N)`) CDS form (see the relations above). It remains research-grade:

- It re-uses the field arithmetic and Bulletproofs we already depend on, but the
  index-consistent selection + range binding is where subtle unsoundness hides —
  which is exactly why `HiddenSolventSpend` fuses ownership + delta-binding into the
  same OR-composition as the solvency relation, so all three pin the same secret `l`.
- A log-size variant (Groth–Kohlweiss) is the efficient form; the linear-size CDS
  form here is simpler to argue but `O(N)`.

**This is the audit boundary.** The primitive is unit-tested (soundness cases:
insolvency has no proof, lying about balance fails against the real ciphertext,
debiting a decoy fails, amount/fee/ring are all bound in) but **not** wired into any
transaction. Do not integrate D, or ship any of this with real value, before a
professional review.

## Integration sketch (later, post-audit)

> The full consensus-integration design — state model fork (account vs. note), epoch
> nullifiers, value-movement linking (brick E), decoy selection, and the audit
> checklist — is written up in [`ANON_INTEGRATION.md`](ANON_INTEGRATION.md).

An `AnonUnshield` / `AnonTransfer` transaction would carry: the anonymity-set ids,
the delta commitments `{C_i}`, proofs A–D, the key image, and (for unshield) the
revealed public amount + destination. Consensus would verify A–D, reject a seen
key image, apply the homomorphic deltas to every set member's balance, and (for
unshield) credit the public destination. The mempool/fee rules mirror the
existing transfer types.

## What exists after this turn

Bricks **A, B, C, D** are now all implemented and unit-tested as **primitives** —
none are wired into transactions or consensus. `HiddenSolventSpend` (brick D) fuses
C+D so the owned, debited, and solvent index are provably one and the same. What
remains is the **transaction/consensus integration** (an `AnonTransfer` /
`AnonUnshield` type, key-image tracking, applying the homomorphic deltas across the
set, mempool/fee rules) — all behind the audit gate. This mirrors how `ring.rs` and
`solvent.rs` were built (primitive-first, integrate later).

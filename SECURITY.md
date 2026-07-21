# Security policy

Latebra is a privacy chain. A flaw in its cryptography or consensus can be
unrecoverable — de-anonymising a transfer cannot be undone after the fact, and
neither can a silently inflated supply. Please report suspected issues privately
so they can be fixed before they are exploited.

## Reporting a vulnerability

**Do not open a public issue for a security bug.**

Use GitHub's private reporting:
[**Report a vulnerability**](https://github.com/latebranetwork/latebra-core/security/advisories/new)
(Security → Advisories → Report a vulnerability). This opens a private thread
visible only to the maintainers.

Please include, as far as you can:

- what breaks, and the security consequence (forged value, de-anonymisation,
  fund loss, consensus split, node crash);
- the affected component (`lat-crypto`, `lat-state`, `lat-chain`, `lat-p2p`, …)
  and the commit or release you tested;
- reproduction steps — a failing test, a transaction, or a patch against the
  repo is ideal;
- whether you have disclosed it anywhere else.

You will get an acknowledgement within **72 hours** and an assessment with a
fix timeline within **7 days**. If you do not hear back, please ping the thread
before disclosing publicly.

## Disclosure

We ask for **90 days** from acknowledgement before public disclosure, or until a
fix ships — whichever is sooner. If a flaw is being actively exploited we will
move faster and say so. We will credit you in the advisory and the changelog
unless you would rather stay anonymous.

There is **no bug bounty programme** at this stage. Latebra is unfunded and
pre-audit; we will not pretend otherwise, and we would rather say so than let a
researcher assume a reward exists.

## Scope

In scope — anything that breaks the chain's guarantees:

- **Cryptography** — the confidential/solvent transfer proofs, the Σ-protocol,
  the range proofs, stealth addresses, the anonymous-transfer construction.
- **Consensus** — supply inflation, double spends, proof-of-work or difficulty
  manipulation, fork-choice or finality faults, state-transition bugs.
- **Privacy** — anything that links a sender to a receiver, recovers an amount,
  or de-anonymises an account beyond what is documented as public in
  [CRYPTO_SPEC.md](CRYPTO_SPEC.md) and [THREAT_MODEL.md](THREAT_MODEL.md).
- **Node** — remote crashes, memory exhaustion, mempool wedging, RPC flaws.
- **Wallets** — key or seed leakage in `lat-wallet`, `lat-wallet-web`, or the
  Vault extension.

Out of scope — the **already-documented** limitations in
[TESTNET.md](TESTNET.md) §9. These are known and published, not findings:

- no network-level privacy (no Dandelion++) — the broadcasting IP is visible;
- plain-TCP P2P with no transport encryption or authentication;
- sender anonymity bounded by the ring size (≤ 16) and wallet-side decoy choice;
- not post-quantum;
- the testnet premine seeds are published in this repository on purpose, so
  spending testnet funds with them is expected, not a vulnerability;
- BLAKE3 proof-of-work being ASIC-friendly (RandomX is behind
  `--features randomx`).

If you think one of those is worse than we have documented, that *is* worth
reporting — tell us why.

## Supported versions

Latebra is **pre-audit, testnet-grade** software and has not been through a
professional security review. Do not hold real value on it. Only the latest
release and `master` receive fixes; there are no long-term support branches.

| Version | Supported |
|---|---|
| `master` / latest release | ✅ |
| anything older | ❌ |

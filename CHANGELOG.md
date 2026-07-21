# Changelog

Notable changes to Latebra. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Latebra is **pre-audit and testnet-grade**, so `0.x` makes no compatibility
promise. Consensus and wire-format changes are called out explicitly because
they split the network: nodes on older code reject the new blocks, and joining
after one means starting from a new genesis.

## [Unreleased]

### Fixed

- **Finality latency was bounded by a 15-second heartbeat, not by the block
  time.** Adopting a block received over gossip cast no finality vote, so a
  non-mining validator — which is how every validator except the block's
  producer learns of a block — did not vote until `latebrad`'s periodic re-vote
  tick. Quorum therefore took up to ~15s on a 3s chain. Validators now vote the
  moment they adopt a gossiped tip, and flood the vote (and any certificate it
  completes) alongside the block, so a quorum converges within the block that
  produced it. Covered by a regression test that fails without the fix.

## [0.1.0] — 2026-07-21

First tagged release, and the first with **prebuilt binaries** — running a node
no longer requires a Rust toolchain.

### Added

- **Release pipeline.** Tagged builds publish `latebrad`, `lat-wallet`,
  `lat-explorer` and `lat-wallet-web` for Linux x86-64, Windows x86-64 and macOS
  (Apple silicon + Intel), each archived with docs and licences, alongside a
  `SHA256SUMS.txt` covering every archive.
- **[INSTALL.md](INSTALL.md)** — download, verify, run a node, join a network,
  mine, and use the wallet and explorer.
- **Native DEX.** Constant-product AMM pools with LP shares, plus curve trades,
  in the ledger and consensus.
- **Cross-chain bridge** (`lat-bridge`) — HTLC atomic swaps with per-chain
  adapters for Bitcoin, EVM chains and Solana, a swap coordinator and a chain
  watcher.
- **Web wallet** (`lat-wallet-web`) — browser UI over the Rust chain with swap
  and shield/unshield flows.
- **Bootstrap seeds** (T18) — a fresh node dials compiled-in seeds when it has
  no `--peer` and no `peers.txt`, and now *reports* when it finds nobody rather
  than silently mining a private chain.
- **[SECURITY.md](SECURITY.md)** and **[CONTRIBUTING.md](CONTRIBUTING.md)** —
  private vulnerability reporting, scope, and the review bar for consensus and
  cryptography changes.

### Fixed

- `docker build` could never succeed: the image copied a `lat-wallet-cli`
  binary, but that package's `[[bin]]` is named `lat-wallet`. This also broke
  the CI docker job.
- Cleared the clippy lints failing CI's `-D warnings` gate — including a manual
  `div_ceil` in the LP-share integer square root, which additionally removed a
  theoretical `u128` overflow.

### Known limitations

Unchanged from [TESTNET.md](TESTNET.md) §9 and worth restating: **no
professional security audit**, no network-level privacy (no Dandelion++, so the
broadcasting IP is visible), plain-TCP P2P, sender anonymity bounded by a ring
size of ≤ 16, throughput capped near 333 TPS by consensus, and not
post-quantum. Do not hold real value on Latebra.

The compiled-in seed list ships **empty** in this release, so joining a network
requires passing `--peer <host>:4040` until public seeds are announced.

[Unreleased]: https://github.com/latebranetwork/latebra-core/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/latebranetwork/latebra-core/releases/tag/v0.1.0

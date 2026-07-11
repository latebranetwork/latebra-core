# Latebra — public testnet launch checklist

A step-by-step for standing up a public Latebra **testnet**: seed nodes, a
miner, a faucet/explorer, and the launchpad. For the security posture and what
is *not* ready, read [THREAT_MODEL.md](THREAT_MODEL.md) first. For per-node
operation detail, see [TESTNET.md](TESTNET.md).

> **Testnet only.** Do not put real value on this. Mainnet requires a security
> audit and the changes in §5.

## 1. Chain parameters (must be identical on every node)

Every node built from this source derives the same genesis and agrees
automatically. These are the consensus/economic constants as shipped:

| Parameter | Value | Where |
|---|---|---|
| Decimals | 5 (100,000 base units = 1 LAT) | wallet/ledger |
| Initial block reward | 50 LAT (`INITIAL_BLOCK_REWARD = 5_000_000`) | lat-chain |
| Halving interval | 131,072 blocks (`HALVING_INTERVAL`) | lat-chain |
| Emission end | 0 after 64 halvings (capped supply) | lat-chain |
| Target block time | 3 s (`BLOCK_INTERVAL_SECS`) | latebrad |
| Genesis difficulty | 256 (`DEFAULT_DIFFICULTY`) | lat-chain |
| Registration PoW | 8 leading zero bits (`REGISTRATION_POW_BITS`) | lat-chain |
| Min transfer fee | 0.01 LAT (`MIN_TRANSFER_FEE = 1_000`) | lat-chain |
| Max txs / block | 1,000 (`MAX_TXS_PER_BLOCK`) | latebrad |
| Max contract code | 24 KiB (`MAX_CONTRACT_CODE_BYTES`) | lat-chain |
| Anon ring cap | 16 (`MAX_RING_SIZE`) | lat-chain |
| Anonymity epoch | 20 blocks (`EPOCH_BLOCKS`) | lat-state |
| Snapshot interval | 500 blocks (`SNAPSHOT_INTERVAL`) | lat-chain |
| PoW hash | BLAKE3 (default) · RandomX with `--features randomx` | lat-chain |
| Min validator stake | 1,000 LAT (`MIN_VALIDATOR_STAKE`) | lat-state |
| Unbonding window | 240 blocks (`UNBONDING_BLOCKS`) | lat-state |
| Max validators | 64 (`MAX_VALIDATORS`) | lat-state |
| Finality quorum | strictly > 2/3 of bonded stake | lat-chain |
| Finality set window | 64 blocks (`FINALITY_SET_WINDOW`) | lat-chain |
| Slash penalty (equivocation) | full burn: bonded stake + unbonding | lat-state |

**Mainnet must additionally decide a validator genesis** (T13/T14): with the
testnet premine, the genesis wallet can trivially hold every validator seat.
A real launch needs a deliberate initial stake distribution (or a PoW→PoS
transition height) before BFT-PoS finality (T14) activates — revisit the
staking + finality parameters at the same time.

### Becoming a validator (testnet)

Finality (T14) is live but opt-in: with no stake bonded the network is pure
PoW. To run a validator:

1. Get **public** LAT (staking spends the transparent balance; miner rewards
   are confidential — `unshield` them first, or use the faucet):
   `lat-wallet balance --seed <hex>`
2. Bond at least the minimum stake:
   `lat-wallet stake --seed <hex> --amount 1000`
3. Restart your node with `--validator` (it votes with the **miner wallet**'s
   key, so stake THAT wallet's account):
   `latebrad --mine --validator --data ... --listen ...`
4. Check it: `lat-wallet staking --seed <hex>` shows the bond;
   the node log prints `[finality] height N finalized` once a >2/3 quorum of
   stake has voted; peers expose it via the `GetFinalized` RPC.
5. Leave with `lat-wallet unstake --amount <LAT>`, wait out the unbonding
   window, then claim with `lat-wallet stake --amount 0`.

**Equivocation is fatal**: signing finality votes for two different blocks at
one height is provable by anyone (`SlashEvidence` transaction) and burns the
offender's entire bond, including funds still unbonding. Run ONE node per
validator key.

Testnet genesis (in `latebrad`) — **well-known, testnet-only secrets**:

- Genesis wallet seed: `0x2a` × 32 (`GENESIS_SEED`) — also the **faucet** wallet.
- Miner reward wallet seed: `0x2b` × 32 (`MINER_SEED`).
- Confidential premine: 1,000,000 LAT to genesis (`GENESIS_PREMINE`).
- Public premine: 1,000,000 LAT to genesis (`GENESIS_PUBLIC_PREMINE`).

## 2. Build

```sh
cd latebra-core
cargo build --release          # optionally: --features randomx (needs CMake + a C toolchain)
```

Binaries land in `target/release/`: `latebrad` (node), `lat-wallet` (CLI wallet),
`lat-explorer` (Latscan), `latfun` (launchpad backend), `lat-wallet-web`.

## 3. Bring up the network

Run these on VPS instances with stable public IPs. The `--data` path is a redb
database (created on first run); back it up — it is the chain.

1. **Seed node(s)** — 2–3 always-on, public. The first has no `--peer`:
   ```sh
   latebrad --data ./latebra-data/chain.db --listen 0.0.0.0:4040 \
            --public-addr <this-host>:4040
   ```
   Additional seeds point `--peer` at the first (and each other).
2. **Miner** — at least one, so blocks are produced:
   ```sh
   latebrad --mine --data ./miner/chain.db --listen 0.0.0.0:4040 \
            --public-addr <miner-host>:4040 --peer <seed-host>:4040
   ```
   Nodes handshake on genesis id + version and drop mismatches; discovered peers
   persist to `peers.txt`, so restarts rejoin without `--peer`.
3. **Explorer (Latscan)** — public read UI:
   ```sh
   lat-explorer --testnet <seed-host>:4040 --listen 0.0.0.0:8080
   ```
4. **Launchpad (latfun)** — serves the frontend + API against a node:
   ```sh
   latfun --node <seed-host>:4040 --listen 0.0.0.0:5180 \
          --frontend latebra-launchpad/frontend --data latfun-data/store.json
   ```
5. **Faucet** — the explorer's `/faucet` page pays testnet LAT from the genesis
   wallet (per-address + global cooldowns). It needs to reach a node with the
   genesis premine.

Publish the seed `ip:port`s so others can `--peer` them (see TESTNET.md §4).

**Docker alternative:** `docker compose up --build` brings up a miner/validator,
two followers, and the explorer in one command (see `docker-compose.yml`); the
single-node image is the repo `Dockerfile`.

**Monitoring (T22):** every node serves HTTP `GET /status` (JSON) and
`GET /metrics` (Prometheus text) — default `127.0.0.1:4090`, set
`--metrics 0.0.0.0:4090` to expose it (read-only, but consider firewalling it
to your monitoring host anyway). Fields: height, tip, difficulty, peers,
mempool, finalized height (T14 watermark; `-1` until a certificate forms),
boot mode, uptime. Point Prometheus/Grafana or curl-in-cron at it; alert if
`latebra_height` stalls or `latebra_peers` drops to 0.

**New-node bootstrap (T19):** a fresh node fast-syncs automatically — it
downloads a peer's state records and verifies the rebuilt state root against
the PoW-validated header chain instead of re-verifying every historical proof,
falling back to full block sync if anything mismatches.

## 4. Pre-flight checklist

- [ ] All hosts built from the **same commit** (same genesis id) — verify each
      node prints the same `genesis addr` on boot.
- [ ] `cargo test --workspace --exclude latfun` is green on the release commit.
- [ ] Full local dry run passes: `./scripts/local-testnet.ps1` (miner + syncer +
      explorer) — a second node syncs and a wallet can register/send.
- [ ] Seed nodes reachable on their advertised `--public-addr` (firewall/port).
- [ ] `--data` directories are on persistent disk and **backed up**.
- [ ] Explorer + launchpad reachable; faucet pays a fresh address end-to-end.
- [ ] THREAT_MODEL.md limitations are published so users know it's testnet-grade.

## 5. Before any mainnet / real value — do NOT skip

- [ ] **Security audit** of the confidential + anonymous transfer crypto
      (hard blocker — see THREAT_MODEL.md §2.1).
- [ ] **Fresh genesis + faucet secrets** — the shipped `0x2a…`/`0x2b…` seeds are
      public. Generate new ones; do not reuse testnet seeds.
- [ ] **Reviewed tokenomics** — premine, emission, halving, fees.
- [ ] **Deterministic finality** (BFT-PoS, roadmap M3) and **hardened networking**
      (transport encryption, discovery) if the threat model demands it.
- [ ] **Legal review** of the launchpad/token model (bonding-curve launchpads can
      be regulated securities/MSB activity — see the launchpad README).
- [ ] Hide the amount on anonymous transfers if full-privacy is a launch claim.

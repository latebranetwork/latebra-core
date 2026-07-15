# Running & joining the Latebra testnet

This guide covers running a Latebra node, joining the network, mining, using a
wallet, and running the explorer. It is for a **testnet** — play money, no real
value. Do not put real value on Latebra until it has been audited.

> Every node built from the same code shares the same genesis block, so nodes
> automatically agree and synchronize once they can reach each other.

---

## 1. Prerequisites

- **Rust** (install via <https://rustup.rs>).
- Open a firewall port if you want others to reach your node (default `4040/tcp`).
- Optional: **CMake**, only if you build with real RandomX proof-of-work.

## 2. Build

```sh
cd latebra-core
cargo build --release
```

Binaries are produced in `target/release/`:

| Binary | Purpose |
|---|---|
| `latebrad` | the node daemon (sync, gossip, RPC, mining) |
| `lat-wallet` | command-line wallet |
| `lat-explorer` | block explorer (web) |
| `lat-node` | a scripted local demo (no networking) |

## 3. Run a node

**A public node others can connect to** (bind to all interfaces):

```sh
latebrad --data ./latebra-data/chain.db --listen 0.0.0.0:4040 --peer <seed-ip>:4040
```

**A mining node** (also secures the network and earns block rewards).

> **Sync first. Mine second.** Do NOT start a fresh node with `--mine` and
> `--peer` at once. The miner thread starts immediately, so it begins building on
> *genesis* while the sync is still running — you mine a competing chain against
> the network you are trying to join. Fork choice is heaviest-work, so your blocks
> lose and the work is thrown away.
>
> This is easy to hit because every `latebrad` derives the **same** genesis, so
> the handshake happily accepts you: you are a legitimate peer on a divergent
> chain, not an obvious stranger. Nothing warns you.

Start without `--mine`, let it reach the network's height, stop it, then restart
with `--mine` (peers persist, so no `--peer` needed the second time):

```sh
# 1. sync only
latebrad --data ./latebra-data/chain.db --listen 0.0.0.0:4040 --peer <seed-ip>:4040
#    wait until the height stops climbing and matches the explorer, then Ctrl-C

# 2. now mine
latebrad --mine --data ./latebra-data/chain.db --listen 0.0.0.0:4040
```

Only the **first** node on a brand-new network should mine from genesis — it has
nothing to sync to, and it is what everyone else syncs *from*.

- `--peer` can be repeated to connect to several seed nodes.
- The node persists to `--data`; restart it any time and it resumes from disk.
- **Peers persist too.** Discovered peers are written to `peers.txt` next to your
  `--data` file, so after the first successful connection a restart **rejoins the
  network automatically — no `--peer` needed**. Pass `--peer` again only to add a
  brand-new seed.
- On first contact nodes **handshake**: they compare protocol version and genesis
  id and keep each other only if both match. A node on a different network (or an
  incompatible version) is dropped, never synced — so you always join the *right*
  chain. Unreachable peers are evicted automatically after repeated failures.
- On a testnet, run at least one **seed node** with a stable, public IP; everyone
  else points `--peer` at it.

## 4. Join an existing testnet

1. Get one or more **seed node addresses** (`ip:port`) from whoever runs them.
   There is no discovery yet — a node with no `--peer` and no `peers.txt` finds
   nobody and mines its own private chain in silence.
2. Start your node pointing at them — **without `--mine`** (see §3):
   ```sh
   latebrad --data ./my-node/chain.db --listen 0.0.0.0:4040 --peer <seed-ip>:4040
   ```
3. Watch it sync — it pulls and re-validates every block, then follows the tip.
   Compare your height against the explorer before you do anything else.
4. Only once your height matches, restart with `--mine` if you want to mine.

### This testnet may be reset without notice

Testnet LAT is **worthless by design** and the chain carries no promise of
continuity. The genesis and faucet seeds are published in this repository
(`[42u8; 32]` / `[43u8; 32]`) — anyone can spend the premine, which is exactly
why the coins mean nothing.

A reset means a **new genesis**: your `chain.db` becomes unloadable against the
new network and your balances are gone. Expect one whenever the wire format
changes (the anonymous-transfer format already went v2 → v3 once), whenever
consensus parameters move, or whenever the chain wedges. Nothing here is
mainnet, and nothing here is a rehearsal for your savings.

## 5. Use a wallet

```sh
lat-wallet new                                          # create a wallet; SAVE the seed
lat-wallet register --seed <hex> --node 127.0.0.1:4040  # register on-chain
lat-wallet balance  --seed <hex> --node 127.0.0.1:4040
lat-wallet send      --seed <hex> --to <latt1…> --amount 25 --node 127.0.0.1:4040  # confidential (amount hidden)
lat-wallet anon-send --seed <hex> --to <latt1…> --amount 25 --node 127.0.0.1:4040  # anonymous (sender + receiver hidden)
lat-wallet rollover  --seed <hex> --node 127.0.0.1:4040  # make received funds spendable
```

Point `--node` at any reachable node's `ip:port`. Keys never leave the wallet; the
node only sees ciphertexts. Received funds land in *pending* until you `rollover`.

`anon-send` hides **who pays whom**: you spend from inside a ring of decoy
accounts and the receiver is a one-time stealth address, so no on-chain field
names either party (the amount is still public in this phase). It needs a few
other funded accounts on-chain to hide among, and is limited to one anonymous
spend per account per epoch (20 blocks). This path is **unaudited** — testnet
only. The receiver detects incoming anonymous funds with `scan-stealth`.

## 6. Run the explorer

```sh
lat-explorer --testnet 127.0.0.1:4040 --mainnet 127.0.0.1:4041 --listen 0.0.0.0:8080
```

Open `http://<your-ip>:8080`. It has a mainnet/testnet switcher and a block-height
search. Point `--testnet`/`--mainnet` at the node(s) you want it to read.

## 7. A local multi-node testnet (for testing)

To try the whole thing on one machine, use the helper script:

```powershell
# Windows PowerShell
./scripts/local-testnet.ps1
```

It builds the binaries, starts a mining node and a second syncing node, and an
explorer — then prints how to connect a wallet and how to stop everything.

## 8. Operating a real public testnet — checklist

Ordered. Each line is blocked by the one above it.

**Infrastructure**
- [ ] Run **2–3 seed nodes** on stable public IPs (cheap VPS instances work).
      Keep them always-on; they are how new nodes bootstrap. A laptop is not a
      seed node: it is almost certainly behind NAT (there is no NAT traversal —
      §9), its address rotates, and the network dies when it sleeps.
- [ ] Run at least one **miner** so blocks are produced at all.
- [ ] Deploy the explorer, faucet, RPC and (optionally) the launchpad —
      [DEPLOY.md](DEPLOY.md) is the runbook.
- [ ] Back up each node's `--data` file (it is the chain), and `latfun.json`
      if you run the launchpad (it is *not* reconstructible from the chain).

**Before telling anyone it exists**
- [ ] **Publish the seed `ip:port`s** — without them nobody can join at all.
- [ ] Hardcode those seeds as bootstrap defaults (**T18**) so a fresh node needs
      no `--peer`. Until this ships, "join the testnet" means "ask someone for an
      IP", and a node started without one silently mines its own private chain.
- [ ] Say **sync first, mine second** in your join instructions (§3). Your first
      users will otherwise fork themselves off and conclude the chain is broken.
- [ ] State the **reset policy** up front (§4). Announcing it afterwards reads as
      confiscation, however worthless the coins are.
- [ ] Give people somewhere to report bugs.

**While it runs**
- [ ] Actually watch `/metrics` — height climbing, peers non-zero, mempool not
      wedged. Built-in monitoring nobody reads is not monitoring.
- [ ] Run it **yourself for a week before announcing**. Things that survive
      fifteen minutes on a laptop routinely fail overnight on a network.
- [ ] Re-measure throughput on the real network:
      `cargo run --release --example loadtest -p lat-attack -- --node <seed>:4040`.
      The local figure (~333 TPS, the `MAX_TXS_PER_BLOCK / 3s` cap) has no
      propagation, no latency and no competing miners in it. The public number
      will be lower, and it is the only one worth quoting.

## 9. Known limitations (testnet-grade)

- **Not audited** — do not hold real value. The anonymous-transfer path in
  particular is an unaudited cryptographic construction.
- **What `anon-send` hides (v3).** Sender (ring), receiver (one-time stealth
  address) **and amount** (Pedersen debit commitment + aggregated range proof).
  Still public: the **fee**, the ring size, the epoch, and the transaction's
  *timing*. Sender anonymity is bounded by the ring size (≤ 16) — and decoy
  selection is wallet-side and unspecified, which is an open design item, not a
  solved one. Ordinary `send` hides the amount but not the parties.
- **Network-level privacy: none.** There is no Dandelion++. The IP that first
  broadcasts a transaction is visible to every peer it touches, so a
  well-connected observer can map transactions to origins regardless of what the
  chain hides. This is the widest gap between Latebra's on-chain privacy and
  privacy in practice.
- **Peer discovery is seed-based, not a DHT.** One reachable seed is enough — a
  node handshakes, pulls that peer's peer list, and persists what it learns — but
  there is no global DHT/mDNS discovery, and no hard-coded seed list in the binary
  yet (T18: pass `--peer` for the first connection, or you find nobody).
- **Transport is plain TCP** — no libp2p, no transport encryption or NAT
  traversal. Anyone on the path can read and modify P2P traffic. Fine for a
  testnet of known nodes; a production upgrade otherwise.
- **One anonymous spend per account per epoch** (20 blocks); one **confidential**
  spend per account per block (its solvency proof binds a balance snapshot, so a
  second in the same block would prove against a stale one). **Public** spends
  have no such limit — measured: 1000 in one block from a single sender.
- **Throughput is capped at ~333 TPS** by consensus, for every lane:
  `MAX_TXS_PER_BLOCK` (1000) / `TARGET_BLOCK_TIME_SECS` (3). The execution
  benchmarks in `bench.rs` (23-30k/s transparent, ~650/s confidential) are
  in-process numbers with no chain around them and are NOT reachable on-chain.
- **Not post-quantum**, and for privacy that is retroactive: an adversary
  archiving the chain today can de-anonymize it once a quantum computer exists,
  and no future fork repairs that. Peer-parity with Monero/Zcash — see
  [CRYPTO_SPEC.md](CRYPTO_SPEC.md) §5.6.
- Very large balances decrypt slowly in the wallet.

## 10. Troubleshooting

- *"could not reach a node"* — the node isn't running, or a firewall is blocking the
  port. Check `--listen`/`--node` and that the port is open.
- *Node won't sync* — it must use the **same build** (same genesis) as its peers.
- *Wallet says "not registered"* — run `lat-wallet register` and wait for a block.

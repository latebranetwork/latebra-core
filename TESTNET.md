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
latebrad --data ./latebra-data/chain.log --listen 0.0.0.0:4040 --peer <seed-ip>:4040
```

**A mining node** (also secures the network and earns block rewards):

```sh
latebrad --mine --data ./latebra-data/chain.log --listen 0.0.0.0:4040 --peer <seed-ip>:4040
```

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
2. Start your node pointing at them:
   ```sh
   latebrad --data ./my-node/chain.log --listen 0.0.0.0:4040 --peer <seed-ip>:4040
   ```
3. Watch it sync — it will pull and re-validate every block, then follow the tip.

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

- Run **2–3 seed nodes** on stable public IPs (cheap VPS instances work). Keep them
  always-on; they are how new nodes bootstrap.
- Publish the seed node `ip:port`s so others can `--peer` them.
- Run at least one **miner** so blocks are produced.
- Run a **public explorer** so participants can see the chain.
- Back up each node's `--data` file (it is the chain).

## 9. Known limitations (testnet-grade)

- **Not audited** — do not hold real value. The anonymous-transfer path in
  particular is an unaudited cryptographic construction.
- **Amounts are still public on anonymous transfers.** Sender/receiver hiding
  (`anon-send`) is wired into consensus, but hiding the *amount* too is a later
  phase. Ordinary `send` hides the amount but not the parties.
- **Peer discovery is seed-based, not a DHT.** One reachable seed is enough — a
  node handshakes, pulls that peer's peer list, and persists what it learns — but
  there is no global DHT/mDNS discovery, and no hard-coded seed list in the binary
  yet (pass `--peer` for the first connection).
- **Transport is plain TCP** — no libp2p, no transport encryption or NAT
  traversal. Fine for a testnet of known nodes; a production upgrade otherwise.
- **One anonymous spend per account per epoch** (20 blocks); one confidential
  spend per account per block. Known models; batching is future work.
- Very large balances decrypt slowly in the wallet.

## 10. Troubleshooting

- *"could not reach a node"* — the node isn't running, or a firewall is blocking the
  port. Check `--listen`/`--node` and that the port is open.
- *Node won't sync* — it must use the **same build** (same genesis) as its peers.
- *Wallet says "not registered"* — run `lat-wallet register` and wait for a block.

# Install Latebra

Download a prebuilt binary, run a node, sync a wallet. **No Rust toolchain
required** — if you would rather build from source, see
[TESTNET.md](TESTNET.md) §2.

> **Testnet only.** Latebra has **not** been through a professional security
> audit. Do not hold real value on it. Testnet LAT is worthless by design and
> the chain may be reset without notice — see [TESTNET.md](TESTNET.md) §4.

---

## 1. Download

Grab the archive for your platform from the
[latest release](https://github.com/latebranetwork/latebra-core/releases/latest):

| Platform | Archive |
|---|---|
| Linux (x86-64) | `latebra-<version>-x86_64-unknown-linux-gnu.tar.gz` |
| Windows (x86-64) | `latebra-<version>-x86_64-pc-windows-msvc.zip` |
| macOS (Apple silicon) | `latebra-<version>-aarch64-apple-darwin.tar.gz` |
| macOS (Intel) | `latebra-<version>-x86_64-apple-darwin.tar.gz` |

Each archive contains four binaries:

| Binary | Purpose |
|---|---|
| `latebrad` | the node daemon — sync, gossip, RPC, mining |
| `lat-wallet` | command-line wallet |
| `lat-explorer` | block explorer (web UI) |
| `lat-wallet-web` | web wallet (local browser UI) |

## 2. Verify and unpack

Always verify before running a binary you downloaded.

```sh
# Linux / macOS
sha256sum -c SHA256SUMS.txt --ignore-missing
tar xzf latebra-*-x86_64-unknown-linux-gnu.tar.gz
cd latebra-*/
```

```powershell
# Windows PowerShell — compare against the matching line in SHA256SUMS.txt
Get-FileHash .\latebra-*-x86_64-pc-windows-msvc.zip -Algorithm SHA256
Expand-Archive .\latebra-*-x86_64-pc-windows-msvc.zip -DestinationPath .
```

On macOS the binaries are unsigned, so Gatekeeper will block them on first run.
Clear the quarantine flag:

```sh
xattr -d com.apple.quarantine latebrad lat-wallet lat-explorer lat-wallet-web
```

## 3. Run a node

```sh
./latebrad --data ./latebra-data/chain.db --listen 0.0.0.0:4040
```

The node persists to `--data` and resumes from disk on restart. Open port
`4040/tcp` in your firewall if you want other nodes to reach you.

Running a node others should be able to dial (a VPS, a seed) needs one more
flag: `--listen 0.0.0.0:4040` binds every interface, but the address the node
*advertises* to peers defaults to that same value, and `0.0.0.0` is not dialable.
Tell it what to advertise:

```sh
./latebrad --data ./latebra-data/chain.db \
  --listen 0.0.0.0:4040 --public-addr <your-public-host>:4040
```

### Joining the network

A fresh node needs at least one reachable peer. It uses, in order: any `--peer`
you pass, the `peers.txt` it wrote next to your `--data` file on a previous run,
and the seeds compiled into the binary.

```sh
./latebrad --data ./latebra-data/chain.db --listen 0.0.0.0:4040 --peer <seed-host>:4040
```

`--peer` can be repeated. After the first successful connection peers persist,
so later restarts rejoin on their own with no `--peer`.

> **A node that finds nobody does not error.** Every `latebrad` derives the same
> deterministic genesis, so an isolated node quietly mines its own private chain
> and looks perfectly healthy while being alone. On startup the node prints what
> it is bootstrapping from — if it says `peers : NONE`, you are not on the
> network, whatever the height does afterwards.

**Current seed nodes are listed on the
[releases page](https://github.com/latebranetwork/latebra-core/releases/latest)
and in the release notes.** Until public seeds are announced, joining means
getting an `ip:port` from whoever is running a node.

### Mining

**Sync first. Mine second.** Do not start a fresh node with `--mine` and
`--peer` together: the miner begins building on *genesis* while the sync is
still running, so you mine a competing chain against the network you are trying
to join. Fork choice is heaviest-work, so that work is simply thrown away.

```sh
# 1. sync only — wait until the height stops climbing and matches the explorer
./latebrad --data ./latebra-data/chain.db --listen 0.0.0.0:4040 --peer <seed-host>:4040

# 2. then mine (peers persist, so no --peer needed)
./latebrad --mine --data ./latebra-data/chain.db --listen 0.0.0.0:4040
```

Only the **first** node on a brand-new network should mine from genesis.

## 4. Use a wallet

```sh
./lat-wallet new                                          # create a wallet — SAVE the seed
./lat-wallet register --seed <hex> --node 127.0.0.1:4040  # register on-chain
./lat-wallet balance  --seed <hex> --node 127.0.0.1:4040
./lat-wallet send      --seed <hex> --to <latt1…> --amount 25 --node 127.0.0.1:4040
./lat-wallet anon-send --seed <hex> --to <latt1…> --amount 25 --node 127.0.0.1:4040
./lat-wallet rollover  --seed <hex> --node 127.0.0.1:4040  # make received funds spendable
```

Point `--node` at any reachable node. Keys never leave the wallet — the node
only ever sees ciphertexts. Received funds land in a *pending* pool until you
`rollover`, which is what makes them spendable.

For a browser UI instead:

```sh
./lat-wallet-web --listen 127.0.0.1:8090
```

## 5. Run the explorer

```sh
./lat-explorer --testnet 127.0.0.1:4040 --listen 0.0.0.0:8080
```

Open `http://<your-ip>:8080` for blocks, transactions and a height search.

## 6. Docker

```sh
docker build -t latebra .
docker run -p 4040:4040 -p 4090:4090 -v latebra-data:/data latebra \
  --data /data/chain.db --listen 0.0.0.0:4040 --metrics 0.0.0.0:4090
```

## 7. Monitoring

Pass `--metrics 127.0.0.1:4090` and scrape `http://127.0.0.1:4090/metrics`.
Watch that height climbs, peers stay non-zero, and the mempool does not wedge.

## Troubleshooting

- **"could not reach a node"** — the node isn't running or a firewall is blocking
  it. Check `--listen`/`--node` and that the port is open.
- **Node won't sync** — peers must be on the same protocol version *and* genesis.
  Mismatched nodes are dropped at the handshake, never synced, so you always join
  the right chain or none at all.
- **Height climbs but you have no peers** — you are mining a private fork. Stop,
  delete the `--data` file, and restart with a working `--peer`.
- **Wallet says "not registered"** — run `lat-wallet register` and wait a block.
- **macOS "cannot be opened"** — clear the quarantine flag, §2.

## Building from source

```sh
git clone https://github.com/latebranetwork/latebra-core
cd latebra-core
cargo build --release          # always release: ~15x faster curve math
```

Binaries land in `target/release/`. Full detail in [TESTNET.md](TESTNET.md).

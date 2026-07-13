# Latebra — VPS deployment runbook (testnet)

Stand up the whole public testnet on a Linux VPS: the chain (`latebrad`), the
explorer (Latscan), the web wallet, the marketing site, and a **public
JSON-RPC API** at `api.<your-domain>` — the Solana-style endpoint developers
call to read the chain.

> Testnet only. Read [THREAT_MODEL.md](THREAT_MODEL.md) and [LAUNCH.md](LAUNCH.md)
> §5 before putting real value on anything. The shipped genesis/faucet seeds
> (`0x2a…`/`0x2b…`) are public.

---

## 0. What runs where

| Service | Binary | Binds (localhost) | Public URL (via proxy) |
|---|---|---|---|
| Node / seed / miner | `latebrad` | `0.0.0.0:4040` (P2P), `127.0.0.1:4090` (RPC+metrics) | `seed1.<domain>:4040` (raw TCP) |
| **Public API** | `latebrad` `/rpc` | `127.0.0.1:4090` | `https://api.<domain>` |
| Explorer (Latscan) | `lat-explorer` | `127.0.0.1:8080` | `https://scan.<domain>` |
| Web wallet | `lat-wallet-web` | `127.0.0.1:8090` | `https://wallet.<domain>` |
| Website | `node run-ssr.mjs` | `127.0.0.1:5174` | `https://<domain>` |

The P2P port `4040` is exposed **raw** (nodes speak a binary TCP protocol, not
HTTP). Everything else sits behind an HTTPS reverse proxy. The RPC/metrics port
`4090` stays on loopback — the proxy forwards only the safe paths to it.

## 1. Provision

- 1 VPS to start (Ubuntu 22.04, 2 vCPU / 4 GB / 40 GB SSD is plenty for testnet).
  Add more later for extra seeds.
- DNS **A records**, all pointing at the VPS IP:
  `@` (root), `www`, `scan`, `api`, `wallet`, `seed1`.
- Firewall (ufw):
  ```sh
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw allow 4040/tcp        # P2P — must be reachable
  ufw enable
  # NOTE: do NOT open 4090 — the API/metrics port stays loopback-only.
  ```

## 2. Build

```sh
# toolchain
curl https://sh.rustup.rs -sSf | sh -s -- -y && . "$HOME/.cargo/env"
sudo apt-get update && sudo apt-get install -y git build-essential caddy

git clone <your-repo-url> latebra-core && cd latebra-core
cargo build --release           # add --features randomx for ASIC-resistant PoW (needs cmake+clang)
# binaries in target/release/: latebrad lat-explorer lat-wallet lat-wallet-web
```

Verify the genesis fingerprint is what you expect (every node must match):
```sh
./target/release/latebrad --data /tmp/probe.db --mine-blocks 0 | grep genesis
```

## 3. systemd services

Create `/etc/systemd/system/latebrad.service` (seed + miner in one, to start):

```ini
[Unit]
Description=Latebra node (seed + miner)
After=network.target

[Service]
User=latebra
WorkingDirectory=/home/latebra/latebra-core
ExecStart=/home/latebra/latebra-core/target/release/latebrad \
  --mine \
  --data /home/latebra/data/chain.db \
  --listen 0.0.0.0:4040 \
  --public-addr seed1.YOURDOMAIN:4040 \
  --metrics 127.0.0.1:4090
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/lat-explorer.service`:
```ini
[Unit]
Description=Latscan explorer
After=latebrad.service
[Service]
User=latebra
ExecStart=/home/latebra/latebra-core/target/release/lat-explorer --testnet 127.0.0.1:4040 --listen 127.0.0.1:8080
Restart=always
[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/lat-wallet-web.service`:
```ini
[Unit]
Description=Latebra web wallet
After=latebrad.service
[Service]
User=latebra
ExecStart=/home/latebra/latebra-core/target/release/lat-wallet-web --listen 127.0.0.1:8090
Restart=always
[Install]
WantedBy=multi-user.target
```

> **Wallet caution:** `lat-wallet-web` takes the user's seed server-side. Hosting
> it publicly is acceptable for a play-money testnet **with a visible "testnet
> only" banner**; also offer it as a local download. Never for mainnet seeds.

Enable them:
```sh
sudo useradd -r -m -d /home/latebra latebra   # if not already
sudo systemctl daemon-reload
sudo systemctl enable --now latebrad lat-explorer lat-wallet-web
journalctl -u latebrad -f                      # watch it mine
```

## 4. The public API (api.YOURDOMAIN)

`latebrad --metrics 127.0.0.1:4090` already serves the JSON-RPC (see
[RPC.md](RPC.md)). The proxy exposes only the safe paths and keeps `/metrics`
private. `/rpc` sends permissive CORS, so browser dApps work out of the box.

Test locally on the box first:
```sh
curl -s 127.0.0.1:4090/health
curl -s 127.0.0.1:4090/rpc -d '{"jsonrpc":"2.0","id":1,"method":"lat_status","params":[]}'
curl -s 127.0.0.1:4090/rpc -d '{"jsonrpc":"2.0","id":1,"method":"lat_latestBlocks","params":[5]}'
```

## 5. Reverse proxy (Caddy — automatic HTTPS)

`/etc/caddy/Caddyfile` (replace `YOURDOMAIN`):

```
YOURDOMAIN, www.YOURDOMAIN {
    reverse_proxy 127.0.0.1:5174        # website
}

scan.YOURDOMAIN {
    reverse_proxy 127.0.0.1:8080        # explorer
}

wallet.YOURDOMAIN {
    reverse_proxy 127.0.0.1:8090        # web wallet
}

api.YOURDOMAIN {
    # Public API: forward ONLY the read paths + submit; /metrics stays private.
    @api path /rpc /status /health
    handle @api {
        reverse_proxy 127.0.0.1:4090
    }
    # Simple landing for anything else.
    handle {
        respond "Latebra API — POST /rpc (JSON-RPC 2.0). Docs: https://YOURDOMAIN" 200
    }
    # Basic abuse protection for a public endpoint.
    rate_limit {
        zone api { key {remote_host}; events 120; window 1m }
    }
}
```

```sh
sudo systemctl restart caddy
curl -s https://api.YOURDOMAIN/rpc -d '{"jsonrpc":"2.0","id":1,"method":"lat_health","params":[]}'
```

(The `rate_limit` directive needs the `caddy-ratelimit` plugin; drop the block
if you use stock Caddy and add rate limiting at your CDN/WAF instead.)

## 6. Point the site + explorer at the real hosts

Before building the website, set the explorer URL (it ships as a placeholder):

- `latebra-web/website/app/src/routes/index.tsx` and `how-it-works.tsx`:
  `const EXPLORER_URL = "https://scan.YOURDOMAIN";`

Then build and run the site:
```sh
cd latebra-web/website/app
curl -fsSL https://bun.sh/install | bash && . ~/.bashrc
bun install
bun run build:dev
node run-ssr.mjs                 # serves 127.0.0.1:5174 (front it with Caddy)
```
Wrap `node run-ssr.mjs` in its own systemd unit the same way as the others.

The web wallet's default node endpoint (editable in-UI) lives in
`crates/lat-wallet-web/src/wallet.html` (`let NODE=...`); set it to
`api.YOURDOMAIN` (or your seed) and rebuild `lat-wallet-web` if you want a
sensible default.

## 7. Public API — what developers get

`POST https://api.YOURDOMAIN/rpc`, JSON-RPC 2.0. Highlights (full list in
[RPC.md](RPC.md)):

| Method | Returns |
|---|---|
| `lat_health` | `"ok"` |
| `lat_status` | height, tip, difficulty, genesis, peers, mempool, finalized |
| `lat_supply` | emission + premine + total supply (base units) |
| `lat_latestBlocks` `[n]` | newest-first block summaries |
| `lat_getBlock` `[height]` / `lat_getBlockByHash` `[id]` | decoded block + tx summaries |
| `lat_getTransaction` `[hash]` | decoded tx + location |
| `lat_validators` | active validator set + stake |
| `lat_token` `[ticker]` | token registry entry (id, creator, supply) |
| `lat_publicBalance` `[acct,token]` | plaintext balance |
| `lat_submitTx` `[tx_hex]` | broadcast a signed tx |

Confidential amounts / anon senders are never exposed — the API surfaces only
what is public on-chain.

## 8. Scale to real seed redundancy

Add a second VPS, build the same commit, and run `latebrad` **without** `--mine`
pointing at the first: `--peer seed1.YOURDOMAIN:4040 --public-addr seed2.YOURDOMAIN:4040`.
Publish both seed `ip:port`s. Peers persist to `peers.txt`, so restarts rejoin
automatically.

## 9. Pre-flight

Run the [LAUNCH.md](LAUNCH.md) §4 checklist. Minimum green light:
- [ ] `scan.YOURDOMAIN` shows blocks climbing
- [ ] `api.YOURDOMAIN/rpc lat_status` returns the same `genesis` on every node
- [ ] `/metrics` is **not** reachable from the internet (only `/rpc /status /health`)
- [ ] faucet pays a fresh address end-to-end
- [ ] `--data` on persistent disk and backed up

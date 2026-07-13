# Latebra JSON-RPC

`latebrad` serves JSON-RPC 2.0 over HTTP on the metrics port (default
`127.0.0.1:4090`, flag `--metrics <addr|off>`):

```
POST /rpc
content-type: application/json

{"jsonrpc": "2.0", "id": 1, "method": "lat_status", "params": []}
```

The same port also serves `GET /status` (plain JSON summary) and
`GET /metrics` (Prometheus text). The endpoint is read-only except
`lat_submitTx`. It binds loopback by default — expose it deliberately
(`--metrics 0.0.0.0:4090`) and firewall it if you do.

**CORS.** All responses send `Access-Control-Allow-Origin: *` and answer
`OPTIONS` preflight, so browser dApps, the explorer, and the web wallet can
call `/rpc` from any origin. Everything is read-only except the
self-authenticating `lat_submitTx`, so an open origin is safe.

> **Publishing a public API.** For a Solana-style public endpoint
> (`api.<your-domain>`), put a reverse proxy in front and forward **only**
> `POST /rpc`, `GET /status`, and `GET /health` — keep `/metrics` (peer/mempool
> internals) on the loopback interface or firewalled to your monitoring host.
> Add rate limiting at the proxy. See LAUNCH.md.

Conventions: params are **positional**. Account/contract/tx ids and byte
blobs are lowercase hex strings (no `0x` prefix). Token `0` is native LAT
(5 decimals: 1 LAT = 100000 units). Missing entities read as `result: null`
rather than an error.

## Methods

### Chain

| Method | Params | Result |
|---|---|---|
| `lat_health` | `[]` | `"ok"` — liveness probe |
| `lat_status` | `[]` | `{height, tip, difficulty, genesis, peers, mempool, finalized: {height, id} \| null}` |
| `lat_supply` | `[]` | `{height, decimals, current_block_reward, halving_interval, halvings_done, premine_base_units, mined_base_units, total_base_units}` |
| `lat_blockByHeight` | `[height]` | `{height, bytes}` (hex-encoded block) or `null` |
| `lat_txByHash` | `[tx_hash_hex]` | `{block, index}` or `null` |

`genesis` is the network fingerprint — check it before trusting a node.
`lat_blockByHeight` returns the canonical consensus encoding
(`lat-chain::Block`); prefer the **decoded** reads below for app/explorer use.

### Decoded reads (developer-friendly)

These return structured JSON — no client-side consensus decoding needed. They
only surface **public** data: confidential amounts, ZK proofs, and
anonymity-set members are never expanded. Amounts are base units (1 LAT =
100000).

| Method | Params | Result |
|---|---|---|
| `lat_getBlock` | `[height]` | `{height, id, prev_hash, timestamp, tx_root, state_root, miner, nonce, reward, tx_count, txs: [...] }` or `null` |
| `lat_getBlockByHash` | `[block_id_hex]` | same shape as `lat_getBlock` or `null` |
| `lat_latestBlocks` | `[count?]` | newest-first block summaries `[{height, id, timestamp, miner, tx_count, reward}]` (count 1–50, default 10) |
| `lat_getTransaction` | `[tx_hash_hex]` | `{hash, block, height, index, tx: {...} }` or `null` |
| `lat_validators` | `[]` | active validator set `[{account, stake}]` |
| `lat_token` | `[ticker]` | `{id, ticker, creator, supply}` or `null` |

Each element of a block's `txs` (and `lat_getTransaction`'s `tx`) is a summary
tagged with `type`: `register`, `create_token`, `public_transfer`, `shield`,
`unshield`, `shield_stealth`, `confidential_transfer` (amount hidden),
`anon_transfer` (sender+receiver hidden), `rollover`, `deploy_contract`,
`call_contract`, `stake`, `unstake`, `slash_evidence`. Every summary carries
its `hash`.

### Accounts

| Method | Params | Result |
|---|---|---|
| `lat_publicBalance` | `[account_hex, token]` | plaintext balance or `null` |
| `lat_encryptedBalance` | `[account_hex, token]` | 64-byte ElGamal ciphertext (hex) or `null` |
| `lat_pending` | `[account_hex, token]` | pending-pool ciphertext (hex) or `null` |
| `lat_nonce` | `[account_hex]` | next spend nonce or `null` |
| `lat_stake` | `[account_hex]` | `{staked, unbonding: [{amount, release_height}]}` |

Encrypted balances are readable only by the account key (see CRYPTO_SPEC.md
§0); the RPC returns the ciphertext for wallets to decrypt client-side.

### Contracts & privacy helpers

| Method | Params | Result |
|---|---|---|
| `lat_contractStorage` | `[contract_hex, key]` | slot value (u64; 0 if unset) |
| `lat_ringCandidates` | `[token, max?]` | `[{account, balance}]` — decoy pool for anonymous transfers (capped at 64) |

### Submitting transactions

| Method | Params | Result |
|---|---|---|
| `lat_submitTx` | `[tx_hex]` | `true` iff accepted into the mempool |

The transaction must be a canonically-encoded, signed/proven
`lat-types::Transaction`. Accepted transactions are gossiped to peers, so
submitting to any node reaches every miner. Build transactions with
`lat-wallet` (library or CLI) — the RPC does not hold keys.

## Errors

JSON-RPC 2.0 error objects: `-32700` parse error, `-32601` method not
found, `-32602` invalid params. Request bodies over 1 MiB are refused with
HTTP 413.

## Example

```sh
curl -s http://127.0.0.1:4090/rpc -d \
  '{"jsonrpc":"2.0","id":1,"method":"lat_status","params":[]}'

curl -s http://127.0.0.1:4090/rpc -d \
  '{"jsonrpc":"2.0","id":2,"method":"lat_publicBalance","params":["<account-hex>",0]}'
```

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

Conventions: params are **positional**. Account/contract/tx ids and byte
blobs are lowercase hex strings (no `0x` prefix). Token `0` is native LAT
(5 decimals: 1 LAT = 100000 units). Missing entities read as `result: null`
rather than an error.

## Methods

### Chain

| Method | Params | Result |
|---|---|---|
| `lat_status` | `[]` | `{height, tip, difficulty, genesis, peers, mempool, finalized: {height, id} \| null}` |
| `lat_blockByHeight` | `[height]` | `{height, bytes}` (hex-encoded block) or `null` |
| `lat_txByHash` | `[tx_hash_hex]` | `{block, index}` or `null` |

`genesis` is the network fingerprint — check it before trusting a node.
Block/transaction byte formats are the canonical consensus encodings
(`lat-chain::Block`, `lat-types::Transaction`).

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

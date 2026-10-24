# bitcoin

Status: **Implemented (one-shot assessments).** CPM scheduled monitoring and console views remain EVM-only.

Read-only Bitcoin Core collector (`src/index.ts`) for addresses (P2PKH, P2SH, P2WPKH, P2WSH, P2TR) and public keys (`combo()`: P2PK, P2PKH, P2WPKH, P2SH-P2WPKH) on mainnet, testnet3, signet and regtest.

## Method

1. `getblockhash 0` must equal the configured network's genesis hash (verified in tests by re-hashing each genesis header).
2. `scantxoutset start [descriptor]` reads the current UTXO set; no address index or wallet is needed. Every returned `scriptPubKey` is re-derived and must belong to the target, or the scan fails.
3. Optional `getrawtransaction <txid> true <blockhash>`: a confirmed spend proves which key or script the target revealed (key reuse). Revealed keys must match the target's HASH160/SHA-256 commitment and be valid secp256k1 points; signatures are not re-verified because publication in an active-chain block is what exposes the key.
4. `getblockhash <scan height>` must still equal the scan's best block, or the scan fails (reorganization during collection).

## Exposure model

| Unspent output             | On-chain key              | Classification                                             |
| -------------------------- | ------------------------- | ---------------------------------------------------------- |
| P2PK, bare multisig        | in the output script      | public-key-in-script                                       |
| P2TR                       | output key is the address | public-key-in-script                                       |
| P2PKH, P2WPKH, P2SH, P2WSH | hash only                 | hash-locked (exposed if a supplied spend revealed the key) |

## Operation

- Configure with `BITCOIN_NODES` and a credential variable per node; credentials never appear in JSON or URLs and are attached only by the pinned transport. Allowed RPC methods: `getblockhash`, `scantxoutset`, `getrawtransaction`.
- `scantxoutset` reads the whole chainstate: minutes on mainnet (timeout 170 s). Bitcoin Core runs one scan at a time; the API returns 429 while a scan is running.
- Responses above 1 MB (very large UTXO sets) fail the scan rather than being truncated. Spend history is not indexed: without a supplied spend, hash-locked value is reported as hash-protected, which does not rule out earlier spends or off-chain disclosure. Bitcoin has no finality; outputs under 6 confirmations are flagged.
- Not supported: testnet4 (genesis constants not independently verified here), Electrum/Esplora indexes, CPM drift.

See the [root README](../../../README.md) for the working milestone and activation criteria.

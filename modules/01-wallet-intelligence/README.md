# ChainVanta Discover

Status: **Partially implemented**.

Finalized EVM account observations, explicit transaction signature verification (types 0/1/2), CBOM, versioned QBOM/CPM findings, evidence references and relational observation graph. The API validates source chain, block context, transaction hash, recovered sender and receipt context. Assessments persist atomically with tenant RLS and idempotency.

## Account structure discovery

`src/discovery/account-structure.ts` classifies code-bearing accounts at the snapshot block. All reads go through a `StructureReader` port that the EVM connector pins to the block hash (EIP-1898). Accounts without code cost no extra reads.

| Pattern                | Evidence                                                                                            | What it establishes                                                                             | Confidence           |
| ---------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | -------------------- |
| EIP-7702 delegation    | Code is exactly `0xef0100 ‖ delegate`                                                               | The account's secp256k1 key signed the delegation and remains a valid signer                    | observed             |
| EIP-1167 minimal proxy | Exact canonical runtime                                                                             | All calls delegate to the implementation; not upgradeable                                       | observed             |
| EIP-1967 proxy         | Implementation, admin and beacon slots (`keccak256(label) - 1`); `implementation()` on the beacon   | Upgradeable logic and who the slots name; upgrade authorization not analyzed                    | observed (slots)     |
| Safe                   | `getOwners()`, `getThreshold()`, `VERSION()`, `getModulesPaginated()`, slot 0 singleton, owner code | k-of-n policy; owners without code can only approve with ECDSA secp256k1; modules bypass owners | inferred (accessors) |
| ERC-4337               | `entryPoint()` and its code                                                                         | An entry point is reported; validation logic is vendor-specific                                 | inferred             |

Rules:

- **Reverts and exceptional halts are answers** ("interface not present"). Any other provider error fails the observation, so a rate limit can never read as "not a Safe".
- **Accessor data is validated before use**: owners must be distinct, non-zero, non-sentinel and at most 50; `1 ≤ threshold ≤ owners`. Inconsistent data is discarded, not guessed at.
- **Bounded**: at most 40 reads per account (real Safe 2-of-3: 12). Owner code is read for at most 10 owners; the rest stay `not-checked`. Call return data above 4 KB is recorded as hash and size only and never decoded, so a contract cannot inflate stored evidence.
- **Not detected**: diamonds (EIP-2535), custom proxy slots, non-canonical clones, Safe deployments without accessors, signer logic inside delegate/implementation/module code.

Consumers: CBOM adds secp256k1 components (observed for 7702, inferred for Safe owners without code); QBOM marks 7702 accounts `classical-signature-observed`; posture adds `CV-WALLET-003`, `CV-PROXY-001/002`, `CV-SAFE-001/002`, `CV-AA-001`; the trust graph adds edges whose relation names state how each was observed; CPM tracks these edges as dependencies, so implementation, owner and module changes raise `DEPENDENCY_CHANGED` drift. CPM's policy rules still classify quantum exposure only from verified transactions (see limitations).

## Transaction discovery

`src/discovery/transaction-discovery.ts` finds the account's latest signature without a user-supplied hash, using only standard JSON-RPC (no explorer, no API keys). Opt in per request with `"discoverTransaction": true` (CLI: `assess <address> --discover`). The chain must be configured with `"archive": true`, because historical nonces need archive state; otherwise the API returns 400.

Method (nonce bisection): an account nonce never decreases, so binary search over `[0, snapshot]` for the first block whose post-state nonce reaches the snapshot nonce N. That block B holds the account's last nonce use. Cost: at most ⌈log₂(snapshot + 1)⌉ historical nonce reads (≤ 25 on mainnet) plus one full-block read. Every probe is recorded for replay.

Evidence chosen from block B, strongest first:

| Outcome                        | Meaning                                                                                                      |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| `found`                        | Latest sent transaction (type 0/1/2); verified by the existing signature path                                |
| `authorization-signature`      | EIP-7702 authorization signed by the account; signer recovered from the signature (chain ID 0 or this chain) |
| `unsupported-transaction-type` | Latest sent transaction is type 3/4 and carries no own authorization; recorded, not verified                 |
| `no-sent-transactions`         | Nonce 0; finding `CV-WALLET-004` (off-chain signatures remain unobservable)                                  |
| `no-matching-transaction`      | Delegated accounts only: nonce used without a signed transaction or authorization (CREATE by delegated code) |
| `not-applicable`               | Contract account; no search                                                                                  |

Fail closed: probes must be monotone (each agrees with every earlier probe and the snapshot), block transactions must all parse, at most 1024 authorization recoveries per block, and for non-delegated accounts a nonce change with no matching transaction or authorization fails the scan rather than being reported. Full-block responses above the 1 MB RPC limit also fail the scan. For delegated accounts, an inconsistent provider cannot be distinguished from CREATE nonce use; that outcome stays `unknown` and claims no signature.

## Bitcoin

Bitcoin addresses and public keys are assessed through `POST /v1/bitcoin/assessments`. Pure code lives in `src/key-dependencies/bitcoin-codec.ts` (BIP-13/16/141/173/350 address decoding, script classification from bytes, push and multisig parsing), `src/signature-analysis/bitcoin-spend.ts` (key material a confirmed spend revealed) and `src/assessment/bitcoin.ts`. Findings: `CV-BTC-001` key in output scripts, `CV-BTC-002` key reuse proven by a supplied spend, `CV-BTC-003` hash-locked value with unknown spend history, `CV-BTC-004` non-standard scripts, `CV-BTC-005` fewer than 6 confirmations. See the [connector README](../../connectors/blockchains/bitcoin/README.md) for the method and limits.

## Limitations

No exhaustive wallet discovery, custody inference, complete transaction history or independent consensus validation. A verified historical transaction does not prove the account's current authorization mechanism. CPM policy rules do not yet consume structure evidence for quantum classification: that needs a new evidence requirement in the policy schema. Unknowns remain unknown.

Tests: `tests/unit/{assessment,rpc,intelligence,account-structure,account-structure-connector,account-structure-engines}.test.ts`, `tests/integration/pipeline.test.ts`.

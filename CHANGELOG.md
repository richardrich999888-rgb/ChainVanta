# Changelog

## Unreleased — Incremental role history

- Monitoring runs carry verified role history forward from the previous assessment (`roleHistory.basedOn`, method `access-control-events/1.1.0`) and request only new blocks plus old gaps, so range-capped providers converge to complete coverage over successive runs. Holders are re-checked with `hasRole` every run. The seed comes only from the worker's hash-verified, canonicality-checked previous assessment, never from API input; mismatched seeds are ignored and corrupt ones fail closed.

## Unreleased — Authority holder control

- `token-authority/1.2.0`: up to 2 contract holders of supply or logic roles are profiled as Safe (threshold, owners), OpenZeppelin TimelockController or Compound Timelock (delay), at most 3 reads each, inside the 60-call worker cap (worst case 58).
- New findings `CV-TOKEN-006` (1-of-N Safe with supply or upgrade power, high) and `CV-TOKEN-007` (zero-delay timelock, medium); unprofiled powerful contract holders are reported in `CV-TOKEN-004`. Safe owners and timelock delays are graph dependencies, so changes drift in CPM.
- Role history `hasRole` checks drop from 8 to 6 to fund profiling; earlier adapter documents remain valid.

## Unreleased — Token role history

- `token-authority/1.1.0`: for non-enumerable AccessControl, role holders are reconstructed from `RoleGranted`/`RoleRevoked` logs (range-limited requests are bisected, newest-first) and confirmed with `hasRole` at the pinned block. Fixed budget: 8 log requests and 8 checks, inside the worker's 60-call cap.
- New chain setting `fullLogHistory`; without it, event-derived role sets are never claimed complete. `eth_getLogs` joins the EVM RPC allowlist. Evidence (requests, gaps, events, reads) is stored in `tokenAuthority.roleHistory`; 1.0.0 documents remain valid.

## Unreleased — Bitcoin collector

- Read-only Bitcoin Core collector (`scantxoutset`) for addresses and public keys on mainnet, testnet3, signet and regtest; network identity proven by the genesis hash; every returned script re-derived against the target.
- Exposure model: keys in output scripts (P2PK, bare multisig, P2TR) versus hash-locked outputs, with key reuse proven from an optional supplied spend. Findings `CV-BTC-001`..`005`; Bitcoin QBOM statuses; CycloneDX export with a reviewed BIP-340 Schnorr entry.
- API `/v1/bitcoin/{networks,assessments}`, SDK methods, `BITCOIN_NODES` configuration with credentials from named environment variables. Assets generalize to CAIP-10 (`bip122:` namespace, migration `011_bitcoin`); EVM endpoints exclude Bitcoin documents.
- The pinned RPC transport is now policy-driven (method allowlist, per-method timeout, configured credentials).

## Unreleased (on `feature/web3-cpm-engine`)

- Export CBOMs as CycloneDX 1.6 (`GET /v1/assessments/:id/cbom`), validated against a strict model of the emitted subset. Sample output was also validated against the official 1.6 JSON Schema during development.
- Activate CLI commands `assess`, `cbom`, `qbom` and `posture` (CPM posture by asset). SDK adds `cbom()`.

## Unreleased — Transaction discovery

- Opt-in `discoverTransaction` finds the latest sent transaction by nonce bisection over archive state (standard JSON-RPC only) and verifies it, or recovers the account's EIP-7702 authorization signature. Requires `"archive": true` on the chain; CLI `assess --discover`.
- New findings `CV-QUANTUM-002` (verified authorization signature), `CV-WALLET-004` (nonce 0) and `CV-WALLET-005` (latest transaction not verifiable). Inconsistent historical state fails closed.

## Unreleased — EVM account structure

- Detect EIP-7702 delegated accounts, EIP-1167 minimal proxies, EIP-1967 proxies (implementation, admin, beacon), Safe multisig owners/threshold/modules and ERC-4337 entry points for code-bearing accounts. Reads are pinned to the snapshot block hash and bounded.
- CBOM, QBOM (`quantum-exposure/1.1.0`), posture findings and trust graph consume the structure evidence; CPM tracks structure edges as dependencies for drift.
- Collector: treat EVM execution failures (reverts and halts) from probe calls as answers while failing on all other provider errors; accept JSON-RPC error replies that carry no `result`. Transport allows read-only `eth_getStorageAt`.

## 0.1.0 — Unreleased

- Establish modular TypeScript application and all 12 domain module boundaries.
- Add read-only finalized EVM snapshots, conservative CBOM/QBOM, baseline posture and evidence graph.
- Add tenant-scoped PostgreSQL persistence, row policies, append-only records and hash verification.
- Add Next.js console, TypeScript client, CLI, local bootstrap, tests and GitHub workflow definitions.
- Mark unimplemented modules and infrastructure as planned; document production deployment gates.
- Align the repository with the prescribed 303-directory layout, enforce it in CI, and add authenticated page entry points for all ten console routes.

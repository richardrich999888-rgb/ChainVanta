# Changelog

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

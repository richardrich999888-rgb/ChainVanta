# Changelog

## Unreleased (on `feature/web3-cpm-engine`)

- Export CBOMs as CycloneDX 1.6 (`GET /v1/assessments/:id/cbom`), validated against a strict model of the emitted subset. Sample output was also validated against the official 1.6 JSON Schema during development.
- Activate CLI commands `assess`, `cbom`, `qbom` and `posture` (CPM posture by asset). SDK adds `cbom()`.

## 0.1.0 — Unreleased

- Establish modular TypeScript application and all 12 domain module boundaries.
- Add read-only finalized EVM snapshots, conservative CBOM/QBOM, baseline posture and evidence graph.
- Add tenant-scoped PostgreSQL persistence, row policies, append-only records and hash verification.
- Add Next.js console, TypeScript client, CLI, local bootstrap, tests and GitHub workflow definitions.
- Mark unimplemented modules and infrastructure as planned; document production deployment gates.
- Align the repository with the prescribed 303-directory layout, enforce it in CI, and add authenticated page entry points for all ten console routes.

# Repository layout

The user-supplied [repository tree](repository-structure.txt) is recorded as a
[machine-readable contract](repository-structure.json). `pnpm check:structure` requires every
listed directory and file, rejects additional directories at explicitly enumerated boundaries,
and restricts root files, workflow names and architecture document names. Leaf directories
remain open for their implementation files. CI and `make check` run the validator.

## Source placement

- Wallet assessment and transaction verification live in `modules/01-wallet-intelligence/src/assessment`
  and `src/signature-analysis`. The explicit token adapter lives in module 09's `src/privileged-roles`.
- The ten planned module contracts live within their respective domain subdirectories. Their
  acceptance specifications live in each module's `tests`; threat models live in `security/threat-models`.
- CBOM generation, QBOM rules, posture evaluation, evidence hashing and graph building live in
  the corresponding named engine subdirectories under `core`. Tenant authorization owns quotas.
- Shared test helpers live in `packages/test-fixtures/src`; the test API entry point lives in
  `tests/integration/server.ts`.
- CLI handlers live in `cli/chainvanta/commands/{scan,assess,inventory,report,cbom,qbom,posture}`.
- CycloneDX export lives in `core/cbom-engine/exporters`, its strict output model in
  `core/cbom-engine/schema-validation`.
- TypeScript configurations live in `packages/config`; Vitest, Playwright and structure validation
  live in `scripts/testing`. Package scripts explicitly select those configurations.
- API generation lives in `scripts/development`; SBOM generation lives in `scripts/release`.
- Each of the ten customer routes has its own Next.js page. They share authenticated loading in
  `components/console-page.tsx`, navigation in `hooks`, and styling in `styles`.

## Supporting files

The supplied tree describes architecture boundaries; working tools also need implementation and
framework files inside them. `pnpm-lock.yaml` is retained at the root for reproducible dependencies.
Next.js keeps its app-local package/config/type files, `AGENTS.md`, root page/layout and `app/api`
session/proxy handlers. The validator explicitly permits the lockfile and `app/api` boundary.
Existing `.env` stays private and ignored. Generated `node_modules`, `.next`, `dist`, test output
and `.local` content are ignored and are not source architecture boundaries.

Empty reserved folders contain `.gitkeep` so they survive a Git checkout. Root `Cargo.toml` is
a valid empty workspace for future Rust packages, not an implemented Rust agent or SDK.

## Workflow status

All six requested workflow files exist. CI verifies the layout and implementation. Security
regression checks exercise authorization, quotas, tenant isolation and evidence persistence;
CodeQL and dependency auditing remain separate workflows. Manual release builds upload a
candidate build artifact; they do not publish a release. Manual staging deployment fails with an
explicit configuration-required error until a deployment target and operational controls are
implemented. None of these workflows have been run on GitHub by this local restructuring task.

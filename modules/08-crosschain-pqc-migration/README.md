# ChainVanta Quantum

Status: **Planned**. Contracts only; no operational adapter is registered.

Capability: `migration-readiness`. Asset kinds: signature-domain, transport-domain, consensus-domain.

Integration: consume tenant-scoped canonical asset IDs and evidence references through `src/migration-planner/contract.ts`. Runtime output validation and a reviewed, versioned adapter are prerequisites to activation.

Transport PQC does not protect classical transaction signatures. Plans require explicit compatibility evidence.

See [threat model](../../security/threat-models/08-crosschain-pqc-migration.md) and [test specification](tests/acceptance.md).

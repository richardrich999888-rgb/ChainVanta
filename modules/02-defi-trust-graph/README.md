# ChainVanta Graph

Status: **Planned**. Contracts only; no operational adapter is registered.

Capability: `protocol-dependencies`. Asset kinds: protocol, oracle, contract.

Integration: consume tenant-scoped canonical asset IDs and evidence references through `src/protocol-analysis/contract.ts`. Runtime output validation and a reviewed, versioned adapter are prerequisites to activation.

Do not infer a dependency or causal risk propagation from co-occurrence. Require a verifiable contract call or authorized configuration.

See [threat model](../../security/threat-models/02-defi-trust-graph.md) and [test specification](tests/acceptance.md).

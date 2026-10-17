# ChainVanta Zero

Status: **Planned**. Contracts only; no operational adapter is registered.

Capability: `proof-system-inventory`. Asset kinds: proof-system, trusted-setup, verifier.

Integration: consume tenant-scoped canonical asset IDs and evidence references through `src/proof-system-discovery/contract.ts`. Runtime output validation and a reviewed, versioned adapter are prerequisites to activation.

Proof systems and setup assumptions are not interchangeable. Unsupported curves and schemes must remain unknown.

See [threat model](../../security/threat-models/06-zk-crypto-inventory.md) and [test specification](tests/acceptance.md).

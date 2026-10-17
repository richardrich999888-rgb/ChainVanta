# ChainVanta Provenance

Status: **Planned**. Contracts only; no operational adapter is registered.

Capability: `content-signature`. Asset kinds: content, signature, provenance-reference.

Integration: consume tenant-scoped canonical asset IDs and evidence references through `src/asset-verification/contract.ts`. Runtime output validation and a reviewed, versioned adapter are prerequisites to activation.

Content integrity and signature validity do not establish legal ownership or authentic real-world claims.

See [threat model](../../security/threat-models/11-digital-provenance.md) and [test specification](tests/acceptance.md).

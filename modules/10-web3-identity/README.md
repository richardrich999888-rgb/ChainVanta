# ChainVanta Identity

Status: **Planned**. Contracts only; no operational adapter is registered.

Capability: `credential-verification`. Asset kinds: did-method, credential, issuer.

Integration: consume tenant-scoped canonical asset IDs and evidence references through `src/did-analysis/contract.ts`. Runtime output validation and a reviewed, versioned adapter are prerequisites to activation.

Method-specific resolution and revocation semantics are required; a valid signature alone is not current issuer authorization.

See [threat model](../../security/threat-models/10-web3-identity.md) and [test specification](tests/acceptance.md).

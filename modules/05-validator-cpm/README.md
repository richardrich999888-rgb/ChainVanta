# ChainVanta Validator

Status: **Planned**. Contracts only; no operational adapter is registered.

Capability: `validator-configuration`. Asset kinds: validator, certificate, key-management.

Integration: consume tenant-scoped canonical asset IDs and evidence references through `src/validator-discovery/contract.ts`. Runtime output validation and a reviewed, versioned adapter are prerequisites to activation.

Authorized infrastructure facts must remain separate from public-chain inferences. Never request signing keys.

See [threat model](../../security/threat-models/05-validator-cpm.md) and [test specification](tests/acceptance.md).

# ChainVanta Agility

Status: **Planned**. Contracts only; no operational adapter is registered.

Capability: `contract-agility`. Asset kinds: contract, verifier, upgrade-authority.

Integration: consume tenant-scoped canonical asset IDs and evidence references through `src/contract-analysis/contract.ts`. Runtime output validation and a reviewed, versioned adapter are prerequisites to activation.

Untrusted bytecode, proxy indirection and selector collisions must not imply upgradeability. Foundry fixtures are required before adapter activation.

See [threat model](../../security/threat-models/04-contract-crypto-agility.md) and [test specification](tests/acceptance.md).

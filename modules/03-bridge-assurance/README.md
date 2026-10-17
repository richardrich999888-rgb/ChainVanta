# ChainVanta Bridge

Status: **Planned**. Contracts only; no operational adapter is registered.

Capability: `bridge-verification`. Asset kinds: bridge, relayer, validator.

Integration: consume tenant-scoped canonical asset IDs and evidence references through `src/bridge-discovery/contract.ts`. Runtime output validation and a reviewed, versioned adapter are prerequisites to activation.

Each bridge adapter must declare its own validation architecture; generic signature counts cannot establish bridge security.

See [threat model](../../security/threat-models/03-bridge-assurance.md) and [test specification](tests/acceptance.md).

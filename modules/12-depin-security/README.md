# ChainVanta Edge

Status: **Planned**. Contracts only; no operational adapter is registered.

Capability: `device-attestation`. Asset kinds: device, firmware, root-of-trust.

Integration: consume tenant-scoped canonical asset IDs and evidence references through `src/device-identity/contract.ts`. Runtime output validation and a reviewed, versioned adapter are prerequisites to activation.

Attestation requires a supported device, verified trust anchor, freshness and replay defenses. No simulated hardware assurance.

See [threat model](../../security/threat-models/12-depin-security.md) and [test specification](tests/acceptance.md).

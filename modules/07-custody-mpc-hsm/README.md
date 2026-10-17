# ChainVanta Vault

Status: **Planned**. Contracts only; no operational adapter is registered.

Capability: `custody-configuration`. Asset kinds: custodian, mpc-scheme, hsm.

Integration: consume tenant-scoped canonical asset IDs and evidence references through `src/custody-inventory/contract.ts`. Runtime output validation and a reviewed, versioned adapter are prerequisites to activation.

Read-only authorized metadata only. Never ingest private keys, seed phrases, secret shares or HSM master keys.

See [threat model](../../security/threat-models/07-custody-mpc-hsm.md) and [test specification](tests/acceptance.md).

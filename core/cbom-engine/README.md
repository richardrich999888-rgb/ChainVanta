# cbom-engine

Status: **Partially implemented.** `generators/`, `exporters/` and `schema-validation/` are
implemented; `inventory-merging/` remains planned.

- `generators/`: native `chainvanta-cbom/0.1` components from a validated observation.
- `exporters/cyclonedx.ts`: CycloneDX 1.6 JSON. One assessment maps to one BOM identity
  (`serialNumber` = assessment UUID, `version` = 1) so re-exports are byte-identical. This departs
  from CycloneDX's recommendation of fresh serials per generation in favor of reproducibility.
  Composition is always `incomplete`. Only reviewed algorithms get attributes; anything else is
  `primitive: unknown`. Execution environment, platform and certification are always `unknown`
  because on-chain evidence cannot reveal the signer's implementation.
- `schema-validation/cyclonedx.ts`: strict Zod model of the emitted subset, with enum values
  taken from the official `bom-1.6.schema.json`. The exporter fails closed if its output does not
  match. This is not a general CycloneDX validator.

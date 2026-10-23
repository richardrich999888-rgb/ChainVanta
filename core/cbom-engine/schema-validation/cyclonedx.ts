import { z } from 'zod';

/**
 * Strict Zod model of the CycloneDX 1.6 JSON subset that ChainVanta emits.
 *
 * Enum values are copied from the official bom-1.6.schema.json (definitions.cryptoProperties).
 * `.strict()` rejects any field the exporter is not known to emit, so an exporter change cannot
 * silently produce unreviewed output. This validates our subset only; it is not a general
 * CycloneDX validator and does not replace validation against the official JSON Schema.
 */

export const CDX_SPEC_VERSION = '1.6';

const Property = z.object({ name: z.string().min(1), value: z.string() }).strict();

const Primitive = z.enum([
  'drbg',
  'mac',
  'block-cipher',
  'stream-cipher',
  'signature',
  'hash',
  'pke',
  'xof',
  'kdf',
  'key-agree',
  'kem',
  'ae',
  'combiner',
  'other',
  'unknown',
]);
const ExecutionEnvironment = z.enum([
  'software-plain-ram',
  'software-encrypted-ram',
  'software-tee',
  'hardware',
  'other',
  'unknown',
]);
// Subset of the 1.6 enumeration: ChainVanta never infers a platform or certification.
const ImplementationPlatform = z.enum(['generic', 'other', 'unknown']);
const CertificationLevel = z.enum(['none', 'other', 'unknown']);
const CryptoFunction = z.enum([
  'generate',
  'keygen',
  'encrypt',
  'decrypt',
  'digest',
  'tag',
  'keyderive',
  'sign',
  'verify',
  'encapsulate',
  'decapsulate',
  'other',
  'unknown',
]);

export const AlgorithmProperties = z
  .object({
    primitive: Primitive,
    curve: z.string().min(1).optional(),
    executionEnvironment: ExecutionEnvironment,
    implementationPlatform: ImplementationPlatform,
    certificationLevel: z.array(CertificationLevel).min(1),
    cryptoFunctions: z.array(CryptoFunction).min(1),
    classicalSecurityLevel: z.number().int().nonnegative().optional(),
    // Schema bounds: 0 (no NIST PQC category met) through 6.
    nistQuantumSecurityLevel: z.number().int().min(0).max(6).optional(),
  })
  .strict();
export type AlgorithmProperties = z.infer<typeof AlgorithmProperties>;

export const CryptoComponent = z
  .object({
    type: z.literal('cryptographic-asset'),
    'bom-ref': z.string().min(1),
    name: z.string().min(1),
    cryptoProperties: z
      .object({ assetType: z.literal('algorithm'), algorithmProperties: AlgorithmProperties })
      .strict(),
    properties: z.array(Property),
  })
  .strict();

export const CycloneDxCbom = z
  .object({
    bomFormat: z.literal('CycloneDX'),
    specVersion: z.literal(CDX_SPEC_VERSION),
    // Pattern from the official schema (RFC 4122 URN, lowercase hex).
    serialNumber: z
      .string()
      .regex(/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/),
    version: z.number().int().min(1),
    metadata: z
      .object({
        timestamp: z.iso.datetime(),
        tools: z
          .object({
            components: z.array(
              z
                .object({ type: z.literal('application'), name: z.string(), version: z.string() })
                .strict(),
            ),
          })
          .strict(),
        properties: z.array(Property),
      })
      .strict(),
    components: z.array(CryptoComponent),
    compositions: z.array(
      z.object({ aggregate: z.enum(['complete', 'incomplete', 'unknown']) }).strict(),
    ),
  })
  .strict()
  .superRefine((bom, context) => {
    const refs = bom.components.map((component) => component['bom-ref']);
    if (new Set(refs).size !== refs.length)
      context.addIssue({ code: 'custom', message: 'bom-ref values must be unique' });
  });
export type CycloneDxCbom = z.infer<typeof CycloneDxCbom>;

/** Validates an exported BOM; throws a ZodError describing the first violations. */
export function validateCycloneDxCbom(value: unknown): CycloneDxCbom {
  return CycloneDxCbom.parse(value);
}

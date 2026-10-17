import { z } from 'zod';
import { Digest, Confidence } from '../../../../packages/domain-models/src/index.js';
export const moduleId = '12-depin-security' as const;
export const status = 'planned' as const;
export const capability = 'device-attestation' as const;
export const Input = z
  .object({
    tenantId: z.uuid(),
    assetId: z.string().min(1),
    assetKind: z.enum(['device', 'firmware', 'root-of-trust']),
    evidenceRefs: z.array(Digest).min(1),
  })
  .strict();
export const Result = z.object({
  schemaVersion: z.literal('1.0.0'),
  moduleId: z.literal(moduleId),
  status: z.enum(['supported', 'unsupported']),
  confidence: Confidence,
  evidenceRefs: z.array(Digest),
  limitations: z.array(z.string()),
});
export interface Adapter {
  readonly version: string;
  supports(input: z.infer<typeof Input>): boolean;
  inspect(input: z.infer<typeof Input>, signal: AbortSignal): Promise<z.infer<typeof Result>>;
}

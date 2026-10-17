import { createHash, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';

export const TenantKeys = z
  .array(
    z.object({
      tenantId: z.uuid(),
      key: z.string().min(32).max(256),
      role: z.enum(['viewer', 'analyst', 'admin']).optional(),
    }),
  )
  .superRefine((items, ctx) => {
    if (new Set(items.map((item) => item.key)).size !== items.length)
      ctx.addIssue({ code: 'custom', message: 'API keys must be unique' });
  });
export type TenantKey = z.infer<typeof TenantKeys>[number];

export function authorize(authorization: string | undefined, keys: TenantKey[]): string | null {
  const match = /^Bearer ([^\s]{32,256})$/.exec(authorization ?? '');
  if (!match?.[1]) return null;
  const digest = createHash('sha256').update(match[1]).digest();
  let tenantId: string | null = null;
  for (const entry of keys) {
    if (timingSafeEqual(digest, createHash('sha256').update(entry.key).digest()))
      tenantId = entry.tenantId;
  }
  return tenantId;
}

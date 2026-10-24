import { OidcConfig } from '../../../services/identity-service/auth.js';
import { z } from 'zod';
import { TenantKeys } from '../../../core/tenant-authorization/src/index.js';
export const Chains = z
  .array(
    z.object({
      chainId: z.number().int().positive().safe(),
      name: z.string().min(1).max(80),
      demonstration: z.boolean().optional(),
      /** Provider serves historical state; required for transaction discovery. */
      archive: z.boolean().optional(),
      rpcUrl: z.url().refine((value) => {
        const url = new URL(value);
        return (
          !['169.254.169.254', 'metadata.google.internal', '0.0.0.0', '[::]'].includes(
            url.hostname,
          ) &&
          !url.username &&
          !url.password &&
          (url.protocol === 'https:' ||
            (url.protocol === 'http:' &&
              ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))
        );
      }, 'RPC must use HTTPS, or HTTP on loopback for local tests'),
    }),
  )
  .min(1)
  .max(20)
  .refine(
    (items) => new Set(items.map((item) => item.chainId)).size === items.length,
    'Chain IDs must be unique',
  );

export function readConfig(env: NodeJS.ProcessEnv = process.env) {
  const config = {
    oidc: env.OIDC_CONFIG ? OidcConfig.parse(JSON.parse(env.OIDC_CONFIG)) : undefined,
    redisUrl: z.url().parse(env.REDIS_URL ?? 'redis://127.0.0.1:6379'),
    databaseUrl: z.string().min(1).parse(env.DATABASE_URL),
    tenantKeys: TenantKeys.parse(JSON.parse(env.TENANT_API_KEYS ?? '[]')),
    chains: Chains.parse(JSON.parse(env.CHAINS ?? '[]')),
    port: z.coerce
      .number()
      .int()
      .min(1)
      .max(65535)
      .parse(env.PORT ?? 4000),
    host: env.API_HOST ?? '127.0.0.1',
  };
  if (
    env.NODE_ENV === 'production' &&
    config.chains.some(
      (chain) => chain.demonstration || new URL(chain.rpcUrl).protocol !== 'https:',
    )
  )
    throw new Error(
      'Production requires approved HTTPS RPC providers and prohibits demonstration chains',
    );
  return config;
}
export type Config = ReturnType<typeof readConfig>;

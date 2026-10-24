import { OidcConfig } from '../../../services/identity-service/auth.js';
import { z } from 'zod';
import { BitcoinNetwork } from '../../domain-models/src/bitcoin.js';
import type { BitcoinNodeConfig } from '../../../connectors/blockchains/bitcoin/src/index.js';
import { TenantKeys } from '../../../core/tenant-authorization/src/index.js';
/** HTTPS, or HTTP on loopback for local tests; never metadata hosts or embedded credentials. */
export const RpcUrl = z.url().refine((value) => {
  const url = new URL(value);
  return (
    !['169.254.169.254', 'metadata.google.internal', '0.0.0.0', '[::]'].includes(url.hostname) &&
    !url.username &&
    !url.password &&
    (url.protocol === 'https:' ||
      (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))
  );
}, 'RPC must use HTTPS, or HTTP on loopback for local tests');
export const Chains = z
  .array(
    z.object({
      chainId: z.number().int().positive().safe(),
      name: z.string().min(1).max(80),
      demonstration: z.boolean().optional(),
      /** Provider serves historical state; required for transaction discovery. */
      archive: z.boolean().optional(),
      rpcUrl: RpcUrl,
    }),
  )
  .min(1)
  .max(20)
  .refine(
    (items) => new Set(items.map((item) => item.chainId)).size === items.length,
    'Chain IDs must be unique',
  );

/**
 * Bitcoin Core nodes. Credentials are never part of this JSON or the URL: `credentialsEnv` names
 * an environment variable holding `user:password` (Bitcoin Core rpcauth or cookie credentials).
 */
export const BitcoinNodes = z
  .array(
    z
      .object({
        network: BitcoinNetwork,
        name: z.string().min(1).max(80),
        rpcUrl: RpcUrl,
        demonstration: z.boolean().optional(),
        credentialsEnv: z
          .string()
          .regex(/^BITCOIN_RPC_[A-Z0-9_]{1,40}$/)
          .optional(),
      })
      .strict(),
  )
  .max(4)
  .refine(
    (items) => new Set(items.map((item) => item.network)).size === items.length,
    'One node per network',
  );

/** Resolves configured Bitcoin nodes and their credentials; a missing credential is fatal. */
export function readBitcoinNodes(env: NodeJS.ProcessEnv): BitcoinNodeConfig[] {
  return BitcoinNodes.parse(JSON.parse(env.BITCOIN_NODES ?? '[]')).map(
    ({ credentialsEnv, ...node }) => {
      if (!credentialsEnv) return node;
      const value = env[credentialsEnv] ?? '';
      const separator = value.indexOf(':');
      if (separator < 1 || separator === value.length - 1)
        throw new Error(`${credentialsEnv} must hold user:password for the ${node.network} node`);
      return {
        ...node,
        credentials: { user: value.slice(0, separator), password: value.slice(separator + 1) },
      };
    },
  );
}

export function readConfig(env: NodeJS.ProcessEnv = process.env) {
  const config = {
    oidc: env.OIDC_CONFIG ? OidcConfig.parse(JSON.parse(env.OIDC_CONFIG)) : undefined,
    redisUrl: z.url().parse(env.REDIS_URL ?? 'redis://127.0.0.1:6379'),
    databaseUrl: z.string().min(1).parse(env.DATABASE_URL),
    tenantKeys: TenantKeys.parse(JSON.parse(env.TENANT_API_KEYS ?? '[]')),
    chains: Chains.parse(JSON.parse(env.CHAINS ?? '[]')),
    bitcoinNodes: readBitcoinNodes(env),
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
    [...config.chains, ...config.bitcoinNodes].some(
      (endpoint) => endpoint.demonstration || new URL(endpoint.rpcUrl).protocol !== 'https:',
    )
  )
    throw new Error(
      'Production requires approved HTTPS RPC providers and prohibits demonstration chains',
    );
  return config;
}
export type Config = ReturnType<typeof readConfig>;

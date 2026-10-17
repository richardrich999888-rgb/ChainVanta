import { createHash } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import { z } from 'zod';
import { authorize, type TenantKey } from '../../core/tenant-authorization/src/index.js';
export const OidcConfig = z
  .object({
    issuer: z.url().refine((v) => v.startsWith('https://')),
    audience: z.string().min(1),
    jwksUrl: z.url().refine((v) => v.startsWith('https://')),
    memberships: z
      .array(
        z.object({
          subject: z.string().min(1),
          tenantId: z.uuid(),
          role: z.enum(['viewer', 'analyst', 'admin']),
        }),
      )
      .min(1),
  })
  .strict()
  .refine(
    (v) => new Set(v.memberships.map((m) => m.subject)).size === v.memberships.length,
    'One tenant membership per subject is supported in this release',
  );
export type Principal = { tenantId: string; subject: string; role: 'viewer' | 'analyst' | 'admin' };
export class Authenticator {
  private jwks?: JWTVerifyGetKey;
  constructor(
    private keys: TenantKey[],
    private oidc?: z.infer<typeof OidcConfig>,
    getKey?: JWTVerifyGetKey,
  ) {
    this.jwks =
      getKey ??
      (oidc
        ? createRemoteJWKSet(new URL(oidc.jwksUrl), {
            timeoutDuration: 5000,
            cooldownDuration: 30_000,
          })
        : undefined);
  }
  async authenticate(header?: string): Promise<Principal | null> {
    const tenantId = authorize(header, this.keys);
    if (tenantId) {
      const key = header!.slice(7);
      const entry = this.keys.find((v) => v.key === key)!;
      return {
        tenantId,
        subject: `api-key:${createHash('sha256').update(key).digest('hex').slice(0, 16)}`,
        role: entry.role ?? 'analyst',
      };
    }
    if (!this.oidc || !this.jwks || !header?.startsWith('Bearer ') || header.length > 8192)
      return null;
    try {
      const { payload } = await jwtVerify(header.slice(7), this.jwks, {
        issuer: this.oidc.issuer,
        audience: this.oidc.audience,
        algorithms: ['RS256', 'ES256'],
        requiredClaims: ['sub', 'exp', 'iat'],
      });
      // Tenant/roles from operator-owned membership mapping, never arbitrary token claims.
      return this.oidc.memberships.find((v) => v.subject === payload.sub) ?? null;
    } catch {
      return null;
    }
  }
}

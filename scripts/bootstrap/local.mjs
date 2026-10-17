import { randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
if (existsSync('.env') || existsSync('apps/web-console/.env.local')) {
  console.error(
    'Local configuration already exists. Keep it or move it aside before bootstrapping.',
  );
  process.exit(1);
}
const ownerPassword = randomBytes(24).toString('hex');
const appPassword = randomBytes(24).toString('hex');
const key = randomBytes(32).toString('hex');
const tenantId = randomUUID();
mkdirSync('apps/web-console', { recursive: true });
writeFileSync(
  '.env',
  [
    `POSTGRES_PASSWORD=${ownerPassword}`,
    `POSTGRES_APP_PASSWORD=${appPassword}`,
    `MIGRATION_DATABASE_URL=postgres://chainvanta_owner:${ownerPassword}@127.0.0.1:5432/chainvanta`,
    `DATABASE_URL=postgres://chainvanta_app:${appPassword}@127.0.0.1:5432/chainvanta`,
    `TENANT_API_KEYS='${JSON.stringify([{ tenantId, key }])}'`,
    `CHAINS='${JSON.stringify([{ chainId: 1, name: 'Ethereum', rpcUrl: 'https://ethereum-rpc.publicnode.com' }])}'`,
    'PORT=4000',
    'API_HOST=127.0.0.1',
    'API_BASE_URL=http://127.0.0.1:4000',
    '',
  ].join('\n'),
  { mode: 0o600, flag: 'wx' },
);
writeFileSync(
  'apps/web-console/.env.local',
  'API_BASE_URL=http://127.0.0.1:4000\nWEB_ORIGIN=http://127.0.0.1:3000\nNEXT_TELEMETRY_DISABLED=1\n',
  { mode: 0o600, flag: 'wx' },
);
console.log('Created local configuration with random database passwords and tenant credentials.');
console.log(
  'Read TENANT_API_KEYS in .env for your login key. Review CHAINS before collecting data.',
);

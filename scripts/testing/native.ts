import { spawnSync } from 'node:child_process';
if (!process.env.MIGRATION_DATABASE_URL) throw new Error('Local migration URL required');
const url = new URL(process.env.MIGRATION_DATABASE_URL);
url.pathname = '/chainvanta_foundation_test';
// Explicit dedicated test database. Never execute destructive test setup on the application DB.
const result = spawnSync('pnpm', [process.argv.includes('--e2e') ? 'test:e2e' : 'test'], {
  stdio: 'inherit',
  env: { ...process.env, TEST_DATABASE_URL: url.toString() },
});
process.exit(result.status ?? 1);

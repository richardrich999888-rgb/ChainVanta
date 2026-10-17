import { fileURLToPath } from 'node:url';
import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: '../../tests/end-to-end',
  outputDir: '../../test-results',
  workers: 1,
  timeout: 60_000,
  use: {
    channel: process.env.PLAYWRIGHT_CHANNEL,
    baseURL: 'http://127.0.0.1:3400',
    viewport: { width: 1440, height: 1000 },
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      cwd: fileURLToPath(new URL('../../', import.meta.url)),
      command: 'pnpm exec tsx --tsconfig packages/config/tsconfig.json tests/integration/server.ts',
      url: 'http://127.0.0.1:4400/health/ready',
      env: { CHAINVANTA_TEST_MODE: '1' },
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      cwd: fileURLToPath(new URL('../../', import.meta.url)),
      command:
        'pnpm --filter @chainvanta/web-console exec next dev --hostname 127.0.0.1 --port 3400',
      url: 'http://127.0.0.1:3400',
      env: {
        API_BASE_URL: 'http://127.0.0.1:4400',
        WEB_ORIGIN: 'http://127.0.0.1:3400',
        NEXT_TELEMETRY_DISABLED: '1',
      },
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});

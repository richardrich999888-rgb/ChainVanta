import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
export default defineConfig({
  root: fileURLToPath(new URL('../../', import.meta.url)),
  esbuild: { tsconfigRaw: { compilerOptions: { experimentalDecorators: true } } },
  test: {
    include: ['tests/**/*.test.ts', 'modules/**/tests/**/*.test.ts', 'cli/**/tests/**/*.test.ts'],
    testTimeout: 20000,
  },
});

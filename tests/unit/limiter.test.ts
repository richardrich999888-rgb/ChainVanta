import { it, expect } from 'vitest';
import { RedisLimiter } from '../../core/tenant-authorization/src/rate-limit.js';
import type { RedisClientType } from 'redis';
it('uses a tenant-specific atomic Redis quota and propagates Redis failure', async () => {
  let count = 119;
  const client = {
    eval: async (script: string, options: { keys: string[] }) => {
      expect(script).toContain('PEXPIRE');
      expect(options.keys).toEqual(['chainvanta:rate:tenant-a']);
      return ++count;
    },
    ping: async () => {
      throw new Error('offline');
    },
  } as unknown as RedisClientType;
  const limiter = new RedisLimiter(client);
  expect(await limiter.consume('tenant-a')).toBe(true);
  expect(await limiter.consume('tenant-a')).toBe(false);
  await expect(limiter.ping()).rejects.toThrow('offline');
});

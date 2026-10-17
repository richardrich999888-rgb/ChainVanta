import type { RedisClientType } from 'redis';
export interface RequestLimiter {
  consume(tenantId: string): Promise<boolean>;
  ping(): Promise<void>;
}
export class RedisLimiter implements RequestLimiter {
  constructor(private client: RedisClientType) {}
  async consume(tenantId: string) {
    const count = await this.client.eval(
      "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],60000) end; return n",
      { keys: [`chainvanta:rate:${tenantId}`], arguments: [] },
    );
    return Number(count) <= 120;
  }
  async ping() {
    await this.client.ping();
  }
}
// Deterministic tests only. Production startup always supplies RedisLimiter.
export class TestLimiter implements RequestLimiter {
  private windows = new Map<string, { count: number; reset: number }>();
  async consume(tenantId: string) {
    const now = Date.now();
    let value = this.windows.get(tenantId);
    if (!value || value.reset <= now) {
      value = { count: 0, reset: now + 60_000 };
      this.windows.set(tenantId, value);
    }
    return ++value.count <= 120;
  }
  async ping() {}
}

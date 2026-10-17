import { expect, it, vi } from 'vitest';
import { runCommand } from '../commands/index.js';

const client = () => ({ assess: vi.fn(), list: vi.fn(), get: vi.fn() });
it('validates addresses before making a request', () => {
  const api = client();
  expect(() => runCommand(api, ['scan', 'invalid'])).toThrow();
  expect(api.assess).not.toHaveBeenCalled();
});
it('preserves the scan command and its default network', () => {
  const api = client();
  const address = '0x' + 'ab'.repeat(20);
  runCommand(api, ['scan', address]);
  expect(api.assess).toHaveBeenCalledWith({ address, chainId: 1 });
  runCommand(api, ['scan', address, '8453']);
  expect(api.assess).toHaveBeenLastCalledWith({ address, chainId: 8453 });
});
it('dispatches inventory and report commands to the existing SDK', () => {
  const api = client();
  runCommand(api, ['inventory']);
  runCommand(api, ['report', 'assessment-id']);
  expect(api.list).toHaveBeenCalledOnce();
  expect(api.get).toHaveBeenCalledWith('assessment-id');
});
it('keeps reserved commands unavailable until implemented', () => {
  const api = client();
  for (const args of [[], ['report'], ['cbom'], ['qbom'], ['posture'], ['assess']])
    expect(() => runCommand(api, args)).toThrow('Usage:');
  expect(api.assess).not.toHaveBeenCalled();
});

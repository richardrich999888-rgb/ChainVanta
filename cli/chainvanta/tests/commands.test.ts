import { expect, it, vi } from 'vitest';
import { runCommand } from '../commands/index.js';
import { assessWallet } from '../../../modules/01-wallet-intelligence/src/assessment/index.js';
import { TENANT_A, observation } from '../../../packages/test-fixtures/src/fixtures.js';

const ADDRESS = '0x' + 'ab'.repeat(20);
const TX = '0x' + 'cd'.repeat(32);
const STORED = assessWallet(TENANT_A, observation);
const ID = STORED.id;
const client = () => ({
  assess: vi.fn(),
  list: vi.fn(),
  get: vi.fn(async () => STORED),
  cbom: vi.fn(),
  posture: vi.fn(),
});
const untouched = (api: ReturnType<typeof client>) =>
  Object.values(api).forEach((fn) => expect(fn).not.toHaveBeenCalled());

it('validates addresses before making a request', () => {
  const api = client();
  expect(() => runCommand(api, ['scan', 'invalid'])).toThrow();
  expect(() => runCommand(api, ['assess', 'invalid'])).toThrow();
  untouched(api);
});
it('preserves the scan command and its default network', () => {
  const api = client();
  runCommand(api, ['scan', ADDRESS]);
  expect(api.assess).toHaveBeenCalledWith({ address: ADDRESS, chainId: 1 });
  runCommand(api, ['scan', ADDRESS, '8453']);
  expect(api.assess).toHaveBeenLastCalledWith({ address: ADDRESS, chainId: 8453 });
});
it('dispatches inventory and report commands to the existing SDK', () => {
  const api = client();
  runCommand(api, ['inventory']);
  runCommand(api, ['report', 'assessment-id']);
  expect(api.list).toHaveBeenCalledOnce();
  expect(api.get).toHaveBeenCalledWith('assessment-id');
});
it('assess forwards transaction and adapter options through request validation', () => {
  const api = client();
  runCommand(api, ['assess', ADDRESS, '8453', '--transaction', TX, '--adapter', 'ownable-erc20']);
  expect(api.assess).toHaveBeenCalledWith({
    address: ADDRESS,
    chainId: 8453,
    transactionHash: TX,
    adapter: 'ownable-erc20',
  });
  runCommand(api, ['assess', ADDRESS]);
  expect(api.assess).toHaveBeenLastCalledWith({ address: ADDRESS, chainId: 1 });
});
it('assess --discover requests transaction discovery, exclusive of --transaction', () => {
  const api = client();
  runCommand(api, ['assess', ADDRESS, '--discover']);
  expect(api.assess).toHaveBeenCalledWith({
    address: ADDRESS,
    chainId: 1,
    discoverTransaction: true,
  });
  expect(() => runCommand(api, ['assess', ADDRESS, '--discover', '--transaction', TX])).toThrow();
  expect(api.assess).toHaveBeenCalledOnce();
});
it('assess rejects unknown adapters, malformed hashes, unknown flags and extra arguments', () => {
  const api = client();
  for (const args of [
    ['assess', ADDRESS, '--adapter', 'arbitrary'],
    ['assess', ADDRESS, '--transaction', '0x1234'],
    ['assess', ADDRESS, '--private-key', 'secret'],
    ['assess', ADDRESS, '1', 'extra'],
    ['assess', ADDRESS, '0'],
  ])
    expect(() => runCommand(api, args)).toThrow();
  untouched(api);
});
it('dispatches cbom, qbom and posture to the SDK', async () => {
  const api = client();
  runCommand(api, ['cbom', ID]);
  expect(api.cbom).toHaveBeenCalledWith(ID);
  expect(await runCommand(api, ['qbom', ID])).toEqual({
    assessmentId: ID,
    evidenceHash: STORED.evidenceHash,
    qbom: STORED.qbom,
  });
  runCommand(api, ['posture', `eip155:8453:${ADDRESS}`]);
  expect(api.posture).toHaveBeenLastCalledWith(`eip155:8453:${ADDRESS}`);
  runCommand(api, ['posture', ADDRESS.toUpperCase().replace('0X', '0x'), '10']);
  expect(api.posture).toHaveBeenLastCalledWith(`eip155:10:${ADDRESS}`);
  runCommand(api, ['posture', ADDRESS]);
  expect(api.posture).toHaveBeenLastCalledWith(`eip155:1:${ADDRESS}`);
});
it('posture rejects malformed asset ids before any request', () => {
  const api = client();
  for (const args of [
    ['posture', 'eip155:1:0x1234'],
    ['posture', `eip155:0:${ADDRESS}`],
    ['posture', `eip155:1:${ADDRESS}`, '1'],
    ['posture', 'invalid'],
    ['posture', ADDRESS, '0'],
  ])
    expect(() => runCommand(api, args)).toThrow();
  untouched(api);
});
it('rejects unknown and incomplete commands with usage before any request', () => {
  const api = client();
  for (const args of [
    [],
    ['unknown'],
    ['report'],
    ['cbom'],
    ['qbom'],
    ['report', ID, 'extra'],
    ['posture'],
    ['posture', ADDRESS, '1', 'extra'],
  ])
    expect(() => runCommand(api, args)).toThrow('Usage:');
  untouched(api);
});

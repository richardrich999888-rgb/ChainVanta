import type { ChainVantaClient } from '../../../sdks/typescript/src/index.js';
import { scan } from './scan/index.js';
import { inventory } from './inventory/index.js';
import { report } from './report/index.js';
import { assess } from './assess/index.js';
import { cbom } from './cbom/index.js';
import { qbom } from './qbom/index.js';
import { posture } from './posture/index.js';

export const USAGE = [
  'Usage: pnpm cli <command>',
  '  scan <address> [chainId]',
  '  assess <address> [chainId] [--transaction <hash> | --discover] [--adapter ownable-erc20]',
  '  inventory',
  '  report <assessment-id>',
  '  cbom <assessment-id>                 CycloneDX 1.6 export',
  '  qbom <assessment-id>',
  '  posture <asset-id | address [chainId]>   current CPM posture',
].join('\n');

type Client = Pick<ChainVantaClient, 'assess' | 'list' | 'get' | 'cbom' | 'posture'>;

/** Dispatches CLI arguments to SDK calls. Throws `USAGE` for unknown or incomplete commands. */
export function runCommand(client: Client, [command, ...args]: string[]) {
  const [value, chain] = args;
  if (command === 'scan') return scan(client, value, chain);
  if (command === 'assess') return assess(client, args);
  if (command === 'inventory') return inventory(client);
  if (command === 'posture' && value && args.length <= 2) return posture(client, value, chain);
  if (value && args.length === 1) {
    if (command === 'report') return report(client, value);
    if (command === 'cbom') return cbom(client, value);
    if (command === 'qbom') return qbom(client, value);
  }
  throw new Error(USAGE);
}

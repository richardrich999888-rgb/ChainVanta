import type { ChainVantaClient } from '../../../sdks/typescript/src/index.js';
import { scan } from './scan/index.js';
import { inventory } from './inventory/index.js';
import { report } from './report/index.js';

export function runCommand(
  client: Pick<ChainVantaClient, 'assess' | 'list' | 'get'>,
  [command, value, chain]: string[],
) {
  if (command === 'scan') return scan(client, value, chain);
  if (command === 'inventory') return inventory(client);
  if (command === 'report' && value) return report(client, value);
  throw new Error('Usage: pnpm cli scan <address> [chainId] | inventory | report <assessment-id>');
}

import { parseArgs } from 'node:util';
import type { ChainVantaClient } from '../../../../sdks/typescript/src/index.js';
import { ScanRequest } from '../../../../packages/domain-models/src/index.js';

const DEFAULT_CHAIN_ID = '1';

/**
 * Full assessment request: `assess <address> [chainId] [--transaction <hash> | --discover] [--adapter <name>]`.
 * Unknown flags and extra positionals are rejected before any request is made.
 */
export function assess(client: Pick<ChainVantaClient, 'assess'>, args: string[]) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    strict: true,
    options: {
      transaction: { type: 'string' },
      discover: { type: 'boolean' },
      adapter: { type: 'string' },
    },
  });
  if (positionals.length < 1 || positionals.length > 2)
    throw new Error('assess requires <address> and an optional [chainId]');
  const [address, chain = DEFAULT_CHAIN_ID] = positionals;
  return client.assess(
    ScanRequest.parse({
      address,
      chainId: Number(chain),
      ...(values.transaction === undefined ? {} : { transactionHash: values.transaction }),
      ...(values.discover ? { discoverTransaction: true } : {}),
      ...(values.adapter === undefined ? {} : { adapter: values.adapter }),
    }),
  );
}

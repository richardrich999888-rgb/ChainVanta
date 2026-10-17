import type { ChainVantaClient } from '../../../../sdks/typescript/src/index.js';

export function inventory(client: Pick<ChainVantaClient, 'list'>) {
  return client.list();
}

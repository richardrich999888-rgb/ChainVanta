import { mkdir, writeFile } from 'node:fs/promises';
import { EvmConnector } from '../../connectors/blockchains/ethereum/src/index.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import { Chains } from '../../packages/config/src/index.js';
const chains = Chains.parse([
  {
    chainId: 1,
    name: 'Ethereum',
    rpcUrl: process.env.CHAINVANTA_RPC_URL ?? 'https://ethereum-rpc.publicnode.com',
  },
]);
const observation = await new EvmConnector(chains[0]!).observe(
  '0x0000000000000000000000000000000000000000',
);
const assessment = assessWallet('00000000-0000-4000-8000-000000000001', observation);
await mkdir('.local', { recursive: true });
await writeFile('.local/live-assessment.json', JSON.stringify(assessment, null, 2));
console.log(
  JSON.stringify(
    {
      source: 'live Ethereum RPC',
      blockNumber: observation.blockNumber,
      blockHash: observation.blockHash,
      evidenceHash: assessment.evidenceHash,
      output: '.local/live-assessment.json',
    },
    null,
    2,
  ),
);

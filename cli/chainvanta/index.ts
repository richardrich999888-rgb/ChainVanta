import { ChainVantaClient } from '../../sdks/typescript/src/index.js';
import { runCommand } from './commands/index.js';
if (!process.env.CHAINVANTA_API_KEY) {
  console.error('Set CHAINVANTA_API_KEY to a provisioned tenant key.');
  process.exit(1);
}
const client = new ChainVantaClient(
  process.env.API_BASE_URL ?? 'http://127.0.0.1:4000',
  process.env.CHAINVANTA_API_KEY,
);
try {
  const result = await runCommand(client, process.argv.slice(2));
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Command failed');
  process.exitCode = 1;
}

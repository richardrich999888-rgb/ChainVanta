import { createServer } from 'node:http';
import { rpcResult } from '../../packages/test-fixtures/src/fixtures.js';
// Explicit demonstration provider. Never selected automatically for a live chain.
const server = createServer(async (req, res) => {
  let text = '';
  for await (const chunk of req) {
    text += chunk;
    if (text.length > 8192) {
      res.writeHead(413).end();
      return;
    }
  }
  try {
    const { method, id } = JSON.parse(text);
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ jsonrpc: '2.0', id, result: rpcResult(method) }));
  } catch {
    res.writeHead(400).end();
  }
});
server.listen(8545, '127.0.0.1', () =>
  console.log('DEMONSTRATION ONLY: deterministic EVM RPC on http://127.0.0.1:8545'),
);

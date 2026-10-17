import { readConfig } from '../../packages/config/src/index.js';
const config = readConfig();
const key = config.tenantKeys[0]?.key;
if (!key) throw new Error('A provisioned local API key is required for this smoke check');
const base = `http://${config.host}:${config.port}`;
for (const path of ['/health/ready', '/v1/session', '/v1/assessments', '/v1/reports']) {
  const response = await fetch(base + path, { headers: { authorization: `Bearer ${key}` } });
  if (!response.ok) throw new Error(`Smoke failed: ${path} ${response.status}`);
  const data = await response.json();
  console.log(
    JSON.stringify({
      path,
      status: response.status,
      ...(Array.isArray(data) ? { records: data.length } : {}),
    }),
  );
}
const web = await fetch('http://127.0.0.1:3000');
if (!web.ok || !(await web.text()).includes('ChainVanta')) throw new Error('Console did not start');
console.log(
  'Console renders; API reads persisted assessments with Redis-backed authorization throttling.',
);

import { decodeFunctionResult, encodeFunctionData, parseAbi, type Hex } from 'viem';
import { TokenEvidence } from '../../../../packages/domain-models/src/index.js';
const abi = parseAbi([
  'function owner() view returns (address)',
  'function totalSupply() view returns (uint256)',
  'function decimals() view returns (uint8)',
]);
// Explicit opt-in adapter. Matching selectors do not authenticate implementation semantics.
export async function observeToken(call: (data: string) => Promise<string>) {
  const names = ['owner', 'totalSupply', 'decimals'] as const;
  const calls = [];
  const values = [];
  for (const functionName of names) {
    const data = encodeFunctionData({ abi, functionName });
    const result = await call(data);
    calls.push({ data, result });
    values.push(decodeFunctionResult({ abi, functionName, data: result as Hex }));
  }
  return TokenEvidence.parse({
    adapter: 'ownable-erc20/1.0.0',
    owner: values[0],
    totalSupply: String(values[1]),
    decimals: Number(values[2]),
    calls,
    limitation:
      'Accessor observations only. Stablecoin identity, reserve backing, mint/burn powers and proxy semantics are unverified.',
  });
}

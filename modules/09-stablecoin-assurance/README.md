# ChainVanta Mint

Status: **Partially implemented**.

The explicitly selected `ownable-erc20/1.0.0` adapter reads `owner()`, `totalSupply()` and `decimals()` at the same canonical block hash. It records calldata, raw return data, decoded values and parser version as evidence, with an owner-accessor relationship in the graph. It fails on malformed/unsupported returns or absent code.

This is not automatic stablecoin discovery. Matching selectors do not prove contract semantics. Minting/burning privileges, reserve backing, proxy resolution, role-grant/revoke event decoding and issuer-specific adapters remain planned. No financial writes are exposed.

Threat boundary: arbitrary contract bytecode can return deceptive accessor values; record provider-reported facts without asserting authority semantics. Test specification: valid ABI fixtures, short/malformed return values, large integer preservation, no-code accounts, pinned block calls, reorg rejection and tenant isolation. Current tests: `tests/unit/intelligence.test.ts` and `tests/integration/pipeline.test.ts`.

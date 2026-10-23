# ChainVanta Discover

Status: **Partially implemented**.

Finalized EVM account observations, explicit transaction signature verification (types 0/1/2), CBOM, versioned QBOM/CPM findings, evidence references and relational observation graph. The API validates source chain, block context, transaction hash, recovered sender and receipt context. Assessments persist atomically with tenant RLS and idempotency.

## Account structure discovery

`src/discovery/account-structure.ts` classifies code-bearing accounts at the snapshot block. All reads go through a `StructureReader` port that the EVM connector pins to the block hash (EIP-1898). Accounts without code cost no extra reads.

| Pattern                | Evidence                                                                                            | What it establishes                                                                             | Confidence           |
| ---------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | -------------------- |
| EIP-7702 delegation    | Code is exactly `0xef0100 ‖ delegate`                                                               | The account's secp256k1 key signed the delegation and remains a valid signer                    | observed             |
| EIP-1167 minimal proxy | Exact canonical runtime                                                                             | All calls delegate to the implementation; not upgradeable                                       | observed             |
| EIP-1967 proxy         | Implementation, admin and beacon slots (`keccak256(label) - 1`); `implementation()` on the beacon   | Upgradeable logic and who the slots name; upgrade authorization not analyzed                    | observed (slots)     |
| Safe                   | `getOwners()`, `getThreshold()`, `VERSION()`, `getModulesPaginated()`, slot 0 singleton, owner code | k-of-n policy; owners without code can only approve with ECDSA secp256k1; modules bypass owners | inferred (accessors) |
| ERC-4337               | `entryPoint()` and its code                                                                         | An entry point is reported; validation logic is vendor-specific                                 | inferred             |

Rules:

- **Reverts and exceptional halts are answers** ("interface not present"). Any other provider error fails the observation, so a rate limit can never read as "not a Safe".
- **Accessor data is validated before use**: owners must be distinct, non-zero, non-sentinel and at most 50; `1 ≤ threshold ≤ owners`. Inconsistent data is discarded, not guessed at.
- **Bounded**: at most 40 reads per account (real Safe 2-of-3: 12). Owner code is read for at most 10 owners; the rest stay `not-checked`. Call return data above 4 KB is recorded as hash and size only and never decoded, so a contract cannot inflate stored evidence.
- **Not detected**: diamonds (EIP-2535), custom proxy slots, non-canonical clones, Safe deployments without accessors, signer logic inside delegate/implementation/module code.

Consumers: CBOM adds secp256k1 components (observed for 7702, inferred for Safe owners without code); QBOM marks 7702 accounts `classical-signature-observed`; posture adds `CV-WALLET-003`, `CV-PROXY-001/002`, `CV-SAFE-001/002`, `CV-AA-001`; the trust graph adds edges whose relation names state how each was observed; CPM tracks these edges as dependencies, so implementation, owner and module changes raise `DEPENDENCY_CHANGED` drift. CPM's policy rules still classify quantum exposure only from verified transactions (see limitations).

## Limitations

No exhaustive wallet discovery, custody inference, complete transaction history or independent consensus validation. A verified historical transaction does not prove the account's current authorization mechanism. CPM policy rules do not yet consume structure evidence for quantum classification: that needs a new evidence requirement in the policy schema. Unknowns remain unknown.

Tests: `tests/unit/{assessment,rpc,intelligence,account-structure,account-structure-connector,account-structure-engines}.test.ts`, `tests/integration/pipeline.test.ts`.

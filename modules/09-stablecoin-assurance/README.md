# ChainVanta Mint

Status: **Partially implemented**.

## Adapters

Both adapters are opt-in (`adapter` on the scan request), run only against accounts with code, and read at the observation's pinned block hash.

### `ownable-erc20/1.0.0`

Reads `owner()`, `totalSupply()` and `decimals()`. It records calldata, raw return data, decoded values and parser version as evidence, with an owner-accessor relationship in the graph. It fails on malformed or unsupported returns.

### `token-authority/1.2.0`

Answers "who can mint, burn, pause, blacklist or upgrade this token, and is each holder a single secp256k1 key?" (`src/mint-burn-authorities/token-authority.ts`).

| Source                               | Reads                                                                                   | Roles                                                                        |
| ------------------------------------ | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `ownable`                            | `owner()` (Ownable, or ERC-5313 as implemented by `AccessControlDefaultAdminRules`)     | owner                                                                        |
| `ownable2step`                       | `pendingOwner()`                                                                        | pending-owner                                                                |
| `access-control-enumerable`          | ERC-165 `0x7965db0b` / `0x5a05180f`, then `getRoleMemberCount` / `getRoleMember`        | default-admin, minter, burner, pauser, upgrader (`keccak256("<NAME>_ROLE")`) |
| `access-control-default-admin-rules` | `defaultAdmin()`                                                                        | default-admin                                                                |
| `fiat-token`                         | `masterMinter()`, `pauser()`, `blacklister()`, `rescuer()` (Circle FiatToken)           | master-minter, pauser, blacklister, rescuer                                  |
| `eip1967-admin-slot`                 | reused from account-structure discovery                                                 | proxy-admin                                                                  |
| `zeppelinos-admin-slot`              | storage `keccak256("org.zeppelinos.proxy.admin")` (AdminUpgradeabilityProxy, e.g. USDC) | proxy-admin                                                                  |
| `proxy-admin-owner`                  | `owner()` on each proxy admin (OpenZeppelin `ProxyAdmin`)                               | upgrader                                                                     |

It also reads `symbol()`, `decimals()`, `totalSupply()` and `paused()`. Each distinct holder is classified by `eth_getCode`: `no-code`, `eip-7702-delegated`, `contract`, or `not-checked` (over budget). A zero-address holder means the role was renounced and yields an empty holder list.

Budget (`TOKEN_AUTHORITY_LIMITS`): at most 38 reads, 5 holders per role, 8 classified holders; return data above 4 KB is fingerprinted. Holder classification and proxy-admin hops are reserved before role members, so the budget is never exceeded. Reverts and halts are interface answers; any other provider error fails the observation.

Findings: `CV-TOKEN-002` (authorities reported, inferred), `CV-TOKEN-003` (high: a single-key holder of owner, default-admin, minter, master-minter, upgrader or proxy-admin; one finding listing every such holder, because finding lifecycle is keyed by rule id), `CV-TOKEN-004` (authority set incomplete: non-enumerable AccessControl without history, truncated roles, history gaps or unattested history, or unclassified holders), `CV-TOKEN-005` (paused), `CV-TOKEN-006` and `CV-TOKEN-007` (holder control, below). CBOM: one inferred `ECDSA-secp256k1` component per single-key holder (domain `token-administration`) and one unknown component for contract holders. Trust graph: `token-<role>-accessor-reports`, `zeppelinos-admin-slot-reports` and `proxy-admin-owner-accessor-reports` edges, tracked by CPM, so a holder change is `DEPENDENCY_CHANGED` drift. QBOM status is unchanged: the holders' keys are not the observed account's.

#### Holder control (1.2.0)

Contract holders of supply or logic roles (owner, default-admin, minter, master-minter, upgrader) are profiled from standard accessors (`src/mint-burn-authorities/authority-control.ts`):

| Accessors                           | Result                                                                                                        |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `getThreshold()` then `getOwners()` | Safe, `threshold`-of-`owners`; accepted only when 1 ≤ threshold ≤ owners and owners are distinct and non-zero |
| `getMinDelay()`                     | OpenZeppelin TimelockController, minimum delay in seconds                                                     |
| `delay()`                           | Compound Timelock, delay in seconds                                                                           |
| none consistent                     | `unrecognized`                                                                                                |

Probes stop at the first consistent answer: at most 3 reads per holder, for at most 2 holders, reserved inside the token budget (`maxReads` 38). Proxy admins are skipped because their owner is already followed. Powerful contract holders left unprofiled by the budget are reported in `CV-TOKEN-004`, never silently skipped.

New findings: `CV-TOKEN-006` (high: a 1-of-N Safe holds a supply or logic role, so any one owner acts alone) and `CV-TOKEN-007` (medium: a zero-delay timelock holds one). `CV-TOKEN-002` summarizes every profiled control. Safe owners become `authority-safe-owner-accessor-reports` edges, and the delay a `timelock-delay:<chain>:<address>:<seconds>` value node. CPM tracks both, so an owner swap or a delay change is `DEPENDENCY_CHANGED` drift.

Not analyzed: Safe owners' own keys and modules, timelock proposer and executor roles, and governor voting rules. Validated on Hardhat with Safe v1.4.1 proxies from the real factory (1-of-2, 2-of-3) and OpenZeppelin 5.6.1 `TimelockController` (0 s and 172800 s) holding `Ownable` and `AccessControlEnumerable` roles. Compound Timelock is covered by synthetic fixtures only.

#### Role history (1.1.0)

When AccessControl is present but not enumerable, holders are reconstructed from events (`src/mint-burn-authorities/role-history.ts`):

1. `eth_getLogs` for `RoleGranted`/`RoleRevoked` from the token over `[0, snapshot block]` (finalized, so results are stable). A range the provider refuses (EIP-1474 `-32005`, result-count or response-size limits, or a body over 1 MB) is split at its midpoint; ranges are processed newest-first. Pruned history is recorded as a gap and not split. Any other provider error, or a log that does not match the filter (wrong address, out-of-range block, `removed`, non-address topic), fails the observation.
2. Every (role, account) whose latest event is a grant is checked with `hasRole` at the pinned block hash. Only `true` answers become holders, so logs never create a holder on their own. Supply and logic roles are asked first.

`holdersComplete` is true only when coverage has no gaps, every candidate was checked, and the chain sets `"fullLogHistory": true` in `CHAINS`, an operator attestation that the provider serves unpruned log history (history-expiring nodes can return empty ranges). It also assumes the contract emits the standard events for every role change, as OpenZeppelin AccessControl does. Non-standard role ids seen in events are recorded (`unrecognizedRoleIds`) but not analyzed.

Budget (`ROLE_HISTORY_LIMITS`): 8 log requests, 6 `hasRole` checks, 256 events kept. The worst case through the connector, including control profiling, is 58 RPC calls, inside the monitoring worker's 60-call cap (`tests/unit/role-history-connector.test.ts`). Requests, gaps, events and `hasRole` reads are stored in `tokenAuthority.roleHistory`, so coverage can be replayed. `token-authority/1.0.0` documents remain valid.

Validated on Hardhat (Prague) with an OpenZeppelin 5.6.1 `AccessControl` token after grants, a revoke and a custom-role grant. The revoked minter was excluded, the custom role recorded, and a provider range cap modelled in front of the node: a 120-block cap still reached full coverage in 7 requests; a 20-block cap produced gaps and an incomplete verdict. Without the attestation, the same history was reported but not claimed complete.

Validated against OpenZeppelin 5.6.1 `AccessControlEnumerable`, `AccessControlDefaultAdminRules`, `Ownable2Step` and `TransparentUpgradeableProxy`/`ProxyAdmin`, compiled with solc 0.8.30, on Hardhat (Prague), including an EIP-7702 delegated minter. FiatToken accessors and the ZeppelinOS slot layout are covered by synthetic fixtures only.

## Limits

Accessor responses come from contract code; a lookalike can return the same data, so holder claims are `inferred`. Custom role names and semantics, FiatToken minter allowances (not enumerable from accessors), and the owners and rules behind profiled Safes and timelocks are not analyzed. Reserve backing, stablecoin identity and issuer-specific adapters remain planned. No financial writes are exposed.

Threat boundary: arbitrary contract bytecode can return deceptive accessor values; record provider-reported facts without asserting authority semantics. Tests: `tests/unit/token-authority.test.ts`, `tests/unit/token-authority-engines.test.ts`, `tests/unit/intelligence.test.ts` and `tests/integration/pipeline.test.ts`.

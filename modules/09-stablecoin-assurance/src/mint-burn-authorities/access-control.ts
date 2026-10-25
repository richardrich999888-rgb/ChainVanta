import { keccak256, toEventSelector, toHex, type Hex } from 'viem';
import type { TokenRole } from '../../../../packages/domain-models/src/index.js';

/** OpenZeppelin AccessControl constants shared by accessor and event-history collectors. */

export const ROLE_IDS = {
  // DEFAULT_ADMIN_ROLE is the zero word; the others are keccak256 of the role name.
  'default-admin': toHex(0n, { size: 32 }),
  minter: keccak256(toHex('MINTER_ROLE')),
  burner: keccak256(toHex('BURNER_ROLE')),
  pauser: keccak256(toHex('PAUSER_ROLE')),
  upgrader: keccak256(toHex('UPGRADER_ROLE')),
} as const satisfies Partial<Record<TokenRole, Hex>>;
export type AccessControlRole = keyof typeof ROLE_IDS;

/** Reverse lookup from a role id to its standard name; null for custom roles. */
export function roleName(roleId: Hex): AccessControlRole | null {
  const id = roleId.toLowerCase();
  const entry = (Object.entries(ROLE_IDS) as [AccessControlRole, Hex][]).find(
    ([, value]) => value === id,
  );
  return entry ? entry[0] : null;
}

// ERC-165 ids: XOR of each interface's function selectors (re-derived in test fixtures).
export const IACCESS_CONTROL = '0x7965db0b';
export const IACCESS_CONTROL_ENUMERABLE = '0x5a05180f';

/** IAccessControl events; both index role, account and sender (topics 1..3). */
export const ROLE_GRANTED = toEventSelector('RoleGranted(bytes32,address,address)');
export const ROLE_REVOKED = toEventSelector('RoleRevoked(bytes32,address,address)');

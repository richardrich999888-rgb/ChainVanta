import { it, expect } from 'vitest';
import * as module0 from '../../modules/02-defi-trust-graph/src/protocol-analysis/contract.js';
import * as module1 from '../../modules/03-bridge-assurance/src/bridge-discovery/contract.js';
import * as module2 from '../../modules/04-contract-crypto-agility/src/contract-analysis/contract.js';
import * as module3 from '../../modules/05-validator-cpm/src/validator-discovery/contract.js';
import * as module4 from '../../modules/06-zk-crypto-inventory/src/proof-system-discovery/contract.js';
import * as module5 from '../../modules/07-custody-mpc-hsm/src/custody-inventory/contract.js';
import * as module6 from '../../modules/08-crosschain-pqc-migration/src/migration-planner/contract.js';
import * as module7 from '../../modules/10-web3-identity/src/did-analysis/contract.js';
import * as module8 from '../../modules/11-digital-provenance/src/asset-verification/contract.js';
import * as module9 from '../../modules/12-depin-security/src/device-identity/contract.js';
const modules = [
  module0,
  module1,
  module2,
  module3,
  module4,
  module5,
  module6,
  module7,
  module8,
  module9,
];
it('all ten planned modules require provenance, validate asset kinds and remain non-operational', () => {
  expect(modules).toHaveLength(10);
  for (const contract of modules) {
    expect(contract.status).toBe('planned');
    const valid = {
      tenantId: '11111111-1111-4111-8111-111111111111',
      assetId: 'eip155:1:account',
      assetKind: contract.Input.shape.assetKind.options[0],
      evidenceRefs: ['sha256:' + 'ab'.repeat(32)],
    };
    expect(contract.Input.safeParse(valid).success).toBe(true);
    expect(contract.Input.safeParse({ ...valid, evidenceRefs: [] }).success).toBe(false);
    expect(contract.Input.safeParse({ ...valid, assetKind: 'unsupported' }).success).toBe(false);
    expect(
      contract.Result.safeParse({
        schemaVersion: '1.0.0',
        moduleId: contract.moduleId,
        status: 'supported',
        confidence: 'invented',
        evidenceRefs: [],
        limitations: [],
      }).success,
    ).toBe(false);
  }
});

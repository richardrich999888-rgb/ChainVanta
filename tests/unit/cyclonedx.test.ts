import { describe, expect, it } from 'vitest';
import { ZodError } from 'zod';
import { toCycloneDx } from '../../core/cbom-engine/exporters/cyclonedx.js';
import { validateCycloneDxCbom } from '../../core/cbom-engine/schema-validation/cyclonedx.js';
import { assessWallet } from '../../modules/01-wallet-intelligence/src/assessment/index.js';
import type { Assessment } from '../../packages/domain-models/src/index.js';
import { BLOCK_HASH, TENANT_A, observation } from '../../packages/test-fixtures/src/fixtures.js';

const signature = {
  hash: `0x${'cd'.repeat(32)}`,
  blockHash: BLOCK_HASH,
  blockNumber: '0x100',
  sender: observation.address,
  algorithm: 'ECDSA-secp256k1' as const,
  serializedTransaction: '0x02',
  receiptStatus: 'success' as const,
  parserVersion: 'evm-transaction/1.0.0' as const,
};
const props = (entries: { name: string; value: string }[]) =>
  Object.fromEntries(entries.map((p) => [p.name, p.value]));

describe('CycloneDX 1.6 CBOM export', () => {
  const signed = assessWallet(TENANT_A, { ...observation, signature });
  const unsigned = assessWallet(TENANT_A, observation);

  it('maps a verified secp256k1 signature to a quantum-vulnerable signature algorithm', () => {
    const bom = toCycloneDx(signed);
    expect(bom).toMatchObject({
      bomFormat: 'CycloneDX',
      specVersion: '1.6',
      serialNumber: `urn:uuid:${signed.id}`,
      version: 1,
      compositions: [{ aggregate: 'incomplete' }],
    });
    const [algorithm, unknown] = bom.components;
    expect(algorithm?.name).toBe('ECDSA-secp256k1');
    expect(algorithm?.cryptoProperties.algorithmProperties).toEqual({
      primitive: 'signature',
      curve: 'secp256k1',
      executionEnvironment: 'unknown',
      implementationPlatform: 'unknown',
      certificationLevel: ['unknown'],
      cryptoFunctions: ['sign', 'verify'],
      classicalSecurityLevel: 128,
      nistQuantumSecurityLevel: 0,
    });
    expect(props(algorithm!.properties)).toMatchObject({
      'chainvanta:confidence': 'observed',
      'chainvanta:domain': 'transaction-signature',
      'chainvanta:evidenceRef': signed.evidenceHash,
    });
    expect(unknown?.cryptoProperties.algorithmProperties.primitive).toBe('unknown');
    expect(props(bom.metadata.properties)).toMatchObject({
      'chainvanta:asset': `eip155:1:${observation.address}`,
      'chainvanta:evidenceHash': signed.evidenceHash,
      'chainvanta:qbomStatus': 'classical-signature-observed',
      'chainvanta:demonstration': 'false',
    });
  });

  it('keeps undiscovered authorization entirely unknown and claims no quantum level', () => {
    const bom = toCycloneDx(unsigned);
    expect(bom.components).toHaveLength(1);
    const properties = bom.components[0]!.cryptoProperties.algorithmProperties;
    expect(properties).toEqual({
      primitive: 'unknown',
      executionEnvironment: 'unknown',
      implementationPlatform: 'unknown',
      certificationLevel: ['unknown'],
      cryptoFunctions: ['unknown'],
    });
    expect(bom.components[0]!.name).toBe('unknown (account authorization)');
  });

  it('is deterministic for the same assessment', () => {
    expect(JSON.stringify(toCycloneDx(signed))).toBe(JSON.stringify(toCycloneDx(signed)));
  });

  it('keeps bom-refs unique when an algorithm appears twice', () => {
    const component = signed.cbom.components[0]!;
    const doubled: Assessment = {
      ...signed,
      cbom: { ...signed.cbom, components: [component, component] },
    };
    const refs = toCycloneDx(doubled).components.map((c) => c['bom-ref']);
    expect(new Set(refs).size).toBe(2);
  });

  it('marks unrecognized algorithm names unknown instead of guessing properties', () => {
    const odd: Assessment = {
      ...unsigned,
      cbom: {
        ...unsigned.cbom,
        components: [
          { algorithm: 'Ed25519', purpose: 'transport', confidence: 'inferred', basis: 'test' },
        ],
      },
    };
    const [component] = toCycloneDx(odd).components;
    expect(component?.name).toBe('unknown (transport)');
    expect(component?.cryptoProperties.algorithmProperties.primitive).toBe('unknown');
  });

  it('rejects documents outside the reviewed subset', () => {
    const bom = toCycloneDx(signed);
    for (const broken of [
      { ...bom, specVersion: '1.5' },
      { ...bom, serialNumber: 'urn:uuid:NOT-A-UUID' },
      { ...bom, unexpected: true },
      { ...bom, components: [bom.components[0], bom.components[0]] },
      {
        ...bom,
        components: [
          {
            ...bom.components[0],
            cryptoProperties: {
              assetType: 'algorithm',
              algorithmProperties: {
                ...bom.components[0]!.cryptoProperties.algorithmProperties,
                nistQuantumSecurityLevel: 7,
              },
            },
          },
        ],
      },
    ])
      expect(() => validateCycloneDxCbom(broken)).toThrow(ZodError);
  });
});

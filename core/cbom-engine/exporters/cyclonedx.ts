import { canonicalAssetId, type Assessment } from '../../../packages/domain-models/src/index.js';
import {
  CDX_SPEC_VERSION,
  validateCycloneDxCbom,
  type AlgorithmProperties,
  type CycloneDxCbom,
} from '../schema-validation/cyclonedx.js';

export const CDX_EXPORTER_VERSION = 'chainvanta-cdx-exporter/1.0.0';
export const CDX_MEDIA_TYPE = 'application/vnd.cyclonedx+json; version=1.6';

type Component = Assessment['cbom']['components'][number];

/**
 * Reviewed algorithm descriptions. Only facts that follow from the algorithm itself are stated:
 * - secp256k1 ECDSA: 256-bit curve, about 128-bit classical security (Pollard rho, sqrt(2^256)).
 *   Shor's algorithm breaks elliptic-curve discrete logarithms, so no NIST PQC category is met (0).
 * Execution environment, platform and certification describe the signer's implementation, which
 * an on-chain observation cannot reveal; they are therefore always `unknown`.
 */
const KNOWN_ALGORITHMS: Readonly<Record<string, AlgorithmProperties>> = {
  'ECDSA-secp256k1': {
    primitive: 'signature',
    curve: 'secp256k1',
    executionEnvironment: 'unknown',
    implementationPlatform: 'unknown',
    certificationLevel: ['unknown'],
    cryptoFunctions: ['sign', 'verify'],
    classicalSecurityLevel: 128,
    nistQuantumSecurityLevel: 0,
  },
};

/** Unrecognized or undiscovered algorithms: every attribute stays explicitly unknown. */
const UNKNOWN_ALGORITHM: AlgorithmProperties = {
  primitive: 'unknown',
  executionEnvironment: 'unknown',
  implementationPlatform: 'unknown',
  certificationLevel: ['unknown'],
  cryptoFunctions: ['unknown'],
};

const property = (name: string, value: string) => ({ name: `chainvanta:${name}`, value });

function componentProperties(component: Component) {
  return [
    property('purpose', component.purpose),
    property('confidence', component.confidence),
    property('basis', component.basis),
    ...(component.domain ? [property('domain', component.domain)] : []),
    ...(component.evidenceRefs ?? []).map((ref) => property('evidenceRef', ref)),
  ];
}

function exportComponent(component: Component, index: number) {
  const known = KNOWN_ALGORITHMS[component.algorithm];
  return {
    type: 'cryptographic-asset' as const,
    // Index-qualified so two observations of one algorithm keep distinct references.
    'bom-ref': `crypto/${index}/${component.algorithm}`,
    name: known ? component.algorithm : `unknown (${component.purpose})`,
    cryptoProperties: {
      assetType: 'algorithm' as const,
      algorithmProperties: known ?? UNKNOWN_ALGORITHM,
    },
    properties: componentProperties(component),
  };
}

/**
 * Exports an assessment's CBOM as a CycloneDX 1.6 JSON document.
 *
 * Deterministic: the output is a pure function of the assessment. The serial number reuses the
 * assessment UUID and `version` is fixed at 1, so one assessment maps to exactly one BOM identity.
 * This intentionally departs from CycloneDX's SHOULD that re-generated BOMs get fresh serials: an
 * auditor can re-export and compare byte-for-byte. The composition is always `incomplete`; a
 * single read-only observation never establishes a complete cryptographic inventory.
 */
export function toCycloneDx(assessment: Assessment): CycloneDxCbom {
  const o = assessment.observation;
  const bom = {
    bomFormat: 'CycloneDX' as const,
    specVersion: CDX_SPEC_VERSION,
    serialNumber: `urn:uuid:${assessment.id.toLowerCase()}`,
    version: 1,
    metadata: {
      timestamp: assessment.createdAt,
      tools: {
        components: [
          { type: 'application' as const, name: 'ChainVanta', version: CDX_EXPORTER_VERSION },
        ],
      },
      properties: [
        property('asset', canonicalAssetId(o.chainId, o.address)),
        property('assetKind', assessment.assetKind),
        property('evidenceHash', assessment.evidenceHash),
        property('blockHash', o.blockHash),
        property('blockNumber', o.blockNumber),
        property('finality', o.finality),
        property('source', o.source),
        property('nativeCbomFormat', assessment.cbom.format),
        property('qbomStatus', assessment.qbom.status),
        property('demonstration', String(o.demonstration === true)),
      ],
    },
    components: assessment.cbom.components.map(exportComponent),
    compositions: [{ aggregate: 'incomplete' as const }],
  };
  // Fail closed: never return a document that violates the reviewed subset.
  return validateCycloneDxCbom(bom);
}

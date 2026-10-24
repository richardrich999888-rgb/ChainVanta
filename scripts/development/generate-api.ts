import { writeFile } from 'node:fs/promises';
import { z } from 'zod';
import { cpmSchemas, cpmPaths } from './cpm-contracts.js';
import {
  Assessment,
  Observation,
  Finding,
  ScanRequest,
  FindingUpdate,
} from '../../packages/domain-models/src/index.js';
import { CycloneDxCbom } from '../../core/cbom-engine/schema-validation/cyclonedx.js';
import { BitcoinAssessment, BitcoinScanRequest } from '../../packages/domain-models/src/bitcoin.js';
const schemas = Object.fromEntries(
  Object.entries({
    Assessment,
    Observation,
    Finding,
    ScanRequest,
    FindingUpdate,
    CycloneDxCbom,
    BitcoinScanRequest,
    BitcoinAssessment,
  }).map(([name, schema]) => [name, z.toJSONSchema(schema, { io: 'input' })]),
);
const json = (schema: unknown) => ({ 'application/json': { schema } });
const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const response = (schema: unknown) => ({
  '200': { description: 'Success', content: json(schema) },
  '401': { description: 'Authentication required' },
  '403': { description: 'Role denied' },
});
const doc = {
  openapi: '3.1.0',
  info: { title: 'ChainVanta API', version: '0.2.0' },
  security: [{ Bearer: [] }],
  paths: {
    ...cpmPaths,
    '/v1/session': {
      get: {
        responses: response({
          type: 'object',
          properties: {
            tenantId: { type: 'string', format: 'uuid' },
            role: { enum: ['viewer', 'analyst', 'admin'] },
          },
          required: ['tenantId', 'role'],
        }),
      },
    },
    '/v1/chains': {
      get: {
        responses: response({
          type: 'array',
          items: {
            type: 'object',
            properties: { chainId: { type: 'integer' }, name: { type: 'string' } },
            required: ['chainId', 'name'],
          },
        }),
      },
    },
    '/v1/assessments': {
      get: { responses: response({ type: 'array', items: ref('Assessment') }) },
      post: {
        parameters: [
          {
            in: 'header',
            name: 'Idempotency-Key',
            schema: { type: 'string', pattern: '^[a-zA-Z0-9_-]{8,128}$' },
          },
        ],
        requestBody: { required: true, content: json(ref('ScanRequest')) },
        responses: {
          '201': { description: 'Created or idempotent replay', content: json(ref('Assessment')) },
          '409': { description: 'Idempotency key reused with different input' },
        },
      },
    },
    '/v1/assessments/{id}': {
      get: {
        parameters: [
          { in: 'path', name: 'id', required: true, schema: { type: 'string', format: 'uuid' } },
        ],
        responses: response(ref('Assessment')),
      },
    },
    '/v1/bitcoin/networks': {
      get: {
        description:
          'Configured Bitcoin networks. Empty when Bitcoin collection is not configured.',
        responses: response({
          type: 'array',
          items: {
            type: 'object',
            properties: { network: { type: 'string' }, name: { type: 'string' } },
            required: ['network', 'name'],
          },
        }),
      },
    },
    '/v1/bitcoin/assessments': {
      get: {
        description: 'Latest 50 Bitcoin assessments for the tenant.',
        responses: response({ type: 'array', items: ref('BitcoinAssessment') }),
      },
      post: {
        description:
          'Assess a Bitcoin address or public key from the configured node UTXO set (scantxoutset; can take minutes on mainnet). One scan per node at a time (429 while busy).',
        parameters: [
          {
            in: 'header',
            name: 'Idempotency-Key',
            schema: { type: 'string', pattern: '^[a-zA-Z0-9_-]{8,128}$' },
          },
        ],
        requestBody: { required: true, content: json(ref('BitcoinScanRequest')) },
        responses: {
          '201': {
            description: 'Created or idempotent replay',
            content: json(ref('BitcoinAssessment')),
          },
          '400': { description: 'Invalid address or unconfigured network' },
          '409': { description: 'Idempotency key reused with different input' },
          '429': { description: 'A scan is already running on this node' },
          '502': { description: 'Node could not complete a consistent snapshot' },
        },
      },
    },
    '/v1/bitcoin/assessments/{id}': {
      get: {
        parameters: [
          { in: 'path', name: 'id', required: true, schema: { type: 'string', format: 'uuid' } },
        ],
        responses: response(ref('BitcoinAssessment')),
      },
    },
    '/v1/bitcoin/assessments/{id}/cbom': {
      get: {
        description: 'CycloneDX 1.6 CBOM export of one Bitcoin assessment.',
        parameters: [
          { in: 'path', name: 'id', required: true, schema: { type: 'string', format: 'uuid' } },
        ],
        responses: {
          '200': {
            description: 'Success',
            content: {
              'application/vnd.cyclonedx+json; version=1.6': { schema: ref('CycloneDxCbom') },
            },
          },
          '401': { description: 'Authentication required' },
          '404': { description: 'Assessment not found' },
        },
      },
    },
    '/v1/assessments/{id}/cbom': {
      get: {
        description:
          'CycloneDX 1.6 CBOM export of one assessment. Deterministic; composition is always incomplete.',
        parameters: [
          { in: 'path', name: 'id', required: true, schema: { type: 'string', format: 'uuid' } },
        ],
        responses: {
          '200': {
            description: 'Success',
            content: {
              'application/vnd.cyclonedx+json; version=1.6': { schema: ref('CycloneDxCbom') },
            },
          },
          '401': { description: 'Authentication required' },
          '404': { description: 'Assessment not found' },
        },
      },
    },
    '/v1/assessments/{id}/findings/{ruleId}': {
      patch: {
        parameters: ['id', 'ruleId'].map((name) => ({
          in: 'path',
          name,
          required: true,
          schema: { type: 'string' },
        })),
        requestBody: { required: true, content: json(ref('FindingUpdate')) },
        responses: response({ type: 'object', properties: { ok: { type: 'boolean' } } }),
      },
    },
    '/v1/reports': { get: { responses: response({ type: 'object' }) } },
    '/v1/history': {
      get: {
        parameters: [
          { in: 'query', name: 'chainId', required: true, schema: { type: 'integer' } },
          { in: 'query', name: 'address', required: true, schema: { type: 'string' } },
        ],
        responses: response({
          type: 'object',
          properties: {
            assessments: { type: 'array', items: ref('Assessment') },
            drift: { type: 'array', items: { type: 'object' } },
          },
        }),
      },
    },
    '/v1/graph': {
      get: {
        parameters: [{ in: 'query', name: 'source', required: true, schema: { type: 'string' } }],
        responses: response({ type: 'array', items: { type: 'object' } }),
      },
    },
    '/v1/audit': { get: { responses: response({ type: 'array', items: { type: 'object' } }) } },
    '/v1/findings/events': {
      get: { responses: response({ type: 'array', items: { type: 'object' } }) },
    },
  },
  components: {
    securitySchemes: {
      Bearer: {
        type: 'http',
        scheme: 'bearer',
        description: 'Opaque tenant key or validated OIDC JWT access token',
      },
    },
    schemas: { ...schemas, ...cpmSchemas },
  },
};
await writeFile(
  new URL('../../packages/api-contracts/openapi.yaml', import.meta.url),
  JSON.stringify(doc, null, 2) + '\n',
);

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
const schemas = Object.fromEntries(
  Object.entries({ Assessment, Observation, Finding, ScanRequest, FindingUpdate }).map(
    ([name, schema]) => [name, z.toJSONSchema(schema, { io: 'input' })],
  ),
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

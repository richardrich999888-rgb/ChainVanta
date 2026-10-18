import { z } from 'zod';
import {
  CpmPolicy,
  PolicyAssignment,
  CpmAssessRequest,
  MonitoringRequest,
  MonitoringUpdate,
  FindingTransition,
  MigrationRequest,
  MigrationResult,
  PostureSnapshot,
  PostureResponse,
  HistoricalPosture,
  MonitoringSchedule,
  AssessmentJob,
  PolicyVersionRecord,
  DriftEvent,
  Remediation,
} from '../../packages/domain-models/src/cpm.js';
export const cpmSchemas = Object.fromEntries(
  Object.entries({
    CpmPolicy,
    PolicyAssignment,
    CpmAssessRequest,
    MonitoringRequest,
    MonitoringUpdate,
    FindingTransition,
    MigrationRequest,
    MigrationResult,
    PostureSnapshot,
    PostureResponse,
    HistoricalPosture,
    MonitoringSchedule,
    AssessmentJob,
    PolicyVersionRecord,
    DriftEvent,
    Remediation,
  }).map(([name, schema]) => [name, z.toJSONSchema(schema, { io: 'input' })]),
);
const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const json = (schema: unknown) => ({ 'application/json': { schema } });
const parameter = (name: string) => ({
  in: 'path',
  name,
  required: true,
  schema: { type: 'string' },
});
const page = [
  {
    in: 'query',
    name: 'limit',
    schema: { type: 'integer', minimum: 1, maximum: 100, default: 25 },
  },
  {
    in: 'query',
    name: 'offset',
    schema: { type: 'integer', minimum: 0, maximum: 100000, default: 0 },
  },
];
function operation(
  method: string,
  out: unknown,
  input?: unknown,
  parameters: unknown[] = [],
  admin = false,
) {
  return {
    description: admin
      ? 'Tenant administrator required.'
      : 'Tenant authentication required; writes require analyst or administrator.',
    parameters,
    ...(input ? { requestBody: { required: true, content: json(input) } } : {}),
    responses: {
      [method === 'post' ? '201' : '200']: { description: 'Success', content: json(out) },
      '400': { description: 'Invalid input' },
      '401': { description: 'Authentication required' },
      '403': { description: 'Role denied' },
      '404': { description: 'Tenant resource not found' },
      '409': { description: 'State or immutable version conflict' },
      '429': { description: 'Quota exceeded' },
      '502': { description: 'Collection failed' },
      '503': { description: 'Dependency unavailable' },
    },
  };
}
const array = (name: string) => ({ type: 'array', items: ref(name) });
const ok = { type: 'object' };
export const cpmPaths = {
  '/v1/cpm/assess': { post: operation('post', ref('PostureSnapshot'), ref('CpmAssessRequest')) },
  '/v1/cpm/posture/{assetId}': {
    get: operation('get', ref('PostureResponse'), undefined, [parameter('assetId')]),
  },
  '/v1/cpm/history/{assetId}': {
    get: operation('get', array('HistoricalPosture'), undefined, [parameter('assetId'), ...page]),
  },
  '/v1/cpm/policies': {
    get: operation('get', array('PolicyVersionRecord'), undefined, page),
    post: operation('post', ref('CpmPolicy'), ref('CpmPolicy'), [], true),
  },
  '/v1/cpm/policies/{id}': {
    patch: operation(
      'patch',
      {
        type: 'object',
        properties: { id: { type: 'string' }, active: { type: 'boolean' } },
        required: ['id', 'active'],
      },
      {
        type: 'object',
        properties: { active: { type: 'boolean' } },
        required: ['active'],
        additionalProperties: false,
      },
      [parameter('id')],
      true,
    ),
  },
  '/v1/cpm/assignments': {
    post: operation('post', ref('PolicyAssignment'), ref('PolicyAssignment'), [], true),
  },
  '/v1/cpm/monitoring': {
    get: operation('get', array('MonitoringSchedule'), undefined, page),
    post: operation('post', ref('MonitoringSchedule'), ref('MonitoringRequest')),
  },
  '/v1/cpm/monitoring/{id}': {
    patch: operation(
      'patch',
      ref('MonitoringSchedule'),
      ref('MonitoringUpdate'),
      [parameter('id')],
      true,
    ),
    delete: operation('delete', ref('MonitoringSchedule'), undefined, [parameter('id')], true),
  },
  '/v1/cpm/jobs/{id}': {
    get: operation('get', ref('AssessmentJob'), undefined, [parameter('id')]),
  },
  '/v1/cpm/jobs/{id}/cancel': { post: operation('post', ok, undefined, [parameter('id')], true) },
  '/v1/cpm/drift': { get: operation('get', array('DriftEvent'), undefined, page) },
  '/v1/cpm/remediation': { get: operation('get', array('Remediation'), undefined, page) },
  '/v1/cpm/notifications': { get: operation('get', { type: 'array', items: ok }, undefined, page) },
  '/v1/cpm/findings/{snapshotId}/{ruleId}': {
    patch: operation(
      'patch',
      ok,
      ref('FindingTransition'),
      [parameter('snapshotId'), parameter('ruleId')],
      true,
    ),
  },
  '/v1/cpm/migrations/assess': {
    post: operation('post', ref('MigrationResult'), ref('MigrationRequest')),
  },
  '/v1/cpm/migrations/{id}': {
    get: operation('get', ref('MigrationResult'), undefined, [parameter('id')]),
  },
  '/v1/cpm/migrations/{id}/verify': {
    post: operation(
      'post',
      ref('MigrationResult'),
      {
        type: 'object',
        properties: { assessmentId: { type: 'string', format: 'uuid' } },
        required: ['assessmentId'],
        additionalProperties: false,
      },
      [parameter('id')],
    ),
  },
};

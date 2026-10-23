import type { components } from '../../../packages/api-contracts/generated.js';
type Assessment = components['schemas']['Assessment'];
type ScanInput = components['schemas']['ScanRequest'];
export class ChainVantaClient {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
  ) {}
  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(`${this.baseUrl.replace(/\/$/, '')}/v1${path}`, {
      ...init,
      redirect: 'error',
      headers: {
        ...init.headers,
        authorization: `Bearer ${this.apiKey}`,
        'content-type': 'application/json',
      },
      signal: AbortSignal.timeout(50_000),
    });
    if (!response.ok) throw new Error(`ChainVanta request failed (${response.status})`);
    return response.json() as Promise<T>;
  }
  assess(input: ScanInput, idempotencyKey = crypto.randomUUID()) {
    return this.request<Assessment>('/assessments', {
      method: 'POST',
      headers: { 'idempotency-key': idempotencyKey },
      body: JSON.stringify(input),
    });
  }
  list() {
    return this.request<Assessment[]>('/assessments');
  }
  get(id: string) {
    return this.request<Assessment>(`/assessments/${encodeURIComponent(id)}`);
  }
  cpmAssess(input: components['schemas']['CpmAssessRequest']) {
    return this.request<components['schemas']['PostureSnapshot']>('/cpm/assess', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }
  posture(assetId: string) {
    return this.request<components['schemas']['PostureResponse']>(
      `/cpm/posture/${encodeURIComponent(assetId)}`,
    );
  }
  postureHistory(assetId: string, limit = 25, offset = 0) {
    return this.request<components['schemas']['HistoricalPosture'][]>(
      `/cpm/history/${encodeURIComponent(assetId)}?limit=${limit}&offset=${offset}`,
    );
  }
  policies(limit = 25, offset = 0) {
    return this.request<components['schemas']['PolicyVersionRecord'][]>(
      `/cpm/policies?limit=${limit}&offset=${offset}`,
    );
  }
  publishPolicy(input: components['schemas']['CpmPolicy']) {
    return this.request<components['schemas']['CpmPolicy']>('/cpm/policies', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }
  setPolicyActive(id: string, active: boolean) {
    return this.request<{ id: string; active: boolean }>(
      `/cpm/policies/${encodeURIComponent(id)}`,
      { method: 'PATCH', body: JSON.stringify({ active }) },
    );
  }
  assignPolicy(input: components['schemas']['PolicyAssignment']) {
    return this.request<components['schemas']['PolicyAssignment']>('/cpm/assignments', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }
  monitor(input: components['schemas']['MonitoringRequest']) {
    return this.request<components['schemas']['MonitoringSchedule']>('/cpm/monitoring', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }
  monitoring(limit = 25, offset = 0) {
    return this.request<components['schemas']['MonitoringSchedule'][]>(
      `/cpm/monitoring?limit=${limit}&offset=${offset}`,
    );
  }
  updateMonitoring(id: string, input: components['schemas']['MonitoringUpdate']) {
    return this.request<components['schemas']['MonitoringSchedule']>(
      `/cpm/monitoring/${encodeURIComponent(id)}`,
      { method: 'PATCH', body: JSON.stringify(input) },
    );
  }
  stopMonitoring(id: string) {
    return this.request<components['schemas']['MonitoringSchedule']>(
      `/cpm/monitoring/${encodeURIComponent(id)}`,
      { method: 'DELETE' },
    );
  }
  job(id: string) {
    return this.request<components['schemas']['AssessmentJob']>(
      `/cpm/jobs/${encodeURIComponent(id)}`,
    );
  }
  cancelJob(id: string) {
    return this.request<{ id: string; status: string }>(
      `/cpm/jobs/${encodeURIComponent(id)}/cancel`,
      { method: 'POST' },
    );
  }
  drift(limit = 25, offset = 0) {
    return this.request<components['schemas']['DriftEvent'][]>(
      `/cpm/drift?limit=${limit}&offset=${offset}`,
    );
  }
  remediation(limit = 25, offset = 0) {
    return this.request<components['schemas']['Remediation'][]>(
      `/cpm/remediation?limit=${limit}&offset=${offset}`,
    );
  }
  transitionFinding(
    snapshotId: string,
    ruleId: string,
    input: components['schemas']['FindingTransition'],
  ) {
    return this.request<{ status: string }>(
      `/cpm/findings/${encodeURIComponent(snapshotId)}/${encodeURIComponent(ruleId)}`,
      { method: 'PATCH', body: JSON.stringify(input) },
    );
  }
  assessMigration(input: components['schemas']['MigrationRequest']) {
    return this.request<components['schemas']['MigrationResult']>('/cpm/migrations/assess', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }
  migration(id: string) {
    return this.request<components['schemas']['MigrationResult']>(
      `/cpm/migrations/${encodeURIComponent(id)}`,
    );
  }
  verifyMigration(id: string, assessmentId: string) {
    return this.request<components['schemas']['MigrationResult']>(
      `/cpm/migrations/${encodeURIComponent(id)}/verify`,
      { method: 'POST', body: JSON.stringify({ assessmentId }) },
    );
  }
}

import type { components } from '../../../packages/api-contracts/generated.js';
type Assessment = components['schemas']['Assessment'];
type ScanInput = components['schemas']['ScanRequest'];
type EffectiveFinding = components['schemas']['EffectiveFinding'];
type CycloneDxCbom = components['schemas']['CycloneDxCbom'];
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
  /** CycloneDX 1.6 CBOM export of one assessment. */
  cbom(id: string) {
    return this.request<CycloneDxCbom>(`/assessments/${encodeURIComponent(id)}/cbom`);
  }
  /** Findings with effective lifecycle status; scoped to one assessment when an id is given. */
  findings(assessmentId?: string) {
    const query =
      assessmentId === undefined ? '' : `?assessmentId=${encodeURIComponent(assessmentId)}`;
    return this.request<EffectiveFinding[]>(`/findings${query}`);
  }
}

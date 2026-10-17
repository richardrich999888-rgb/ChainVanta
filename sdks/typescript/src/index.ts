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
}

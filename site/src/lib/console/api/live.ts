import type {
  ApiClient,
  FindingAction,
  InsuranceData,
  OverviewData,
  PluginGroups,
  ReadinessData,
  RuleDoc,
  Ruleset,
  SettingsData
} from './types';

interface RulesListResponse {
  rulesets: Ruleset[];
  selected: RuleDoc;
}

export class LiveClient implements ApiClient {
  constructor(private base: string, private token: () => string | null = () => null) {}

  private async get<T>(path: string): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    const t = this.token();
    if (t) headers.Authorization = `Bearer ${t}`;
    const res = await fetch(`${this.base}${path}`, { headers });
    if (!res.ok) throw new Error(`${path} -> ${res.status} ${res.statusText}`);
    return (await res.json()) as T;
  }

  private async send(path: string, method: string, body?: unknown): Promise<void> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const t = this.token();
    if (t) headers.Authorization = `Bearer ${t}`;
    const res = await fetch(`${this.base}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined
    });
    if (!res.ok) {
      const detail = await res.text();
      throw new Error(`${method} ${path} -> ${res.status}: ${detail}`);
    }
  }

  getOverview() {
    return this.get<OverviewData>('/v1/console/overview');
  }

  getReadiness() {
    return this.get<ReadinessData>('/v1/console/readiness');
  }

  async getRules() {
    const payload = await this.get<RulesListResponse>('/v1/rules');
    return { rulesets: payload.rulesets, selected: payload.selected };
  }

  getRuleDoc(id: string) {
    return this.get<RuleDoc>(`/v1/rules/${encodeURIComponent(id)}`);
  }

  getPlugins() {
    return this.get<PluginGroups>('/v1/plugins');
  }

  getInsurance() {
    return this.get<InsuranceData>('/v1/insurance');
  }

  getSettings() {
    return this.get<SettingsData>('/v1/settings');
  }

  revokeDelegation(agent: string) {
    return this.send(`/v1/delegations/${encodeURIComponent(agent)}/revoke`, 'POST');
  }

  actOnFinding(id: string, intent: FindingAction['intent']) {
    return this.send(`/v1/findings/${encodeURIComponent(id)}/act`, 'POST', { intent });
  }

  setTransport(label: string, on: boolean) {
    return this.send('/v1/insurance/transport', 'PATCH', { label, on });
  }

  revokeConsent(carrier: string) {
    return this.send(`/v1/insurance/consent/${encodeURIComponent(carrier)}/revoke`, 'POST');
  }

  connectPlugin(pluginId: string) {
    return this.send(`/v1/plugins/${encodeURIComponent(pluginId)}/connect`, 'POST');
  }
}

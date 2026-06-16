// Live client. Same contract as MockClient, backed by the AIR API. Each method
// maps to a documented endpoint and throws on a non-2xx so screens render their
// error state instead of fake data. Fill the response mappers as the backend
// endpoints land; until then PUBLIC_AIR_API_MODE=mock keeps the UI fully usable.
import type {
  AgentSummary,
  ApiClient,
  FindingAction,
  InsuranceData,
  OverviewData,
  PluginGroups,
  ReadinessData,
  RuleDoc,
  SettingsData
} from './types';

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
    const res = await fetch(`${this.base}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
    if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}`);
  }

  // GET /v1/console/overview   (aggregates: delegations, enforcement feed,
  //   findings from the SV checks, proof status, the operator session)
  getOverview() { return this.get<OverviewData>('/v1/console/overview'); }

  // GET /v1/console/agents  (identity registry via the operator-authed console
  // route; /v1/agents itself is behind the API-key middleware, not the Auth0 token)
  async getAgents(): Promise<AgentSummary[]> {
    const raw = await this.get<Array<Record<string, unknown>>>('/v1/console/agents');
    return (raw ?? []).map((a) => ({
      agentId: String(a.agent_id ?? ''),
      name: String(a.name ?? ''),
      permittedTools: (a.permitted_tools as string[]) ?? [],
      dataScope: (a.data_scope as string[]) ?? [],
      status: a.status === 'suspended' ? 'suspended' : 'active',
      suspendedReason: String(a.suspended_reason ?? ''),
      createdAt: String(a.created_at ?? '')
    }));
  }

  // GET /v1/console/readiness  (the four-question assessment + compliance rings)
  getReadiness() { return this.get<ReadinessData>('/v1/console/readiness'); }

  // GET /v1/rules  and  GET /v1/rules/{id}
  async getRules() {
    const rulesets = await this.get<RuleDoc[] | any>('/v1/rules');
    const list = (rulesets as any).rulesets ?? rulesets;
    const firstId = list[0]?.id ?? 'company-floor';
    const selected = await this.getRuleDoc(firstId);
    return { rulesets: list, selected };
  }
  getRuleDoc(id: string) { return this.get<RuleDoc>(`/v1/rules/${encodeURIComponent(id)}`); }

  // GET /v1/plugins
  getPlugins() { return this.get<PluginGroups>('/v1/plugins'); }

  // GET /v1/insurance  (posture summary + transport config + carrier consents)
  getInsurance() { return this.get<InsuranceData>('/v1/insurance'); }

  // GET /v1/settings
  getSettings() { return this.get<SettingsData>('/v1/settings'); }

  // mutations
  revokeDelegation(agent: string) { return this.send(`/v1/delegations/${encodeURIComponent(agent)}/revoke`, 'POST'); }
  actOnFinding(id: string, intent: FindingAction['intent']) { return this.send(`/v1/findings/${encodeURIComponent(id)}/act`, 'POST', { intent }); }
  setTransport(label: string, on: boolean) { return this.send('/v1/insurance/transport', 'PATCH', { label, on }); }
  revokeConsent(carrier: string) { return this.send(`/v1/insurance/consent/${encodeURIComponent(carrier)}/revoke`, 'POST'); }
}

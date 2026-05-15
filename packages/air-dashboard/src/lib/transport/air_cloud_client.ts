/**
 * AIR Cloud client for the dashboard.
 *
 * Talks to the hosted AIR Cloud ingest service (vindicara/cloud) over HTTPS,
 * authenticated with either an API key (X-API-Key) or a session token
 * (Authorization: Bearer). The dashboard uses this to fetch the live chain
 * instead of the bundled /scenarios JSONL files; both data sources remain
 * available so demos still work offline.
 */

import type { AgDRRecord } from '../agdr/types.ts';

export const DEFAULT_BASE_URL = 'https://cloud.vindicara.io';

export interface CloudWorkspace {
	workspace_id: string;
	name: string;
	owner_email: string;
	created_at: string;
}

export interface CapsulesPage {
	workspace_id: string;
	count: number;
	records: AgDRRecord[];
}

export interface RedactedKey {
	key_id: string;
	workspace_id: string;
	role: string;
	name: string | null;
	created_at: string;
	revoked_at: string | null;
}

export interface SsoSessionResponse {
	workspace_id: string;
	session_token: string;
	role: string;
	sub: string;
	email: string | null;
}

export interface ControlScore {
	control_id: string;
	control_name: string;
	evidence_count: number;
	required: number;
	met: boolean;
}

export interface FrameworkScore {
	framework_id: string;
	name: string;
	total_controls: number;
	met_controls: number;
	coverage_pct: number;
	controls: ControlScore[];
}

export interface ComplianceSummary {
	frameworks: FrameworkScore[];
}

export interface AnalyticsSummary {
	total_capsules: number;
	capsules_this_week: number;
	unique_agents: number;
	active_members: number;
	detector_counts: Record<string, number>;
	chain_health: { verified: number; tampered: number; broken_link: number };
	daily_ingestion: { date: string; count: number }[];
}

export interface MemberInvited {
	workspace_id: string;
	invited_email: string;
}

export class AirCloudHttpError extends Error {
	readonly status: number;
	readonly body: string;
	constructor(status: number, body: string) {
		super(`AIR Cloud request failed: HTTP ${status}: ${body.slice(0, 200)}`);
		this.status = status;
		this.body = body;
		this.name = 'AirCloudHttpError';
	}
}

export interface AirCloudClientConfig {
	baseUrl?: string;
	apiKey?: string;
	sessionToken?: string;
	fetchImpl?: typeof fetch;
}

export class AirCloudClient {
	readonly baseUrl: string;
	private readonly _apiKey?: string;
	private readonly _sessionToken?: string;
	private readonly _fetch: typeof fetch;

	constructor(config: AirCloudClientConfig) {
		if (!config.apiKey && !config.sessionToken) {
			throw new Error('AIR Cloud: apiKey or sessionToken is required');
		}
		this.baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
		this._apiKey = config.apiKey;
		this._sessionToken = config.sessionToken;
		this._fetch = config.fetchImpl ?? fetch;
	}

	get authMode(): 'bearer' | 'api-key' {
		return this._sessionToken ? 'bearer' : 'api-key';
	}

	get apiKey(): string {
		return this._apiKey ?? '';
	}

	private get _headers(): Record<string, string> {
		if (this._sessionToken) {
			return { Authorization: `Bearer ${this._sessionToken}`, Accept: 'application/json' };
		}
		return { 'X-API-Key': this._apiKey ?? '', Accept: 'application/json' };
	}

	async whoami(): Promise<CloudWorkspace> {
		return this._get<CloudWorkspace>('/v1/workspaces/me');
	}

	async listCapsules(opts?: { limit?: number; offset?: number }): Promise<CapsulesPage> {
		const params = new URLSearchParams();
		if (opts?.limit !== undefined) params.set('limit', String(opts.limit));
		if (opts?.offset !== undefined) params.set('offset', String(opts.offset));
		const qs = params.toString();
		return this._get<CapsulesPage>(`/v1/capsules${qs ? `?${qs}` : ''}`);
	}

	async listKeys(): Promise<RedactedKey[]> {
		return this._get<RedactedKey[]>('/v1/keys');
	}

	async getCapsule(stepId: string): Promise<AgDRRecord> {
		return this._get<AgDRRecord>(`/v1/capsules/${encodeURIComponent(stepId)}`);
	}

	async ssoLogin(token: string, workspaceId?: string): Promise<SsoSessionResponse> {
		const body: Record<string, string> = { token };
		if (workspaceId) body.workspace_id = workspaceId;
		const response = await this._fetch(`${this.baseUrl}/v1/sso/login`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
			body: JSON.stringify(body),
		});
		if (!response.ok) {
			const text = await response.text();
			throw new AirCloudHttpError(response.status, text);
		}
		return (await response.json()) as SsoSessionResponse;
	}

	async complianceSummary(): Promise<ComplianceSummary> {
		return this._get<ComplianceSummary>('/v1/compliance/summary');
	}

	async analyticsSummary(): Promise<AnalyticsSummary> {
		return this._get<AnalyticsSummary>('/v1/analytics/summary');
	}

	async listMembers(): Promise<RedactedKey[]> {
		return this.listKeys();
	}

	async inviteMember(email: string, role: string = 'member'): Promise<MemberInvited> {
		return this._request<MemberInvited>('POST', '/v1/workspaces/me/members', { email, role });
	}

	async updateKeyRole(keyId: string, role: string): Promise<{ key_id: string; role: string }> {
		return this._request<{ key_id: string; role: string }>(
			'PATCH',
			`/v1/keys/${encodeURIComponent(keyId)}`,
			{ role }
		);
	}

	async revokeKey(keyId: string): Promise<{ key_id: string; revoked: boolean }> {
		return this._request<{ key_id: string; revoked: boolean }>(
			'DELETE',
			`/v1/keys/${encodeURIComponent(keyId)}`
		);
	}

	private async _get<T>(path: string): Promise<T> {
		const response = await this._fetch(`${this.baseUrl}${path}`, {
			method: 'GET',
			headers: this._headers
		});
		if (!response.ok) {
			const body = await response.text();
			throw new AirCloudHttpError(response.status, body);
		}
		return (await response.json()) as T;
	}

	private async _request<T>(method: string, path: string, body?: unknown): Promise<T> {
		const headers: Record<string, string> = { ...this._headers };
		if (body !== undefined) headers['Content-Type'] = 'application/json';
		const response = await this._fetch(`${this.baseUrl}${path}`, {
			method,
			headers,
			body: body !== undefined ? JSON.stringify(body) : undefined,
		});
		if (!response.ok) {
			const text = await response.text();
			throw new AirCloudHttpError(response.status, text);
		}
		return (await response.json()) as T;
	}
}

/**
 * Convenience: fetch the entire current chain from the live cloud endpoint as
 * a flat AgDRRecord[] (matching the loadScenario() return shape so callers can
 * swap data sources without touching downstream rendering).
 */
export async function loadCloudChain(client: AirCloudClient, opts?: { limit?: number }): Promise<AgDRRecord[]> {
	const page = await client.listCapsules({ limit: opts?.limit ?? 1000 });
	return page.records;
}

/**
 * Open an SSE connection to ``/v1/capsules/stream``. Each ``data:`` frame
 * is a JSON-encoded AgDRRecord. Returns a handle with ``close()`` to
 * terminate the connection.
 *
 * Falls back to polling ``/v1/capsules`` every ``pollIntervalMs`` if
 * EventSource is unavailable or the connection fails.
 */
export interface StreamHandle {
	close(): void;
}

export function streamCapsules(
	client: AirCloudClient,
	onRecord: (record: AgDRRecord) => void,
	opts?: { pollIntervalMs?: number }
): StreamHandle {
	const pollInterval = opts?.pollIntervalMs ?? 2000;
	const url = `${client.baseUrl}/v1/capsules/stream`;

	if (typeof EventSource !== 'undefined') {
		try {
			const es = new EventSource(url, { withCredentials: false });
			let closed = false;

			es.onmessage = (event) => {
				if (closed) return;
				try {
					const record = JSON.parse(event.data) as AgDRRecord;
					onRecord(record);
				} catch {
					/* malformed frame, skip */
				}
			};

			es.onerror = () => {
				if (closed) return;
				es.close();
				const fallback = startPolling(client, onRecord, pollInterval);
				return fallback;
			};

			return {
				close() {
					closed = true;
					es.close();
				}
			};
		} catch {
			/* EventSource constructor failed, fall through to polling */
		}
	}

	return startPolling(client, onRecord, pollInterval);
}

function startPolling(
	client: AirCloudClient,
	onRecord: (record: AgDRRecord) => void,
	intervalMs: number
): StreamHandle {
	let offset = 0;
	let stopped = false;

	const poll = async (): Promise<void> => {
		while (!stopped) {
			try {
				const page = await client.listCapsules({ limit: 100, offset });
				for (const record of page.records) {
					onRecord(record);
				}
				if (page.records.length > 0) {
					offset += page.records.length;
				}
			} catch {
				/* retry next tick */
			}
			await new Promise((r) => setTimeout(r, intervalMs));
		}
	};

	poll();

	return {
		close() {
			stopped = true;
		}
	};
}

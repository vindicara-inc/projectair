/**
 * AIR Cloud client for the dashboard.
 *
 * Talks to the hosted W3.7 ingest service (vindicara/cloud) over HTTPS,
 * authenticated with the workspace's API key. The dashboard uses this
 * to fetch the live chain instead of the bundled /scenarios JSONL
 * files; both data sources remain available so demos still work
 * offline.
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
	apiKey: string;
	fetchImpl?: typeof fetch;
}

export class AirCloudClient {
	readonly baseUrl: string;
	readonly apiKey: string;
	private readonly _fetch: typeof fetch;

	constructor(config: AirCloudClientConfig) {
		if (!config.apiKey) throw new Error('AIR Cloud apiKey is required');
		this.baseUrl = (config.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
		this.apiKey = config.apiKey;
		this._fetch = config.fetchImpl ?? fetch;
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

	private async _get<T>(path: string): Promise<T> {
		const response = await this._fetch(`${this.baseUrl}${path}`, {
			method: 'GET',
			headers: {
				'X-API-Key': this.apiKey,
				Accept: 'application/json'
			}
		});
		if (!response.ok) {
			const body = await response.text();
			throw new AirCloudHttpError(response.status, body);
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

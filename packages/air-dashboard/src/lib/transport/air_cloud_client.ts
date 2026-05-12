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

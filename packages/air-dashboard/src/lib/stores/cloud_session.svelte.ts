/**
 * AIR Cloud session store — holds the live ingest credentials the dashboard
 * uses to swap from bundled `/scenarios/*.jsonl` to a real workspace's
 * chain. The credentials are cached in localStorage so a refresh does not
 * log the user out; calling ``disconnect()`` clears them.
 */

import { AirCloudClient, AirCloudHttpError, DEFAULT_BASE_URL, loadCloudChain, streamCapsules } from '../transport/index.ts';
import type { CloudWorkspace, StreamHandle } from '../transport/index.ts';
import type { AgDRRecord } from '../agdr/types.ts';

const STORAGE_KEY = 'vindicara.air_cloud_session.v1';

export type CloudConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error';

interface PersistedSession {
	baseUrl: string;
	apiKey: string;
}

function readPersisted(): PersistedSession | null {
	if (typeof globalThis.localStorage === 'undefined') return null;
	const raw = globalThis.localStorage.getItem(STORAGE_KEY);
	if (!raw) return null;
	try {
		const parsed = JSON.parse(raw) as Partial<PersistedSession>;
		if (typeof parsed.baseUrl !== 'string' || typeof parsed.apiKey !== 'string') return null;
		return { baseUrl: parsed.baseUrl, apiKey: parsed.apiKey };
	} catch {
		return null;
	}
}

function writePersisted(session: PersistedSession | null): void {
	if (typeof globalThis.localStorage === 'undefined') return;
	if (session === null) {
		globalThis.localStorage.removeItem(STORAGE_KEY);
		return;
	}
	globalThis.localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

class CloudSessionStore {
	status = $state<CloudConnectionStatus>('disconnected');
	baseUrl = $state(DEFAULT_BASE_URL);
	workspace = $state<CloudWorkspace | null>(null);
	error = $state<string | null>(null);
	private apiKey: string | null = null;
	private fetchImpl: typeof fetch | undefined;
	private streamHandle: StreamHandle | null = null;

	constructor(fetchImpl?: typeof fetch) {
		this.fetchImpl = fetchImpl;
	}

	get isConnected(): boolean {
		return this.status === 'connected' && this.apiKey !== null;
	}

	/**
	 * Restore a session from localStorage. Called on dashboard mount so a
	 * page refresh does not log the user out. Failures move the status to
	 * 'error' but leave the persisted credentials in place; the user can
	 * either retry or disconnect explicitly.
	 */
	async restore(): Promise<void> {
		const persisted = readPersisted();
		if (!persisted) return;
		await this._connectInternal(persisted.baseUrl, persisted.apiKey);
	}

	async connect(baseUrl: string, apiKey: string): Promise<void> {
		await this._connectInternal(baseUrl, apiKey);
		if (this.status === 'connected') {
			writePersisted({ baseUrl: this.baseUrl, apiKey });
		}
	}

	disconnect(): void {
		this.stopStream();
		this.status = 'disconnected';
		this.workspace = null;
		this.error = null;
		this.apiKey = null;
		writePersisted(null);
	}

	startStream(onRecord: (record: AgDRRecord) => void): void {
		this.stopStream();
		const client = this._buildClient();
		this.streamHandle = streamCapsules(client, onRecord);
	}

	stopStream(): void {
		this.streamHandle?.close();
		this.streamHandle = null;
	}

	async loadCurrentChain(opts?: { limit?: number }): Promise<AgDRRecord[]> {
		const client = this._buildClient();
		return loadCloudChain(client, opts);
	}

	private _buildClient(): AirCloudClient {
		if (this.apiKey === null) throw new Error('AIR Cloud session is not connected');
		return new AirCloudClient({ baseUrl: this.baseUrl, apiKey: this.apiKey, fetchImpl: this.fetchImpl });
	}

	private async _connectInternal(baseUrl: string, apiKey: string): Promise<void> {
		this.status = 'connecting';
		this.error = null;
		this.baseUrl = baseUrl.replace(/\/+$/, '');
		this.apiKey = apiKey;
		try {
			const client = this._buildClient();
			this.workspace = await client.whoami();
			this.status = 'connected';
		} catch (cause) {
			this.workspace = null;
			this.apiKey = null;
			this.status = 'error';
			if (cause instanceof AirCloudHttpError) {
				this.error = `HTTP ${cause.status}: ${cause.body.slice(0, 120)}`;
			} else {
				this.error = (cause as Error).message;
			}
		}
	}
}

export const cloudSession = new CloudSessionStore();

// Re-exported for tests so they can construct a fresh store with a mock
// fetch without touching localStorage on the global one.
export { CloudSessionStore };

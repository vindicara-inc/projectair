/**
 * AIR Cloud session store — holds the live ingest credentials used to swap
 * from bundled /scenarios/*.jsonl to a real workspace's chain. The session
 * lives in memory only: no localStorage. Credentials are obtained via SSO
 * token exchange on login and are dropped on disconnect or page unload.
 */

import {
	AirCloudClient,
	AirCloudHttpError,
	DEFAULT_BASE_URL,
	loadCloudChain,
	streamCapsules
} from '../transport/index.ts';
import type { CloudWorkspace, StreamHandle } from '../transport/index.ts';
import type { AgDRRecord } from '../agdr/types.ts';
import { roleStore, type Role } from './role.svelte.ts';

export type CloudConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error';

class CloudSessionStore {
	status = $state<CloudConnectionStatus>('disconnected');
	baseUrl = $state(DEFAULT_BASE_URL);
	workspace = $state<CloudWorkspace | null>(null);
	error = $state<string | null>(null);
	client = $state<AirCloudClient | null>(null);
	private sessionToken: string | null = null;
	private streamHandle: StreamHandle | null = null;

	get isConnected(): boolean {
		return this.status === 'connected' && this.client !== null;
	}

	/**
	 * Exchange an Auth0 JWT for an AIR Cloud session token, then populate
	 * workspace metadata and the role store. Called automatically by
	 * authStore.init() after successful Auth0 authentication.
	 */
	async ssoConnect(baseUrl: string, auth0Token: string): Promise<void> {
		this.status = 'connecting';
		this.error = null;
		this.baseUrl = baseUrl.replace(/\/+$/, '');
		try {
			const tempClient = new AirCloudClient({ baseUrl: this.baseUrl, apiKey: 'unused' });
			const resp = await tempClient.ssoLogin(auth0Token);
			this.sessionToken = resp.session_token;
			this.client = new AirCloudClient({
				baseUrl: this.baseUrl,
				sessionToken: resp.session_token
			});
			this.workspace = await this.client.whoami();
			roleStore.set(resp.role as Role, resp.sub, resp.email);
			this.status = 'connected';
		} catch (cause) {
			this.workspace = null;
			this.client = null;
			this.sessionToken = null;
			this.status = 'error';
			if (cause instanceof AirCloudHttpError) {
				this.error = `HTTP ${cause.status}: ${cause.body.slice(0, 120)}`;
			} else {
				this.error = (cause as Error).message;
			}
		}
	}

	disconnect(): void {
		this.stopStream();
		this.status = 'disconnected';
		this.workspace = null;
		this.error = null;
		this.client = null;
		this.sessionToken = null;
		roleStore.clear();
	}

	startStream(onRecord: (record: AgDRRecord) => void): void {
		this.stopStream();
		if (!this.client) return;
		this.streamHandle = streamCapsules(this.client, onRecord);
	}

	stopStream(): void {
		this.streamHandle?.close();
		this.streamHandle = null;
	}

	async loadCurrentChain(opts?: { limit?: number }): Promise<AgDRRecord[]> {
		if (!this.client) throw new Error('AIR Cloud session is not connected');
		return loadCloudChain(this.client, opts);
	}
}

export const cloudSession = new CloudSessionStore();

// Re-exported for tests so they can construct a fresh store with a mock
// fetch without touching the global instance.
export { CloudSessionStore };

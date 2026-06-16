/**
 * Team store — manages workspace member list and role operations.
 * Wraps the AIR Cloud client's member/key endpoints and keeps the
 * local member list in sync after each mutation.
 */

import type { RedactedKey } from '$lib/transport/air_cloud_client';
import { cloudSession } from '$lib/stores/cloud_session.svelte';

class TeamStore {
	members = $state<RedactedKey[]>([]);
	loading = $state(false);
	error = $state<string | null>(null);

	async load(): Promise<void> {
		if (!cloudSession.client) return;
		this.loading = true;
		this.error = null;
		try {
			this.members = await cloudSession.client.listMembers();
		} catch (err) {
			this.error = err instanceof Error ? err.message : String(err);
		} finally {
			this.loading = false;
		}
	}

	async invite(email: string, role: string): Promise<boolean> {
		if (!cloudSession.client) return false;
		try {
			await cloudSession.client.inviteMember(email, role);
			await this.load();
			return true;
		} catch (err) {
			this.error = err instanceof Error ? err.message : String(err);
			return false;
		}
	}

	async changeRole(keyId: string, role: string): Promise<boolean> {
		if (!cloudSession.client) return false;
		try {
			await cloudSession.client.updateKeyRole(keyId, role);
			await this.load();
			return true;
		} catch (err) {
			this.error = err instanceof Error ? err.message : String(err);
			return false;
		}
	}

	async revoke(keyId: string): Promise<boolean> {
		if (!cloudSession.client) return false;
		try {
			await cloudSession.client.revokeKey(keyId);
			await this.load();
			return true;
		} catch (err) {
			this.error = err instanceof Error ? err.message : String(err);
			return false;
		}
	}
}

export const teamStore = new TeamStore();

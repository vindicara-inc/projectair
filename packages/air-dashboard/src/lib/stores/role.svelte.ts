/**
 * Role store — holds the authenticated user's role within their AIR Cloud
 * workspace. Populated by cloudSession.ssoConnect() after a successful SSO
 * token exchange; cleared on disconnect. Lives in memory only: no persistence.
 */

export type Role = 'owner' | 'admin' | 'member' | 'viewer';

class RoleStore {
	current = $state<Role>('viewer');
	sub = $state('');
	email = $state<string | null>(null);

	get isAdmin(): boolean {
		return this.current === 'owner' || this.current === 'admin';
	}

	get isOwner(): boolean {
		return this.current === 'owner';
	}

	set(role: Role, sub: string, email: string | null): void {
		this.current = role;
		this.sub = sub;
		this.email = email;
	}

	clear(): void {
		this.current = 'viewer';
		this.sub = '';
		this.email = null;
	}
}

export const roleStore = new RoleStore();

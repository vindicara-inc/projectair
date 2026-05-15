import { createAuth0Client, type Auth0Client, type User } from '@auth0/auth0-spa-js';
import { cloudSession } from './cloud_session.svelte.ts';

const DOMAIN = import.meta.env.VITE_AUTH0_DOMAIN as string | undefined;
const CLIENT_ID = import.meta.env.VITE_AUTH0_CLIENT_ID as string | undefined;

class AuthStore {
	phase = $state<'loading' | 'gate' | 'authenticated'>('loading');
	user = $state<User | null>(null);
	private client: Auth0Client | null = null;

	async init(): Promise<void> {
		if (!DOMAIN || !CLIENT_ID) {
			this.phase = 'gate';
			return;
		}
		const origin = typeof window !== 'undefined' ? window.location.origin : '';
		this.client = await createAuth0Client({
			domain: DOMAIN,
			clientId: CLIENT_ID,
			cacheLocation: 'memory',
			authorizationParams: {
				redirect_uri: `${origin}/dashboard/`,
			},
			useRefreshTokens: true,
		});
		const params = new URLSearchParams(window.location.search);
		if (params.has('code') && params.has('state')) {
			await this.client.handleRedirectCallback();
			window.history.replaceState({}, '', window.location.pathname);
		}
		if (await this.client.isAuthenticated()) {
			this.user = (await this.client.getUser()) ?? null;
			const token = await this.client.getTokenSilently();
			if (token) {
				const cloudUrl =
					(import.meta.env.VITE_AIR_CLOUD_URL as string | undefined) ??
					'https://cloud.vindicara.io';
				await cloudSession.ssoConnect(cloudUrl, token);
			}
			this.phase = 'authenticated';
		} else {
			this.phase = 'gate';
		}
	}

	async login(): Promise<void> {
		await this.client?.loginWithRedirect();
	}

	async logout(): Promise<void> {
		const origin = typeof window !== 'undefined' ? window.location.origin : '';
		await this.client?.logout({
			logoutParams: { returnTo: `${origin}/dashboard/` },
		});
	}

	async getToken(): Promise<string | null> {
		try {
			return (await this.client?.getTokenSilently()) ?? null;
		} catch {
			return null;
		}
	}
}

export const authStore = new AuthStore();

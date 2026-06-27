import { describe, expect, it } from 'vitest';
import { buildAuthorizeUrl } from './authorize';

const input = {
	domain: 'tenant.us.auth0.com',
	clientId: 'spa-client-id',
	origin: 'https://vindicara.io',
	codeChallenge: 'challenge-value',
	audience: 'https://api.vindicara.io'
};

describe('buildAuthorizeUrl', () => {
	it('selects the configured Google connection', () => {
		const url = buildAuthorizeUrl({ ...input, connection: 'google-oauth2' });
		expect(url.origin).toBe('https://tenant.us.auth0.com');
		expect(url.pathname).toBe('/authorize');
		expect(url.searchParams.get('connection')).toBe('google-oauth2');
		expect(url.searchParams.get('redirect_uri')).toBe('https://vindicara.io/dashboard/auth/callback/');
		expect(url.searchParams.get('code_challenge_method')).toBe('S256');
	});

	it('selects the configured GitHub connection', () => {
		const url = buildAuthorizeUrl({ ...input, connection: 'github' });
		expect(url.searchParams.get('connection')).toBe('github');
	});

	it('omits connection for generic email and enterprise login', () => {
		const url = buildAuthorizeUrl(input);
		expect(url.searchParams.has('connection')).toBe(false);
		expect(url.searchParams.get('scope')).toBe('openid profile email');
		expect(url.searchParams.get('audience')).toBe('https://api.vindicara.io');
	});

	it('does not include an empty audience parameter', () => {
		const url = buildAuthorizeUrl({ ...input, audience: undefined, connection: 'github' });
		expect(url.searchParams.has('audience')).toBe(false);
		expect(url.searchParams.get('connection')).toBe('github');
	});
});

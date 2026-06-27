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
	it('selects the configured Google connection for Flightdeck', () => {
		const url = buildAuthorizeUrl({ ...input, connection: 'google-oauth2' });
		expect(url.searchParams.get('connection')).toBe('google-oauth2');
		expect(url.searchParams.get('redirect_uri')).toBe('https://vindicara.io/flightdeck/auth/callback/');
		expect(url.searchParams.get('code_challenge_method')).toBe('S256');
	});

	it('selects GitHub and leaves generic login unconstrained', () => {
		expect(buildAuthorizeUrl({ ...input, connection: 'github' }).searchParams.get('connection')).toBe('github');
		expect(buildAuthorizeUrl(input).searchParams.has('connection')).toBe(false);
	});
});

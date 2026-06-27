export const AUTH0_CONNECTIONS = ['google-oauth2', 'github'] as const;

export type Auth0Connection = (typeof AUTH0_CONNECTIONS)[number];

export interface AuthorizeUrlInput {
	domain: string;
	clientId: string;
	origin: string;
	codeChallenge: string;
	audience?: string;
	connection?: Auth0Connection;
}

export function buildAuthorizeUrl(input: AuthorizeUrlInput): URL {
	const url = new URL(`https://${input.domain}/authorize`);
	url.searchParams.set('response_type', 'code');
	url.searchParams.set('client_id', input.clientId);
	url.searchParams.set('redirect_uri', `${input.origin}/flightdeck/auth/callback/`);
	url.searchParams.set('scope', 'openid profile email');
	url.searchParams.set('code_challenge', input.codeChallenge);
	url.searchParams.set('code_challenge_method', 'S256');
	if (input.audience) url.searchParams.set('audience', input.audience);
	if (input.connection) url.searchParams.set('connection', input.connection);
	return url;
}

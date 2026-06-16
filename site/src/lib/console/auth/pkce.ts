const VERIFIER_KEY = 'air_flightdeck_pkce';
const TOKEN_KEY = 'air_flightdeck_token';

function toBase64Url(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

export function randomVerifier(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	return toBase64Url(bytes);
}

export async function challengeFromVerifier(verifier: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	return toBase64Url(new Uint8Array(digest));
}

export function storeVerifier(verifier: string): void {
	sessionStorage.setItem(VERIFIER_KEY, verifier);
}

export function takeVerifier(): string | null {
	const value = sessionStorage.getItem(VERIFIER_KEY);
	sessionStorage.removeItem(VERIFIER_KEY);
	return value;
}

export function storeAccessToken(token: string): void {
	sessionStorage.setItem(TOKEN_KEY, token);
}

export function loadAccessToken(): string | null {
	return sessionStorage.getItem(TOKEN_KEY);
}

export function clearAccessToken(): void {
	sessionStorage.removeItem(TOKEN_KEY);
}

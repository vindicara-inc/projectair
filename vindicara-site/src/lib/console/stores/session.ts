// Session + lock state. The lock screen and the route guard both read this.
// Live mode runs a real Auth0 Authorization Code + PKCE flow; the access token
// is attached to every API call by $lib/console/api/client.
import { writable } from 'svelte/store';
import { env } from '$env/dynamic/public';
import {
  challengeFromVerifier,
  clearAccessToken,
  loadAccessToken,
  randomVerifier,
  storeAccessToken,
  storeVerifier,
  takeVerifier
} from '$lib/console/auth/pkce';

export const locked = writable(false);
export const sessionToken = writable<string | null>(loadAccessToken());
export const authError = writable<string | null>(null);

export function lockSession() {
  clearAccessToken();
  sessionToken.set(null);
  locked.set(true);
}

// Full sign-out: drop the local token, then end the Auth0 session so the next
// login shows the Auth0 login screen instead of silently re-authenticating.
// Auth0 returns the operator to the logout confirmation page.
export function logout(): void {
  const domain = env.PUBLIC_AUTH0_DOMAIN;
  const clientId = env.PUBLIC_AUTH0_CLIENT_ID;
  clearAccessToken();
  sessionToken.set(null);
  locked.set(true);
  authError.set(null);
  const returnTo = `${location.origin}/flightdeck/auth/logout/`;
  if (domain && clientId) {
    const url = new URL(`https://${domain}/v2/logout`);
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('returnTo', returnTo);
    location.assign(url.toString());
  } else {
    location.assign(returnTo);
  }
}

export async function beginAuth0Login(): Promise<void> {
  authError.set(null);
  const domain = env.PUBLIC_AUTH0_DOMAIN;
  const clientId = env.PUBLIC_AUTH0_CLIENT_ID;
  const audience = env.PUBLIC_AUTH0_AUDIENCE;
  if (!domain || !clientId) {
    authError.set('Auth0 is not configured. Set PUBLIC_AUTH0_DOMAIN and PUBLIC_AUTH0_CLIENT_ID.');
    return;
  }

  const verifier = randomVerifier();
  storeVerifier(verifier);
  const challenge = await challengeFromVerifier(verifier);
  // Trailing slash is required: the static host canonicalizes to the slash form
  // and drops the ?code= query on the redirect, so we must land on it directly.
  const redirect = `${location.origin}/flightdeck/auth/callback/`;
  const url = new URL(`https://${domain}/authorize`);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', redirect);
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  if (audience) url.searchParams.set('audience', audience);
  location.assign(url.toString());
}

export function unlock(token: string | null = null) {
  if (token) {
    storeAccessToken(token);
    sessionToken.set(token);
  }
  locked.set(false);
  authError.set(null);
}

export async function exchangeAuthCode(code: string): Promise<string> {
  const domain = env.PUBLIC_AUTH0_DOMAIN;
  const clientId = env.PUBLIC_AUTH0_CLIENT_ID;
  if (!domain || !clientId) {
    throw new Error('Auth0 is not configured for token exchange.');
  }
  const verifier = takeVerifier();
  if (!verifier) {
    throw new Error('Missing PKCE verifier. Start sign-in again from the lock screen.');
  }
  // Trailing slash is required: the static host canonicalizes to the slash form
  // and drops the ?code= query on the redirect, so we must land on it directly.
  const redirect = `${location.origin}/flightdeck/auth/callback/`;
  const response = await fetch(`https://${domain}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      client_id: clientId,
      code_verifier: verifier,
      code,
      redirect_uri: redirect
    })
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Auth0 token exchange failed (${response.status}): ${detail}`);
  }
  const payload = (await response.json()) as { access_token?: string };
  if (!payload.access_token) {
    throw new Error('Auth0 token response did not include access_token.');
  }
  return payload.access_token;
}

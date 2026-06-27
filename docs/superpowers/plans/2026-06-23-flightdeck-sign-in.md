# Flightdeck Sign-in Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the supplied Project AIR onboarding design as Flightdeck's dedicated sign-in route, backed by the existing Auth0 Authorization Code plus PKCE flow.

**Architecture:** Keep Auth0 as the only OAuth broker. Add a small pure URL builder so provider selection is testable without browser globals, then have the session store use it when it creates the PKCE redirect. The sign-in route resets the dashboard layout and owns the supplied visual design. The existing dashboard shell redirects unauthenticated live sessions to that route and the lock screen redirects there after clearing the session.

**Tech Stack:** Svelte 5, SvelteKit 2, TypeScript, Auth0 Authorization Code plus PKCE, Vitest, Testing Library, static adapter.

## Global Constraints

- Implement the supplied onboarding design, not the current Flightdeck console visual system.
- Reuse the existing Auth0 domain, SPA client, callback route, session storage, PKCE verifier, and token exchange.
- Google uses the Auth0 connection name `google-oauth2`; GitHub uses `github`.
- Never put OAuth provider secrets, Auth0 client secrets, access tokens, or identity profile data in source code, public environment variables, screenshots, logs, or test fixtures.
- The only durable authenticated identity is the Auth0 `sub` claim. Email is optional profile data and must not determine authorization.
- Auth0 redirects must use `https://{PUBLIC_AUTH0_DOMAIN}/authorize`, `response_type=code`, `code_challenge_method=S256`, and exact callback URI `${location.origin}/dashboard/auth/callback/`.
- Preserve mock-mode dashboard access when `PUBLIC_AIR_API_MODE !== 'live'`; enforce the sign-in guard in live mode.
- Use no em dashes in copy or comments.
- Preserve visible keyboard focus, semantic controls, and `prefers-reduced-motion` support.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `site/src/lib/console/auth/authorize.ts` | Pure, browser-independent Auth0 authorization URL construction and social-connection allowlist. |
| `site/src/lib/console/stores/session.ts` | PKCE lifecycle, session state, and browser redirect to the URL builder result. |
| `site/src/lib/console/components/FlightdeckSignIn.svelte` | Supplied desktop and mobile sign-in visual with real Auth0 entry actions. |
| `site/src/routes/dashboard/sign-in/+layout@.svelte` | Removes the Flightdeck shell from the sign-in route. |
| `site/src/routes/dashboard/sign-in/+page.svelte` | Reads Auth0 callback errors and renders the sign-in component. |
| `site/src/routes/dashboard/+layout.svelte` | Redirects a live unauthenticated operator to the sign-in route. |
| `site/src/lib/console/components/LockScreen.svelte` | Clears a locked session and redirects to the dedicated route rather than rendering credentials in the dashboard. |
| `site/src/routes/dashboard/auth/callback/+page.svelte` | Returns failed OAuth callbacks to sign-in with a safe user-facing error. |
| `site/vitest.config.ts`, `site/src/**/*.test.ts` | Regression coverage for authorization URLs and sign-in route controls. |

### Task 1: Add a testable Auth0 authorization URL contract

**Files:**
- Create: `site/src/lib/console/auth/authorize.ts`
- Create: `site/src/lib/console/auth/authorize.test.ts`
- Modify: `site/package.json`
- Create: `site/vitest.config.ts`

**Interfaces:**
- Produces: `Auth0Connection`, `buildAuthorizeUrl(input)`.
- Consumes later: `beginAuth0Login(connection?: Auth0Connection)` in `session.ts`.

- [ ] **Step 1: Add the minimal test runner configuration and failing URL tests.**

Add dev dependencies with `npm install -D vitest` and create `site/vitest.config.ts`:

```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: { environment: 'node', include: ['src/**/*.test.ts'] }
});
```

Add this script to `site/package.json`:

```json
"test": "vitest run"
```

Create `site/src/lib/console/auth/authorize.test.ts`:

```ts
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
```

- [ ] **Step 2: Run the focused test and verify the expected red failure.**

Run: `cd site && npm test -- src/lib/console/auth/authorize.test.ts`

Expected: FAIL because `./authorize` does not exist.

- [ ] **Step 3: Implement the smallest pure URL builder.**

Create `site/src/lib/console/auth/authorize.ts`:

```ts
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
	url.searchParams.set('redirect_uri', `${input.origin}/dashboard/auth/callback/`);
	url.searchParams.set('scope', 'openid profile email');
	url.searchParams.set('code_challenge', input.codeChallenge);
	url.searchParams.set('code_challenge_method', 'S256');
	if (input.audience) url.searchParams.set('audience', input.audience);
	if (input.connection) url.searchParams.set('connection', input.connection);
	return url;
}
```

- [ ] **Step 4: Run the focused test and verify green.**

Run: `cd site && npm test -- src/lib/console/auth/authorize.test.ts`

Expected: PASS, 4 tests.

- [ ] **Step 5: Commit the isolated contract.**

```bash
git add site/package.json site/package-lock.json site/vitest.config.ts site/src/lib/console/auth/authorize.ts site/src/lib/console/auth/authorize.test.ts
git commit -m "test: cover Auth0 authorization URL selection"
```

### Task 2: Connect provider selection to the existing PKCE session flow

**Files:**
- Modify: `site/src/lib/console/stores/session.ts`
- Modify: `site/src/lib/console/auth/authorize.test.ts`

**Interfaces:**
- Consumes: `Auth0Connection` and `buildAuthorizeUrl()` from Task 1.
- Produces: `beginAuth0Login(connection?: Auth0Connection): Promise<void>`.

- [ ] **Step 1: Use the green URL contract from Task 1 as the regression boundary.**

Run: `cd site && npm test -- src/lib/console/auth/authorize.test.ts`

Expected: PASS, 4 tests. The URL contract already failed before the implementation in Task 1, so this integration refactor must preserve that tested behavior rather than duplicate browser-global tests.

- [ ] **Step 2: Replace inline authorization URL construction in `session.ts`.**

Add this import:

```ts
import { buildAuthorizeUrl, type Auth0Connection } from '$lib/console/auth/authorize';
```

Replace the whole `beginAuth0Login` function with:

```ts
export async function beginAuth0Login(connection?: Auth0Connection): Promise<void> {
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
	const codeChallenge = await challengeFromVerifier(verifier);
	const url = buildAuthorizeUrl({
		domain,
		clientId,
		origin: location.origin,
		codeChallenge,
		audience,
		connection
	});
	location.assign(url.toString());
}
```

Leave `exchangeAuthCode` untouched so authorization and token exchange keep the exact same callback URI.

- [ ] **Step 3: Run the tests and static check.**

Run: `cd site && npm test -- src/lib/console/auth/authorize.test.ts && npm run check`

Expected: URL tests pass and `svelte-check` reports no errors.

- [ ] **Step 4: Commit the session change.**

```bash
git add site/src/lib/console/stores/session.ts site/src/lib/console/auth/authorize.test.ts
git commit -m "feat: select Auth0 social connection at sign-in"
```

### Task 3: Build the dedicated Svelte sign-in route from the supplied design

**Files:**
- Create: `site/src/lib/console/components/FlightdeckSignIn.svelte`
- Create: `site/src/routes/dashboard/sign-in/+layout@.svelte`
- Create: `site/src/routes/dashboard/sign-in/+page.svelte`

**Interfaces:**
- Consumes: `beginAuth0Login(connection?: Auth0Connection)` and `authError` from `session.ts`.
- Produces: `/dashboard/sign-in/`, rendered outside `dashboard/+layout.svelte`.

- [ ] **Step 1: Add a failing source-level regression test for the real provider actions.**

Create `site/src/lib/console/components/FlightdeckSignIn.test.ts`:

```ts
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const source = readFileSync(fileURLToPath(new URL('./FlightdeckSignIn.svelte', import.meta.url)), 'utf8');

describe('FlightdeckSignIn', () => {
	it('uses dedicated Auth0 connections for the two social buttons', () => {
		expect(source).toContain("beginAuth0Login('google-oauth2')");
		expect(source).toContain("beginAuth0Login('github')");
	});

	it('uses generic Auth0 login for email and enterprise SSO', () => {
		expect(source).toContain('beginAuth0Login()');
		expect(source).toContain('Sign in with SSO');
		expect(source).toContain('Continue with email');
	});
});
```

- [ ] **Step 2: Run the component test and verify red.**

Run: `cd site && npm test -- src/lib/console/components/FlightdeckSignIn.test.ts`

Expected: FAIL because the component file does not exist.

- [ ] **Step 3: Implement `FlightdeckSignIn.svelte`.**

Implement the supplied layout as two sections named `left` and `right`, preserving the original panel proportions, red AIR accent, terminal trust card, badges, and `@media (max-width: 880px)` behavior. Use no credentials fields. Use event handlers with this exact logic:

```ts
let pending = $state<'google' | 'github' | 'generic' | null>(null);

function startGoogle() {
	pending = 'google';
	void beginAuth0Login('google-oauth2');
}

function startGitHub() {
	pending = 'github';
	void beginAuth0Login('github');
}

function startGeneric() {
	pending = 'generic';
	void beginAuth0Login();
}
```

The Google, GitHub, SSO, and email buttons call those functions. Each uses `disabled={pending !== null}` and changes its label to `Redirecting…` only when it owns the pending state. Render `authError` in an `aria-live="polite"` message below the controls. The demo chain control is a disabled button with `aria-disabled="true"` and title `Public demo access is not configured yet.` Keep the visual wording from the supplied design while preventing a false action.

Render brand and provider marks with accessible text or project-owned raster assets. Do not add raw secrets, inline external scripts, or hand-drawn replacement icons.

Create `site/src/routes/dashboard/sign-in/+layout@.svelte`:

```svelte
<script lang="ts">
	let { children } = $props();
</script>

{@render children()}
```

Create `site/src/routes/dashboard/sign-in/+page.svelte`:

```svelte
<script lang="ts">
	import { page } from '$app/stores';
	import FlightdeckSignIn from '$lib/console/components/FlightdeckSignIn.svelte';
	import { authError } from '$lib/console/stores/session';

	$effect(() => {
		const error = $page.url.searchParams.get('error');
		if (error) authError.set(error);
	});
</script>

<svelte:head>
	<title>Sign in · Flightdeck · Project AIR</title>
	<meta name="description" content="Sign in to Project AIR Flightdeck." />
	<meta name="robots" content="noindex" />
</svelte:head>

<FlightdeckSignIn />
```

- [ ] **Step 4: Run component and URL tests.**

Run: `cd site && npm test -- src/lib/console/components/FlightdeckSignIn.test.ts src/lib/console/auth/authorize.test.ts`

Expected: PASS, 6 tests.

- [ ] **Step 5: Commit the sign-in page.**

```bash
git add site/src/lib/console/components/FlightdeckSignIn.svelte site/src/lib/console/components/FlightdeckSignIn.test.ts site/src/routes/dashboard/sign-in/+layout@.svelte site/src/routes/dashboard/sign-in/+page.svelte
git commit -m "feat: add Flightdeck sign-in page"
```

### Task 4: Redirect live unauthenticated and locked sessions to sign-in

**Files:**
- Modify: `site/src/routes/dashboard/+layout.svelte`
- Modify: `site/src/lib/console/components/LockScreen.svelte`
- Modify: `site/src/routes/dashboard/auth/callback/+page.svelte`

**Interfaces:**
- Consumes: `sessionToken`, `lockSession()`, `authError`, and the `/dashboard/sign-in/` route.
- Produces: live unauthenticated route protection and a single credential entry point.

- [ ] **Step 1: Add source-level tests for guard and lock redirects.**

Create `site/src/routes/dashboard/sign-in-flow.test.ts`:

```ts
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const read = (relative: string) =>
	readFileSync(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');

	describe('Flightdeck sign-in flow', () => {
	it('redirects a live dashboard without a session to sign-in', () => {
		expect(read('./+layout.svelte')).toContain("goto('/dashboard/sign-in/')");
	});

	it('returns callback failures to sign-in', () => {
		expect(read('./auth/callback/+page.svelte')).toContain("goto(`/dashboard/sign-in/?error=${encodeURIComponent(error)}`)");
	});

	it('does not render credentials inside the lock screen', () => {
		const lockScreen = read('../../lib/console/components/LockScreen.svelte');
		expect(lockScreen).toContain("goto('/dashboard/sign-in/')");
		expect(lockScreen).not.toContain('Continue with passkey');
	});
});
```

- [ ] **Step 2: Run the flow tests and verify red.**

Run: `cd site && npm test -- src/routes/dashboard/sign-in-flow.test.ts`

Expected: FAIL because the guard and redirects are not implemented.

- [ ] **Step 3: Implement the live guard, lock redirect, and callback error handoff.**

In `site/src/routes/dashboard/+layout.svelte`, import `goto`, `onMount`, and `sessionToken`. Add this exact live-only guard:

```ts
onMount(() => {
	if (!isLive) return;
	const unsubscribe = sessionToken.subscribe((token) => {
		if (!token) void goto('/dashboard/sign-in/');
	});
	return unsubscribe;
});
```

In `LockScreen.svelte`, replace the credential-card implementation with an `onMount` subscription that calls `goto('/dashboard/sign-in/')` after `lockSession()` has cleared state. Keep only a short visual transition that says `Session locked. Redirecting to sign-in…`; it must contain no email, password, passkey, or Auth0 button.

In the callback page, add a helper:

```ts
function returnToSignIn(error: string): void {
	authError.set(error);
	void goto(`/dashboard/sign-in/?error=${encodeURIComponent(error)}`);
}
```

Use `returnToSignIn(error)` for authorization errors, a missing code, and token exchange failures. Leave the successful `goto('/dashboard/')` unchanged.

- [ ] **Step 4: Run the full test suite and static checks.**

Run: `cd site && npm test && npm run check`

Expected: PASS for all tests and zero `svelte-check` errors.

- [ ] **Step 5: Commit the protected navigation flow.**

```bash
git add site/src/routes/dashboard/+layout.svelte site/src/lib/console/components/LockScreen.svelte site/src/routes/dashboard/auth/callback/+page.svelte site/src/routes/dashboard/sign-in-flow.test.ts
git commit -m "feat: route Flightdeck sessions through sign-in"
```

### Task 5: Verify the complete route and visual behavior

**Files:**
- Modify only if needed from visual or accessibility findings in Tasks 1 through 4.

**Interfaces:**
- Consumes: completed sign-in component, Auth0 URL builder, and session route guard.
- Produces: verified production-ready static build.

- [ ] **Step 1: Run the full automated gate.**

Run: `cd site && npm test && npm run check && npm run build`

Expected: each command exits with status 0.

- [ ] **Step 2: Run the application locally and inspect exact route states.**

Run: `cd site && npm run dev -- --host 127.0.0.1`

Inspect `/dashboard/sign-in/` at 1440 px and 390 px widths. Confirm the desktop has both panels, the mobile view retains the left sign-in panel, controls have keyboard focus, and reduced motion removes the cursor blink animation.

- [ ] **Step 3: Validate non-secret Auth0 redirect properties.**

Click Google, GitHub, SSO, and email one at a time in a local environment with a disposable Auth0 test client. Confirm the resulting authorization URLs contain only the expected connection value for Google and GitHub, no connection value for SSO and email, and no provider secret or token.

- [ ] **Step 4: Validate callback and lock navigation.**

Confirm a successful callback returns to `/dashboard/`, an Auth0 error returns to `/dashboard/sign-in/?error=...`, and using Lock clears the session before the sign-in route loads.

- [ ] **Step 5: Commit any verification fixes only when tests stay green.**

```bash
git add site
git commit -m "fix: polish Flightdeck sign-in accessibility"
```

## Self-review

- Spec coverage: Tasks 1 and 2 cover Auth0 provider routing and PKCE preservation. Task 3 covers the supplied Svelte visual and responsive layout. Task 4 covers unauthenticated and lock behavior. Task 5 covers static checks, route flow, and visual verification.
- Placeholder scan: no implementation step relies on a TODO, unspecified file, or unspecified command. The public demo control is explicitly disabled because no truthful target has been supplied.
- Type consistency: `Auth0Connection` is defined by Task 1, accepted by `beginAuth0Login` in Task 2, and used only with `google-oauth2` and `github` in Task 3.

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
		expect(read('./auth/callback/+page.svelte')).toContain(
		"goto(`/dashboard/sign-in/?error=${encodeURIComponent(error)}`)"
	);
	});

	it('does not render credentials inside the lock screen', () => {
		const lockScreen = read('../../lib/console/components/LockScreen.svelte');
		expect(lockScreen).toContain("goto('/dashboard/sign-in/')");
		expect(lockScreen).not.toContain('Continue with passkey');
	});
});

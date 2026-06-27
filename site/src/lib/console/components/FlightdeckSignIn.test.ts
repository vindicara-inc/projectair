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

	it('keeps the trust rail free of terminal and identity-pitch clutter', () => {
		expect(source).not.toContain('Bring your identity');
		expect(source).not.toContain('terminal-body');
		expect(source).not.toContain('air verify-intent');
	});

	it('renders a reduced-motion-safe perimeter glow', () => {
		expect(source).toContain('class="rim-glow"');
		expect(source).toContain('@keyframes rim-flow');
		expect(source).toContain('prefers-reduced-motion: reduce');
		expect(source).toContain('rgba(255,255,255,.9)');
		expect(source).not.toContain('rgba(230,57,70,.85)');
	});
});

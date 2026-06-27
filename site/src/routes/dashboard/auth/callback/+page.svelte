<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { authError, exchangeAuthCode, unlock } from '$lib/console/stores/session';

	let message = $state('Completing sign-in…');

	function returnToSignIn(error: string): void {
		authError.set(error);
		void goto(`/dashboard/sign-in/?error=${encodeURIComponent(error)}`);
	}

	onMount(async () => {
		const params = new URLSearchParams(location.search);
		const code = params.get('code');
		const error = params.get('error_description') ?? params.get('error');
		if (error) {
			message = error;
			returnToSignIn(error);
			return;
		}
		if (!code) {
			message = 'Missing authorization code.';
			returnToSignIn(message);
			return;
		}
		try {
			const token = await exchangeAuthCode(code);
			unlock(token);
			goto('/dashboard/');
		} catch (err) {
			message = err instanceof Error ? err.message : 'Sign-in failed.';
			returnToSignIn(message);
		}
	});
</script>

<div class="wrap">
	<p>{message}</p>
	{#if message !== 'Completing sign-in…'}
		<a href="/dashboard/">Return to Flightdeck</a>
	{/if}
</div>

<style>
	.wrap {
		display: grid;
		place-items: center;
		gap: 12px;
		height: 100vh;
		font-family: var(--console-mono);
		color: var(--console-muted);
	}
	a {
		color: #cfe9ff;
	}
</style>

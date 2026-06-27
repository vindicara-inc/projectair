<script lang="ts">
	import { goto } from '$app/navigation';
	import { locked } from '$lib/console/stores/session';

	let isLocked = $state(false);

	$effect(() =>
		locked.subscribe((value) => {
			isLocked = value;
			if (value) void goto('/dashboard/sign-in/');
		})
	);
</script>

{#if isLocked}
	<div class="lock-state" role="status" aria-live="polite">Session locked. Redirecting to sign-in…</div>
{/if}

<style>
	.lock-state {
		position: fixed;
		inset: 0;
		z-index: 60;
		display: grid;
		place-items: center;
		background: #040508;
		color: #ffd0d4;
		font-family: var(--console-mono);
		font-size: 12px;
		letter-spacing: .14em;
		text-transform: uppercase;
	}
</style>

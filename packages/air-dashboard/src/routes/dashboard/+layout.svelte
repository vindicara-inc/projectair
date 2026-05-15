<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { authStore } from '$lib/stores/auth.svelte';
	import { roleStore } from '$lib/stores/role.svelte';
	import Sidebar from '$lib/panels/Sidebar.svelte';
	import { onMount } from 'svelte';

	let { children } = $props();

	const adminRoutes = ['/dashboard/team', '/dashboard/activity', '/dashboard/compliance', '/dashboard/analytics'];

	onMount(() => {
		authStore.init();
	});

	$effect(() => {
		const path = $page.url.pathname;
		if (adminRoutes.some((r) => path.startsWith(r)) && !roleStore.isAdmin) {
			goto('/dashboard/');
		}
	});
</script>

{#if authStore.phase === 'loading'}
	<div class="flex items-center justify-center h-screen bg-zinc-950 text-zinc-500" style="font-family: var(--font-mono);">
		Authenticating...
	</div>
{:else if authStore.phase === 'gate'}
	<div class="flex flex-col items-center justify-center h-screen bg-zinc-950 gap-6">
		<h1 class="text-[48px] font-bold tracking-[0.04em] leading-[0.9] uppercase" style="font-family: var(--font-display); color: var(--color-obsidian, #f8f6f1);">
			Project <span style="color: var(--color-red, #dc2626); text-shadow: 0 0 24px rgba(220,38,38,.4);">AIR</span>
		</h1>
		<p class="text-[11px] tracking-[0.32em] uppercase" style="color: rgba(248,246,241,.45); font-family: var(--font-mono);">
			Forensic Evidence Console
		</p>
		<button
			onclick={() => authStore.login()}
			class="mt-4 px-6 py-3 bg-red-600 text-white text-sm uppercase tracking-wider hover:bg-red-500 transition-colors"
			style="font-family: var(--font-mono);"
		>
			Sign in with Auth0
		</button>
	</div>
{:else}
	<div class="fixed inset-0 z-0 pointer-events-none overflow-hidden">
		<div class="orb absolute w-[600px] h-[600px] -top-40 -left-36" style="background:radial-gradient(circle, rgba(220,38,38,.5) 0%, transparent 70%);"></div>
		<div class="orb absolute w-[680px] h-[680px] -bottom-60 -right-56" style="background:radial-gradient(circle, rgba(180,210,255,.5) 0%, transparent 70%); animation-delay:-12s;"></div>
		<div class="orb absolute w-[420px] h-[420px] top-[38%] left-[42%]" style="background:radial-gradient(circle, rgba(255,180,140,.4) 0%, transparent 70%); animation-delay:-6s;"></div>
	</div>
	<div class="ascii-grid"></div>
	<div class="hud-scanline" aria-hidden="true"></div>
	<Sidebar />
	<main class="ml-14">
		{@render children()}
	</main>
{/if}

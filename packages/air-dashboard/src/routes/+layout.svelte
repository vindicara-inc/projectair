<script lang="ts">
	import '../app.css';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { onMount } from 'svelte';
	import { base } from '$app/paths';
	import { authStore } from '$lib/stores/auth.svelte';
	import { roleStore } from '$lib/stores/role.svelte';
	import { cloudSession } from '$lib/stores/cloud_session.svelte';
	import Sidebar from '$lib/panels/Sidebar.svelte';
	import WelcomeGate from '$lib/panels/WelcomeGate.svelte';

	let { children } = $props();

	const adminRoutes = [`${base}/team`, `${base}/activity`, `${base}/compliance`, `${base}/analytics`];

	onMount(() => {
		authStore.init();
	});

	$effect(() => {
		if (!cloudSession.isConnected) return;
		const path = $page.url.pathname;
		if (adminRoutes.some((r) => path.startsWith(r)) && !roleStore.isAdmin) {
			goto(`${base}/`);
		}
	});
</script>

<svelte:head>
	<meta name="description" content="AIR Cloud: forensic evidence console for instrumented AI agents." />
</svelte:head>

{#if authStore.phase === 'loading'}
	<div class="flex items-center justify-center h-screen bg-zinc-950 text-zinc-500" style="font-family: var(--font-mono);">
		Authenticating...
	</div>
{:else if authStore.phase === 'gate'}
	<WelcomeGate />
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

<script lang="ts">
	import '$lib/console/console.css';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { onMount } from 'svelte';
	import Rail from '$lib/console/components/Rail.svelte';
	import Drawer from '$lib/console/components/Drawer.svelte';
	import LockScreen from '$lib/console/components/LockScreen.svelte';
	import { beginAuth0Login, lockSession, sessionToken, unlock } from '$lib/console/stores/session';
	import { env } from '$env/dynamic/public';

	let { children } = $props();
	let drawerOpen = $state(false);
	const isLive = env.PUBLIC_AIR_API_MODE === 'live';

	onMount(() => {
		if (!isLive) return;
		const unsubscribe = sessionToken.subscribe((token) => {
			if (!token) void goto('/dashboard/sign-in/');
		});
		return unsubscribe;
	});

	function authorize() {
		if (isLive) void beginAuth0Login();
		else unlock();
	}

	const productName = 'Flightdeck';

	const titles: Record<string, { title: string; crumb: string; dept: boolean }> = {
		'/dashboard': { title: productName, crumb: '/ department', dept: true },
		'/dashboard/': { title: productName, crumb: '/ department', dept: true },
		'/dashboard/readiness': { title: 'Buyer readiness', crumb: '/ buyer readiness', dept: false },
		'/dashboard/readiness/': { title: 'Buyer readiness', crumb: '/ buyer readiness', dept: false },
		'/dashboard/rules': { title: 'Rules', crumb: '/ rules', dept: false },
		'/dashboard/rules/': { title: 'Rules', crumb: '/ rules', dept: false },
		'/dashboard/plugins': { title: 'Plugins', crumb: '/ plugins', dept: false },
		'/dashboard/plugins/': { title: 'Plugins', crumb: '/ plugins', dept: false },
		'/dashboard/insurance': { title: 'Insurance API', crumb: '/ insurance API', dept: false },
		'/dashboard/insurance/': { title: 'Insurance API', crumb: '/ insurance API', dept: false },
		'/dashboard/settings': { title: 'Settings', crumb: '/ settings', dept: false },
		'/dashboard/settings/': { title: 'Settings', crumb: '/ settings', dept: false }
	};
	let meta = $derived(
		titles[$page.url.pathname] ?? { title: productName, crumb: $page.url.pathname, dept: false }
	);
	let pageTitle = $derived(
		meta.title === productName
			? `${productName} · Project AIR`
			: `${meta.title} · ${productName} · Project AIR`
	);
</script>

<svelte:head>
	<title>{pageTitle}</title>
	<meta name="description" content="Project AIR Flightdeck: operator dashboard for agent monitoring, enforcement, and evidence." />
	<meta name="robots" content="noindex" />
</svelte:head>

<div class="console-shell" data-theme="dark">
	<div class="aurora"><i></i><i></i><i></i></div>
	<div class="grain"></div>

	<div class="app">
		<Rail />

		<main class="work">
			<div class="wbar reveal">
				<button class="burger" onclick={() => (drawerOpen = true)} aria-label="menu"
					><span></span><span></span><span></span></button
				>
				<h1>{meta.title}</h1><span class="crumb">{meta.crumb}</span>
				{#if meta.dept}<span class="deptTag">Department view</span>{/if}
				<span class="spacer"></span>
				<a href="/" class="siteLink">vindicara.io</a>
				<button class="authbtn" onclick={authorize}><span class="key"></span>Authorize</button>
				<button class="lockbtn" onclick={lockSession}>Lock</button>
				<div class="me">
					<div class="meav"
						><svg viewBox="0 0 64 64"
							><defs
								><linearGradient id="uav0" x1="0" y1="0" x2="1" y2="1"
									><stop offset="0" stop-color="#9b6bff" /><stop offset="1" stop-color="#6db5ff" /></linearGradient
								></defs
							><rect width="64" height="64" fill="url(#uav0)" /><circle
								cx="32"
								cy="25"
								r="11"
								fill="#fff"
								opacity=".92"
							/><path d="M12 56c2-12 11-18 20-18s18 6 20 18z" fill="#fff" opacity=".92" /></svg
						></div
					>
					<div><div class="men">Kevin Minn</div><div class="mer">Founder · root</div></div>
					<span class="melock">passkey</span>
				</div>
			</div>

			{@render children()}
		</main>
	</div>

	<Drawer open={drawerOpen} onclose={() => (drawerOpen = false)} />
	<LockScreen />
</div>

<style>
	.console-shell {
		position: relative;
		min-height: 100vh;
		color: var(--console-ink);
		background: var(--console-bg);
		font-family: var(--console-ui);
	}
	.app {
		position: relative;
		z-index: 2;
		display: grid;
		grid-template-columns: 320px 1fr;
		gap: 18px;
		align-items: start;
		min-height: 100vh;
		padding: 22px;
	}
	.work {
		display: flex;
		flex-direction: column;
		gap: 24px;
		min-width: 0;
	}
	.wbar {
		display: flex;
		align-items: center;
		gap: 14px;
		height: 44px;
	}
	.wbar h1 {
		font-family: var(--console-display);
		font-weight: 600;
		font-size: 25px;
		letter-spacing: -0.02em;
	}
	.crumb {
		color: var(--console-muted);
		font-size: 13px;
	}
	.spacer {
		flex: 1;
	}
	.siteLink {
		font-family: var(--console-mono);
		font-size: 10px;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--console-faint);
		text-decoration: none;
		padding: 6px 10px;
		border: 1px solid var(--console-hair);
		transition: color 0.15s;
	}
	.siteLink:hover {
		color: var(--console-ink);
	}
	.burger {
		width: 38px;
		height: 38px;
		border: 1px solid var(--console-hair);
		background: rgba(255, 255, 255, 0.04);
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 4px;
		cursor: pointer;
		flex: 0 0 38px;
	}
	.burger span {
		display: block;
		width: 16px;
		height: 1.5px;
		background: var(--console-ink);
	}
	.deptTag {
		font-family: var(--console-mono);
		font-size: 9px;
		letter-spacing: 0.1em;
		text-transform: uppercase;
		color: #cdbcff;
		border: 1px solid rgba(155, 107, 255, 0.3);
		background: rgba(155, 107, 255, 0.1);
		padding: 3px 8px;
	}
	.lockbtn {
		padding: 9px 12px;
		border: 1px solid var(--console-hair);
		background: rgba(255, 255, 255, 0.04);
		color: var(--console-muted);
		font-size: 12px;
		cursor: pointer;
	}
	.authbtn {
		display: flex;
		align-items: center;
		gap: 9px;
		padding: 9px 15px;
		border: 1px solid rgba(155, 107, 255, 0.4);
		background: linear-gradient(180deg, rgba(155, 107, 255, 0.22), rgba(155, 107, 255, 0.05));
		color: #e0d3ff;
		font-weight: 600;
		font-size: 13px;
		cursor: pointer;
	}
	.key {
		width: 14px;
		height: 14px;
		border-radius: 3px;
		background: radial-gradient(circle at 30% 30%, #fff, #b69bff);
		box-shadow: 0 0 12px rgba(155, 107, 255, 0.6);
	}
	.me {
		display: flex;
		align-items: center;
		gap: 9px;
		padding: 5px 11px 5px 6px;
		border: 1px solid var(--console-hair);
		background: rgba(255, 255, 255, 0.03);
	}
	.meav {
		width: 28px;
		height: 28px;
		overflow: hidden;
		flex: 0 0 28px;
	}
	.meav svg {
		width: 100%;
		height: 100%;
		display: block;
	}
	.men {
		font-size: 12.5px;
		font-weight: 600;
		line-height: 1.1;
	}
	.mer {
		font-size: 10px;
		color: var(--console-faint);
		margin-top: 1px;
	}
	.melock {
		font-family: var(--console-mono);
		font-size: 8.5px;
		letter-spacing: 0.06em;
		color: #cdbcff;
		border: 1px solid rgba(155, 107, 255, 0.3);
		background: rgba(155, 107, 255, 0.1);
		padding: 2px 6px;
	}
	@media (max-width: 980px) {
		.app {
			grid-template-columns: 1fr;
		}
	}
</style>

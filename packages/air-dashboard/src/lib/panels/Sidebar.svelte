<script lang="ts">
	import { page } from '$app/stores';
	import { roleStore } from '$lib/stores/role.svelte';
	import { cloudSession } from '$lib/stores/cloud_session.svelte';
	import { authStore } from '$lib/stores/auth.svelte';

	let expanded = $state(false);

	const navItems = [
		{ href: '/dashboard/', label: 'Chain', icon: '⬡', adminOnly: false },
		{ href: '/dashboard/team', label: 'Team', icon: '◈', adminOnly: true },
		{ href: '/dashboard/activity', label: 'Activity', icon: '◉', adminOnly: true },
		{ href: '/dashboard/compliance', label: 'Compliance', icon: '⬢', adminOnly: true },
		{ href: '/dashboard/analytics', label: 'Analytics', icon: '△', adminOnly: true },
	];

	const visibleItems = $derived(
		navItems.filter((item) => !item.adminOnly || roleStore.isAdmin)
	);
</script>

<nav
	class="fixed left-0 top-0 h-full bg-zinc-950/95 border-r border-zinc-800/60 z-50 transition-all duration-200 flex flex-col backdrop-blur-sm"
	class:w-14={!expanded}
	class:w-52={expanded}
	onmouseenter={() => (expanded = true)}
	onmouseleave={() => (expanded = false)}
>
	<div class="flex-1 pt-4">
		{#each visibleItems as item}
			<a
				href={item.href}
				class="flex items-center gap-3 px-4 py-3 text-sm transition-colors"
				class:text-red-500={$page.url.pathname === item.href}
				class:text-zinc-400={$page.url.pathname !== item.href}
				class:hover:text-white={true}
			>
				<span class="text-lg w-6 text-center" style="font-family: var(--font-mono);">{item.icon}</span>
				{#if expanded}
					<span class="text-xs tracking-wider uppercase" style="font-family: var(--font-mono);">{item.label}</span>
				{/if}
			</a>
		{/each}
	</div>

	<div class="border-t border-zinc-800/60 p-3">
		{#if expanded}
			<p class="text-xs text-zinc-500 truncate" style="font-family: var(--font-mono);">{cloudSession.workspace?.name ?? ''}</p>
			<p class="text-xs text-zinc-600 truncate" style="font-family: var(--font-mono);">{roleStore.email ?? ''}</p>
			<span class="inline-block mt-1 px-2 py-0.5 text-[10px] uppercase tracking-wider {roleStore.current === 'owner' ? 'bg-red-900/50 text-red-400' : roleStore.current === 'admin' ? 'bg-amber-900/50 text-amber-400' : 'bg-zinc-800 text-zinc-400'}" style="font-family: var(--font-mono);">
				{roleStore.current}
			</span>
			<button
				onclick={() => authStore.logout()}
				class="block mt-3 text-[10px] text-zinc-600 hover:text-zinc-400 uppercase tracking-wider transition-colors"
				style="font-family: var(--font-mono);"
			>
				Sign out
			</button>
		{/if}
	</div>
</nav>

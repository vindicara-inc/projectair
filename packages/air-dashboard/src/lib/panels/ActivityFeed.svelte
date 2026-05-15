<script lang="ts">
	import { onMount } from 'svelte';
	import { cloudSession } from '$lib/stores/cloud_session.svelte';
	import type { AgDRRecord } from '$lib/agdr/types';

	let records = $state<AgDRRecord[]>([]);
	let loading = $state(true);
	let filterAgent = $state('all');

	onMount(async () => {
		if (!cloudSession.client) return;
		try {
			const page = await cloudSession.client.listCapsules({ limit: 1000 });
			records = page.records.slice().reverse();
		} finally {
			loading = false;
		}
	});

	const filtered = $derived(
		records.filter((r) => {
			if (filterAgent !== 'all' && r.signer_key !== filterAgent) return false;
			return true;
		})
	);

	const uniqueAgents = $derived(
		[...new Set(records.map((r) => r.signer_key).filter(Boolean))]
	);

	function truncateKey(key: string): string {
		return key.slice(0, 8) + '...';
	}

	function findingCount(record: AgDRRecord): number {
		const raw = (record as unknown as Record<string, unknown>)['findings'];
		if (!Array.isArray(raw)) return 0;
		return raw.length;
	}

	function previewText(record: AgDRRecord): string {
		return record.payload?.prompt?.slice(0, 80) ?? record.payload?.tool_name ?? '';
	}
</script>

<div class="p-6 max-w-5xl mx-auto">
	<h1
		class="text-xl font-bold text-white mb-6 tracking-wider uppercase"
		style="font-family: var(--font-mono);"
	>
		Activity
	</h1>

	<div class="flex gap-3 mb-6">
		<select
			bind:value={filterAgent}
			class="bg-zinc-900 border border-zinc-700 text-white text-sm px-3 py-2"
			style="font-family: var(--font-mono);"
		>
			<option value="all">All agents</option>
			{#each uniqueAgents as agent}
				<option value={agent}>{truncateKey(agent)}</option>
			{/each}
		</select>
	</div>

	{#if loading}
		<p class="text-zinc-500 text-sm" style="font-family: var(--font-mono);">Loading activity...</p>
	{:else}
		<div class="space-y-0">
			{#each filtered as record}
				{@const count = findingCount(record)}
				<div
					class="flex items-center gap-4 py-2 px-3 border-b border-zinc-800/50 hover:bg-zinc-900/30 text-sm"
					style="font-family: var(--font-mono);"
				>
					<span class="text-zinc-600 text-xs w-40 shrink-0"
						>{record.timestamp?.slice(0, 19) ?? ''}</span
					>
					<span class="text-zinc-400 w-20 shrink-0">{truncateKey(record.signer_key)}</span>
					<span class="px-2 py-0.5 text-xs bg-zinc-800 text-zinc-300 shrink-0">{record.kind}</span>
					<span class="text-zinc-500 flex-1 truncate">{previewText(record)}</span>
					{#if count > 0}
						<span class="px-2 py-0.5 text-xs bg-red-900/50 text-red-400">
							{count}
							{count > 1 ? 'findings' : 'finding'}
						</span>
					{/if}
				</div>
			{/each}
		</div>
		{#if filtered.length === 0}
			<p class="text-zinc-500 text-sm mt-4" style="font-family: var(--font-mono);">
				No activity records found.
			</p>
		{/if}
	{/if}
</div>

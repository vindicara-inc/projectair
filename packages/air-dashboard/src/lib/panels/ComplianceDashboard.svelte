<script lang="ts">
	import { onMount } from 'svelte';
	import { cloudSession } from '$lib/stores/cloud_session.svelte';
	import type { ComplianceSummary } from '$lib/transport/air_cloud_client';
	import ComplianceCard from './ComplianceCard.svelte';

	let summary = $state<ComplianceSummary | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	onMount(async () => {
		if (!cloudSession.client) return;
		try {
			summary = await cloudSession.client.complianceSummary();
		} catch (err) {
			error = err instanceof Error ? err.message : String(err);
		} finally {
			loading = false;
		}
	});
</script>

<div class="p-6 max-w-4xl mx-auto">
	<h1
		class="text-xl font-bold text-white mb-6 tracking-wider uppercase"
		style="font-family: var(--font-mono);"
	>
		Compliance
	</h1>

	{#if loading}
		<p class="text-zinc-500 text-sm" style="font-family: var(--font-mono);">
			Loading compliance data...
		</p>
	{:else if error}
		<p class="text-red-400 text-sm" style="font-family: var(--font-mono);">{error}</p>
	{:else if summary}
		<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
			{#each summary.frameworks as framework}
				<ComplianceCard {framework} />
			{/each}
		</div>
	{/if}
</div>

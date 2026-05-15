<script lang="ts">
	import { onMount } from 'svelte';
	import { cloudSession } from '$lib/stores/cloud_session.svelte';
	import type { AnalyticsSummary } from '$lib/transport/air_cloud_client';

	let data = $state<AnalyticsSummary | null>(null);
	let loading = $state(true);
	let error = $state<string | null>(null);

	onMount(async () => {
		if (!cloudSession.client) return;
		try {
			data = await cloudSession.client.analyticsSummary();
		} catch (err) {
			error = err instanceof Error ? err.message : String(err);
		} finally {
			loading = false;
		}
	});

	const sortedDetectors = $derived(
		data ? Object.entries(data.detector_counts).sort((a, b) => b[1] - a[1]) : []
	);

	const maxDetectorCount = $derived(
		sortedDetectors.length > 0 ? (sortedDetectors[0]?.[1] ?? 1) : 1
	);

	const healthTotal = $derived(
		data
			? data.chain_health.verified + data.chain_health.tampered + data.chain_health.broken_link
			: 1
	);
</script>

<div class="p-6 max-w-5xl mx-auto">
	<h1
		class="text-xl font-bold text-white mb-6 tracking-wider uppercase"
		style="font-family: var(--font-mono);"
	>
		Analytics
	</h1>

	{#if loading}
		<p class="text-zinc-500 text-sm" style="font-family: var(--font-mono);">
			Loading analytics...
		</p>
	{:else if error}
		<p class="text-red-400 text-sm" style="font-family: var(--font-mono);">{error}</p>
	{:else if data}
		<!-- Headline stats -->
		<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
			{#each [
				{ label: 'Total Capsules', value: data.total_capsules.toLocaleString() },
				{ label: 'This Week', value: data.capsules_this_week.toLocaleString() },
				{ label: 'Unique Agents', value: data.unique_agents.toString() },
				{ label: 'Active Members', value: data.active_members.toString() },
			] as stat}
				<div class="border border-zinc-800 bg-zinc-950/80 p-4">
					<p
						class="text-xs text-zinc-500 uppercase tracking-wider"
						style="font-family: var(--font-mono);"
					>
						{stat.label}
					</p>
					<p class="text-2xl font-bold text-white mt-1" style="font-family: var(--font-mono);">
						{stat.value}
					</p>
				</div>
			{/each}
		</div>

		<!-- Detector triggers -->
		{#if sortedDetectors.length > 0}
			<h2
				class="text-sm font-bold text-white mb-3 tracking-wider uppercase"
				style="font-family: var(--font-mono);"
			>
				Detector Triggers
			</h2>
			<div class="space-y-2 mb-8">
				{#each sortedDetectors as [detector, count]}
					<div class="flex items-center gap-3">
						<span
							class="text-xs text-zinc-400 w-16 shrink-0"
							style="font-family: var(--font-mono);">{detector}</span
						>
						<div class="flex-1 h-5 bg-zinc-900 relative">
							<div
								class="h-full bg-red-600/70"
								style="width: {(count / maxDetectorCount) * 100}%"
							></div>
						</div>
						<span
							class="text-xs text-zinc-500 w-12 text-right"
							style="font-family: var(--font-mono);">{count}</span
						>
					</div>
				{/each}
			</div>
		{/if}

		<!-- Chain health -->
		<h2
			class="text-sm font-bold text-white mb-3 tracking-wider uppercase"
			style="font-family: var(--font-mono);"
		>
			Chain Health
		</h2>
		<div class="flex gap-4 mb-8">
			<div class="flex items-center gap-2">
				<span class="w-3 h-3 rounded-full bg-green-500"></span>
				<span class="text-xs text-zinc-400" style="font-family: var(--font-mono);"
					>Verified: {data.chain_health.verified} ({healthTotal > 0
						? Math.round((data.chain_health.verified / healthTotal) * 100)
						: 0}%)</span
				>
			</div>
			<div class="flex items-center gap-2">
				<span class="w-3 h-3 rounded-full bg-red-500"></span>
				<span class="text-xs text-zinc-400" style="font-family: var(--font-mono);"
					>Tampered: {data.chain_health.tampered}</span
				>
			</div>
			<div class="flex items-center gap-2">
				<span class="w-3 h-3 rounded-full bg-amber-500"></span>
				<span class="text-xs text-zinc-400" style="font-family: var(--font-mono);"
					>Broken: {data.chain_health.broken_link}</span
				>
			</div>
		</div>

		<!-- Daily ingestion -->
		{#if data.daily_ingestion.length > 0}
			<h2
				class="text-sm font-bold text-white mb-3 tracking-wider uppercase"
				style="font-family: var(--font-mono);"
			>
				Daily Ingestion (30d)
			</h2>
			<div class="flex items-end gap-1 h-32">
				{#each data.daily_ingestion.slice().reverse() as day}
					{@const maxDay = Math.max(...data.daily_ingestion.map((d) => d.count), 1)}
					<div class="flex-1 flex flex-col items-center justify-end">
						<div
							class="w-full bg-red-600/50 min-h-[2px]"
							style="height: {(day.count / maxDay) * 100}%"
							title="{day.date}: {day.count}"
						></div>
					</div>
				{/each}
			</div>
		{/if}
	{/if}
</div>

<script lang="ts">
	import type { FrameworkScore } from '$lib/transport/air_cloud_client';

	let { framework }: { framework: FrameworkScore } = $props();
	let expanded = $state(false);

	const statusColor = $derived(
		framework.coverage_pct >= 80
			? 'text-green-400 bg-green-900/30'
			: framework.coverage_pct >= 50
				? 'text-amber-400 bg-amber-900/30'
				: 'text-red-400 bg-red-900/30'
	);

	const statusLabel = $derived(
		framework.coverage_pct >= 80
			? 'compliant'
			: framework.coverage_pct >= 50
				? 'partial'
				: 'insufficient'
	);
</script>

<div class="border border-zinc-800 bg-zinc-950/80 p-4">
	<button onclick={() => (expanded = !expanded)} class="w-full text-left">
		<div class="flex items-center justify-between mb-2">
			<h3
				class="text-sm font-bold text-white tracking-wider"
				style="font-family: var(--font-mono);"
			>
				{framework.name}
			</h3>
			<span
				class="px-2 py-0.5 text-[10px] uppercase tracking-wider {statusColor}"
				style="font-family: var(--font-mono);"
			>
				{statusLabel}
			</span>
		</div>
		<div
			class="flex items-center gap-4 text-xs text-zinc-400"
			style="font-family: var(--font-mono);"
		>
			<span>{framework.met_controls}/{framework.total_controls} controls met</span>
			<span>{framework.coverage_pct}%</span>
		</div>
	</button>

	{#if expanded}
		<div class="mt-4 border-t border-zinc-800 pt-3 space-y-2">
			{#each framework.controls as ctrl}
				<div
					class="flex items-center justify-between text-xs py-1"
					style="font-family: var(--font-mono);"
				>
					<div class="flex items-center gap-2">
						<span
							class="w-2 h-2 rounded-full {ctrl.met ? 'bg-green-500' : 'bg-red-500'}"
						></span>
						<span class="text-zinc-400">{ctrl.control_id}</span>
						<span class="text-zinc-300">{ctrl.control_name}</span>
					</div>
					<span class="text-zinc-500">{ctrl.evidence_count}/{ctrl.required}</span>
				</div>
			{/each}
		</div>
	{/if}
</div>

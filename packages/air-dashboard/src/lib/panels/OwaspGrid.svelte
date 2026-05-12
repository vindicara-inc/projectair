<script lang="ts">
	import { DETECTOR_SWARM } from '$lib/detectors';
	import { findingsStore } from '$lib/stores/findings.svelte';

	const allIds = ['ASI01','ASI02','ASI03','ASI04','ASI05','ASI06','ASI07','ASI08','ASI09','ASI10'] as const;

	const activeIds = $derived(new Set(DETECTOR_SWARM.map((d) => d.id)));
	const triggeredIds = $derived(new Set(findingsStore.all.map((f) => f.detector_id)));

	function cellStyle(id: string): string {
		if (triggeredIds.has(id)) {
			return 'background:rgba(255,84,104,.15); border:1px solid rgba(255,84,104,.4); color:var(--color-critical);';
		}
		if (activeIds.has(id)) {
			return 'background:rgba(110,255,179,.15); border:1px solid rgba(110,255,179,.35); color:var(--color-terminal-green);';
		}
		return 'background:rgba(255,181,71,.15); border:1px solid rgba(255,181,71,.35); color:var(--color-high);';
	}

	const implementedCount = $derived(activeIds.size);
	const partialIds = $derived(allIds.filter((id) => !activeIds.has(id)));
</script>

<div>
	<div class="module-label"><span class="id">MOD.05</span> OWASP Coverage</div>
	<div class="obsidian">
		<span class="sweep"></span>
		<div class="reactor"></div>
		<div class="relative z-[5] p-5">
			<div class="flex items-center justify-between mb-4">
				<span class="text-xs font-bold tracking-[0.22em] uppercase" style="font-family:var(--font-display); color:var(--color-white);">Agentic Top 10</span>
				<span class="text-[9px] tracking-[0.18em] uppercase" style="color:var(--color-red);">10/10</span>
			</div>
			<div class="grid grid-cols-5 gap-1.5">
				{#each allIds as id, i}
					<div
						class="aspect-square flex items-center justify-center text-[10px] font-bold"
						style="{cellStyle(id)} font-family:var(--font-mono);"
					>
						{String(i + 1).padStart(2, '0')}
					</div>
				{/each}
			</div>
			<div class="mt-3.5 text-[9px] tracking-[0.18em] uppercase leading-relaxed" style="color:var(--color-white-3);">
				{implementedCount} BROWSER-ACTIVE · {10 - implementedCount} BACKEND-ONLY<br/>
				{#if partialIds.length > 0}
					<span style="color:var(--color-red);">{partialIds.join(' / ')}</span> REQUIRE LIVE MODE
				{/if}
			</div>
		</div>
	</div>
</div>

<script lang="ts">
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { replayStore } from '$lib/stores/replay.svelte';

	const eligibleCount = $derived(
		verifierStore.entries.filter((e) => e.status === 'ok').length
	);
	const totalCount = $derived(replayStore.records.length);
	const integrity = $derived(verifierStore.integrityScore);
</script>

<footer
	class="hud-rail flex items-center justify-between px-6 py-1.5 border-t border-[var(--color-panel-edge)] text-[10px]"
>
	<div class="flex items-center gap-6">
		<span class="hud-label">EU AI ACT ART. 72 · POST-MARKET MONITORING</span>
		<span class="hud-readout">
			{eligibleCount} of {totalCount} capsules · evidence-eligible
		</span>
	</div>
	<div class="flex items-center gap-3">
		<span class="hud-tick text-[var(--color-bone-faint)]">CHAIN INTEGRITY</span>
		<span
			class="hud-readout"
			style:color={integrity === 100
				? 'var(--color-cyan)'
				: integrity >= 75
					? 'var(--color-amber)'
					: 'var(--color-alert)'}
		>
			{integrity}%
		</span>
	</div>
</footer>

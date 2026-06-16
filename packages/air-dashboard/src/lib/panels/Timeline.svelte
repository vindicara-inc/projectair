<script lang="ts">
	import { replayStore } from '$lib/stores/replay.svelte';
	import { focusStore } from '$lib/stores/focus.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { findingsStore } from '$lib/stores/findings.svelte';

	function statusColor(index: number): string {
		const entry = verifierStore.entries[index];
		if (!entry) return 'var(--color-obsidian-edge)';
		if (entry.status !== 'ok') return 'var(--color-alert)';
		if (findingsStore.forStep(index).length > 0) return 'var(--color-red)';
		return 'var(--color-cyan)';
	}
</script>

<section class="hud-rail px-6 py-2 border-t border-[var(--color-panel-edge)]">
	<div class="flex items-center gap-4">
		<span class="hud-label">TIMELINE</span>
		<div class="flex-1 flex items-stretch gap-px">
			{#each replayStore.records as _record, index}
				{@const isEmitted = index <= replayStore.currentIndex}
				{@const isFocused = focusStore.manualIndex === index}
				<button
					class="flex-1 h-6 transition-colors"
					style:background-color={isEmitted ? statusColor(index) : 'var(--color-obsidian-edge)'}
					style:opacity={isEmitted ? 1 : 0.4}
					style:outline={isFocused ? '2px solid var(--color-bone)' : 'none'}
					title="step {index} · {_record.kind}"
					onclick={() => focusStore.select(index)}
					aria-label="focus step {index}"
				></button>
			{/each}
		</div>
		<span class="hud-tick text-[var(--color-bone-faint)] tabular-nums">
			{Math.max(replayStore.currentIndex + 1, 0).toString().padStart(2, '0')}/{replayStore.records.length.toString().padStart(2, '0')}
		</span>
	</div>
</section>

<script lang="ts">
	import { findingsStore } from '$lib/stores/findings.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { replayStore } from '$lib/stores/replay.svelte';

	interface ConsoleLine {
		text: string;
		severity: 'info' | 'finding' | 'tamper';
	}

	const lines = $derived.by<ConsoleLine[]>(() => {
		const out: ConsoleLine[] = [];
		for (const entry of verifierStore.entries) {
			if (entry.status === 'tampered' || entry.status === 'broken_link') {
				out.push({
					text: `${entry.kind.padEnd(13, ' ')} step ${entry.index.toString().padStart(2, '0')} · CHAIN INTEGRITY BREACH · ${entry.reason ?? 'verifier halt'}`,
					severity: 'tamper'
				});
			}
		}
		for (const finding of findingsStore.all) {
			out.push({
				text: `${finding.detector_id.padEnd(7, ' ')} ${finding.severity.toUpperCase().padEnd(8, ' ')} step ${finding.step_index.toString().padStart(2, '0')} · ${finding.title}`,
				severity: 'finding'
			});
		}
		if (out.length === 0 && replayStore.records.length > 0) {
			out.push({
				text: `chain quiet · ${verifierStore.entries.length} of ${replayStore.records.length} capsules verified`,
				severity: 'info'
			});
		}
		return out;
	});
</script>

<section class="hud-rail border-t border-[var(--color-panel-edge)] px-6 py-2 max-h-32 overflow-y-auto">
	<header class="hud-label mb-1">WATCHER CONSOLE</header>
	{#if lines.length === 0}
		<p class="hud-tick text-[var(--color-bone-faint)]">awaiting forensic chain · pick a scenario above</p>
	{:else}
		<ul class="text-[10px] font-mono leading-snug">
			{#each lines as line}
				<li
					style:color={line.severity === 'tamper'
						? 'var(--color-alert)'
						: line.severity === 'finding'
							? 'var(--color-amber)'
							: 'var(--color-bone-dim)'}
				>
					› {line.text}
				</li>
			{/each}
		</ul>
	{/if}
</section>

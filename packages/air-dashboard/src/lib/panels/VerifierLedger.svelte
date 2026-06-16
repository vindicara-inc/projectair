<script lang="ts">
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { focusStore } from '$lib/stores/focus.svelte';
	import { replayStore } from '$lib/stores/replay.svelte';
	import { glyphSvg } from '$lib/capsules/glyph';
</script>

<section class="hud-rail p-4 overflow-y-auto h-full">
	<header class="hud-bracket pb-2 mb-3">
		<span class="hud-label">VERIFIER LEDGER</span>
	</header>
	{#if verifierStore.entries.length === 0}
		<p class="text-xs text-[var(--color-bone-faint)]">No capsules verified yet.</p>
	{:else}
		<ul class="space-y-1 text-[11px] font-mono">
			{#each verifierStore.entries as entry}
				{@const record = replayStore.emitted[entry.index]}
				<li>
					<button
						class="w-full text-left flex items-center gap-2 px-2 py-1
							   hover:bg-[var(--color-obsidian-edge)]"
						onclick={() => focusStore.select(entry.index)}
					>
						<span class="hud-tick w-6 text-right">{String(entry.index).padStart(2, '0')}</span>
						<span
							class="w-2 h-2 shrink-0"
							style:background-color={entry.status === 'ok'
								? 'var(--color-cyan)'
								: 'var(--color-alert)'}
						></span>
						{#if record}
							<span class="shrink-0">
								{@html glyphSvg(record.content_hash, { pixel: 3, margin: 0 })}
							</span>
						{/if}
						<span class="text-[var(--color-bone-dim)] uppercase tracking-wider">{entry.kind}</span>
						<span class="hud-readout text-[var(--color-bone-faint)] ml-auto">{entry.contentHashShort}</span>
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</section>

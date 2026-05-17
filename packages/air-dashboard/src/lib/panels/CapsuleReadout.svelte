<script lang="ts">
	import { replayStore } from '$lib/stores/replay.svelte';
	import { focusStore } from '$lib/stores/focus.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { findingsStore } from '$lib/stores/findings.svelte';
	import { glyphSvg } from '$lib/capsules/glyph';

	const focused = $derived(focusStore.resolve(replayStore.emitted, replayStore.currentIndex));
	const ledgerEntry = $derived(
		focused.index >= 0 ? verifierStore.entries[focused.index] ?? null : null
	);
	const findings = $derived(focused.index >= 0 ? findingsStore.forStep(focused.index) : []);
</script>

<aside class="hud-rail p-4 overflow-y-auto h-full">
	<header class="hud-bracket pb-2 mb-3">
		<span class="hud-label">CAPSULE READOUT</span>
	</header>

	{#if !focused.record}
		<p class="text-xs text-[var(--color-bone-faint)]">No capsule selected. Press ▸ PLAY to begin.</p>
	{:else}
		<dl class="text-xs space-y-2">
			<div>
				<dt class="hud-label">STEP INDEX</dt>
				<dd class="hud-readout">{focused.index}</dd>
			</div>
			<div>
				<dt class="hud-label">KIND</dt>
				<dd class="hud-readout">{focused.record.kind}</dd>
			</div>
			<div>
				<dt class="hud-label">STEP ID</dt>
				<dd class="hud-readout break-all">{focused.record.step_id}</dd>
			</div>
			<div>
				<dt class="hud-label">TIMESTAMP</dt>
				<dd class="hud-readout">{focused.record.timestamp}</dd>
			</div>
			<div>
				<dt class="hud-label">PREV HASH</dt>
				<dd class="hud-readout text-[var(--color-bone-faint)] break-all">
					{focused.record.prev_hash.slice(0, 32)}…
				</dd>
			</div>
			<div>
				<dt class="hud-label">CONTENT HASH</dt>
				<dd class="hud-readout break-all">
					{focused.record.content_hash.slice(0, 32)}…
				</dd>
				<dd class="mt-2 inline-block border border-[var(--color-panel-edge)] p-1 bg-[var(--color-obsidian)]">
					{@html glyphSvg(focused.record.content_hash, { pixel: 7, margin: 1 })}
				</dd>
			</div>
			<div>
				<dt class="hud-label">SIGNER KEY</dt>
				<dd class="hud-readout text-[var(--color-bone-faint)] break-all">
					{focused.record.signer_key.slice(0, 32)}…
				</dd>
			</div>

			{#if ledgerEntry}
				<div>
					<dt class="hud-label">VERIFICATION</dt>
					<dd
						class="hud-readout"
						class:text-cyan={ledgerEntry.status === 'ok'}
						class:text-alert={ledgerEntry.status !== 'ok'}
						style:color={ledgerEntry.status === 'ok' ? 'var(--color-cyan)' : 'var(--color-alert)'}
					>
						{ledgerEntry.status.toUpperCase()}
					</dd>
					{#if ledgerEntry.reason}
						<dd class="text-[var(--color-alert)] mt-1">{ledgerEntry.reason}</dd>
					{/if}
				</div>
			{/if}
		</dl>

		<section class="mt-4">
			<header class="hud-label mb-2">PAYLOAD</header>
			<pre class="text-[10px] leading-snug text-[var(--color-bone)] whitespace-pre-wrap break-words bg-[var(--color-obsidian-elev)] p-3 border border-[var(--color-panel-edge)]">{JSON.stringify(
					focused.record.payload,
					null,
					2
				)}</pre>
		</section>

		{#if findings.length > 0}
			<section class="mt-4">
				<header class="hud-label mb-2">FINDINGS ({findings.length})</header>
				<ul class="space-y-2">
					{#each findings as finding}
						<li class="border-l-2 border-[var(--color-alert)] pl-3">
							<div class="flex items-baseline justify-between">
								<span class="hud-readout text-[var(--color-alert)]">{finding.detector_id}</span>
								<span class="hud-tick">{finding.severity}</span>
							</div>
							<p class="text-[var(--color-bone-dim)] mt-1">{finding.title}</p>
							<p class="text-[10px] text-[var(--color-bone-faint)] mt-1">{finding.description}</p>
						</li>
					{/each}
				</ul>
			</section>
		{/if}
	{/if}
</aside>

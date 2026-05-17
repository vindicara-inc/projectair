<script lang="ts">
	import { replayStore } from '$lib/stores/replay.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { findingsStore } from '$lib/stores/findings.svelte';
	import { focusStore } from '$lib/stores/focus.svelte';

	function exportEvidence(): void {
		if (replayStore.records.length === 0) return;
		const lines = replayStore.records.map((r) => JSON.stringify(r));
		const blob = new Blob([lines.join('\n') + '\n'], { type: 'application/x-ndjson' });
		const url = URL.createObjectURL(blob);
		const link = document.createElement('a');
		link.href = url;
		link.download = `${replayStore.scenarioId ?? 'evidence'}.jsonl`;
		document.body.appendChild(link);
		link.click();
		document.body.removeChild(link);
		URL.revokeObjectURL(url);
	}

	function statusFor(index: number): 'pending' | 'ok' | 'tampered' | 'broken_link' {
		const entry = verifierStore.entries[index];
		return entry?.status ?? 'pending';
	}

	function findingsFor(index: number): number {
		return findingsStore.forStep(index).length;
	}
</script>

<section class="absolute inset-0 overflow-y-auto p-6 bg-[var(--color-obsidian)]">
	<header class="hud-bracket pb-4 mb-6">
		<span class="hud-label block">TACTICAL MODE</span>
		<p class="text-xs text-[var(--color-bone-dim)] mt-2">
			3D scene suspended for narrow viewport or reduced-motion preference.
			Forensic chain rendered as table. Verification, findings, and chain integrity unchanged.
		</p>
	</header>

	<div class="flex flex-wrap items-center gap-4 mb-6">
		<div>
			<span class="hud-label block">CAPSULES</span>
			<span class="hud-readout text-lg">
				{verifierStore.entries.length}/{replayStore.records.length}
			</span>
		</div>
		<div>
			<span class="hud-label block">INTEGRITY</span>
			<span
				class="hud-readout text-lg"
				style:color={verifierStore.integrityScore === 100
					? 'var(--color-cyan)'
					: 'var(--color-alert)'}
			>
				{verifierStore.integrityScore}%
			</span>
		</div>
		<div>
			<span class="hud-label block">FINDINGS</span>
			<span class="hud-readout text-lg text-[var(--color-alert)]">
				{findingsStore.all.length}
			</span>
		</div>
		<div class="ml-auto">
			<button
				class="px-4 py-2 border border-[var(--color-cyan)] text-[var(--color-cyan)]
					   hover:bg-[var(--color-cyan-deep)] hover:text-[var(--color-bone)]
					   text-xs font-bold tracking-wider"
				onclick={exportEvidence}
				disabled={replayStore.records.length === 0}
			>
				EXPORT EVIDENCE (.jsonl)
			</button>
		</div>
	</div>

	<table class="w-full text-xs border-collapse">
		<thead>
			<tr class="border-b border-[var(--color-panel-edge)]">
				<th class="hud-label text-left p-2">#</th>
				<th class="hud-label text-left p-2">KIND</th>
				<th class="hud-label text-left p-2">CONTENT HASH</th>
				<th class="hud-label text-left p-2">VERIFIED</th>
				<th class="hud-label text-left p-2">FINDINGS</th>
			</tr>
		</thead>
		<tbody>
			{#each replayStore.emitted as record, index}
				{@const verifyStatus = statusFor(index)}
				{@const findingCount = findingsFor(index)}
				<tr
					class="border-b border-[var(--color-panel-edge)] hover:bg-[var(--color-obsidian-edge)]
						   cursor-pointer"
					class:bg-[var(--color-obsidian-edge)]={focusStore.manualIndex === index}
					tabindex="0"
					role="button"
					onclick={() => focusStore.select(index)}
					onkeydown={(e) => {
						if (e.key === 'Enter' || e.key === ' ') focusStore.select(index);
					}}
				>
					<td class="hud-tick p-2">{String(index).padStart(2, '0')}</td>
					<td class="hud-readout p-2 uppercase tracking-wider">{record.kind}</td>
					<td class="p-2 text-[var(--color-bone-faint)] font-mono">
						{record.content_hash.slice(0, 24)}…
					</td>
					<td class="p-2">
						<span
							style:color={verifyStatus === 'ok'
								? 'var(--color-cyan)'
								: 'var(--color-alert)'}
						>
							{verifyStatus.toUpperCase()}
						</span>
					</td>
					<td class="p-2">
						{#if findingCount > 0}
							<span class="text-[var(--color-alert)]">{findingCount}</span>
						{:else}
							<span class="text-[var(--color-bone-faint)]">—</span>
						{/if}
					</td>
				</tr>
				{#if focusStore.manualIndex === index}
					<tr class="bg-[var(--color-obsidian-elev)]">
						<td colspan="5" class="p-3">
							<pre class="text-[10px] text-[var(--color-bone)] whitespace-pre-wrap break-words">{JSON.stringify(
									record.payload,
									null,
									2
								)}</pre>
							{#each findingsStore.forStep(index) as finding}
								<div class="mt-2 border-l-2 border-[var(--color-alert)] pl-3">
									<div class="hud-readout text-[var(--color-alert)]">
										{finding.detector_id} · {finding.severity.toUpperCase()}
									</div>
									<div class="text-[var(--color-bone-dim)]">{finding.title}</div>
									<div class="text-[10px] text-[var(--color-bone-faint)]">{finding.description}</div>
								</div>
							{/each}
						</td>
					</tr>
				{/if}
			{:else}
				<tr>
					<td colspan="5" class="p-6 text-center text-[var(--color-bone-faint)]">
						No capsules emitted yet. Pick a scenario and press ▸ PLAY.
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</section>

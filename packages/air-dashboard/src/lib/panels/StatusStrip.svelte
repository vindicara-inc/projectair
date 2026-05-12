<script lang="ts">
	import { replayStore } from '$lib/stores/replay.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { findingsStore } from '$lib/stores/findings.svelte';

	const now = $derived(new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC');
	const alertCount = $derived(findingsStore.bySeverity().critical.length);
</script>

<div class="status-strip">
	<div class="flex items-center gap-2">
		<span class="w-1.5 h-1.5 rounded-full" style="background:var(--color-terminal-green); box-shadow:0 0 8px var(--color-terminal-green); animation:blink 2s infinite;"></span>
		SYS ONLINE
	</div>
	<div class="flex items-center gap-2">
		<span class="w-1.5 h-1.5 rounded-full" style="background:var(--color-terminal-green); box-shadow:0 0 8px var(--color-terminal-green);"></span>
		SIGSTORE REKOR
	</div>
	<div class="flex items-center gap-2">
		<span class="w-1.5 h-1.5 rounded-full" style="background:var(--color-terminal-green); box-shadow:0 0 8px var(--color-terminal-green);"></span>
		AUTH0 ACTIVE
	</div>
	{#if alertCount > 0}
		<div class="flex items-center gap-2">
			<span class="w-1.5 h-1.5 rounded-full" style="background:var(--color-critical); box-shadow:0 0 8px var(--color-critical); animation:blink 1s infinite;"></span>
			{alertCount} ALERT{alertCount > 1 ? 'S' : ''}
		</div>
	{/if}
	<div class="flex-1"></div>
	<div style="color:var(--color-red);">PROJECT AIR · 0.8.1</div>
	<div>CAPSULES {replayStore.emitted.length}/{replayStore.records.length} · INTEGRITY {verifierStore.integrityScore}%</div>
</div>

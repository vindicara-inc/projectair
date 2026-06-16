<script lang="ts">
	import { replayStore } from '$lib/stores/replay.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { audioStore } from '$lib/stores/audio.svelte';
	import { unlockAudio, startAmbient, stopAmbient } from '$lib/audio/tones';

	async function toggleAudio(): Promise<void> {
		if (audioStore.enabled) {
			audioStore.disable();
			stopAmbient();
		} else {
			audioStore.enable();
			await unlockAudio();
			startAmbient();
		}
	}

	let nowUtc = $state(new Date().toISOString().slice(11, 19));

	$effect(() => {
		const handle = setInterval(() => {
			nowUtc = new Date().toISOString().slice(11, 19);
		}, 1000);
		return () => clearInterval(handle);
	});

	const integrityClass = $derived.by(() => {
		const score = verifierStore.integrityScore;
		if (score === 100) return 'text-[var(--color-cyan)]';
		if (score >= 75) return 'text-[var(--color-red)]';
		return 'text-[var(--color-alert)]';
	});
</script>

<header class="hud-rail flex items-center justify-between px-6 py-3 gap-8">
	<div class="flex items-center gap-8">
		<div class="flex items-baseline gap-2">
			<span class="hud-label">AIR HUD</span>
			<span class="hud-tick">v0.0.1</span>
		</div>
		<div class="flex items-baseline gap-2">
			<span class="hud-label">UTC</span>
			<span class="hud-readout text-xs">{nowUtc}</span>
		</div>
		<div class="flex items-baseline gap-2">
			<span class="hud-label">SCENARIO</span>
			<span class="hud-readout text-xs">{replayStore.scenarioId ?? 'idle'}</span>
		</div>
	</div>
	<div class="flex items-center gap-8">
		<div class="flex items-baseline gap-2">
			<span class="hud-label">CAPSULES</span>
			<span class="hud-readout text-xs">
				{verifierStore.entries.length}/{replayStore.records.length}
			</span>
		</div>
		<div class="flex items-baseline gap-2">
			<span class="hud-label">INTEGRITY</span>
			<span class="hud-readout text-xs {integrityClass}">{verifierStore.integrityScore}%</span>
		</div>
		<button
			class="hud-label px-3 py-1 border border-[var(--color-panel-edge)] hover:bg-[var(--color-obsidian-edge)]"
			onclick={toggleAudio}
			aria-pressed={audioStore.enabled}
		>
			AUDIO {audioStore.enabled ? 'ON' : 'OFF'}
		</button>
	</div>
</header>

<script lang="ts">
	import { DETECTOR_SCENARIOS, SCENARIOS, loadScenario } from '$lib/capsules/loader';
	import { replayStore } from '$lib/stores/replay.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { findingsStore } from '$lib/stores/findings.svelte';
	import { focusStore } from '$lib/stores/focus.svelte';

	interface ButtonSpec {
		id: string;
		label: string;
		active: boolean;
		dormantReason?: string;
	}

	const BUTTONS: ButtonSpec[] = [
		{ id: 'ASI01', label: 'ASI01', active: false, dormantReason: 'fuzzy token-overlap (backend)' },
		{ id: 'ASI02', label: 'ASI02', active: true },
		{ id: 'ASI03', label: 'ASI03', active: false, dormantReason: 'registry attribution (backend)' },
		{ id: 'ASI04', label: 'ASI04', active: false, dormantReason: 'MCP naming (backend)' },
		{ id: 'ASI05', label: 'ASI05', active: true },
		{ id: 'ASI06', label: 'ASI06', active: false, dormantReason: 'memory-tool semantics (backend)' },
		{ id: 'ASI07', label: 'ASI07', active: false, dormantReason: 'inter-agent comms (backend)' },
		{ id: 'ASI08', label: 'ASI08', active: false, dormantReason: 'sliding-window stats (backend)' },
		{ id: 'ASI09', label: 'ASI09', active: false, dormantReason: 'manipulation NLP (backend)' },
		{ id: 'ASI10', label: 'ASI10', active: true },
		{ id: 'AIR-01', label: 'AIR·01', active: false, dormantReason: 'injection patterns (backend)' },
		{ id: 'AIR-02', label: 'AIR·02', active: true },
		{ id: 'AIR-03', label: 'AIR·03', active: false, dormantReason: 'burst-window stats (backend)' },
		{ id: 'AIR-04', label: 'AIR·04', active: true }
	];

	let loadingId: string | null = $state(null);
	let lastError: string | null = $state(null);

	async function injectScenario(detectorId: string): Promise<void> {
		const scenario = DETECTOR_SCENARIOS[detectorId];
		if (!scenario) return;
		loadingId = detectorId;
		lastError = null;
		try {
			const records = await loadScenario({
				id: scenario.detectorId.toLowerCase(),
				label: scenario.detectorId,
				description: scenario.headline,
				path: scenario.scenarioPath
			});
			verifierStore.reset();
			findingsStore.reset();
			focusStore.clear();
			replayStore.load(records, scenario.detectorId);
			replayStore.play();
		} catch (cause) {
			lastError = (cause as Error).message;
		} finally {
			loadingId = null;
		}
	}

	async function loadGeneralScenario(scenarioId: string): Promise<void> {
		const s = SCENARIOS.find((x) => x.id === scenarioId);
		if (!s) return;
		loadingId = scenarioId;
		lastError = null;
		try {
			const records = await loadScenario(s);
			verifierStore.reset();
			findingsStore.reset();
			focusStore.clear();
			replayStore.load(records, s.id);
			replayStore.play();
		} catch (cause) {
			lastError = (cause as Error).message;
		} finally {
			loadingId = null;
		}
	}
</script>

<div class="hud-rail flex flex-wrap items-center gap-3 px-6 py-3">
	<span class="hud-label">DETECTORS</span>
	<div class="flex flex-wrap items-center gap-1.5">
		{#each BUTTONS as btn}
			{@const isLoading = loadingId === btn.id}
			{@const isActiveScenario = replayStore.scenarioId === btn.id}
			<button
				class="px-2.5 py-1.5 text-[10px] tracking-wider font-bold border transition-colors min-w-[62px]"
				class:cursor-not-allowed={!btn.active}
				class:opacity-30={!btn.active}
				style:border-color={btn.active
					? isActiveScenario
						? 'var(--color-cyan)'
						: 'var(--color-panel-edge)'
					: 'var(--color-bone-faint)'}
				style:color={btn.active
					? isActiveScenario
						? 'var(--color-cyan)'
						: 'var(--color-bone)'
					: 'var(--color-bone-faint)'}
				style:background={isActiveScenario ? 'rgba(34,211,238,0.10)' : 'transparent'}
				disabled={!btn.active || isLoading}
				title={btn.active ? DETECTOR_SCENARIOS[btn.id]?.headline : btn.dormantReason}
				onclick={() => injectScenario(btn.id)}
			>
				{isLoading ? '···' : btn.label}
			</button>
		{/each}
	</div>

	<span class="hud-label ml-4">SCENARIOS</span>
	<div class="flex items-center gap-1.5">
		{#each SCENARIOS as s}
			<button
				class="px-2.5 py-1.5 text-[10px] tracking-wider font-bold border transition-colors"
				style:border-color={replayStore.scenarioId === s.id
					? 'var(--color-amber)'
					: 'var(--color-panel-edge)'}
				style:color={replayStore.scenarioId === s.id
					? 'var(--color-amber)'
					: 'var(--color-bone-dim)'}
				title={s.description}
				onclick={() => loadGeneralScenario(s.id)}
			>
				{s.label}
			</button>
		{/each}
	</div>

	<div class="ml-auto flex items-center gap-2">
		<span class="hud-label">PLAY</span>
		<button
			class="px-2.5 py-1.5 text-[10px] border border-[var(--color-panel-edge)] hover:bg-[var(--color-obsidian-edge)]"
			onclick={() => replayStore.pause()}
		>
			❙❙
		</button>
		<button
			class="px-2.5 py-1.5 text-[10px] border border-[var(--color-panel-edge)] hover:bg-[var(--color-obsidian-edge)]"
			onclick={() => replayStore.play()}
		>
			▸
		</button>
		<button
			class="px-2.5 py-1.5 text-[10px] border border-[var(--color-panel-edge)] hover:bg-[var(--color-obsidian-edge)]"
			onclick={() => {
				replayStore.reset();
				verifierStore.reset();
				findingsStore.reset();
				focusStore.clear();
			}}
		>
			⟲
		</button>
	</div>

	{#if lastError}
		<span class="text-[10px] text-[var(--color-alert)] basis-full">load error: {lastError}</span>
	{/if}
</div>

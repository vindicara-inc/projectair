<script lang="ts">
	import { SCENARIOS, loadScenario, type Scenario } from '$lib/capsules/loader';
	import { replayStore } from '$lib/stores/replay.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { findingsStore } from '$lib/stores/findings.svelte';
	import { focusStore } from '$lib/stores/focus.svelte';

	let loading = $state(false);
	let lastError = $state<string | null>(null);

	async function selectScenario(scenario: Scenario): Promise<void> {
		loading = true;
		lastError = null;
		try {
			const records = await loadScenario(scenario);
			verifierStore.reset();
			findingsStore.reset();
			focusStore.clear();
			replayStore.load(records, scenario.id);
		} catch (cause) {
			lastError = (cause as Error).message;
		} finally {
			loading = false;
		}
	}

	const speeds = [0.5, 1, 2, 5] as const;
</script>

<div class="hud-rail flex items-center gap-4 px-6 py-3 flex-wrap">
	<span class="hud-label">SCENARIO</span>
	{#each SCENARIOS as scenario (scenario.id)}
		<button
			class="px-3 py-1 text-xs border border-[var(--color-panel-edge)]
				   hover:bg-[var(--color-obsidian-edge)]
				   {replayStore.scenarioId === scenario.id ? 'bg-[var(--color-cyan-deep)] text-[var(--color-bone)]' : 'text-[var(--color-bone-dim)]'}"
			onclick={() => selectScenario(scenario)}
			disabled={loading}
			title={scenario.description}
		>
			{scenario.label}
		</button>
	{/each}

	<div class="ml-6 flex items-center gap-2">
		<span class="hud-label">PLAY</span>
		<button
			class="px-3 py-1 text-xs border border-[var(--color-panel-edge)] hover:bg-[var(--color-obsidian-edge)]"
			onclick={() => replayStore.play()}
			disabled={replayStore.records.length === 0}
		>
			▸ PLAY
		</button>
		<button
			class="px-3 py-1 text-xs border border-[var(--color-panel-edge)] hover:bg-[var(--color-obsidian-edge)]"
			onclick={() => replayStore.pause()}
		>
			❙❙ PAUSE
		</button>
		<button
			class="px-3 py-1 text-xs border border-[var(--color-panel-edge)] hover:bg-[var(--color-obsidian-edge)]"
			onclick={() => replayStore.step()}
		>
			↦ STEP
		</button>
		<button
			class="px-3 py-1 text-xs border border-[var(--color-panel-edge)] hover:bg-[var(--color-obsidian-edge)]"
			onclick={() => {
				replayStore.reset();
				verifierStore.reset();
				findingsStore.reset();
				focusStore.clear();
			}}
		>
			⟲ RESET
		</button>
	</div>

	<div class="flex items-center gap-2">
		<span class="hud-label">SPEED</span>
		{#each speeds as s}
			<button
				class="px-2 py-1 text-xs border border-[var(--color-panel-edge)]
					   {replayStore.speed === s ? 'bg-[var(--color-cyan-deep)] text-[var(--color-bone)]' : 'text-[var(--color-bone-dim)] hover:bg-[var(--color-obsidian-edge)]'}"
				onclick={() => replayStore.setSpeed(s)}
			>
				{s}×
			</button>
		{/each}
	</div>

	{#if lastError}
		<span class="text-xs text-[var(--color-alert)]">load error: {lastError}</span>
	{/if}
</div>

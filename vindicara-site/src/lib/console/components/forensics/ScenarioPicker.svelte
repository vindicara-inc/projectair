<script lang="ts">
  // Demo-only: pick which scripted incident to walk. Data-driven — it lists whatever
  // is registered in scenarios/index.ts, so adding a scenario adds an option here.
  import { scenarios } from '$lib/console/forensics/scenarios';
  import { selectedScenarioId } from '$lib/console/stores/mode';

  let { onpick }: { onpick?: (id: string) => void } = $props();

  function pick(id: string) {
    selectedScenarioId.set(id);
    onpick?.(id);
  }
</script>

<div class="picker">
  <span class="lab">Scenario</span>
  <div class="opts">
    {#each scenarios as s}
      <button class="opt" class:on={$selectedScenarioId === s.id} onclick={() => pick(s.id)}>
        <span class="ttl">{s.title}</span>
        <span class="tag">{s.industryTag}</span>
      </button>
    {/each}
  </div>
</div>

<style>
  .picker { display: flex; flex-direction: column; gap: 9px; }
  .lab { font-family: var(--mono); font-size: 10px; letter-spacing: .14em; text-transform: uppercase; color: var(--faint); }
  .opts { display: flex; flex-wrap: wrap; gap: 10px; }
  .opt {
    text-align: left; cursor: pointer; padding: 11px 14px; min-width: 230px; flex: 1 1 260px;
    border: 1px solid var(--hair); background: rgba(255,255,255,.03); color: var(--muted);
    display: flex; flex-direction: column; gap: 4px; transition: .14s;
  }
  .opt:hover { border-color: var(--stroke); color: var(--ink); background: rgba(255,255,255,.05); }
  .opt.on { border-color: rgba(230,57,70,.5); background: rgba(230,57,70,.08); color: var(--ink); }
  .ttl { font-size: 13px; font-weight: 600; line-height: 1.25; }
  .tag { font-family: var(--mono); font-size: 9px; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); }
  .opt.on .tag { color: #ffb9bf; }
</style>

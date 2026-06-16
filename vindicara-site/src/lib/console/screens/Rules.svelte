<script lang="ts">
  import { api } from '$lib/console/api/client';
  import Panel from '$lib/console/components/Panel.svelte';
  import StateBlock from '$lib/console/components/StateBlock.svelte';
  import type { RuleDoc, Ruleset } from '$lib/console/api/types';

  let load = $state(api.getRules());
  let selected = $state<RuleDoc | null>(null);
  let selectedId = $state<string>('');

  async function pick(r: Ruleset) {
    selectedId = r.id;
    selected = await api.getRuleDoc(r.id);
  }
</script>

{#await load}
  <Panel><StateBlock kind="loading" /></Panel>
{:then d}
  {@const current = selected ?? d.selected}
  {@const curId = selectedId || d.selected.id}
  <div class="rules">
    <Panel reveal klass="rfiles">
      <div class="ph"><h3><span class="acc" style="background:var(--vio)"></span>Rulesets</h3></div>
      {#each d.rulesets as r}
        <button class="rfile {curId === r.id ? 'on' : ''}" onclick={() => pick(r)}>
          <span>{r.name}</span><span class="lyr {r.layer}">{r.layer === 'individual' ? 'INDIV' : r.layer.toUpperCase()}</span>
        </button>
      {/each}
      <button class="rfile new"><span>+ new ruleset</span></button>
    </Panel>

    <Panel reveal delay={0.06} klass="reditor">
      <div class="rebar"><span class="fn">{current.name}</span><span class="lock-note">{current.layerNote}</span><button class="savebtn">Save &amp; version</button></div>
      <pre class="recode">{current.content}</pre>
    </Panel>
  </div>
{:catch err}
  <Panel><StateBlock kind="error" message={err.message} /></Panel>
{/await}

<style>
  .rules { display: grid; grid-template-columns: 232px 1fr; gap: 18px; align-items: stretch; }
  :global(.rfiles) { padding: 14px; }
  .rfile { width: 100%; text-align: left; background: none; border: 0; display: flex; align-items: center; gap: 9px; padding: 9px 10px; cursor: pointer; font-family: var(--mono); font-size: 12px; color: var(--muted); border-left: 2px solid transparent; }
  .rfile:hover { background: rgba(255,255,255,.04); color: var(--ink); }
  .rfile.on { color: var(--ink); background: rgba(255,255,255,.05); border-left-color: var(--vio); }
  .rfile.new { color: var(--faint); }
  .lyr { margin-left: auto; font-size: 8px; letter-spacing: .05em; padding: 1px 5px; border: 1px solid var(--hair); }
  .lyr.floor { color: #ffc4a3; border-color: rgba(255,138,92,.35); }
  .lyr.dept { color: #cdbcff; border-color: rgba(155,107,255,.35); }
  .lyr.individual { color: #cfe9ff; border-color: rgba(109,181,255,.35); }
  :global(.reditor) { padding: 0; overflow: hidden; }
  .rebar { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-bottom: 1px solid var(--hair); }
  .fn { font-family: var(--mono); font-size: 12.5px; }
  .lock-note { font-family: var(--mono); font-size: 9px; color: #ffc4a3; border: 1px solid rgba(255,138,92,.3); padding: 2px 7px; }
  .savebtn { margin-left: auto; font-size: 11.5px; font-weight: 600; padding: 6px 13px; border: 1px solid rgba(155,107,255,.35); background: rgba(155,107,255,.12); color: #e0d3ff; cursor: pointer; }
  .recode { margin: 0; padding: 16px 18px; font-family: var(--mono); font-size: 12px; line-height: 1.7; color: #d7dbe3; white-space: pre-wrap; overflow: auto; background: rgba(0,0,0,.18); }
  @media (max-width: 980px) { .rules { grid-template-columns: 1fr; } }
</style>

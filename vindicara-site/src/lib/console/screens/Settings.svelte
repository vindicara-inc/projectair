<script lang="ts">
  import { api } from '$lib/console/api/client';
  import Panel from '$lib/console/components/Panel.svelte';
  import StateBlock from '$lib/console/components/StateBlock.svelte';
  import Toggle from '$lib/console/components/Toggle.svelte';
  let load = $state(api.getSettings());
</script>

{#await load}
  <Panel><StateBlock kind="loading" /></Panel>
{:then d}
  <div class="vhead"><div><div class="vt">Settings</div><div class="vd">Organization, identity, evidence, and billing.</div></div><span class="sp"></span><span class="pill">{d.plan}</span></div>
  <div class="sgrid">
    {#each d.sections as sec, i}
      <Panel reveal delay={0.05 * i}>
        <div class="ph"><h3>{sec.title}</h3></div>
        {#each sec.rows as r}
          <div class="srow">
            <div class="sl"><div class="t">{r.label}</div>{#if r.detail}<div class="d">{r.detail}</div>{/if}</div>
            {#if r.kind === 'toggle'}
              <Toggle on={r.on ?? false} accent={r.accent ?? 'teal'} />
            {:else}
              <span class="val">{r.value}</span>
            {/if}
          </div>
        {/each}
      </Panel>
    {/each}
  </div>
{:catch err}
  <Panel><StateBlock kind="error" message={err.message} /></Panel>
{/await}

<style>
  .vhead { display: flex; align-items: flex-end; gap: 14px; flex-wrap: wrap; }
  .vt { font-family: var(--display); font-size: 21px; font-weight: 600; }
  .vd { font-size: 12.5px; color: var(--muted); margin-top: 3px; }
  .sp { flex: 1; }
  .pill { font-family: var(--mono); font-size: 9px; letter-spacing: .06em; padding: 4px 9px; color: #cdbcff; border: 1px solid rgba(155,107,255,.3); background: rgba(155,107,255,.1); }
  .sgrid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 18px; }
  .srow { display: flex; align-items: center; gap: 14px; padding: 13px 0; border-top: 1px solid var(--hair); }
  .srow:first-of-type { border-top: 0; }
  .sl { flex: 1; } .sl .t { font-size: 13px; font-weight: 500; } .sl .d { font-size: 11px; color: var(--faint); margin-top: 2px; }
  .val { font-family: var(--mono); font-size: 11.5px; color: #cfe9ff; white-space: nowrap; }
  @media (max-width: 980px) { .sgrid { grid-template-columns: 1fr; } }
</style>

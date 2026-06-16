<script lang="ts">
  import { api } from '$lib/console/api/client';
  import { goto } from '$app/navigation';
  import Panel from '$lib/console/components/Panel.svelte';
  import StateBlock from '$lib/console/components/StateBlock.svelte';
  import Toggle from '$lib/console/components/Toggle.svelte';
  import type { Plugin } from '$lib/console/api/types';

  let load = $state(api.getPlugins());
  const statusClass = (s: Plugin['status']) => s === 'connected' ? 'p-on' : s === 'optional' ? 'p-opt' : 'p-off';
  const statusLabel = (s: Plugin['status']) => s === 'connected' ? 'CONNECTED' : s === 'optional' ? 'OPTIONAL' : 'AVAILABLE';
</script>

{#snippet card(p: Plugin)}
  <Panel klass="pcard">
    <div class="pi" style="background:linear-gradient(135deg,{p.icon.from},{p.icon.to})">{p.icon.label}</div>
    <div class="pn">{p.name}</div>
    <div class="pc">{p.category}</div>
    <div class="pd">{p.description}</div>
    <div class="prow">
      <span class="pstat {statusClass(p.status)}">{statusLabel(p.status)}</span>
      {#if p.status !== 'connected'}<Toggle on={false} />{/if}
    </div>
  </Panel>
{/snippet}

{#await load}
  <Panel><StateBlock kind="loading" /></Panel>
{:then d}
  <div class="pgrid">
    {#each d.core as p}{@render card(p)}{/each}
  </div>

  <div class="vhead">
    <div><div class="vt">Insurance &amp; risk transfer</div><div class="vd">Let a buyer route the signed evidence to their AI-liability carrier for underwriting and claims. Buyer-consented, scoped, revocable.</div></div>
    <span class="sp"></span>
    <button class="btn ok" onclick={() => goto('/flightdeck/insurance')}>Open insurance API &rarr;</button>
  </div>
  <div class="pgrid">
    {#each d.insurance as p}{@render card(p)}{/each}
    <button class="panel glass hud pcard ghost" onclick={() => goto('/flightdeck/insurance')}>
      <div class="pn">+ Generic carrier API</div>
      <div class="pd">Connect any carrier or broker over the AIR evidence API.</div>
    </button>
  </div>
{:catch err}
  <Panel><StateBlock kind="error" message={err.message} /></Panel>
{/await}

<style>
  .pgrid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  :global(.pcard) { padding: 18px; display: flex; flex-direction: column; gap: 10px; }
  .pi { width: 34px; height: 34px; display: grid; place-items: center; font-family: var(--display); font-weight: 700; font-size: 14px; color: #fff; }
  .pn { font-size: 13.5px; font-weight: 600; }
  .pc { font-family: var(--mono); font-size: 9px; letter-spacing: .08em; text-transform: uppercase; color: var(--faint); }
  .pd { font-size: 11.5px; color: var(--muted); flex: 1; line-height: 1.5; }
  .prow { display: flex; align-items: center; gap: 10px; margin-top: 2px; }
  .pstat { font-family: var(--mono); font-size: 9px; font-weight: 600; padding: 3px 8px; }
  .p-on { color: #bff5df; background: rgba(72,230,164,.13); border: 1px solid rgba(72,230,164,.3); }
  .p-off { color: var(--muted); background: rgba(255,255,255,.04); border: 1px solid var(--hair); }
  .p-opt { color: #ffd49a; background: rgba(255,180,84,.12); border: 1px solid rgba(255,180,84,.3); }
  .ghost { align-items: center; justify-content: center; text-align: center; border-style: dashed; color: var(--muted); cursor: pointer; }
  .vhead { display: flex; align-items: flex-end; gap: 14px; flex-wrap: wrap; }
  .vt { font-family: var(--display); font-size: 17px; font-weight: 600; }
  .vd { font-size: 12.5px; color: var(--muted); margin-top: 3px; max-width: 560px; }
  .sp { flex: 1; }
  @media (max-width: 980px) { .pgrid { grid-template-columns: 1fr; } }
</style>

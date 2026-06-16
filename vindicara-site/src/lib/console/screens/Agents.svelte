<script lang="ts">
  import { api } from '$lib/console/api/client';
  import Panel from '$lib/console/components/Panel.svelte';
  import StateBlock from '$lib/console/components/StateBlock.svelte';
  import type { AgentSummary } from '$lib/console/api/types';

  let load = $state(api.getAgents());
</script>

{#await load}
  <Panel><StateBlock kind="loading" /></Panel>
{:then agents}
  {#if agents.length === 0}
    <Panel>
      <StateBlock kind="empty" message="No agents registered yet. Agents appear here once they register via /v1/agents." />
    </Panel>
  {:else}
    <Panel klass="afpanel">
      <div class="ahead">
        <span class="atitle">Agent fleet</span>
        <span class="acount">{agents.length} registered · {agents.filter((a: AgentSummary) => a.status === 'active').length} active</span>
      </div>
      <div class="atable">
        <div class="ar arh">
          <span>Agent</span><span>Status</span><span>Permitted tools</span><span>Data scope</span><span>Registered</span>
        </div>
        {#each agents as a}
          <div class="ar">
            <span class="aname">{a.name}<small>{a.agentId}</small></span>
            <span>
              {#if a.status === 'active'}
                <span class="badge ok">ACTIVE</span>
              {:else}
                <span class="badge bad" title={a.suspendedReason}>SUSPENDED</span>
              {/if}
            </span>
            <span class="chips">
              {#each a.permittedTools as t}<span class="chip">{t}</span>{:else}<span class="dim">—</span>{/each}
            </span>
            <span class="chips">
              {#each a.dataScope as s}<span class="chip dimchip">{s}</span>{:else}<span class="dim">—</span>{/each}
            </span>
            <span class="dim">{a.createdAt || '—'}</span>
          </div>
          {#if a.status === 'suspended' && a.suspendedReason}
            <div class="areason">↳ {a.suspendedReason}</div>
          {/if}
        {/each}
      </div>
    </Panel>
  {/if}
{:catch err}
  <Panel><StateBlock kind="error" message={err.message} /></Panel>
{/await}

<style>
  :global(.afpanel) { padding: 0; overflow: hidden; }
  .ahead { display: flex; align-items: baseline; gap: 12px; padding: 18px 20px; border-bottom: 1px solid var(--hair); }
  .atitle { font-family: var(--display); font-size: 17px; font-weight: 600; }
  .acount { font-family: var(--mono); font-size: 10px; letter-spacing: .06em; text-transform: uppercase; color: var(--faint); }
  .atable { display: flex; flex-direction: column; }
  .ar { display: grid; grid-template-columns: 1.3fr .8fr 2fr 1.4fr .8fr; gap: 12px; align-items: start; padding: 13px 20px; border-bottom: 1px solid var(--hair); font-size: 12.5px; }
  .ar:last-child { border-bottom: 0; }
  .arh { font-family: var(--mono); font-size: 9px; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); }
  .aname { display: flex; flex-direction: column; gap: 2px; font-weight: 600; }
  .aname small { font-family: var(--mono); font-size: 9.5px; color: var(--faint); font-weight: 400; }
  .badge { font-family: var(--mono); font-size: 9px; font-weight: 600; padding: 3px 8px; }
  .badge.ok { color: #bff5df; background: rgba(72,230,164,.13); border: 1px solid rgba(72,230,164,.3); }
  .badge.bad { color: #ffd0d4; background: rgba(230,57,70,.12); border: 1px solid rgba(230,57,70,.32); }
  .chips { display: flex; flex-wrap: wrap; gap: 5px; }
  .chip { font-family: var(--mono); font-size: 9.5px; color: var(--ink); background: rgba(255,255,255,.05); border: 1px solid var(--hair); padding: 2px 6px; }
  .dimchip { color: var(--muted); }
  .dim { color: var(--faint); font-family: var(--mono); font-size: 10.5px; }
  .areason { padding: 0 20px 12px 20px; margin-top: -6px; font-family: var(--mono); font-size: 10.5px; color: #ffb0b6; }
  @media (max-width: 980px) { .ar { grid-template-columns: 1fr 1fr; } .arh { display: none; } }
</style>

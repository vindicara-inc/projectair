<script lang="ts">
  import { api } from '$lib/console/api/client';
  import Panel from '$lib/console/components/Panel.svelte';
  import StateBlock from '$lib/console/components/StateBlock.svelte';
  import type { CoverageStatus } from '$lib/console/api/types';

  let load = $state(api.getOverview());
  const statusLabel: Record<CoverageStatus, string> = {
    covered: 'COVERED', expiring: 'EXPIRING', expired: 'EXPIRED', uncovered: 'UNCOVERED'
  };
</script>

{#await load}
  <Panel><StateBlock kind="loading" /></Panel>
{:then d}
  <Panel klass="hpanel">
    <div class="head">
      <span class="t">Handoff lineage</span>
      <span class="c">{d.delegations.length} chains · who authorized whom, and under which policy</span>
    </div>
    {#if d.delegations.length === 0}
      <StateBlock kind="empty" message="No delegations yet. Each chain shows a human authorizing an agent under a policy." />
    {:else}
      <div class="lanes">
        {#each d.delegations as g}
          <div class="lane {g.status}">
            <div class="node human">
              <div class="nlabel">Authorizer</div>
              <div class="nname">{g.authorizer.name}</div>
              <div class="nsub">{g.authorizer.role}</div>
            </div>
            <div class="arrow"><span class="method">{g.method}</span></div>
            <div class="node agent">
              <div class="nlabel">Agent</div>
              <div class="nname">{g.agent}</div>
              <div class="nsub">{g.policy ?? 'no policy'}</div>
            </div>
            <div class="meta">
              <span class="badge {g.status}">{statusLabel[g.status]}</span>
              <span class="exp">{g.expires}</span>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </Panel>
{:catch err}
  <Panel><StateBlock kind="error" message={err.message} /></Panel>
{/await}

<style>
  :global(.hpanel) { padding: 0; overflow: hidden; }
  .head { display: flex; align-items: baseline; gap: 12px; padding: 18px 20px; border-bottom: 1px solid var(--hair); flex-wrap: wrap; }
  .t { font-family: var(--display); font-size: 17px; font-weight: 600; }
  .c { font-family: var(--mono); font-size: 10px; letter-spacing: .05em; text-transform: uppercase; color: var(--faint); }
  .lanes { display: flex; flex-direction: column; }
  .lane { display: grid; grid-template-columns: 1fr auto 1fr auto; gap: 16px; align-items: center; padding: 16px 20px; border-bottom: 1px solid var(--hair); border-left: 2px solid transparent; }
  .lane:last-child { border-bottom: 0; }
  .lane.covered { border-left-color: #48e6a4; }
  .lane.expiring { border-left-color: #ffb454; }
  .lane.expired, .lane.uncovered { border-left-color: #E63946; }
  .node { display: flex; flex-direction: column; gap: 2px; }
  .nlabel { font-family: var(--mono); font-size: 8.5px; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); }
  .nname { font-size: 13.5px; font-weight: 600; }
  .nsub { font-size: 11px; color: var(--muted); font-family: var(--mono); }
  .arrow { position: relative; min-width: 90px; height: 1px; background: linear-gradient(90deg, transparent, var(--hair), transparent); display: grid; place-items: center; }
  .arrow .method { font-family: var(--mono); font-size: 8.5px; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); background: var(--bg, #0b0d14); padding: 2px 7px; border: 1px solid var(--hair); }
  .meta { display: flex; flex-direction: column; align-items: flex-end; gap: 5px; }
  .badge { font-family: var(--mono); font-size: 8.5px; font-weight: 700; padding: 2px 7px; }
  .badge.covered { color: #bff5df; background: rgba(72,230,164,.13); border: 1px solid rgba(72,230,164,.3); }
  .badge.expiring { color: #ffd49a; background: rgba(255,180,84,.12); border: 1px solid rgba(255,180,84,.3); }
  .badge.expired, .badge.uncovered { color: #ffd0d4; background: rgba(230,57,70,.12); border: 1px solid rgba(230,57,70,.32); }
  .exp { font-family: var(--mono); font-size: 10px; color: var(--faint); }
  @media (max-width: 980px) { .lane { grid-template-columns: 1fr; gap: 8px; } .arrow { display: none; } .meta { flex-direction: row; align-items: center; } }
</style>

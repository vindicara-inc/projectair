<script lang="ts">
  import { api } from '$lib/console/api/client';
  import Panel from '$lib/console/components/Panel.svelte';
  import StateBlock from '$lib/console/components/StateBlock.svelte';
  import type { Finding, FindingAction } from '$lib/console/api/types';

  let load = $state(api.getOverview());
  let busy = $state<string | null>(null);

  async function act(f: Finding, a: FindingAction) {
    busy = f.id + a.intent;
    try {
      await api.actOnFinding(f.id, a.intent);
      load = api.getOverview();
    } finally {
      busy = null;
    }
  }
  const toneClass = (t?: FindingAction['tone']) =>
    t === 'crit' ? 'crit' : t === 'warn' ? 'warn' : t === 'ok' ? 'ok' : 'ghost';
</script>

{#await load}
  <Panel><StateBlock kind="loading" /></Panel>
{:then d}
  {@const queue = d.findings.filter((f) => f.response.state === 'awaiting')}
  {@const events = d.enforcement.filter((e) => e.kind === 'stepup')}

  <div class="grid">
    <Panel klass="col">
      <div class="head"><span class="t">Awaiting your decision</span><span class="c">{queue.length} in queue</span></div>
      {#if queue.length === 0}
        <StateBlock kind="empty" message="Nothing waiting. Every active agent is within its delegated scope." />
      {:else}
        {#each queue as f}
          <div class="item">
            <div class="top"><span class="sev {f.severity}">{f.severity.toUpperCase()}</span><span class="chk">{f.check}</span></div>
            <div class="title">{f.title}</div>
            <div class="resp">{f.response.label}</div>
            <div class="acts">
              {#each f.actions as a}
                <button class="btn {toneClass(a.tone)}" disabled={busy === f.id + a.intent} onclick={() => act(f, a)}>
                  {busy === f.id + a.intent ? '…' : a.label}
                </button>
              {/each}
            </div>
          </div>
        {/each}
      {/if}
    </Panel>

    <Panel klass="col">
      <div class="head"><span class="t">Recent step-up requests</span><span class="c">live</span></div>
      {#if events.length === 0}
        <StateBlock kind="empty" message="No step-up requests yet." />
      {:else}
        {#each events as e}
          <div class="feed"><span class="dot"></span><span class="ftext">{@html e.text}</span><span class="at">{e.at}</span></div>
        {/each}
      {/if}
    </Panel>
  </div>
{:catch err}
  <Panel><StateBlock kind="error" message={err.message} /></Panel>
{/await}

<style>
  .grid { display: grid; grid-template-columns: 1.4fr 1fr; gap: 16px; align-items: start; }
  :global(.col) { padding: 18px 20px; display: flex; flex-direction: column; gap: 12px; }
  .head { display: flex; align-items: baseline; gap: 10px; }
  .t { font-family: var(--display); font-size: 16px; font-weight: 600; }
  .c { font-family: var(--mono); font-size: 9px; letter-spacing: .08em; text-transform: uppercase; color: var(--faint); margin-left: auto; }
  .item { border: 1px solid var(--hair); padding: 13px 14px; display: flex; flex-direction: column; gap: 7px; background: rgba(255,255,255,.02); }
  .top { display: flex; align-items: center; gap: 8px; }
  .sev { font-family: var(--mono); font-size: 8.5px; font-weight: 700; padding: 2px 7px; }
  .sev.critical { color: #ffd0d4; background: rgba(230,57,70,.14); border: 1px solid rgba(230,57,70,.34); }
  .sev.high { color: #ffd49a; background: rgba(255,180,84,.12); border: 1px solid rgba(255,180,84,.3); }
  .sev.medium, .sev.low { color: var(--muted); background: rgba(255,255,255,.04); border: 1px solid var(--hair); }
  .chk { font-family: var(--mono); font-size: 9.5px; color: var(--faint); }
  .title { font-size: 13px; font-weight: 600; }
  .resp { font-size: 11.5px; color: var(--muted); }
  .acts { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 2px; }
  .btn { font-family: var(--ui); font-size: 11.5px; font-weight: 600; padding: 6px 12px; cursor: pointer; border: 1px solid var(--hair); background: rgba(255,255,255,.04); color: var(--ink); }
  .btn:disabled { opacity: .5; cursor: default; }
  .btn.crit { color: #ffd0d4; border-color: rgba(230,57,70,.4); background: rgba(230,57,70,.1); }
  .btn.warn { color: #ffd49a; border-color: rgba(255,180,84,.4); background: rgba(255,180,84,.1); }
  .btn.ok { color: #bff5df; border-color: rgba(72,230,164,.4); background: rgba(72,230,164,.1); }
  .feed { display: flex; align-items: center; gap: 10px; padding: 9px 0; border-bottom: 1px solid var(--hair); font-size: 12px; }
  .feed:last-child { border-bottom: 0; }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: #ffb454; box-shadow: 0 0 8px rgba(255,180,84,.6); flex: 0 0 7px; }
  .ftext { color: var(--muted); }
  .ftext :global(b) { color: var(--ink); font-weight: 600; }
  .at { margin-left: auto; font-family: var(--mono); font-size: 9.5px; color: var(--faint); }
  @media (max-width: 980px) { .grid { grid-template-columns: 1fr; } }
</style>

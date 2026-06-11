<script lang="ts">
  import { api } from '$lib/console/api/client';
  import Panel from '$lib/console/components/Panel.svelte';
  import StateBlock from '$lib/console/components/StateBlock.svelte';

  let load = $state(Promise.all([api.getOverview(), api.getInsurance()]));
</script>

{#await load}
  <Panel><StateBlock kind="loading" /></Panel>
{:then [d, ins]}
  {@const packs = d.stats.find((s) => s.label === 'Evidence packs')}
  <div class="grid">
    <Panel klass="ep">
      <div class="head"><span class="t">Evidence packs</span><span class="c">{ins.format}</span></div>
      <div class="big">{packs?.value ?? '—'}</div>
      <div class="sub">{packs?.meta ?? 'FRE 902(13) self-authenticating'}</div>
      <div class="kv"><span>Last pack sent</span><b>{ins.lastPackSent}</b></div>
      <div class="kv"><span>Format</span><b>{ins.format}</b></div>
    </Panel>

    <Panel klass="ep">
      <div class="head"><span class="t">Chain integrity</span><span class="c {d.proof.chainIntact ? 'good' : 'bad'}">{d.proof.chainIntact ? 'intact' : 'tampered'}</span></div>
      <div class="kv"><span>Records anchored</span><b>{d.proof.records.toLocaleString()}</b></div>
      <div class="kv"><span>Tampered</span><b>{d.proof.tampered}</b></div>
      <div class="kv"><span>Signature</span><b>{d.proof.signature}</b></div>
      <div class="kv"><span>Last anchor</span><b>{d.proof.lastAnchor}</b></div>
      <a class="verify" href="https://search.sigstore.dev" target="_blank" rel="noopener">Verify on Sigstore Rekor · #{d.proof.rekorIndex} &rarr;</a>
    </Panel>
  </div>

  <Panel klass="epwide">
    <div class="head"><span class="t">What each pack contains</span><span class="c">scoped · hash-only · revocable</span></div>
    <div class="inc">
      {#each ins.transport as t}
        <div class="incrow">
          <span class="state {t.on ? 'on' : 'off'}">{t.on ? 'INCLUDED' : t.locked ? 'NEVER' : 'OFF'}</span>
          <span class="il"><b>{t.label}</b><small>{t.detail}</small></span>
        </div>
      {/each}
    </div>
  </Panel>
{:catch err}
  <Panel><StateBlock kind="error" message={err.message} /></Panel>
{/await}

<style>
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; align-items: start; }
  :global(.ep) { padding: 18px 20px; display: flex; flex-direction: column; gap: 9px; }
  :global(.epwide) { padding: 18px 20px; margin-top: 16px; }
  .head { display: flex; align-items: baseline; gap: 10px; }
  .t { font-family: var(--display); font-size: 16px; font-weight: 600; }
  .c { font-family: var(--mono); font-size: 9px; letter-spacing: .07em; text-transform: uppercase; color: var(--faint); margin-left: auto; }
  .c.good { color: #8df0c4; }
  .c.bad { color: #ffb0b6; }
  .big { font-family: var(--display); font-size: 38px; font-weight: 700; line-height: 1; margin-top: 4px; }
  .sub { font-size: 11.5px; color: var(--muted); margin-bottom: 6px; }
  .kv { display: flex; justify-content: space-between; gap: 12px; padding: 8px 0; border-top: 1px solid var(--hair); font-size: 12px; color: var(--muted); }
  .kv b { color: var(--ink); font-weight: 600; font-family: var(--mono); font-size: 11.5px; }
  .verify { margin-top: 10px; font-family: var(--mono); font-size: 11px; color: #cdbcff; text-decoration: none; }
  .verify:hover { color: #fff; }
  .inc { display: flex; flex-direction: column; margin-top: 6px; }
  .incrow { display: flex; align-items: center; gap: 14px; padding: 11px 0; border-top: 1px solid var(--hair); }
  .il { display: flex; flex-direction: column; gap: 2px; }
  .il b { font-size: 12.5px; font-weight: 600; }
  .il small { font-size: 11px; color: var(--muted); }
  .state { font-family: var(--mono); font-size: 8.5px; font-weight: 700; padding: 3px 8px; flex: 0 0 auto; min-width: 74px; text-align: center; }
  .state.on { color: #bff5df; background: rgba(72,230,164,.13); border: 1px solid rgba(72,230,164,.3); }
  .state.off { color: var(--muted); background: rgba(255,255,255,.04); border: 1px solid var(--hair); }
  @media (max-width: 980px) { .grid { grid-template-columns: 1fr; } }
</style>

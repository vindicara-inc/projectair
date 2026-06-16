<script lang="ts">
  import { api } from '$lib/console/api/client';
  import Panel from '$lib/console/components/Panel.svelte';
  import StateBlock from '$lib/console/components/StateBlock.svelte';
  import Toggle from '$lib/console/components/Toggle.svelte';

  let load = $state(api.getInsurance());
  let mutationError = $state<string | null>(null);
  let busy = $state(false);

  async function toggle(label: string, on: boolean) {
    busy = true;
    mutationError = null;
    try {
      await api.setTransport(label, on);
      load = api.getInsurance();
    } catch (err) {
      mutationError = err instanceof Error ? err.message : 'Transport update failed.';
    } finally {
      busy = false;
    }
  }

  async function revoke(carrier: string) {
    busy = true;
    mutationError = null;
    try {
      await api.revokeConsent(carrier);
      load = api.getInsurance();
    } catch (err) {
      mutationError = err instanceof Error ? err.message : 'Consent revoke failed.';
    } finally {
      busy = false;
    }
  }
</script>

{#await load}
  <Panel><StateBlock kind="loading" /></Panel>
{:then d}
  <div class="vhead"><div><div class="vt">Insurance API</div><div class="vd">When a buyer wants it, AIR transports the proof their carrier needs, on the buyer's say-so, scoped and revocable.</div></div><span class="sp"></span><span class="pill">Enterprise tier</span></div>
  {#if mutationError}<div class="mutErr">{mutationError}</div>{/if}

  <div class="row2">
    <Panel reveal>
      <div class="ph"><h3><span class="acc" style="background:var(--blue)"></span>What gets transported</h3><span class="hint">buyer-consented</span></div>
      {#each d.transport as t}
        <div class="srow">
          <div class="sl"><div class="t">{t.label}</div><div class="d">{t.detail}</div></div>
          <Toggle on={t.on} disabled={t.locked || busy} onchange={(v: boolean) => toggle(t.label, v)} />
        </div>
      {/each}
    </Panel>

    <Panel reveal delay={0.06}>
      <div class="ph"><h3><span class="acc" style="background:var(--vio)"></span>Buyer consent</h3><span class="hint">revocable</span></div>
      <div class="naSub">A carrier sees nothing until the buyer grants it, the same delegation model as agents.</div>
      {#each d.consents as c}
        <div class="rdrow">
          <div class="rdq"><div class="q">{c.authorizer}</div><div class="map">{c.detail}</div></div>
          <span class="rstat {c.status === 'active' ? 'r-pass' : 'r-attest'}">{c.status.toUpperCase()}</span>
          <button class="rbtn" disabled={busy || c.status === 'revoked'} onclick={() => revoke(c.carrier)}>{c.status === 'active' ? 'Revoke' : c.status === 'revoked' ? 'Revoked' : 'Review'}</button>
        </div>
      {/each}
    </Panel>
  </div>

  <Panel reveal delay={0.12} klass="why">
    <div class="whygrid">
      <div>
        <div class="wt">Why a carrier wants this feed</div>
        <div class="wx">AI-liability underwriting is guesswork without data. A signed record of what every agent did, who authorized it, and that the deterministic floor held is <b>evidence of due care</b>, which is what prices a policy and settles a claim. AIR turns your audit trail into the carrier's underwriting input, and the buyer stays in control of what is shared.</div>
      </div>
      <div>
        <div class="kv tt"><span class="kk">Connected carriers</span><span class="vv">{d.connectedActive} active · {d.connectedPending} pending</span></div>
        <div class="kv"><span class="kk">Last pack sent</span><span class="vv">{d.lastPackSent}</span></div>
        <div class="kv"><span class="kk">Format</span><span class="vv">{d.format}</span></div>
        <div class="kv bb"><span class="kk">Premium signal</span><span class="vv">posture: {d.premiumSignal}</span></div>
        <button class="verbtn" disabled={busy || d.connectedActive === 0} title={d.connectedActive === 0 ? 'Connect an active carrier consent first' : ''} onclick={() => mutationError = 'Evidence pack dispatch is queued in the workspace store. Carrier webhook delivery ships in a later AIR Cloud release.'}>Send evidence pack to carrier</button>
      </div>
    </div>
  </Panel>
{:catch err}
  <Panel><StateBlock kind="error" message={err.message} /></Panel>
{/await}

<style>
  .vhead { display: flex; align-items: flex-end; gap: 14px; flex-wrap: wrap; }
  .vt { font-family: var(--display); font-size: 21px; font-weight: 600; }
  .vd { font-size: 12.5px; color: var(--muted); margin-top: 3px; max-width: 560px; }
  .sp { flex: 1; }
  .pill { font-family: var(--mono); font-size: 9px; letter-spacing: .06em; padding: 4px 9px; color: #cdbcff; border: 1px solid rgba(155,107,255,.3); background: rgba(155,107,255,.1); }
  .mutErr { font-size: 12px; color: #ffc4a3; }
  .row2 { display: grid; grid-template-columns: 1.7fr 1fr; gap: 20px; align-items: stretch; }
  .srow { display: flex; align-items: center; gap: 14px; padding: 13px 0; border-top: 1px solid var(--hair); }
  .srow:first-of-type { border-top: 0; }
  .sl { flex: 1; } .sl .t { font-size: 13px; font-weight: 500; } .sl .d { font-size: 11px; color: var(--faint); margin-top: 2px; }
  .naSub { font-size: 11.5px; color: var(--muted); margin-bottom: 6px; }
  .rdrow { display: flex; align-items: center; gap: 14px; padding: 14px 0; border-top: 1px solid var(--hair); }
  .rdrow:first-of-type { border-top: 0; }
  .rdq { flex: 1; } .rdq .q { font-size: 13px; font-weight: 600; } .rdq .map { font-size: 11.5px; color: var(--muted); margin-top: 4px; line-height: 1.5; }
  .rstat { font-family: var(--mono); font-size: 9px; padding: 4px 9px; font-weight: 600; white-space: nowrap; }
  .r-pass { color: #bff5df; background: rgba(72,230,164,.13); border: 1px solid rgba(72,230,164,.3); }
  .r-attest { color: #ffd49a; background: rgba(255,180,84,.13); border: 1px solid rgba(255,180,84,.3); }
  .rbtn { font-size: 11px; font-weight: 600; padding: 6px 11px; border: 1px solid var(--hair); background: rgba(255,255,255,.04); color: var(--ink); cursor: pointer; }
  :global(.why) { padding: 22px 24px; }
  .whygrid { display: grid; grid-template-columns: 1.25fr 1fr; gap: 26px; align-items: center; }
  .wt { font-family: var(--display); font-size: 16px; font-weight: 600; margin-bottom: 8px; }
  .wx { font-size: 12.5px; color: var(--muted); line-height: 1.65; }
  .wx :global(b) { color: #cfe9ff; font-weight: 600; }
  .kv { display: flex; justify-content: space-between; font-size: 11.5px; padding: 8px 0; border-top: 1px solid var(--hair); }
  .kv.tt { border-top: 0; } .kv.bb { border-bottom: 1px solid var(--hair); }
  .kk { color: var(--faint); } .vv { font-family: var(--mono); color: var(--ink); }
  .verbtn { margin-top: 12px; padding: 10px; border: 1px solid rgba(72,230,164,.3); background: linear-gradient(180deg, rgba(72,230,164,.16), rgba(72,230,164,.04)); color: #bff5df; font-weight: 600; font-size: 12.5px; cursor: pointer; width: 100%; }
  @media (max-width: 980px) { .row2 { grid-template-columns: 1fr; } .whygrid { grid-template-columns: 1fr; } }
</style>

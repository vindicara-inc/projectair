<script lang="ts">
  import { api } from '$lib/console/api/client';
  import Panel from '$lib/console/components/Panel.svelte';
  import StateBlock from '$lib/console/components/StateBlock.svelte';
  import type { FindingAction } from '$lib/console/api/types';
  import { lockSession } from '$lib/console/stores/session';

  let load = $state(api.getOverview());
  let actionError = $state<string | null>(null);
  let acting = $state<string | null>(null);
  const avclass = (i: number) => ['a', 'b', 'c', 'a', 'x'][i % 5];

  async function act(id: string, intent: FindingAction['intent']) {
    acting = id;
    actionError = null;
    try {
      await api.actOnFinding(id, intent);
      load = api.getOverview();
    } catch (err) {
      actionError = err instanceof Error ? err.message : 'Action failed.';
    } finally {
      acting = null;
    }
  }

  function openRekor(url: string | undefined, index: string) {
    const target = url ?? `https://search.sigstore.dev/?logIndex=${encodeURIComponent(index)}`;
    window.open(target, '_blank', 'noopener,noreferrer');
  }
</script>

{#await load}
  <Panel><StateBlock kind="loading" /></Panel>
{:then d}
  <div class="stats">
    {#each d.stats as s, i}
      <Panel reveal delay={0.06 + i * 0.03} klass={'stat t-' + s.tone}>
        <div class="l">{s.label}</div><div class="v">{s.value}</div>
        <div class="m"><span class="led"></span>{s.meta}</div>
      </Panel>
    {/each}
  </div>

  <div class="row2">
    <Panel reveal delay={0.2}>
      <div class="ph"><h3><span class="acc" style="background:var(--vio)"></span>Active delegations</h3><span class="hint">human · agent · policy · expiry</span></div>
      <table>
        <thead><tr><th>Authorizer</th><th>Agent</th><th>Policy</th><th>Method</th><th>Expires</th><th>Status</th></tr></thead>
        <tbody>
          {#each d.delegations as g, i}
            <tr>
              <td><div class="who"><div class="av {avclass(i)}">{g.authorizer.name === 'none' ? '?' : g.authorizer.name.slice(0,2).toUpperCase()}</div><div><div class="nm">{g.authorizer.name}</div><div class="rl">{g.authorizer.role}</div></div></div></td>
              <td>{g.agent}</td>
              <td class="mono">{g.policy ?? '—'}</td>
              <td><span class="meth {g.method === 'auth0' ? 'o' : ''} {g.method === 'none' ? 'none' : ''}">{g.method}</span></td>
              <td class="exp">{g.expires}</td>
              <td><span class="st s-{g.status}">{g.status.toUpperCase()}</span></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </Panel>

    <Panel reveal delay={0.24}>
      <div class="ph"><h3><span class="acc" style="background:var(--blue)"></span>Enforcement feed</h3><span class="hint">live</span></div>
      <div class="feed">
        {#each d.enforcement as e}
          <div class="ev"><span class="k k-{e.kind}"></span><div class="t">{@html e.text}</div><span class="tm">{e.at}</span></div>
        {/each}
      </div>
    </Panel>
  </div>

  <div class="row3">
    <Panel reveal delay={0.28}>
      <div class="ph"><h3><span class="acc" style="background:var(--amber)"></span>Needs action</h3><span class="badge">{d.findings.filter(f => f.response.state === 'awaiting').length} awaiting you</span></div>
      <div class="naSub">{d.findings.filter(f => f.response.state === 'contained').length} contained automatically · {d.findings.filter(f => f.response.state === 'awaiting').length} need your decision</div>
      {#if actionError}<div class="naErr">{actionError}</div>{/if}
      {#each d.findings as f}
        <div class="naItem">
          <div class="naTop"><span class="sev {f.severity === 'critical' ? 'cr' : 'hi'}">{f.severity === 'critical' ? 'CRIT' : 'HIGH'}</span><span class="ft">{f.title}</span><span class="fm">{f.check}</span></div>
          <div class="naBot">
            <span class="resp {f.response.state === 'contained' ? 'done' : 'wait'}"><span class="rk"></span>{f.response.label}</span>
            <div class="naBtns">{#each f.actions as a}<button class="btn {a.tone ?? ''}" disabled={acting === f.id} onclick={() => act(f.id, a.intent)}>{a.label}</button>{/each}</div>
          </div>
        </div>
      {/each}
    </Panel>

    <div class="col">
      <Panel reveal delay={0.36} klass="proof">
        <div class="ph"><h3><span class="acc" style="background:var(--teal)"></span>Proof</h3><span class="hint">Rekor</span></div>
        <div class="big">{d.proof.chainIntact ? 'Chain intact' : 'Chain BROKEN'}</div>
        <div class="sm">{d.proof.records.toLocaleString()} records · {d.proof.tampered} tampered</div>
        <div class="kv"><span class="kk">Signature</span><span class="vv">{d.proof.signature}</span></div>
        <div class="kv"><span class="kk">Last anchor</span><span class="vv">{d.proof.lastAnchor}</span></div>
        <div class="kv bb"><span class="kk">Rekor index</span><span class="vv">{d.proof.rekorIndex}</span></div>
        <button class="verbtn" onclick={() => openRekor(d.proof.rekorUrl, d.proof.rekorIndex)}>Verify on Sigstore &rarr;</button>
      </Panel>

      <Panel reveal delay={0.4} klass="usr">
        <div class="uhead">
          <div class="uav"><svg viewBox="0 0 64 64"><defs><linearGradient id="uav1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#9b6bff"/><stop offset="1" stop-color="#6db5ff"/></linearGradient></defs><rect width="64" height="64" fill="url(#uav1)"/><circle cx="32" cy="25" r="11" fill="#fff" opacity=".92"/><path d="M12 56c2-12 11-18 20-18s18 6 20 18z" fill="#fff" opacity=".92"/></svg></div>
          <div><div class="un">{d.operator.name}</div><div class="ur">{d.operator.role}</div></div>
        </div>
        <div class="kv tt"><span class="kk">Authenticated</span><span class="vv">{d.operator.authMethod} · FIDO2</span></div>
        <div class="kv"><span class="kk">Session</span><span class="vv">expires {d.operator.sessionExpires}</span></div>
        <div class="kv bb"><span class="kk">Grants you authorized</span><span class="vv">{d.operator.grantsAuthorized} active</span></div>
        <button class="verbtn vio" onclick={lockSession}>Lock session</button>
      </Panel>
    </div>
  </div>
{:catch err}
  <Panel><StateBlock kind="error" message={err.message} /></Panel>
{/await}

<style>
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }
  :global(.stat) { padding: 18px 20px; }
  .l { font-family: var(--mono); font-size: 9.5px; letter-spacing: .14em; text-transform: uppercase; color: var(--faint); }
  .v { font-family: var(--display); font-size: 30px; font-weight: 600; line-height: 1; margin-top: 9px; }
  .m { font-size: 11px; color: var(--muted); margin-top: 6px; display: flex; align-items: center; gap: 6px; }
  .led { width: 7px; height: 7px; border-radius: 50%; }
  :global(.t-vio) .v { color: #cdbcff; } :global(.t-vio) .led { background: var(--vio); box-shadow: 0 0 9px var(--vio); }
  :global(.t-teal) .v { color: #bff5df; } :global(.t-teal) .led { background: var(--teal); }
  :global(.t-amber) .v { color: #ffd49a; } :global(.t-amber) .led { background: var(--amber); }
  :global(.t-blue) .v { color: #cfe9ff; } :global(.t-blue) .led { background: var(--blue); }

  .row2 { display: grid; grid-template-columns: 1.7fr 1fr; gap: 20px; align-items: stretch; }
  .row3 { display: grid; grid-template-columns: 1.6fr 1fr; gap: 20px; align-items: stretch; }
  .col { display: flex; flex-direction: column; gap: 20px; }
  :global(.col .panel) { flex: 1; }

  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-family: var(--mono); font-size: 9.5px; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); padding: 0 10px 11px; font-weight: 500; }
  td { padding: 13px 10px; border-top: 1px solid var(--hair); font-size: 12.5px; vertical-align: middle; }
  .who { display: flex; align-items: center; gap: 10px; }
  .av { width: 28px; height: 28px; display: grid; place-items: center; font-weight: 700; color: #fff; font-size: 10.5px; }
  .av.a { background: linear-gradient(135deg, #9b6bff, #6db5ff); } .av.b { background: linear-gradient(135deg, #2b8bff, #13c08a); }
  .av.c { background: linear-gradient(135deg, #13c08a, #6db5ff); } .av.x { background: rgba(138,146,160,.25); color: #c2c8d2; }
  .nm { font-weight: 600; } .rl { font-size: 10px; color: var(--faint); }
  .exp { font-family: var(--mono); font-size: 11px; color: var(--muted); }
  .meth { font-family: var(--mono); font-size: 9px; padding: 3px 7px; border: 1px solid rgba(155,107,255,.3); color: #cdbcff; background: rgba(155,107,255,.1); }
  .meth.o { border-color: rgba(109,181,255,.3); color: #bcd9ff; background: rgba(109,181,255,.08); }
  .meth.none { border-color: rgba(138,146,160,.3); color: #c2c8d2; background: rgba(138,146,160,.12); }

  .feed { display: flex; flex-direction: column; flex: 1; }
  .ev { display: flex; gap: 11px; padding: 10px 0; border-top: 1px solid var(--hair); align-items: flex-start; }
  .ev:first-child { border-top: 0; }
  .k { width: 7px; height: 7px; border-radius: 50%; margin-top: 5px; flex: 0 0 7px; }
  .k-blocked, .k-stepup { background: var(--amber); } .k-authorized { background: var(--vio); }
  .k-sealed, .k-verified { background: var(--teal); box-shadow: 0 0 8px var(--teal); } .k-revoked { background: var(--slate); }
  .ev .t { font-size: 12px; line-height: 1.4; flex: 1; } .ev .tm { font-family: var(--mono); font-size: 10px; color: var(--faint); white-space: nowrap; }

  .badge { font-family: var(--mono); font-size: 9px; padding: 3px 8px; font-weight: 600; color: #ffd49a; background: rgba(255,180,84,.14); border: 1px solid rgba(255,180,84,.3); }
  .naSub { font-size: 11.5px; color: var(--muted); margin-bottom: 4px; }
  .naErr { font-size: 11.5px; color: #ffc4a3; margin-bottom: 8px; }
  .naItem { padding: 13px 0; border-top: 1px solid var(--hair); }
  .naItem:first-of-type { border-top: 0; }
  .naTop { display: flex; align-items: center; gap: 9px; margin-bottom: 10px; }
  .naTop .ft { font-size: 12.5px; flex: 1; font-weight: 500; } .naTop .fm { font-family: var(--mono); font-size: 9.5px; color: var(--faint); }
  .naBot { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; }
  .sev { font-family: var(--mono); font-size: 9px; padding: 3px 7px; font-weight: 600; }
  .sev.hi { color: #ffd49a; background: rgba(255,180,84,.14); border: 1px solid rgba(255,180,84,.3); }
  .sev.cr { color: #ffc4a3; background: rgba(255,138,92,.16); border: 1px solid rgba(255,138,92,.34); }
  .resp { font-family: var(--mono); font-size: 9.5px; padding: 4px 9px; display: inline-flex; align-items: center; gap: 7px; }
  .resp.done { color: #bff5df; background: rgba(72,230,164,.12); border: 1px solid rgba(72,230,164,.28); }
  .resp.wait { color: #ffd49a; background: rgba(255,180,84,.12); border: 1px solid rgba(255,180,84,.28); }
  .resp .rk { width: 6px; height: 6px; border-radius: 50%; } .resp.done .rk { background: var(--teal); } .resp.wait .rk { background: var(--amber); }
  .naBtns { margin-left: auto; display: flex; gap: 7px; }

  :global(.proof) .big { font-family: var(--display); font-size: 22px; font-weight: 600; color: #bff5df; margin-bottom: 2px; }
  :global(.proof) .sm { font-size: 12px; color: var(--muted); }
  .kv { display: flex; justify-content: space-between; font-size: 11.5px; padding: 8px 0; border-top: 1px solid var(--hair); }
  .kv.tt { border-top: 0; } .kv.bb { border-bottom: 1px solid var(--hair); }
  .kk { color: var(--faint); } .vv { font-family: var(--mono); color: var(--ink); }
  .verbtn { margin-top: auto; padding: 10px; border: 1px solid rgba(72,230,164,.3); background: linear-gradient(180deg, rgba(72,230,164,.16), rgba(72,230,164,.04)); color: #bff5df; font-weight: 600; font-size: 12.5px; cursor: pointer; }
  .verbtn.vio { border-color: rgba(155,107,255,.3); background: linear-gradient(180deg, rgba(155,107,255,.16), rgba(155,107,255,.04)); color: #e0d3ff; }
  :global(.usr) .uhead { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }
  .uav { width: 48px; height: 48px; overflow: hidden; flex: 0 0 48px; border: 1px solid var(--stroke); }
  .uav svg { width: 100%; height: 100%; display: block; }
  .un { font-family: var(--display); font-size: 17px; font-weight: 600; } .ur { font-size: 11px; color: var(--muted); margin-top: 2px; }

  @media (max-width: 980px) { .stats { grid-template-columns: repeat(2,1fr); } .row2, .row3 { grid-template-columns: 1fr; } }
</style>

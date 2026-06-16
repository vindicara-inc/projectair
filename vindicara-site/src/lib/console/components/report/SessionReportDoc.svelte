<script lang="ts">
  import type { ReviewedIncident, SessionDecision } from '$lib/console/stores/sessionlog';

  let {
    operatorName,
    organization,
    role,
    authMethod,
    signInAt,
    clockOutAt,
    reviewed,
    decisions,
    reportId,
    deptHead
  }: {
    operatorName: string;
    organization: string;
    role: string;
    authMethod: string;
    signInAt: string;
    clockOutAt: string;
    reviewed: ReviewedIncident[];
    decisions: SessionDecision[];
    reportId: string;
    deptHead: { name: string; title: string };
  } = $props();

  const fmt = (iso: string) => (iso ? new Date(iso).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' }) : '—');
  let duration = $derived.by(() => {
    const ms = Date.parse(clockOutAt) - Date.parse(signInAt);
    if (!Number.isFinite(ms) || ms < 0) return '—';
    const m = Math.round(ms / 60000);
    return m < 60 ? `${m} min` : `${Math.floor(m / 60)}h ${m % 60}m`;
  });
</script>

<article class="report-doc">
  <section class="page">
    <div class="wordmark"><span class="dot"></span>Project <span class="air">AIR</span></div>
    <div class="tagline">Monitor · Protect · Prove</div>
    <h1>Operator Session Report</h1>
    <div class="subtitle">A signed account of this operator’s session, filed to the department head</div>

    <dl class="meta">
      <div><dt>Report ID</dt><dd class="mono">{reportId}</dd></div>
      <div><dt>Operator</dt><dd>{operatorName} · {role}</dd></div>
      <div><dt>Organization</dt><dd>{organization}</dd></div>
      <div><dt>Signed in</dt><dd>{fmt(signInAt)}</dd></div>
      <div><dt>Clocked out</dt><dd>{fmt(clockOutAt)}</dd></div>
      <div><dt>Session length</dt><dd>{duration}</dd></div>
      <div><dt>Authentication</dt><dd>{authMethod === 'auth0' ? 'Auth0 / OIDC' : 'Passkey · FIDO2 / WebAuthn'}</dd></div>
    </dl>

    <!-- routed to the department head -->
    <div class="filedbox">
      <div class="fl">Filed to</div>
      <div class="fn">{deptHead.name}</div>
      <div class="fr">{deptHead.title} · {organization}</div>
      <div class="fm">Delivered {fmt(clockOutAt)} · signed by {operatorName}</div>
    </div>

    <h2>Incidents reviewed ({reviewed.length})</h2>
    {#if reviewed.length === 0}
      <p class="none">No incidents were opened during this session.</p>
    {:else}
      <table>
        <thead><tr><th>Time</th><th>Incident</th></tr></thead>
        <tbody>
          {#each reviewed as r}
            <tr><td class="mono nowrap">{fmt(r.at)}</td><td>{r.title}</td></tr>
          {/each}
        </tbody>
      </table>
    {/if}

    <h2 class="mt">Decisions made ({decisions.length})</h2>
    {#if decisions.length === 0}
      <p class="none">No step-up approvals were required this session — every halted action remained blocked.</p>
    {:else}
      <table>
        <thead><tr><th>Time</th><th>Incident</th><th>Decision</th><th>Authorized by</th></tr></thead>
        <tbody>
          {#each decisions as d}
            <tr>
              <td class="mono nowrap">{fmt(d.at)}</td>
              <td>{d.title}</td>
              <td class="dec {d.decision}">{d.decision === 'approve' ? 'Approved the change' : 'Kept it blocked'}</td>
              <td>{d.approver}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}

    <p class="closing">
      Every record reviewed or decided in this session is part of a tamper-evident chain
      (BLAKE3 + Ed25519), re-verifiable offline. This report binds the session to
      <b>{operatorName}</b> and is filed to <b>{deptHead.name}</b> for departmental oversight.
    </p>

    <div class="sigline">
      <div><div class="sl"></div>{operatorName}, {role}</div>
      <div><div class="sl"></div>Received — {deptHead.name}, {deptHead.title}</div>
    </div>
    <div class="classification">Demo Mode — synthetic data (illustrative).</div>
  </section>
</article>

<style>
  .report-doc { display: flex; flex-direction: column; align-items: center; gap: 22px; }
  .page { background: #fff; color: #16181d; width: 100%; max-width: 760px; padding: 46px 52px; box-shadow: 0 18px 50px rgba(0,0,0,.5); font-family: 'Hanken Grotesk', system-ui, sans-serif; font-size: 13px; line-height: 1.55; }
  .page :global(.mono) { font-family: 'IBM Plex Mono', monospace; }
  h1 { font-family: 'Fraunces', Georgia, serif; font-size: 28px; font-weight: 700; margin: 22px 0 6px; }
  h2 { font-family: 'Fraunces', Georgia, serif; font-size: 18px; font-weight: 600; margin: 0 0 10px; border-bottom: 2px solid #16181d; padding-bottom: 6px; }
  h2.mt { margin-top: 22px; }
  .wordmark { font-family: 'Fraunces', serif; font-size: 18px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
  .wordmark .air { color: #E63946; font-weight: 700; }
  .wordmark .dot { width: 11px; height: 11px; border-radius: 2px; background: #E63946; }
  .tagline { font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: .28em; text-transform: uppercase; color: #6b7280; margin-top: 4px; }
  .subtitle { color: #4b5563; font-size: 14px; margin-bottom: 22px; }
  .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 5px 26px; margin: 0 0 18px; }
  .meta > div { display: grid; grid-template-columns: 120px 1fr; gap: 10px; border-bottom: 1px solid #eee; padding-bottom: 5px; }
  .meta dt { color: #6b7280; font-size: 11.5px; }
  .meta dd { font-weight: 600; font-size: 12.5px; }
  .filedbox { border: 2px solid #E63946; background: #fff5f5; padding: 14px 18px; margin: 6px 0 22px; }
  .fl { font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: .16em; text-transform: uppercase; color: #b91c1c; }
  .fn { font-family: 'Fraunces', serif; font-size: 20px; font-weight: 700; margin-top: 3px; }
  .fr { font-size: 13px; color: #374151; }
  .fm { font-size: 11px; color: #6b7280; margin-top: 5px; }
  table { width: 100%; border-collapse: collapse; font-size: 11.5px; margin: 4px 0 8px; }
  th { text-align: left; border-bottom: 1.5px solid #16181d; padding: 6px 8px; font-size: 10px; letter-spacing: .04em; text-transform: uppercase; color: #6b7280; }
  td { border-bottom: 1px solid #eee; padding: 6px 8px; vertical-align: top; }
  .nowrap { white-space: nowrap; }
  .dec { font-weight: 700; }
  .dec.approve { color: #b45309; }
  .dec.deny { color: #047857; }
  .none { color: #6b7280; font-style: italic; }
  .closing { font-size: 12.5px; color: #374151; margin-top: 14px; }
  .closing b { font-weight: 700; }
  .sigline { display: grid; grid-template-columns: 1fr 1fr; gap: 40px; margin-top: 34px; }
  .sigline .sl { border-top: 1px solid #16181d; margin-bottom: 5px; }
  .sigline > div { font-size: 11px; color: #6b7280; }
  .classification { margin-top: 16px; font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; color: #9ca3af; }
  @media (max-width: 900px) { .page { padding: 30px 22px; } .meta { grid-template-columns: 1fr; } }
</style>

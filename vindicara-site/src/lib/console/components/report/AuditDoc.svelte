<script lang="ts">
  import { filterAuditEvents, summarize, type AuditFilters } from '$lib/console/forensics/audit';
  import type { ReportAnchor } from '$lib/console/forensics/report';
  import { operator } from '$lib/console/stores/operator';

  let {
    filters,
    reportId,
    generatedAt,
    anchor
  }: { filters: AuditFilters; reportId: string; generatedAt: string; anchor: ReportAnchor } = $props();

  let events = $derived(filterAuditEvents(filters));
  let sum = $derived(summarize(events));

  let authority = $derived(
    $operator.signedInAt
      ? { name: $operator.name, org: $operator.organization, role: $operator.role }
      : { name: 'Dr. Sarah Chen', org: 'Demo Health System', role: 'Privacy & Security Officer' }
  );

  const fmt = (iso: string) => new Date(iso).toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
  const fmtT = (iso: string) => new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  const typeLabel: Record<string, string> = { allowed: 'Allowed', flagged: 'Flagged', halted: 'Halted' };
  const scopeText = (v: string, all: string) => (v === 'all' ? all : v);
</script>

<article class="report-doc">
  <section class="page">
    <div class="wordmark"><span class="dot"></span>Project <span class="air">AIR</span></div>
    <div class="tagline">Monitor · Protect · Prove</div>
    <h1>HIPAA Audit Trail</h1>
    <div class="subtitle">Complete chronological record of AI agent activity for the selected scope</div>

    <dl class="meta">
      <div><dt>Audit ID</dt><dd class="mono">{reportId}-TRAIL</dd></div>
      <div><dt>Covered entity</dt><dd>{authority.org}</dd></div>
      <div><dt>Patient</dt><dd>{scopeText(filters.patient, 'All patients')}</dd></div>
      <div><dt>Agent</dt><dd class="mono">{scopeText(filters.agent, 'All agents')}</dd></div>
      <div><dt>Department</dt><dd>{scopeText(filters.department, 'All departments')}</dd></div>
      <div><dt>Period</dt><dd>{fmt(filters.from)} → {fmt(filters.to)}</dd></div>
      <div><dt>Prepared by</dt><dd>{authority.name} · {authority.role}</dd></div>
      <div><dt>Generated</dt><dd>{fmt(generatedAt)}</dd></div>
    </dl>

    <!-- whole-trail integrity proof -->
    <div class="integrity {sum.allIntact ? 'ok' : 'bad'}">
      <span class="mark">{sum.allIntact ? '✓' : '✕'}</span>
      <div>
        <div class="ih">{sum.allIntact ? 'Every step is authentic and unaltered' : 'Tampering detected in this trail'}</div>
        <div class="ix">{sum.total} actions across {sum.sessions} agent sessions · {sum.allowed} allowed · {sum.flagged} flagged · {sum.halted} halted — the whole chain re-verified for this audit.</div>
      </div>
    </div>

    {#if events.length === 0}
      <p class="none">No agent activity matches this scope. Widen the filters and run the audit again.</p>
    {:else}
      <table class="trail">
        <thead>
          <tr><th>Time</th><th>Agent</th><th>Department</th><th>Patient</th><th>Action</th><th>Type</th></tr>
        </thead>
        <tbody>
          {#each events as e}
            <tr class="t-{e.type}">
              <td class="mono nowrap">{fmtT(e.time)}</td>
              <td class="mono">{e.agent}</td>
              <td>{e.department}</td>
              <td>{e.patient}</td>
              <td>{e.action}</td>
              <td class="type">{typeLabel[e.type]}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      <div class="legend">
        <span><i class="d allowed"></i>Allowed — within scope</span>
        <span><i class="d flagged"></i>Flagged — logged for review</span>
        <span><i class="d halted"></i>Halted — blocked, paused for a human</span>
      </div>
    {/if}

    <div class="anchorline mono">
      Integrity anchor — chain root {anchor.chainRoot.slice(0, 20)}… · Ed25519 {anchor.signerKey.slice(0, 14)}… · Sigstore Rekor #{anchor.rekorLogIndex} · RFC 3161 {fmt(anchor.tsaTimestamp)}
    </div>

    <p class="closing">
      This trail is the HIPAA §164.308(a)(1)(ii)(D) activity review and §164.312(b) audit-control
      evidence for the selected scope. It can be re-verified offline; no trust is placed in
      Vindicara, the covered entity, or the AI vendor.
    </p>

    <div class="sigline">
      <div><div class="sl"></div>Signature — {authority.name}, {authority.role}</div>
      <div><div class="sl"></div>Date</div>
    </div>
    <div class="classification">Demo Mode — synthetic patient data (illustrative).</div>
  </section>
</article>

<style>
  .report-doc { display: flex; flex-direction: column; align-items: center; gap: 22px; padding: 6px 0 30px; }
  .page { background: #fff; color: #16181d; width: 100%; max-width: 880px; padding: 50px 56px; box-shadow: 0 18px 50px rgba(0,0,0,.5); font-family: 'Hanken Grotesk', system-ui, sans-serif; font-size: 13px; line-height: 1.55; }
  .page :global(.mono) { font-family: 'IBM Plex Mono', monospace; }
  h1 { font-family: 'Fraunces', Georgia, serif; font-size: 30px; font-weight: 700; margin: 24px 0 6px; }
  .wordmark { font-family: 'Fraunces', serif; font-size: 18px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
  .wordmark .air { color: #E63946; font-weight: 700; }
  .wordmark .dot { width: 11px; height: 11px; border-radius: 2px; background: #E63946; }
  .tagline { font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: .28em; text-transform: uppercase; color: #6b7280; margin-top: 4px; }
  .subtitle { color: #4b5563; font-size: 14px; margin-bottom: 22px; }
  .meta { display: grid; grid-template-columns: 1fr 1fr; gap: 5px 28px; margin: 0 0 20px; }
  .meta > div { display: grid; grid-template-columns: 120px 1fr; gap: 10px; border-bottom: 1px solid #eee; padding-bottom: 5px; }
  .meta dt { color: #6b7280; font-size: 11.5px; }
  .meta dd { font-weight: 600; font-size: 12.5px; }

  .integrity { display: flex; gap: 13px; align-items: flex-start; padding: 14px 17px; border: 1.5px solid; margin-bottom: 18px; }
  .integrity.ok { border-color: #16a34a; background: #f0fdf4; }
  .integrity.bad { border-color: #dc2626; background: #fef2f2; }
  .mark { width: 26px; height: 26px; border-radius: 50%; display: grid; place-items: center; font-weight: 800; color: #fff; flex: 0 0 26px; }
  .ok .mark { background: #16a34a; }
  .bad .mark { background: #dc2626; }
  .ih { font-family: 'Fraunces', serif; font-size: 17px; font-weight: 700; }
  .ok .ih { color: #15803d; }
  .ix { font-size: 11.5px; color: #4b5563; margin-top: 3px; }

  table { width: 100%; border-collapse: collapse; font-size: 11px; margin: 4px 0 8px; }
  th { text-align: left; border-bottom: 1.5px solid #16181d; padding: 6px 7px; font-size: 9.5px; letter-spacing: .04em; text-transform: uppercase; color: #6b7280; }
  td { border-bottom: 1px solid #eee; padding: 5px 7px; vertical-align: top; }
  .nowrap { white-space: nowrap; }
  .type { font-family: 'IBM Plex Mono', monospace; font-weight: 700; font-size: 10px; }
  .t-allowed .type { color: #16a34a; }
  .t-flagged .type { color: #b45309; }
  .t-halted .type { color: #b91c1c; }
  .t-halted { background: #fef2f2; }
  .t-flagged { background: #fffbeb; }
  .legend { display: flex; gap: 18px; flex-wrap: wrap; font-size: 10.5px; color: #6b7280; margin-bottom: 16px; }
  .legend .d { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; }
  .legend .allowed { background: #16a34a; }
  .legend .flagged { background: #d97706; }
  .legend .halted { background: #dc2626; }
  .none { color: #6b7280; font-style: italic; }
  .anchorline { font-size: 10px; color: #6b7280; border-top: 1px solid #eee; padding-top: 10px; word-break: break-all; }
  .closing { font-size: 12px; color: #374151; margin-top: 12px; }
  .sigline { display: grid; grid-template-columns: 1fr 1fr; gap: 40px; margin-top: 32px; }
  .sigline .sl { border-top: 1px solid #16181d; margin-bottom: 5px; }
  .sigline > div { font-size: 11px; color: #6b7280; }
  .classification { margin-top: 16px; font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: .08em; text-transform: uppercase; color: #9ca3af; }
  @media (max-width: 900px) { .page { padding: 32px 22px; } .meta { grid-template-columns: 1fr; } }
</style>

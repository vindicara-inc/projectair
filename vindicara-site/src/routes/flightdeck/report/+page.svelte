<script lang="ts">
  import { mode } from '$lib/console/stores/mode';
  import { incidentsInRange, buildAnchor, makeReportId } from '$lib/console/forensics/report';
  import { auditFacets } from '$lib/console/forensics/audit';
  import type { BuiltScenario } from '$lib/console/forensics/types';
  import type { ReportAnchor } from '$lib/console/forensics/report';
  import ForensicReportDoc from '$lib/console/components/report/ForensicReportDoc.svelte';
  import AuditDoc from '$lib/console/components/report/AuditDoc.svelte';
  import Panel from '$lib/console/components/Panel.svelte';

  let tab = $state<'report' | 'audit'>('report');
  let from = $state('2026-05-11T00:00');
  let to = $state('2026-05-12T23:59');

  // forensic report
  let reportGen = $state<null | {
    incidents: BuiltScenario[];
    anchor: ReportAnchor;
    reportId: string;
    fromIso: string;
    toIso: string;
    generatedAt: string;
  }>(null);

  function generateReport() {
    tab = 'report';
    const incidents = incidentsInRange(from, to);
    reportGen = {
      incidents,
      anchor: buildAnchor(incidents, to),
      reportId: makeReportId(from),
      fromIso: from,
      toIso: to,
      generatedAt: new Date().toISOString()
    };
  }

  // query-driven audit
  const facets = auditFacets();
  let patient = $state('all');
  let agent = $state('all');
  let department = $state('all');
  let auditGeneratedAt = $state('');

  function openAudit() {
    tab = 'audit';
    auditGeneratedAt = new Date().toISOString();
  }

  let auditFilters = $derived({ patient, agent, department, from, to });
  let auditAnchor = $derived(buildAnchor(incidentsInRange(from, to), to));
  let auditReportId = $derived(makeReportId(from));
  let canPrint = $derived(tab === 'audit' || (tab === 'report' && reportGen !== null));

  function print() {
    setTimeout(() => window.print(), 60);
  }
</script>

{#if $mode === 'live'}
  <Panel>
    <div class="empty">
      <div class="eh">Reporting runs on recorded incidents</div>
      <p>Live Mode isn’t connected to a forensic source here. Switch to <b>Demo Mode</b> to generate a tamper-evident report or audit.</p>
    </div>
  </Panel>
{:else}
  <Panel klass="controls no-print">
    <div class="ph">
      <h3><span class="acc" style="background:var(--teal)"></span>{tab === 'audit' ? 'HIPAA audit trail' : 'Tamper-evident report'}</h3>
      <span class="hint">for court · regulators · OCR audit</span>
    </div>

    {#if tab === 'audit'}
      <div class="row filters">
        <label>Patient
          <select bind:value={patient}>
            <option value="all">All patients</option>
            {#each facets.patients as p}<option value={p}>{p}</option>{/each}
          </select>
        </label>
        <label>Agent
          <select bind:value={agent}>
            <option value="all">All agents</option>
            {#each facets.agents as a}<option value={a}>{a}</option>{/each}
          </select>
        </label>
        <label>Department
          <select bind:value={department}>
            <option value="all">All departments</option>
            {#each facets.departments as d}<option value={d}>{d}</option>{/each}
          </select>
        </label>
      </div>
    {/if}

    <div class="row">
      <label>From<input type="datetime-local" bind:value={from} /></label>
      <label>To<input type="datetime-local" bind:value={to} /></label>
      <button class="btn ok" onclick={generateReport}>Generate report</button>
      <button class="btn audit" onclick={openAudit}>Audit · HIPAA</button>
      {#if canPrint}<button class="btn" onclick={print}>Export PDF</button>{/if}
    </div>
    <div class="status">
      {#if tab === 'audit'}
        Query-driven audit trail — filter by patient, agent, department, and date, then <b>Export PDF</b> for an OCR audit. Every action (allowed, flagged, halted) is shown with whole-trail integrity.
      {:else if reportGen}
        Report <b>{reportGen.reportId}</b> · {reportGen.incidents.length} incidents in range · all chains verified intact. Use <b>Export PDF</b> for a filed copy.
      {:else}
        Set a date range and generate a court-ready forensic report, or switch to the HIPAA audit trail.
      {/if}
    </div>
  </Panel>

  {#if tab === 'audit'}
    <AuditDoc filters={auditFilters} reportId={auditReportId} generatedAt={auditGeneratedAt} anchor={auditAnchor} />
  {:else if reportGen}
    {#if reportGen.incidents.length === 0}
      <Panel><div class="empty"><div class="eh">No incidents in this period</div><p>Widen the date range and generate again.</p></div></Panel>
    {:else}
      <ForensicReportDoc
        incidents={reportGen.incidents}
        anchor={reportGen.anchor}
        reportId={reportGen.reportId}
        fromIso={reportGen.fromIso}
        toIso={reportGen.toIso}
        generatedAt={reportGen.generatedAt}
      />
    {/if}
  {/if}
{/if}

<style>
  :global(.controls) { padding: 20px 24px; }
  .row { display: flex; align-items: flex-end; gap: 14px; flex-wrap: wrap; }
  .filters { margin-bottom: 14px; }
  label { display: flex; flex-direction: column; gap: 6px; font-family: var(--mono); font-size: 10px; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); }
  input, select { padding: 9px 12px; background: rgba(0,0,0,.32); border: 1px solid var(--stroke); color: var(--ink); font-family: var(--mono); font-size: 13px; color-scheme: dark; min-width: 150px; }
  input:focus, select:focus { outline: none; border-color: rgba(72,230,164,.5); }
  .row .btn { padding: 10px 16px; font-size: 12px; }
  .row .btn.audit { border-color: rgba(109,181,255,.4); background: rgba(109,181,255,.12); color: #bcd6ff; }
  .status { margin-top: 14px; font-size: 12.5px; color: var(--muted); max-width: 80ch; }
  .status b { color: var(--ink); }
  .empty { padding: 30px 24px; text-align: center; }
  .eh { font-family: var(--display); font-size: 20px; font-weight: 600; }
  .empty p { font-size: 13.5px; color: var(--muted); line-height: 1.6; max-width: 60ch; margin: 12px auto 0; }
  .empty b { color: var(--ink); }
</style>

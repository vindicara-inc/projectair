<script lang="ts">
  import type { AgDRRecord, BuiltScenario, VerificationResult } from '$lib/console/forensics/types';
  import { verifyChain } from '$lib/console/forensics/crypto';
  import {
    buildForensicReport,
    reportToJson,
    reportToCef,
    downloadText,
    SIEM_TARGETS
  } from '$lib/console/forensics/exports';

  let {
    scenario,
    chain,
    verification = null
  }: { scenario: BuiltScenario; chain: AgDRRecord[]; verification?: VerificationResult | null } = $props();

  let note = $state('');

  function buildReport() {
    const v = verification ?? verifyChain(chain);
    return buildForensicReport(scenario, chain, v, new Date().toISOString());
  }

  function exportJson() {
    downloadText(`projectair-${scenario.id}.json`, reportToJson(buildReport()), 'application/json');
    note = 'Downloaded the JSON forensic report (the fixture artifact).';
  }
  function exportCef() {
    downloadText(`projectair-${scenario.id}.cef`, reportToCef(buildReport()), 'text/plain');
    note = 'Downloaded CEF events — one per finding, ready for SIEM ingestion.';
  }
  function printPdf() {
    note = 'Opening the print dialog — choose “Save as PDF” for a court/regulator copy.';
    setTimeout(() => window.print(), 60);
  }
</script>

<div class="export">
  <div class="btns">
    <button class="btn" onclick={exportJson}>Export JSON</button>
    <button class="btn" onclick={printPdf}>Print / Save as PDF</button>
    <button class="btn" onclick={exportCef}>Export CEF</button>
  </div>
  <div class="siem">
    <span class="lab">SIEM targets</span>
    {#each SIEM_TARGETS as t, i}<span class="t">{t}</span>{#if i < SIEM_TARGETS.length - 1}<span class="sep">·</span>{/if}{/each}
  </div>
  {#if note}<div class="note">{note}</div>{/if}
</div>

<style>
  .export { display: flex; flex-direction: column; gap: 13px; }
  .btns { display: flex; gap: 10px; flex-wrap: wrap; }
  .btns .btn { padding: 9px 16px; font-size: 12px; }
  .siem { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 11.5px; color: var(--muted); }
  .lab { font-family: var(--mono); font-size: 9.5px; letter-spacing: .12em; text-transform: uppercase; color: var(--faint); }
  .sep { color: var(--faint); }
  .note { font-size: 12px; color: #bff5df; }
</style>

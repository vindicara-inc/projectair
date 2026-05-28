<script lang="ts">
  import { replayStore } from '$lib/stores/replay.svelte';
  import { verifierStore } from '$lib/stores/verifier.svelte';
  import { findingsStore } from '$lib/stores/findings.svelte';

  let collapsed = $state(false);

  const hasData = $derived(replayStore.emitted.length > 0);

  function exportJSON(): void {
    const data = {
      exported_at: new Date().toISOString(),
      chain_length: replayStore.emitted.length,
      integrity_score: verifierStore.integrityScore,
      findings: findingsStore.all,
      records: replayStore.emitted,
      verification: verifierStore.entries
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `air-evidence-${dateSuffix()}.json`);
  }

  function exportCSV(): void {
    const headers = ['detector_id', 'severity', 'title', 'description', 'step_index', 'timestamp'];
    const rows = findingsStore.all.map(f => {
      const rec = replayStore.emitted[f.step_index];
      return [
        f.detector_id,
        f.severity,
        f.title,
        f.description,
        f.step_index,
        rec?.timestamp ?? ''
      ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(',');
    });
    const csv = [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    downloadBlob(blob, `air-findings-${dateSuffix()}.csv`);
  }

  function exportPDF(): void {
    const records = replayStore.emitted;
    const findings = findingsStore.all;
    const entries = verifierStore.entries;
    const integrity = verifierStore.integrityScore;
    const start = records[0]?.timestamp ?? '';
    const end = records[records.length - 1]?.timestamp ?? '';

    // Collect unique signer keys
    const signerKeys = [...new Set(records.map(r => r.signer_key))];

    const findingsRows = findings.map(f => {
      const rec = records[f.step_index];
      return `<tr>
        <td>${esc(f.detector_id)}</td>
        <td><span class="sev-${f.severity}">${esc(f.severity)}</span></td>
        <td>${esc(f.title)}</td>
        <td>${esc(f.description)}</td>
        <td>${f.step_index}</td>
        <td>${esc(rec?.timestamp ?? '')}</td>
      </tr>`;
    }).join('');

    const verifyRows = entries.map(e => `<tr>
      <td>${e.index}</td>
      <td>${esc(e.kind)}</td>
      <td><code>${esc(e.contentHashShort)}</code></td>
      <td class="status-${e.status}">${esc(e.status.toUpperCase())}</td>
      <td>${esc(e.reason ?? '')}</td>
    </tr>`).join('');

    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>AIR Forensic Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 900px; margin: 0 auto; padding: 40px 20px; color: #1a1a1a; }
  h1 { font-size: 22px; border-bottom: 2px solid #dc2626; padding-bottom: 8px; }
  h2 { font-size: 16px; margin-top: 32px; color: #333; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; margin: 12px 0; }
  th, td { border: 1px solid #ddd; padding: 6px 8px; text-align: left; }
  th { background: #f5f5f5; font-weight: 600; }
  code { background: #f0f0f0; padding: 1px 4px; font-size: 11px; }
  .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 12px 0; }
  .meta-item { background: #fafafa; padding: 8px 12px; border: 1px solid #eee; }
  .meta-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: #666; }
  .meta-value { font-size: 14px; font-weight: 600; margin-top: 2px; }
  .sev-critical { color: #dc2626; font-weight: 700; }
  .sev-high { color: #ea580c; font-weight: 600; }
  .sev-medium { color: #ca8a04; }
  .status-ok { color: #16a34a; font-weight: 600; }
  .status-tampered, .status-broken_link { color: #dc2626; font-weight: 600; }
  .signer-key { font-family: monospace; font-size: 10px; word-break: break-all; }
  @media print { body { padding: 20px; } }
</style></head><body>
<h1>AIR Forensic Report</h1>
<p style="color:#666; font-size:12px;">Generated ${new Date().toISOString()}</p>

<h2>Chain Summary</h2>
<div class="meta-grid">
  <div class="meta-item"><div class="meta-label">Total Records</div><div class="meta-value">${records.length}</div></div>
  <div class="meta-item"><div class="meta-label">Integrity Score</div><div class="meta-value">${integrity}%</div></div>
  <div class="meta-item"><div class="meta-label">Time Range Start</div><div class="meta-value">${esc(start)}</div></div>
  <div class="meta-item"><div class="meta-label">Time Range End</div><div class="meta-value">${esc(end)}</div></div>
  <div class="meta-item"><div class="meta-label">Total Findings</div><div class="meta-value">${findings.length}</div></div>
  <div class="meta-item"><div class="meta-label">Signer Keys</div><div class="meta-value">${signerKeys.length}</div></div>
</div>

<h2>Findings (${findings.length})</h2>
${findings.length > 0
  ? `<table><thead><tr><th>Detector</th><th>Severity</th><th>Title</th><th>Description</th><th>Step</th><th>Timestamp</th></tr></thead><tbody>${findingsRows}</tbody></table>`
  : '<p style="color:#666;">No findings detected.</p>'}

<h2>Verification Ledger (${entries.length} records)</h2>
${entries.length > 0
  ? `<table><thead><tr><th>#</th><th>Kind</th><th>Hash</th><th>Status</th><th>Reason</th></tr></thead><tbody>${verifyRows}</tbody></table>`
  : '<p style="color:#666;">No records verified.</p>'}

<h2>Signer Keys</h2>
${signerKeys.map(k => `<p class="signer-key">${esc(k)}</p>`).join('')}

<h2>Regulatory Framework Mapping</h2>
<table><thead><tr><th>Framework</th><th>Reference</th><th>Status</th></tr></thead><tbody>
<tr><td>EU AI Act</td><td>Article 72</td><td>Chain integrity ${integrity === 100 ? 'verified' : 'degraded'}</td></tr>
<tr><td>NIST AI RMF</td><td>MAP 1.5, MEASURE 2.6</td><td>${findings.length} findings logged</td></tr>
<tr><td>SOC 2 AI</td><td>CC7.2, CC8.1</td><td>Audit trail ${records.length > 0 ? 'present' : 'missing'}</td></tr>
</tbody></table>

</body></html>`;

    const w = window.open('', '_blank');
    if (w) {
      w.document.write(html);
      w.document.close();
    }
  }

  function esc(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function dateSuffix(): string {
    return new Date().toISOString().slice(0, 10);
  }

  function downloadBlob(blob: Blob, filename: string): void {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }
</script>

{#if hasData}
  <div>
    <button class="section-label w-full text-left cursor-pointer" onclick={() => collapsed = !collapsed}>
      Export Reports
      <span class="ml-auto" style="color: var(--color-text-dim);">{collapsed ? '+' : '-'}</span>
    </button>

    {#if !collapsed}
      <div class="stark-panel p-4 flex flex-col gap-2">
        <button class="btn-primary w-full text-xs" onclick={exportJSON}>
          JSON Evidence Pack
        </button>
        <button class="btn-secondary w-full text-xs" onclick={exportPDF}>
          PDF Summary (printable)
        </button>
        <button class="btn-secondary w-full text-xs" onclick={exportCSV}>
          CSV Findings Export
        </button>
        <span class="text-xs mt-1" style="color: var(--color-text-dim); font-family: var(--font-ui);">
          {replayStore.emitted.length} records, {findingsStore.all.length} findings
        </span>
      </div>
    {/if}
  </div>
{/if}

<script lang="ts">
  import { siemStore, type SiemVendor } from '../../stores/siem.svelte.ts';
  import { replayStore } from '../../stores/replay.svelte.ts';
  import { findingsStore } from '../../stores/findings.svelte.ts';
  import { verifierStore } from '../../stores/verifier.svelte.ts';
  import { cloudSession } from '../../stores/cloud_session.svelte.ts';

  interface ApprovalItem {
    id: string;
    agent: string;
    description: string;
    policy: string;
    severity?: string;
    timestamp?: string;
  }

  let {
    approvalItems = [],
    onApprove,
    onDeny
  }: {
    approvalItems: ApprovalItem[];
    onApprove?: (id: string) => void;
    onDeny?: (id: string) => void;
  } = $props();

  let expandedVendor = $state<string | null>(null);

  const secretFields = new Set(['hec_token', 'api_key', 'shared_key', 'webhook_url']);

  function toggleExpand(id: string): void {
    expandedVendor = expandedVendor === id ? null : id;
  }

  function getSeverityClass(sev: string | undefined): string {
    const s = (sev ?? 'Critical').toLowerCase();
    if (s === 'critical') return 'badge-critical';
    if (s === 'high') return 'badge-warning';
    return 'badge-success';
  }

  function testConnection(vendor: SiemVendor): void {
    if (cloudSession.isConnected && cloudSession.client) {
      const baseUrl = cloudSession.baseUrl;
      const headers: Record<string, string> = { Authorization: `Bearer ${cloudSession.client.apiKey}` };
      void siemStore.testConnection(vendor.id, baseUrl, headers);
    } else {
      const { valid, missing } = siemStore.validateConfig(vendor.id);
      siemStore.setStatus(vendor.id, valid ? 'ok' : 'error', valid ? null : `Missing: ${missing.join(', ')}`);
    }
  }

  function pushToVendor(vendor: SiemVendor): void {
    if (!cloudSession.isConnected || !cloudSession.client) {
      siemStore.setStatus(vendor.id, 'error', 'Connect to AIR Cloud first');
      return;
    }
    const baseUrl = cloudSession.baseUrl;
    const headers: Record<string, string> = { Authorization: `Bearer ${cloudSession.client.apiKey}` };
    void siemStore.pushFindings(vendor.id, baseUrl, headers, findingsStore.all, replayStore.emitted.length);
  }

  function pushToAll(): void {
    if (!cloudSession.isConnected || !cloudSession.client) return;
    const baseUrl = cloudSession.baseUrl;
    const headers: Record<string, string> = { Authorization: `Bearer ${cloudSession.client.apiKey}` };
    void siemStore.pushToAllEnabled(baseUrl, headers, findingsStore.all, replayStore.emitted.length);
  }

  function statusDot(status: SiemVendor['lastStatus']): string {
    if (status === 'ok') return 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.6)]';
    if (status === 'error') return 'bg-red-400 shadow-[0_0_6px_rgba(248,113,113,0.6)]';
    return 'bg-white/20';
  }

  function dateSuffix(): string { return new Date().toISOString().slice(0, 10); }

  function downloadBlob(blob: Blob, filename: string): void {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportJSON(): void {
    const data = {
      exported_at: new Date().toISOString(),
      chain_length: replayStore.emitted.length,
      integrity_score: verifierStore.integrityScore,
      findings: findingsStore.all,
      records: replayStore.emitted
    };
    downloadBlob(
      new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }),
      `air-evidence-${dateSuffix()}.json`
    );
  }

  function exportCSV(): void {
    const headers = ['detector_id', 'severity', 'title', 'description', 'step_index', 'timestamp'];
    const rows = findingsStore.all.map((f) => {
      const rec = replayStore.emitted[f.step_index];
      return [f.detector_id, f.severity, f.title, f.description, f.step_index, rec?.timestamp ?? '']
        .map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',');
    });
    downloadBlob(
      new Blob([[headers.join(','), ...rows].join('\n')], { type: 'text/csv' }),
      `air-findings-${dateSuffix()}.csv`
    );
  }

  function exportPDF(): void {
    const w = window.open('', '_blank');
    if (!w) return;
    const findings = findingsStore.all;
    const records = replayStore.emitted;
    const integrity = verifierStore.integrityScore;
    const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const fRows = findings.map((f) =>
      `<tr><td>${esc(f.detector_id)}</td><td>${esc(f.severity)}</td><td>${esc(f.title)}</td><td>${f.step_index}</td></tr>`
    ).join('');
    w.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>AIR Evidence Export</title>
<style>body{font-family:system-ui;max-width:800px;margin:0 auto;padding:40px 20px}
h1{font-size:20px;border-bottom:2px solid #dc2626;padding-bottom:6px}
table{width:100%;border-collapse:collapse;font-size:12px;margin:12px 0}
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left}th{background:#f5f5f5;font-weight:600}
@media print{body{padding:20px}}</style></head><body>
<h1>AIR Forensic Export</h1><p style="color:#666;font-size:12px">Generated ${new Date().toISOString()}</p>
<p>Records: ${records.length} | Findings: ${findings.length} | Integrity: ${integrity}%</p>
${findings.length > 0 ? `<table><thead><tr><th>Detector</th><th>Severity</th><th>Title</th><th>Step</th></tr></thead><tbody>${fRows}</tbody></table>` : '<p>No findings.</p>'}
</body></html>`);
    w.document.close();
  }

  const hasExportData = $derived(replayStore.emitted.length > 0);
</script>

<div class="flex flex-col h-full gap-3 overflow-auto custom-scroll p-1">
  <!-- Approval Queue -->
  <section class="glass-panel rounded-2xl p-4">
    <div class="flex items-center justify-between mb-3">
      <h3 class="hud-label">APPROVAL QUEUE</h3>
      <span class="font-mono text-[10px] text-white/40">{approvalItems.length} PENDING</span>
    </div>
    {#each approvalItems as item (item.id)}
      <div class="glass-panel rounded-xl p-4 mb-2 border border-white/5">
        <div class="flex justify-between items-start gap-3">
          <div class="min-w-0">
            <div class="font-mono text-[10px] text-white/40">AGENT {item.agent}</div>
            <div class="text-sm font-medium text-white mt-1 leading-snug">{item.description}</div>
            <div class="text-xs text-white/50 mt-1">Policy: <span class="font-mono">{item.policy}</span></div>
          </div>
          <div class="flex-shrink-0 text-right">
            {#if item.severity}
              <span class={getSeverityClass(item.severity)}>{item.severity}</span>
            {/if}
            {#if item.timestamp}
              <div class="text-[10px] text-white/30 mt-1 font-mono">{item.timestamp}</div>
            {/if}
          </div>
        </div>
        <div class="flex gap-2 mt-3">
          <button
            onclick={() => onApprove?.(item.id)}
            class="flex-1 py-2 text-xs font-semibold rounded-lg bg-teal-500/90 hover:bg-teal-400 text-white transition-all active:scale-95"
          >Approve &amp; Sign</button>
          <button
            onclick={() => onDeny?.(item.id)}
            class="flex-1 py-2 text-xs font-semibold rounded-lg bg-violet-600/90 hover:bg-violet-500 text-white transition-all active:scale-95"
          >Deny &amp; Sign</button>
        </div>
      </div>
    {:else}
      <div class="text-center py-6 text-white/30 text-xs font-mono">No pending approvals</div>
    {/each}
  </section>

  <!-- SIEM Integrations -->
  <section class="glass-panel rounded-2xl p-4">
    <h3 class="hud-label mb-3">SIEM INTEGRATIONS</h3>
    {#if siemStore.enabledVendors.length > 0 && findingsStore.all.length > 0}
      <button onclick={pushToAll}
        class="w-full mb-3 py-2 text-xs font-semibold rounded-lg bg-gradient-to-r from-cyan-500/20 to-violet-500/20 border border-cyan-400/30 text-cyan-300 hover:from-cyan-500/30 hover:to-violet-500/30 transition-all active:scale-[0.98]">
        Push {findingsStore.all.length} findings to {siemStore.enabledVendors.length} enabled vendor{siemStore.enabledVendors.length > 1 ? 's' : ''}
      </button>
    {/if}
    {#each siemStore.vendors as vendor (vendor.id)}
      <div class="mb-2">
        <!-- svelte-ignore a11y_no_static_element_interactions -->
        <!-- svelte-ignore a11y_click_events_have_key_events -->
        <div
          onclick={() => toggleExpand(vendor.id)}
          role="button" tabindex="0"
          class="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer bg-white/[0.03] hover:bg-white/[0.06] transition-colors"
        >
          <button
            onclick={(e: MouseEvent) => { e.stopPropagation(); siemStore.toggle(vendor.id); }}
            class="relative w-8 h-4 rounded-full transition-colors flex-shrink-0 {vendor.enabled ? 'bg-teal-500/70' : 'bg-white/10'}"
            aria-label="Toggle {vendor.name}"
          >
            <span class="absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white transition-transform {vendor.enabled ? 'translate-x-4' : 'translate-x-0'}"></span>
          </button>
          <span class="text-xs font-medium text-white/80 flex-1">{vendor.name}</span>
          <span class="w-2 h-2 rounded-full flex-shrink-0 {statusDot(vendor.lastStatus)}"></span>
          <span class="text-white/30 text-xs transition-transform {expandedVendor === vendor.id ? 'rotate-180' : ''}">&#9662;</span>
        </div>
        {#if expandedVendor === vendor.id}
          <div class="px-3 pt-2 pb-3 space-y-2 border-l border-white/5 ml-4 mt-1">
            {#each Object.keys(vendor.config) as field}
              <label class="block">
                <span class="text-[10px] font-mono text-white/40 uppercase tracking-wider">{field}</span>
                <input
                  type={secretFields.has(field) ? 'password' : 'text'}
                  value={vendor.config[field]}
                  oninput={(e: Event) => siemStore.updateConfig(vendor.id, field, (e.target as HTMLInputElement).value)}
                  class="w-full mt-0.5 px-2.5 py-1.5 rounded-md text-xs font-mono bg-black/40 border border-white/10 text-white/80 focus:border-cyan-400/40 focus:outline-none transition-colors"
                  placeholder={field}
                />
              </label>
            {/each}
            <div class="flex gap-2 mt-1">
              <button
                onclick={() => testConnection(vendor)}
                class="flex-1 py-1.5 text-[10px] font-semibold tracking-wider uppercase rounded-md border border-cyan-400/20 text-cyan-400/80 hover:bg-cyan-400/10 hover:border-cyan-400/40 transition-all"
                disabled={vendor.lastStatus === 'testing'}
              >{vendor.lastStatus === 'testing' ? 'Testing...' : 'Test Connection'}</button>
              <button
                onclick={() => pushToVendor(vendor)}
                class="flex-1 py-1.5 text-[10px] font-semibold tracking-wider uppercase rounded-md border border-violet-400/20 text-violet-400/80 hover:bg-violet-400/10 hover:border-violet-400/40 transition-all"
                disabled={vendor.lastStatus === 'pushing' || findingsStore.all.length === 0}
              >{vendor.lastStatus === 'pushing' ? 'Pushing...' : 'Push Findings'}</button>
            </div>
            {#if vendor.lastStatus === 'error' && vendor.lastError}
              <div class="text-[10px] text-red-400 font-mono mt-1">{vendor.lastError}</div>
            {/if}
            {#if vendor.lastStatus === 'ok'}
              <div class="text-[10px] text-emerald-400 font-mono mt-1">
                Connected
                {#if vendor.lastPushAt}
                  &bull; Last push: {new Date(vendor.lastPushAt).toLocaleTimeString()} ({vendor.eventsSent} events total)
                {/if}
              </div>
            {/if}
          </div>
        {/if}
      </div>
    {/each}
  </section>

  <!-- Export -->
  <section class="glass-panel rounded-2xl p-4">
    <h3 class="hud-label mb-3">EXPORT</h3>
    {#if hasExportData}
      <div class="flex flex-col gap-2">
        <button onclick={exportJSON}
          class="w-full py-2.5 text-xs font-semibold rounded-lg bg-cyan-500/10 border border-cyan-400/20 text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400/40 transition-all active:scale-[0.98]"
        >Export JSON</button>
        <button onclick={exportCSV}
          class="w-full py-2.5 text-xs font-semibold rounded-lg bg-violet-500/10 border border-violet-400/20 text-violet-300 hover:bg-violet-500/20 hover:border-violet-400/40 transition-all active:scale-[0.98]"
        >Export CSV</button>
        <button onclick={exportPDF}
          class="w-full py-2.5 text-xs font-semibold rounded-lg bg-indigo-500/10 border border-indigo-400/20 text-indigo-300 hover:bg-indigo-500/20 hover:border-indigo-400/40 transition-all active:scale-[0.98]"
        >Export PDF</button>
        <span class="text-[10px] text-white/30 font-mono mt-1 text-center">
          {replayStore.emitted.length} records, {findingsStore.all.length} findings
        </span>
      </div>
    {:else}
      <div class="text-center py-4 text-white/30 text-xs font-mono">Load a chain to enable exports</div>
    {/if}
  </section>
</div>

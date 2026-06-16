<script lang="ts">
  import type { AgDRRecord, Finding } from '../../agdr/types.ts';
  import { inferAgentId, describeAction } from '../../agents/derive.ts';
  import type { LedgerEntry } from '../../stores/verifier.svelte.ts';

  let {
    record,
    index = 0,
    findings = [],
    verifierEntry,
    onClose,
  }: {
    record: AgDRRecord;
    index: number;
    findings: Finding[];
    verifierEntry?: LedgerEntry | null;
    onClose?: () => void;
  } = $props();

  const agentId = $derived(inferAgentId(record, index));
  const action = $derived(describeAction(record));

  function formatTs(ts: string): string {
    try { return new Date(ts).toISOString().replace('T', ' ').slice(0, 23); } catch { return ts; }
  }

  function sevColor(s: string): string {
    if (s === 'critical') return '#ff5468';
    if (s === 'high') return '#ffb547';
    return '#6effb3';
  }

  function truncate(s: string, n: number): string {
    return s.length > n ? s.slice(0, n) + '...' : s;
  }
</script>

<div class="glass-panel p-4 overflow-auto custom-scroll" style="animation: fade-up 0.2s ease;">
  <div class="flex items-center justify-between mb-3">
    <div class="hud-label" style="font-size: 9px;">RECORD #{index}</div>
    <button onclick={onClose} class="text-white/30 hover:text-white/60 text-sm transition-colors">&times;</button>
  </div>

  <div class="grid grid-cols-2 gap-x-4 gap-y-2 text-[11px] mb-4">
    <div>
      <span class="text-white/30 font-mono text-[9px]">TIMESTAMP</span>
      <div class="font-mono text-white/80">{formatTs(record.timestamp)}</div>
    </div>
    <div>
      <span class="text-white/30 font-mono text-[9px]">AGENT</span>
      <div class="font-mono text-nebula-accent">{agentId}</div>
    </div>
    <div>
      <span class="text-white/30 font-mono text-[9px]">KIND</span>
      <div class="font-mono text-white/80">{record.kind}</div>
    </div>
    <div>
      <span class="text-white/30 font-mono text-[9px]">ACTION</span>
      <div class="font-mono text-white/80">{action}</div>
    </div>
    <div>
      <span class="text-white/30 font-mono text-[9px]">STEP ID</span>
      <div class="font-mono text-white/50 text-[9px]">{record.step_id}</div>
    </div>
    <div>
      <span class="text-white/30 font-mono text-[9px]">CHAIN STATUS</span>
      {#if verifierEntry}
        <div class="font-mono" style="color: {verifierEntry.status === 'ok' ? '#6effb3' : '#ff5468'};">
          {verifierEntry.status.toUpperCase()}
          {#if verifierEntry.reason}
            <span class="text-white/30 text-[9px]"> ({verifierEntry.reason})</span>
          {/if}
        </div>
      {:else}
        <div class="font-mono text-white/30">pending</div>
      {/if}
    </div>
  </div>

  <!-- Payload -->
  {#if record.payload}
    <div class="mb-3">
      <span class="text-white/30 font-mono text-[9px]">PAYLOAD</span>
      {#if record.payload.prompt}
        <div class="mt-1 p-2 bg-white/[0.03] border border-white/5 text-[11px] text-white/70 font-mono leading-relaxed">
          <span class="text-violet-400 text-[9px]">PROMPT</span>
          <div class="mt-0.5">{truncate(record.payload.prompt, 500)}</div>
        </div>
      {/if}
      {#if record.payload.response}
        <div class="mt-1 p-2 bg-white/[0.03] border border-white/5 text-[11px] text-white/70 font-mono leading-relaxed">
          <span class="text-violet-400 text-[9px]">RESPONSE</span>
          <div class="mt-0.5">{truncate(record.payload.response, 500)}</div>
        </div>
      {/if}
      {#if record.payload.tool_name}
        <div class="mt-1 p-2 bg-white/[0.03] border border-white/5 text-[11px] text-white/70 font-mono">
          <span class="text-cyan-400 text-[9px]">TOOL</span>
          <div class="mt-0.5">{record.payload.tool_name}</div>
          {#if record.payload.tool_args}
            <div class="mt-1 text-[10px] text-white/50">{JSON.stringify(record.payload.tool_args, null, 2)}</div>
          {/if}
        </div>
      {/if}
      {#if record.payload.tool_output}
        <div class="mt-1 p-2 bg-white/[0.03] border border-white/5 text-[11px] text-white/70 font-mono leading-relaxed">
          <span class="text-cyan-400 text-[9px]">TOOL OUTPUT</span>
          <div class="mt-0.5">{truncate(record.payload.tool_output, 500)}</div>
        </div>
      {/if}
    </div>
  {/if}

  <!-- Findings at this step -->
  {#if findings.length > 0}
    <div class="mb-3">
      <span class="text-white/30 font-mono text-[9px]">FINDINGS ({findings.length})</span>
      {#each findings as f}
        <div class="mt-1 p-2 border text-[11px] flex items-start gap-2" style="border-color: {sevColor(f.severity)}20; background: {sevColor(f.severity)}08;">
          <div class="w-2 h-2 rounded-full mt-0.5 shrink-0" style="background: {sevColor(f.severity)}; box-shadow: 0 0 4px {sevColor(f.severity)};"></div>
          <div>
            <div class="font-medium text-white/80">{f.title}</div>
            <div class="text-white/50 text-[10px] mt-0.5">{f.description}</div>
            <div class="flex gap-2 mt-1 text-[9px] font-mono">
              <span style="color: {sevColor(f.severity)};">{f.severity.toUpperCase()}</span>
              <span class="text-white/30">{f.detector_id}</span>
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}

  <!-- Crypto evidence -->
  <div>
    <span class="text-white/30 font-mono text-[9px]">CRYPTOGRAPHIC EVIDENCE</span>
    <div class="mt-1 p-2 bg-white/[0.03] border border-white/5 text-[9px] font-mono text-white/40 space-y-1">
      <div>content_hash: {record.content_hash}</div>
      <div>prev_hash: {record.prev_hash}</div>
      <div>signature: {record.signature?.slice(0, 32)}...</div>
      <div>signer_key: {record.signer_key?.slice(0, 32)}...</div>
    </div>
  </div>
</div>

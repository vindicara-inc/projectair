<script lang="ts">
  import type { AgDRRecord, Finding } from '$lib/agdr/types';
  import type { LedgerEntry } from '$lib/stores/verifier.svelte';
  import EventTimeline from './EventTimeline.svelte';
  import WaveformPanel from './WaveformPanel.svelte';
  import RecordDetail from './RecordDetail.svelte';

  let {
    records = [],
    findings = [],
    verifierEntries = [],
    criticalCount = 0,
    highCount = 0,
    mediumCount = 0,
    agentCount = 0,
    recordCount = 0,
    agentActivityValues = [],
    focusedIndex = -1,
    onSelectRecord,
  }: {
    records: AgDRRecord[];
    findings: Finding[];
    verifierEntries: LedgerEntry[];
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    agentCount: number;
    recordCount: number;
    agentActivityValues: number[];
    focusedIndex?: number;
    onSelectRecord?: (index: number) => void;
  } = $props();

  let selectedIndex = $state<number | null>(null);

  const selectedRecord = $derived(selectedIndex !== null ? records[selectedIndex] ?? null : null);
  const selectedFindings = $derived(
    selectedIndex !== null ? findings.filter(f => f.step_index === selectedIndex) : []
  );
  const selectedVerifier = $derived(
    selectedIndex !== null ? verifierEntries.find(e => e.index === selectedIndex) ?? null : null
  );

  function handleSelect(i: number): void {
    selectedIndex = selectedIndex === i ? null : i;
    onSelectRecord?.(i);
  }

  const severityBoxes = $derived([
    { label: 'CRITICAL', count: criticalCount, color: '#ef4444', shadow: 'rgba(239,68,68,0.5)' },
    { label: 'HIGH', count: highCount, color: '#eab308', shadow: 'rgba(234,179,8,0.5)' },
    { label: 'MEDIUM', count: mediumCount, color: '#22c55e', shadow: 'rgba(34,197,94,0.5)' },
  ]);
</script>

<div class="flex h-full gap-3">
  <!-- Left: Timeline + Summary -->
  <div class="flex flex-col flex-1 min-w-0 gap-3">
    <div class="glass-panel scan-line p-3">
      <div class="flex items-center justify-between mb-2">
        <span class="hud-label" style="font-size: 8px;">DETECTION SUMMARY</span>
        <span class="font-mono text-[9px] text-white/30">AGENTS: {agentCount} | RECORDS: {recordCount}</span>
      </div>
      <div class="flex gap-3">
        {#each severityBoxes as box}
          <div class="flex-1 border border-white/10 bg-white/[0.03] p-2 text-center">
            <div class="font-mono text-xl font-bold" style="color: {box.color}; text-shadow: 0 0 8px {box.shadow};">{box.count}</div>
            <div class="text-[7px] font-mono mt-0.5" style="color: {box.color};">{box.label}</div>
          </div>
        {/each}
        <div class="flex-1">
          <WaveformPanel title="ACTIVITY" barCount={32} height={38} color="#d946ef" values={agentActivityValues} />
        </div>
      </div>
    </div>

    <div class="flex-1 min-h-0">
      <EventTimeline
        {records} {findings} {verifierEntries}
        focusedIndex={selectedIndex ?? focusedIndex}
        onSelectRecord={handleSelect}
      />
    </div>
  </div>

  <!-- Right: Record Detail (shows when a record is selected) -->
  {#if selectedRecord && selectedIndex !== null}
    <div class="w-80 shrink-0 overflow-auto custom-scroll">
      <RecordDetail
        record={selectedRecord}
        index={selectedIndex}
        findings={selectedFindings}
        verifierEntry={selectedVerifier}
        onClose={() => selectedIndex = null}
      />
    </div>
  {/if}
</div>

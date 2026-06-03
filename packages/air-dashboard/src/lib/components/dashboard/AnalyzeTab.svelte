<script lang="ts">
  import type { AgDRRecord } from '$lib/agdr/types';

  interface Incident {
    id: string;
    title: string;
    description: string;
    agentId: string;
    severity: string;
    detector: string;
    stepIndex: number;
    toolName: string;
    timestamp: string;
    finding: string;
  }

  let {
    incidents = [],
    records = [],
    onSelectIncident,
  }: {
    incidents: Incident[];
    records: AgDRRecord[];
    onSelectIncident?: (incident: Incident) => void;
  } = $props();

  let selectedIncident: Incident | null = $state(null);
  let severityFilter: string = $state('all');

  const filteredIncidents = $derived(
    severityFilter === 'all'
      ? incidents
      : incidents.filter((i) => i.severity.toLowerCase() === severityFilter)
  );

  function selectIncident(incident: Incident) {
    selectedIncident = incident;
    onSelectIncident?.(incident);
  }

  function severityColor(severity: string): string {
    const s = severity.toLowerCase();
    if (s === 'critical') return '#ff5468';
    if (s === 'high') return '#ffb547';
    return '#6effb3';
  }

  function severityDotClass(severity: string): string {
    const s = severity.toLowerCase();
    if (s === 'critical') return 'severity-dot critical';
    if (s === 'high') return 'severity-dot high';
    return 'severity-dot medium';
  }

  function severityBadgeClass(severity: string): string {
    const s = severity.toLowerCase();
    if (s === 'critical') return 'badge-critical';
    if (s === 'high') return 'badge-warning';
    return 'badge-success';
  }

  function matchedRecord(incident: Incident): AgDRRecord | undefined {
    return records[incident.stepIndex];
  }

  const filterButtons: { label: string; value: string }[] = [
    { label: 'All', value: 'all' },
    { label: 'Critical', value: 'critical' },
    { label: 'High', value: 'high' },
    { label: 'Medium', value: 'medium' },
  ];
</script>

<div class="flex h-full gap-3">
  <!-- Left: Incident list -->
  <div class="flex-1 glass-panel rounded-2xl p-4 overflow-auto custom-scroll flex flex-col">
    <span class="hud-label" style="color: var(--color-nebula-magenta); text-shadow: 0 0 8px rgba(217,70,239,0.4);">
      INCIDENT ANALYSIS
    </span>

    <!-- Filter row -->
    <div class="flex gap-1.5 mt-3 mb-3">
      {#each filterButtons as btn}
        <button
          onclick={() => (severityFilter = btn.value)}
          class="px-3 py-1 text-[10px] font-semibold uppercase tracking-widest border rounded transition-all
            {severityFilter === btn.value
              ? 'border-[var(--color-nebula-magenta)] text-[var(--color-nebula-magenta)] bg-[rgba(217,70,239,0.1)]'
              : 'border-white/10 text-white/40 hover:border-white/25 hover:text-white/60'}"
        >
          {btn.label}
        </button>
      {/each}
    </div>

    <!-- Incident cards -->
    <div class="space-y-2 flex-1">
      {#each filteredIncidents as incident (incident.id)}
        <button
          onclick={() => selectIncident(incident)}
          class="w-full text-left p-3 rounded-xl border transition-all group
            {selectedIncident?.id === incident.id
              ? 'border-[var(--color-nebula-magenta)]/40 bg-[rgba(217,70,239,0.06)]'
              : 'border-white/5 hover:border-white/15 bg-white/[0.02] hover:bg-white/[0.04]'}"
        >
          <div class="flex items-start gap-2.5">
            <div class={severityDotClass(incident.severity)} style="margin-top: 4px;"></div>
            <div class="flex-1 min-w-0">
              <div class="text-[12px] font-medium text-white/85 leading-snug">
                {incident.title}
              </div>
              <div class="text-[11px] text-white/50 mt-1 leading-tight line-clamp-2">
                {incident.description}
              </div>

              <div class="flex items-center gap-2 mt-2 flex-wrap">
                <span class={severityBadgeClass(incident.severity)}>
                  {incident.severity}
                </span>
                <span class="text-[10px] font-mono text-white/40">
                  {incident.agentId}
                </span>
                <span class="text-[10px] font-mono text-white/30">
                  {incident.detector}
                </span>
                <span class="text-[10px] font-mono text-white/25 ml-auto">
                  {incident.timestamp}
                </span>
              </div>
            </div>
          </div>

          <div
            class="mt-2 text-[10px] font-semibold tracking-wider uppercase text-[var(--color-nebula-magenta)]
              opacity-0 group-hover:opacity-100 transition-opacity text-right"
          >
            Investigate &rarr;
          </div>
        </button>
      {:else}
        <div class="text-center py-10 text-white/30 text-xs">No incidents match this filter</div>
      {/each}
    </div>
  </div>

  <!-- Right: Detail panel -->
  <div class="w-80 glass-panel rounded-2xl p-4 overflow-auto custom-scroll flex flex-col shrink-0">
    {#if selectedIncident}
      {@const rec = matchedRecord(selectedIncident)}

      <div class="text-[14px] font-semibold text-white leading-snug mb-4">
        {selectedIncident.title}
      </div>

      <!-- What happened -->
      <div class="mb-4">
        <span class="hud-label" style="font-size: 8px;">WHAT HAPPENED</span>
        <p class="text-[11px] text-white/60 mt-1.5 leading-relaxed">
          {selectedIncident.description}
        </p>
      </div>

      <!-- Agent -->
      <div class="mb-4">
        <span class="hud-label" style="font-size: 8px;">AGENT</span>
        <div class="mt-1.5 space-y-1">
          <div class="flex justify-between text-[11px]">
            <span class="text-white/40">Agent ID</span>
            <span class="font-mono text-white/70">{selectedIncident.agentId}</span>
          </div>
          <div class="flex justify-between text-[11px]">
            <span class="text-white/40">Tool</span>
            <span class="font-mono text-white/70">{selectedIncident.toolName}</span>
          </div>
        </div>
      </div>

      <!-- Detector -->
      <div class="mb-4">
        <span class="hud-label" style="font-size: 8px;">DETECTOR</span>
        <div class="mt-1.5 space-y-1">
          <div class="flex justify-between items-center text-[11px]">
            <span class="text-white/40">Detector</span>
            <span class="font-mono text-white/70">{selectedIncident.detector}</span>
          </div>
          <div class="flex justify-between items-center text-[11px]">
            <span class="text-white/40">Severity</span>
            <span class={severityBadgeClass(selectedIncident.severity)}>
              {selectedIncident.severity}
            </span>
          </div>
        </div>
      </div>

      <!-- Evidence -->
      <div class="mb-4">
        <span class="hud-label" style="font-size: 8px;">EVIDENCE</span>
        <div class="mt-1.5 space-y-1">
          <div class="flex justify-between text-[11px]">
            <span class="text-white/40">Step Index</span>
            <span class="font-mono text-white/70">{selectedIncident.stepIndex}</span>
          </div>
          <div class="flex justify-between text-[11px]">
            <span class="text-white/40">Record Kind</span>
            <span class="font-mono text-white/70">{rec?.kind ?? 'N/A'}</span>
          </div>
          <div class="flex justify-between text-[11px]">
            <span class="text-white/40">Finding</span>
            <span class="font-mono text-[var(--color-nebula-magenta)] text-[10px]">
              {selectedIncident.finding}
            </span>
          </div>
        </div>
      </div>

      <!-- Actions -->
      <div class="mt-auto pt-3 border-t border-white/5">
        <span class="hud-label" style="font-size: 8px;">ACTION</span>
        <div class="flex gap-2 mt-2">
          <button
            onclick={() => console.log('acknowledge', selectedIncident?.id)}
            class="flex-1 py-2.5 text-[11px] font-semibold rounded-xl border border-teal-400/30
              text-teal-400 bg-teal-500/8 hover:bg-teal-500/15 transition-all active:scale-[0.97]"
          >
            Acknowledge
          </button>
          <button
            onclick={() => console.log('quarantine', selectedIncident?.id)}
            class="flex-1 py-2.5 text-[11px] font-semibold rounded-xl border border-red-400/30
              text-red-400 bg-red-500/8 hover:bg-red-500/15 transition-all active:scale-[0.97]"
          >
            Quarantine Agent
          </button>
        </div>
      </div>
    {:else}
      <div class="flex-1 flex items-center justify-center">
        <div class="text-center">
          <div class="text-white/20 text-xs font-mono">Select an incident to analyze</div>
        </div>
      </div>
    {/if}
  </div>
</div>

<style>
  .line-clamp-2 {
    display: -webkit-box;
    -webkit-line-clamp: 2;
    line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
</style>

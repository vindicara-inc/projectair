<script lang="ts">
  import type { Severity } from '$lib/agdr/types';
  import type { IncidentStatus } from '$lib/templates/types';

  interface Props {
    onSeverityChange?: (severity: Severity | null) => void;
    onDetectorChange?: (detectorId: string | null) => void;
    onStatusChange?: (status: IncidentStatus | null) => void;
  }
  let { onSeverityChange, onDetectorChange, onStatusChange }: Props = $props();

  let activeSeverity = $state<Severity | null>(null);
  let activeStatus = $state<IncidentStatus | null>(null);

  const severities: Severity[] = ['critical', 'high', 'medium'];
  const statuses: IncidentStatus[] = ['new', 'acknowledged', 'investigating', 'resolved'];

  function toggleSeverity(s: Severity): void {
    activeSeverity = activeSeverity === s ? null : s;
    onSeverityChange?.(activeSeverity);
  }

  function toggleStatus(s: IncidentStatus): void {
    activeStatus = activeStatus === s ? null : s;
    onStatusChange?.(activeStatus);
  }
</script>

<div class="flex items-center gap-2 flex-wrap py-3" style="border-bottom: 1px solid rgba(255,255,255,0.04);">
  <span class="text-micro mr-1">Filter</span>

  {#each severities as sev}
    <button
      class="text-xs px-2.5 py-1 cursor-pointer transition-all"
      style="font-family: var(--font-ui); font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase;
             border: 1px solid {activeSeverity === sev ? 'var(--color-amber)' : 'rgba(255,255,255,0.08)'};
             background: {activeSeverity === sev ? 'rgba(255,179,71,0.1)' : 'transparent'};
             color: {activeSeverity === sev ? 'var(--color-amber)' : 'var(--color-text-dim)'};"
      onclick={() => toggleSeverity(sev)}
    >{sev}</button>
  {/each}

  <span style="width:1px; height:16px; background:rgba(255,255,255,0.08);"></span>

  {#each statuses as st}
    <button
      class="text-xs px-2.5 py-1 cursor-pointer transition-all"
      style="font-family: var(--font-ui); font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase;
             border: 1px solid {activeStatus === st ? 'var(--color-amber)' : 'rgba(255,255,255,0.08)'};
             background: {activeStatus === st ? 'rgba(255,179,71,0.1)' : 'transparent'};
             color: {activeStatus === st ? 'var(--color-amber)' : 'var(--color-text-dim)'};"
      onclick={() => toggleStatus(st)}
    >{st}</button>
  {/each}
</div>

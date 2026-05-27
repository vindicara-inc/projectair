<script lang="ts">
  import type { Finding, AgDRRecord, Severity } from '$lib/agdr/types';
  import type { FindingTemplate } from '$lib/templates/types';
  import type { IncidentStatus } from '$lib/templates/types';
  import { prioritizeFindings } from '$lib/stores/triage.svelte';
  import { triageStore } from '$lib/stores/triage.svelte';
  import IncidentCard from './IncidentCard.svelte';
  import FilterBar from './FilterBar.svelte';
  import TriageHeader from './TriageHeader.svelte';

  interface Props {
    findings: Finding[];
    records: AgDRRecord[];
    templates: Map<string, FindingTemplate>;
    agentFilter?: string | null;
  }
  let { findings, records, templates, agentFilter = null }: Props = $props();

  let severityFilter = $state<Severity | null>(null);
  let statusFilter = $state<IncidentStatus | null>(null);

  const filtered = $derived.by(() => {
    let result = prioritizeFindings(findings);

    if (severityFilter) {
      result = result.filter((f) => f.severity === severityFilter);
    }
    if (statusFilter) {
      result = result.filter((f) => triageStore.getStatus(f.step_id) === statusFilter);
    }
    if (agentFilter) {
      result = result.filter((f) => {
        const rec = records[f.step_index];
        return (rec?.payload?.source_agent_id as string) === agentFilter;
      });
    }
    return result;
  });

  const priorityIncidents = $derived(filtered.slice(0, 5));
  const remainingIncidents = $derived(filtered.slice(5));
</script>

<TriageHeader alertCount={filtered.length} />

<FilterBar
  onSeverityChange={(s) => severityFilter = s}
  onStatusChange={(s) => statusFilter = s}
/>

<div class="mt-4 flex flex-col">
  {#each priorityIncidents as finding (finding.step_id)}
    {@const record = records[finding.step_index]}
    {#if record}
      <IncidentCard
        {finding}
        {record}
        template={templates.get(finding.detector_id)}
      />
    {/if}
  {/each}

  {#if remainingIncidents.length > 0}
    <div class="mt-4 pt-4" style="border-top: 1px solid rgba(255,255,255,0.04);">
      <span class="text-micro mb-3 block">{remainingIncidents.length} more incidents</span>
      {#each remainingIncidents as finding (finding.step_id)}
        {@const record = records[finding.step_index]}
        {#if record}
          <IncidentCard
            {finding}
            {record}
            template={templates.get(finding.detector_id)}
          />
        {/if}
      {/each}
    </div>
  {/if}

  {#if filtered.length === 0 && findings.length > 0}
    <div class="stark-panel p-6 text-center">
      <p class="text-body" style="color: var(--color-text-secondary);">No incidents match the current filters.</p>
      <button class="btn-secondary text-xs mt-3" onclick={() => { severityFilter = null; statusFilter = null; }}>Clear filters</button>
    </div>
  {/if}
</div>

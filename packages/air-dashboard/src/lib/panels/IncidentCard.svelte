<script lang="ts">
  import type { Finding, AgDRRecord } from '$lib/agdr/types';
  import type { FindingTemplate } from '$lib/templates/types';
  import { fillTemplate } from '$lib/templates/fill';
  import { triageStore } from '$lib/stores/triage.svelte';
  import { drawerStore } from '$lib/stores/drawer.svelte';
  import { checkEntailment } from '$lib/templates/entailment';

  interface Props {
    finding: Finding;
    record: AgDRRecord;
    template: FindingTemplate | undefined;
  }
  let { finding, record, template }: Props = $props();

  let expanded = $state(false);

  const status = $derived(triageStore.getStatus(finding.step_id));

  const translation = $derived.by(() => {
    if (!template) return null;
    const fill = fillTemplate(template, record);
    const entailment = checkEntailment(fill.slotValues, template.slots, record);
    return { ...fill, entailmentPassed: entailment.passed };
  });

  const displayText = $derived(
    translation?.entailmentPassed ? translation.text : finding.description
  );

  const agentName = $derived(
    (record.payload.source_agent_id as string) ?? 'unknown'
  );

  const toolName = $derived(
    (record.payload.tool_name as string) ?? ''
  );

  function formatTime(iso: string): string {
    try { return new Date(iso).toLocaleTimeString(); }
    catch { return '--:--'; }
  }

  function openDrawer(): void {
    triageStore.investigate(finding.step_id);
    drawerStore.open({
      finding,
      record,
      template,
      layer1Text: displayText,
      slotValues: translation?.slotValues ?? {},
      entailmentPassed: translation?.entailmentPassed ?? false
    });
  }
</script>

<div class="stark-panel mb-3" style="animation: fade-up 0.3s ease-out;
  {status === 'acknowledged' ? 'opacity: 0.65;' : ''}
  {status === 'resolved' ? 'opacity: 0.45; pointer-events: none;' : ''}">
  <div class="p-4">
    <div class="flex items-start gap-3">
      <span class="severity-dot {finding.severity} {status === 'new' ? 'new' : ''} mt-1.5"
        style="{status !== 'new' ? 'opacity: 0.4;' : ''}"></span>

      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2 mb-1.5">
          <span class="badge-{finding.severity === 'critical' ? 'critical' : finding.severity === 'high' ? 'warning' : 'success'}">{finding.severity}</span>
          {#if status === 'acknowledged'}
            <span class="badge-info" style="text-transform: uppercase; letter-spacing: 0.12em;">ACKNOWLEDGED</span>
          {:else if status === 'investigating'}
            <span class="badge-info" style="text-transform: uppercase; letter-spacing: 0.12em;">INVESTIGATING</span>
          {:else if status === 'resolved'}
            <span class="badge-success" style="text-transform: uppercase; letter-spacing: 0.12em;">QUARANTINED</span>
          {/if}
        </div>

        {#if status === 'resolved'}
          <p class="text-body mb-2" style="color: var(--color-success); text-shadow: 0 0 6px var(--color-success-glow);">
            Agent quarantined. Incident resolved.
          </p>
        {:else}
          <p class="text-body mb-2">{displayText}</p>
        {/if}

        <div class="flex items-center gap-4 text-xs" style="color: var(--color-text-secondary); font-family: var(--font-ui);">
          <span>Agent: <strong style="color: var(--color-text);">{agentName}</strong></span>
          {#if toolName}
            <span>Tool: <strong style="color: var(--color-text);">{toolName}</strong></span>
          {/if}
          <span class="text-data" style="font-size: 11px; color: var(--color-red);">{formatTime(record.timestamp)}</span>
          <span class="text-micro" style="margin-left: auto;">{finding.detector_id}</span>
        </div>
      </div>
    </div>

    {#if status !== 'resolved'}
      <div class="flex items-center gap-2 mt-4 pt-3" style="border-top: 1px solid rgba(255,255,255,0.04);">
        <button class="btn-primary text-xs" onclick={openDrawer}>Investigate</button>
        <button class="btn-danger text-xs" onclick={() => triageStore.resolve(finding.step_id)}>Quarantine Agent</button>
        {#if status !== 'acknowledged'}
          <button class="btn-secondary text-xs ml-auto" onclick={() => triageStore.acknowledge(finding.step_id)}>Acknowledge</button>
        {/if}
      </div>
    {/if}
  </div>
</div>

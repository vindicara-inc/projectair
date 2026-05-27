<script lang="ts">
  import type { Finding, AgDRRecord } from '$lib/agdr/types.ts';
  import type { FindingTemplate } from '$lib/templates/types.ts';
  import { fillTemplate } from '$lib/templates/fill.ts';
  import { triageStore } from '$lib/stores/triage.svelte';
  import { drawerStore } from '$lib/stores/drawer.svelte';
  import { checkEntailment } from '$lib/templates/entailment.ts';

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

<div class="stark-panel mb-3" style="animation: fade-up 0.3s ease-out;">
  <div class="p-4">
    <div class="flex items-start gap-3">
      <span class="severity-dot {finding.severity} {status === 'new' ? 'new' : ''} mt-1.5"></span>

      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2 mb-1.5">
          <span class="badge-{finding.severity === 'critical' ? 'critical' : finding.severity === 'high' ? 'warning' : 'success'}">{finding.severity}</span>
          {#if status !== 'new'}
            <span class="badge-info">{status}</span>
          {/if}
        </div>

        <p class="text-body mb-2">{displayText}</p>

        <div class="flex items-center gap-4 text-xs" style="color: var(--color-text-secondary); font-family: var(--font-ui);">
          <span>Agent: <strong style="color: var(--color-text);">{agentName}</strong></span>
          {#if toolName}
            <span>Tool: <strong style="color: var(--color-text);">{toolName}</strong></span>
          {/if}
          <span class="text-data" style="font-size: 11px; color: var(--color-amber);">{formatTime(record.timestamp)}</span>
          <span class="text-micro" style="margin-left: auto;">{finding.detector_id}</span>
        </div>
      </div>
    </div>

    <div class="flex items-center gap-2 mt-4 pt-3" style="border-top: 1px solid rgba(255,255,255,0.04);">
      <button class="btn-primary text-xs" onclick={openDrawer}>Investigate</button>
      <button class="btn-danger text-xs" onclick={() => triageStore.resolve(finding.step_id)}>Quarantine Agent</button>
      <button class="btn-secondary text-xs ml-auto" onclick={() => triageStore.acknowledge(finding.step_id)}>Acknowledge</button>
    </div>
  </div>
</div>

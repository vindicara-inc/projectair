<script lang="ts">
  import type { Finding } from '$lib/console/forensics/types';
  import SeverityPill from './SeverityPill.svelte';
  import TechDetails from './TechDetails.svelte';
  let { findings }: { findings: Finding[] } = $props();
</script>

<div class="findings">
  {#each findings as f}
    <div class="finding sev-{f.severity}">
      <div class="fh">
        <span class="ft">{f.plainTitle}</span>
        <SeverityPill severity={f.severity} />
      </div>
      <div class="why">{f.whyItMatters}</div>
      <TechDetails>
        <div><span class="k">detector:</span> <b>{f.detector_id}</b></div>
        {#if f.owasp}<div><span class="k">framework:</span> {f.owasp}</div>{/if}
        <div><span class="k">detector title:</span> {f.title}</div>
        <div><span class="k">at:</span> step {f.step_index + 1}{#if f.step_id} · {f.step_id}{/if}</div>
      </TechDetails>
    </div>
  {/each}
</div>

<style>
  .findings { display: flex; flex-direction: column; gap: 12px; }
  .finding { padding: 14px 16px; border: 1px solid var(--hair); background: rgba(255,255,255,.02); border-left: 3px solid var(--slate); }
  .finding.sev-critical { border-left-color: var(--air); }
  .finding.sev-high { border-left-color: var(--amber); }
  .finding.sev-medium { border-left-color: var(--blue); }
  .fh { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .ft { font-size: 14.5px; font-weight: 600; line-height: 1.3; }
  .why { font-size: 12.5px; color: var(--muted); margin-top: 6px; line-height: 1.5; }
</style>

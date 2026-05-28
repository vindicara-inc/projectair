<script lang="ts">
  import { drawerStore } from '$lib/stores/drawer.svelte';
  import { triageStore } from '$lib/stores/triage.svelte';
  import { assistantStore } from '$lib/stores/assistant.svelte';

  let showProvenance = $state(false);
  let showRawEvidence = $state(false);

  const content = $derived(drawerStore.content);

  function formatTime(iso: string): string {
    try { return new Date(iso).toLocaleString(); }
    catch { return '--'; }
  }
</script>

{#if drawerStore.isOpen && content}
  <div class="fixed top-10 right-0 bottom-0 w-[360px] z-40 overflow-y-auto"
    style="background: linear-gradient(180deg, rgba(10,10,15,0.97) 0%, rgba(8,8,12,0.98) 100%);
           border-left: 1px solid var(--color-panel-edge);
           box-shadow: -10px 0 40px rgba(0,0,0,0.5);
           animation: slide-in-right 0.25s ease-out;">

    <div class="flex items-center justify-between p-4" style="border-bottom: 1px solid rgba(255,255,255,0.06);">
      <span class="text-micro">Investigation</span>
      <button class="text-sm cursor-pointer" style="color: var(--color-text-dim);"
        onclick={() => drawerStore.close()}>&times;</button>
    </div>

    <div class="p-5 flex flex-col gap-5">
      <div>
        <span class="text-micro mb-2 block">What Happened</span>
        <p class="text-base font-medium leading-relaxed" style="font-family: var(--font-ui); color: var(--color-red);
          text-shadow: 0 0 8px var(--color-red-glow);">
          {content.layer1Text}
        </p>
      </div>

      {#if content.template}
        <div>
          <span class="text-micro mb-2 block">Why It Matters</span>
          {#each content.template.layer2 as entry}
            <div class="mb-2 p-3" style="background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.04);">
              <div class="flex items-center gap-2 mb-1">
                <span class="badge-info">{entry.framework}</span>
                <span class="text-data text-xs" style="color: var(--color-red);">{entry.reference}</span>
              </div>
              <p class="text-sm" style="color: var(--color-text-secondary); font-family: var(--font-ui); line-height: 1.5;">{entry.description}</p>
            </div>
          {/each}
        </div>
      {/if}

      <div>
        <span class="text-micro mb-2 block">What To Do</span>
        <div class="flex flex-col gap-2">
          {#if content.template}
            <button class="btn-primary w-full">{content.template.layer3.primary.label}</button>
            {#each content.template.layer3.secondary as action}
              {#if action.action === 'quarantine_agent'}
                <button class="btn-danger w-full"
                  onclick={() => triageStore.resolve(content.finding.step_id)}>{action.label}</button>
              {:else if action.action === 'acknowledge'}
                <button class="btn-secondary w-full"
                  onclick={() => { triageStore.acknowledge(content.finding.step_id); drawerStore.close(); }}>{action.label}</button>
              {:else}
                <button class="btn-secondary w-full">{action.label}</button>
              {/if}
            {/each}
          {:else}
            <button class="btn-secondary w-full" onclick={() => triageStore.acknowledge(content.finding.step_id)}>Acknowledge</button>
          {/if}
        </div>
      </div>

      <div>
        <button class="text-micro w-full text-left cursor-pointer" onclick={() => showRawEvidence = !showRawEvidence}>
          {showRawEvidence ? '- Hide' : '+ View'} Raw Evidence
        </button>
        {#if showRawEvidence}
          <div class="mt-2 p-3" style="background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.04);">
            <div class="flex justify-between mb-2">
              <span class="text-label">Record</span>
              <span class="text-data text-xs" style="color: var(--color-red);">#{content.finding.step_index}</span>
            </div>
            <div class="flex justify-between mb-2">
              <span class="text-label">Hash</span>
              <span class="text-data text-xs" style="color: var(--color-red);">{content.record.content_hash.slice(0, 24)}...</span>
            </div>
            <div class="flex justify-between mb-2">
              <span class="text-label">Signature</span>
              <span class="text-data text-xs" style="color: var(--color-success);">Verified</span>
            </div>
            <details class="mt-3">
              <summary class="text-xs cursor-pointer" style="color: var(--color-text-dim); font-family: var(--font-ui);">Full payload</summary>
              <pre class="mt-2 text-xs p-2 overflow-x-auto" style="font-family: var(--font-data); color: var(--color-text-dim);
                background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.03); white-space: pre-wrap; word-break: break-all;">
{JSON.stringify(content.record.payload, null, 2)}</pre>
            </details>
          </div>
        {/if}
      </div>

      <button class="text-micro w-full text-left cursor-pointer" onclick={() => showProvenance = !showProvenance}>
        {showProvenance ? '- Hide' : '+ View'} Chain Provenance
      </button>
      {#if showProvenance && content.template}
        <div class="p-3" style="background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.04);">
          <div class="flex justify-between mb-2">
            <span class="text-label">Template</span>
            <span class="text-data text-xs">{content.template.template_id} v{content.template.version}</span>
          </div>
          <div class="flex justify-between mb-2">
            <span class="text-label">Entailment</span>
            <span class="text-data text-xs" style="color: {content.entailmentPassed ? 'var(--color-success)' : 'var(--color-critical)'};">
              {content.entailmentPassed ? 'PASS' : 'FAIL'}
            </span>
          </div>
          <div class="mt-2">
            <span class="text-label mb-1 block">Slot Mapping</span>
            {#each Object.entries(content.slotValues) as [slot, value]}
              <div class="flex justify-between py-1" style="border-bottom: 1px solid rgba(255,255,255,0.02);">
                <span class="text-xs" style="color: var(--color-text-dim); font-family: var(--font-ui);">{slot}</span>
                <span class="text-data text-xs">{value || '(empty)'}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}

      <button class="btn-secondary w-full flex items-center justify-center gap-2"
        onclick={() => assistantStore.open(content.finding.step_id)}>
        <span style="color: var(--color-red);">&#9679;</span>
        Ask AIR about this incident
      </button>
    </div>
  </div>
{/if}

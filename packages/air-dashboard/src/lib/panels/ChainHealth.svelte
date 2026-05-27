<script lang="ts">
  import { verifierStore } from '$lib/stores/verifier.svelte';
  import { replayStore } from '$lib/stores/replay.svelte';

  let collapsed = $state(false);

  const integrity = $derived(verifierStore.integrityScore);
  const totalSigned = $derived(replayStore.emitted.length);
  const lastEntry = $derived(verifierStore.entries[verifierStore.entries.length - 1]);
</script>

<div>
  <button class="section-label w-full text-left cursor-pointer" onclick={() => collapsed = !collapsed}>
    Chain Health
    <span class="ml-auto" style="color: var(--color-text-dim);">{collapsed ? '+' : '-'}</span>
  </button>

  {#if !collapsed}
    <div class="stark-panel p-4 flex flex-col gap-3">
      <div class="flex justify-between items-baseline">
        <span class="text-label">Integrity</span>
        <span class="text-value text-lg">{integrity}%</span>
      </div>
      <div class="w-full h-1" style="background: rgba(255,255,255,0.06);">
        <div class="h-full transition-all duration-500"
          style="width: {integrity}%;
                 background: {integrity === 100 ? 'var(--color-success)' : 'var(--color-critical)'};
                 box-shadow: 0 0 8px {integrity === 100 ? 'var(--color-success-glow)' : 'var(--color-critical-glow)'};">
        </div>
      </div>
      <div class="flex justify-between">
        <span class="text-label">Signed</span>
        <span class="text-data text-sm">{totalSigned}</span>
      </div>
      {#if lastEntry}
        <div class="flex justify-between">
          <span class="text-label">Last Hash</span>
          <span class="text-data text-xs" style="color: var(--color-amber);">{lastEntry.contentHashShort}</span>
        </div>
      {/if}
    </div>
  {/if}
</div>

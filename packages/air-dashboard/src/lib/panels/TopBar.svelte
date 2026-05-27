<script lang="ts">
  import { replayStore } from '$lib/stores/replay.svelte';
  import { findingsStore } from '$lib/stores/findings.svelte';
  import { verifierStore } from '$lib/stores/verifier.svelte';
  import { cloudSession } from '$lib/stores/cloud_session.svelte';
  import { roleStore } from '$lib/stores/role.svelte';

  const alertCount = $derived(findingsStore.all.length);
  const chainOk = $derived(verifierStore.chainStatus === 'ok');
  const integrity = $derived(verifierStore.integrityScore);
</script>

<header class="fixed top-0 left-14 right-0 h-10 z-50 flex items-center px-6 gap-6"
  style="background: linear-gradient(180deg, rgba(8,8,13,0.95) 0%, rgba(8,8,13,0.9) 100%);
         border-bottom: 1px solid var(--color-panel-edge);
         box-shadow: 0 2px 20px rgba(0,0,0,0.4);">

  <span class="text-xs font-bold tracking-[0.15em] uppercase"
    style="font-family: var(--font-display); color: var(--color-amber);
           text-shadow: 0 0 8px var(--color-amber-glow);">
    Project AIR
  </span>

  <div class="flex-1"></div>

  <div class="flex items-center gap-5">
    <button class="flex items-center gap-2 cursor-pointer hover:opacity-80 transition-opacity">
      <span class="severity-dot {alertCount > 0 ? 'critical new' : 'success'}"></span>
      <span class="text-micro">Alerts: {alertCount}</span>
    </button>

    <button class="flex items-center gap-2 cursor-pointer hover:opacity-80 transition-opacity">
      <span class="severity-dot {chainOk ? 'success' : 'critical'}"></span>
      <span class="text-micro">Chain: {chainOk ? 'Verified' : 'Broken'}</span>
    </button>

    <button class="flex items-center gap-2 cursor-pointer hover:opacity-80 transition-opacity">
      <span class="severity-dot {integrity === 100 ? 'success' : integrity > 80 ? 'warning' : 'critical'}"></span>
      <span class="text-micro">Integrity: {integrity}%</span>
    </button>
  </div>

  <div class="flex-1"></div>

  <div class="flex items-center gap-3">
    {#if cloudSession.isConnected}
      <span class="text-xs" style="color: var(--color-text-secondary); font-family: var(--font-ui);">
        {cloudSession.workspace?.name ?? ''}
      </span>
    {/if}
    <div class="w-7 h-7 flex items-center justify-center text-xs font-bold"
      style="background: rgba(255,179,71,0.1); border: 1px solid var(--color-amber-dim);
             color: var(--color-amber); font-family: var(--font-ui);">
      {(roleStore.email ?? 'U')[0]!.toUpperCase()}
    </div>
  </div>
</header>

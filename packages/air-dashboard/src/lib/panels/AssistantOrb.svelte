<script lang="ts">
  import { assistantStore } from '$lib/stores/assistant.svelte';
  import { findingsStore } from '$lib/stores/findings.svelte';

  const hasFindings = $derived(findingsStore.all.length > 0);
</script>

<button
  class="fixed bottom-6 right-6 z-50 w-14 h-14 flex items-center justify-center cursor-pointer transition-all"
  style="background: radial-gradient(circle, rgba(255,179,71,0.2) 0%, rgba(255,179,71,0.05) 70%, transparent 100%);
         border: 2px solid var(--color-amber-dim);
         border-radius: 50% !important;
         {hasFindings ? 'animation: orb-pulse 3s ease-in-out infinite;' : ''}"
  onclick={() => assistantStore.toggle()}
  title="Ask AIR"
>
  <div class="w-6 h-6 flex items-center justify-center"
    style="background: radial-gradient(circle, var(--color-amber) 0%, rgba(255,179,71,0.6) 100%);
           border-radius: 50% !important;
           box-shadow: 0 0 12px var(--color-amber-glow);">
  </div>
</button>

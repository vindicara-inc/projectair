<script lang="ts">
  import { findingsStore } from '$lib/stores/findings.svelte';
  import { replayStore } from '$lib/stores/replay.svelte';

  let collapsed = $state(false);

  const score = $derived.by(() => {
    const total = replayStore.emitted.length;
    if (total === 0) return 100;
    const findings = findingsStore.all.length;
    return Math.max(0, Math.round(((total - findings) / total) * 100));
  });

  const circumference = 2 * Math.PI * 36;
  const offset = $derived(circumference - (score / 100) * circumference);
  const gaugeColor = $derived(
    score >= 90 ? 'var(--color-success)' :
    score >= 70 ? 'var(--color-warning)' :
    'var(--color-critical)'
  );
</script>

<div>
  <button class="section-label w-full text-left cursor-pointer" onclick={() => collapsed = !collapsed}>
    Compliance
    <span class="ml-auto" style="color: var(--color-text-dim);">{collapsed ? '+' : '-'}</span>
  </button>

  {#if !collapsed}
    <div class="stark-panel p-5 flex flex-col items-center gap-4">
      <div class="relative w-24 h-24">
        <svg viewBox="0 0 80 80" class="w-full h-full -rotate-90">
          <circle cx="40" cy="40" r="36" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="4" />
          <circle cx="40" cy="40" r="36" fill="none" stroke={gaugeColor} stroke-width="4"
            stroke-dasharray={circumference} stroke-dashoffset={offset}
            stroke-linecap="butt" style="transition: stroke-dashoffset 0.5s, stroke 0.3s; filter: drop-shadow(0 0 4px {gaugeColor});" />
        </svg>
        <div class="absolute inset-0 flex items-center justify-center">
          <span class="text-2xl font-bold" style="font-family: var(--font-ui); color: {gaugeColor};
            text-shadow: 0 0 10px {gaugeColor};">
            {score}%
          </span>
        </div>
      </div>
      <span class="text-label">Overall Score</span>
    </div>
  {/if}
</div>

<script lang="ts">
  interface Props {
    alertCount: number;
  }
  let { alertCount }: Props = $props();
</script>

<div class="mb-6">
  <h2 class="text-xl font-semibold mb-1" style="font-family: var(--font-ui); color: var(--color-text);">
    What needs your attention?
  </h2>
  {#if alertCount === 0}
    <p class="text-sm" style="color: var(--color-success); text-shadow: 0 0 6px var(--color-success-glow); font-family: var(--font-ui);">
      All clear. No incidents detected.
    </p>
  {:else}
    <p class="text-sm" style="color: var(--color-text-secondary); font-family: var(--font-ui);">
      <span class="text-value">{alertCount}</span> incident{alertCount === 1 ? '' : 's'} require{alertCount === 1 ? 's' : ''} review
    </p>
  {/if}
</div>

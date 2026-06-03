<script lang="ts">
  interface Stat {
    label: string;
    value: string | number;
    color?: string;
  }

  let { stats = [] }: { stats: Stat[] } = $props();
</script>

<div class="glass-panel scan-line p-3 space-y-2" style="min-width: 160px;">
  {#each stats as stat}
    <div class="flex items-center justify-between gap-4">
      <span class="hud-label" style="font-size: 7px;">{stat.label}</span>
      <span class="font-mono text-xs font-bold" style="
        color: {stat.color ?? '#22d3ee'};
        text-shadow: 0 0 8px {stat.color ?? 'rgba(34,211,238,0.4)'};
      ">{stat.value}</span>
    </div>
  {/each}
</div>

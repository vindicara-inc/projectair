<script lang="ts">
  let {
    title = 'SIGNAL',
    values = [],
    barCount = 48,
    color = '#22d3ee',
    height = 60,
  }: {
    title?: string;
    values?: number[];
    barCount?: number;
    color?: string;
    height?: number;
  } = $props();

  const bars = $derived((() => {
    if (values.length === 0) return Array.from({ length: barCount }, () => 0.05);
    if (values.length >= barCount) return values.slice(-barCount);
    const padded = Array.from({ length: barCount - values.length }, () => 0);
    return [...padded, ...values];
  })());

  const maxVal = $derived(Math.max(1, ...bars));
</script>

<div class="glass-panel scan-line p-3" style="min-width: 200px;">
  <div class="hud-label mb-2" style="color: {color};">{title}</div>
  <div class="flex items-end gap-[2px]" style="height: {height}px;">
    {#each bars as val, i}
      {@const h = maxVal > 0 ? (val / maxVal) : 0}
      <div
        class="flex-1 rounded-t-sm"
        style="
          height: {Math.max(2, h * 100)}%;
          background: linear-gradient(180deg, {color}, rgba(168, 85, 247, 0.6));
          opacity: {0.3 + h * 0.7};
          box-shadow: {h > 0.5 ? `0 0 3px ${color}` : 'none'};
          transition: height 0.3s ease;
        "
      ></div>
    {/each}
  </div>
</div>

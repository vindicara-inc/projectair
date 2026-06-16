<script lang="ts">
  let {
    value = 0,
    label = '',
    size = 120,
    color = '#22d3ee',
    secondaryColor = '#a855f7',
  }: {
    value?: number;
    label?: string;
    size?: number;
    color?: string;
    secondaryColor?: string;
  } = $props();

  const r = $derived((size - 12) / 2);
  const circumference = $derived(2 * Math.PI * r);
  const dashOffset = $derived(circumference * (1 - value / 100));
  const cx = $derived(size / 2);
  const cy = $derived(size / 2);
</script>

<div class="relative inline-flex items-center justify-center ring-gauge" style="width:{size}px; height:{size}px;">
  <svg width={size} height={size} class="absolute inset-0" style="transform: rotate(-90deg);">
    <!-- Outer track -->
    <circle {cx} {cy} {r} fill="none" stroke="rgba(255,255,255,0.04)" stroke-width="3" />
    <!-- Decorative outer ring -->
    <circle {cx} {cy} r={r + 4} fill="none" stroke="rgba(34,211,238,0.08)" stroke-width="1"
      stroke-dasharray="4 8" style="animation: ring-spin 20s linear infinite;" />
    <!-- Value arc -->
    <circle {cx} {cy} {r} fill="none" stroke="url(#gauge-grad-{label})" stroke-width="4"
      stroke-linecap="round"
      stroke-dasharray={circumference}
      stroke-dashoffset={dashOffset}
      style="transition: stroke-dashoffset 1s ease; filter: drop-shadow(0 0 6px {color});" />
    <!-- Tick marks -->
    {#each Array(12) as _, i}
      <line
        x1={cx + (r - 8) * Math.cos((i / 12) * Math.PI * 2)}
        y1={cy + (r - 8) * Math.sin((i / 12) * Math.PI * 2)}
        x2={cx + r * Math.cos((i / 12) * Math.PI * 2)}
        y2={cy + r * Math.sin((i / 12) * Math.PI * 2)}
        stroke="rgba(34,211,238,0.15)" stroke-width="1"
      />
    {/each}
    <defs>
      <linearGradient id="gauge-grad-{label}" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color={color} />
        <stop offset="100%" stop-color={secondaryColor} />
      </linearGradient>
    </defs>
  </svg>
  <div class="text-center z-10">
    <div class="font-mono text-xl font-bold" style="color:{color}; text-shadow: 0 0 12px {color};">
      {value.toFixed(1)}%
    </div>
    <div class="hud-label mt-1" style="font-size:7px; color:{color};">{label}</div>
  </div>
</div>

<script lang="ts">
  import type { ComplianceRing } from '$lib/console/api/types';
  let { c, graduated = false }: { c: ComplianceRing; graduated?: boolean } = $props();

  const isProg = c.state !== 'good';
  const off = (pct: number) => 100 - pct; // dashoffset over dasharray 100

  // Displayed percentage. In-progress rings count up to 100 when they "graduate";
  // the arc fills in lockstep because its dashoffset is derived from `shown`.
  let shown = $state(c.pct);

  $effect(() => {
    if (!(isProg && graduated)) return;
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    if (reduce) {
      shown = 100;
      return;
    }
    const start = c.pct;
    const dur = 1400;
    let raf = 0;
    let t0 = 0;
    const step = (ts: number) => {
      if (!t0) t0 = ts;
      const k = Math.min(1, (ts - t0) / dur);
      const eased = 1 - Math.pow(1 - k, 3);
      shown = Math.round(start + (100 - start) * eased);
      if (k < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  });

  let green = $derived(c.state === 'good' || (isProg && graduated));
</script>

<div class="rg">
  <svg width="40" height="40" viewBox="0 0 40 40">
    <circle cx="20" cy="20" r="16" fill="none" stroke="rgba(255,255,255,.1)" stroke-width="4" />
    <circle
      class="fill"
      cx="20" cy="20" r="16" fill="none"
      stroke={green ? '#48e6a4' : '#ffb454'}
      stroke-width="4" stroke-linecap="round"
      stroke-dasharray="100" stroke-dashoffset={off(shown)}
      transform="rotate(-90 20 20)"
    />
  </svg>
  <div>
    <div class="t">{c.framework} <span class="pct" class:gd={green}>{shown}%</span></div>
    <div class="d">{isProg && graduated ? 'complete' : c.detail}</div>
  </div>
</div>

<style>
  .rg { display: flex; align-items: center; gap: 11px; }
  .fill { transition: stroke 0.9s ease; }
  .t { font-size: 12px; font-weight: 600; }
  .pct { font-family: var(--mono); font-size: 10px; color: var(--amber); margin-left: 4px; }
  .pct.gd { color: var(--teal); }
  .d { font-family: var(--mono); font-size: 9.5px; color: var(--faint); margin-top: 2px; }
</style>

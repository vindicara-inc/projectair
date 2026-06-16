<script lang="ts">
  // Hard honesty requirement: when Demo Mode is on, this badge is always visible in
  // the chrome so the data can never be mistaken for live production records.
  import { mode } from '$lib/console/stores/mode';
</script>

{#if $mode === 'demo'}
  <div class="badge" title="Demo Mode: every record comes from local fixtures. Real engine, synthetic data.">
    <span class="dot"></span>
    <span class="lbl">DEMO MODE</span>
    <span class="sub">synthetic data · real engine</span>
  </div>
{/if}

<style>
  .badge {
    display: inline-flex; align-items: center; gap: 9px; padding: 6px 12px;
    border: 1px solid rgba(255,180,84,.5);
    background: repeating-linear-gradient(45deg, rgba(255,180,84,.16) 0 10px, rgba(255,180,84,.07) 10px 20px);
    color: #ffdca6; font-family: var(--mono); font-size: 10px; letter-spacing: .14em; font-weight: 600;
    white-space: nowrap;
  }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--amber); box-shadow: 0 0 9px var(--amber); animation: pulse 1.8s ease-in-out infinite; }
  .lbl { text-transform: uppercase; }
  .sub { color: rgba(255,220,166,.62); letter-spacing: .04em; text-transform: none; font-size: 9.5px; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
  @media (prefers-reduced-motion: reduce) { .dot { animation: none; } }
  @media (max-width: 720px) { .sub { display: none; } }
</style>

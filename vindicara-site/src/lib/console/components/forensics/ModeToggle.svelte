<script lang="ts">
  import { mode, type Mode } from '$lib/console/stores/mode';
  function set(m: Mode) {
    mode.set(m);
  }
</script>

<div class="toggle" role="group" aria-label="Data mode">
  <button class="seg demo" class:on={$mode === 'demo'} aria-pressed={$mode === 'demo'} onclick={() => set('demo')}>
    Demo
  </button>
  <button class="seg live" class:on={$mode === 'live'} aria-pressed={$mode === 'live'} onclick={() => set('live')}>
    Live
  </button>
</div>

<style>
  .toggle {
    display: inline-flex; border: 1px solid var(--stroke); background: rgba(0,0,0,.28);
    padding: 2px; flex: 0 0 auto;
  }
  .seg {
    font-family: var(--mono); font-size: 10px; letter-spacing: .12em; text-transform: uppercase;
    font-weight: 600; padding: 6px 13px; border: 0; background: transparent; color: var(--faint);
    cursor: pointer; transition: .14s;
  }
  .seg:hover { color: var(--muted); }
  .demo.on { background: linear-gradient(180deg, rgba(255,180,84,.26), rgba(255,180,84,.1)); color: #ffd9a6; box-shadow: inset 0 0 0 1px rgba(255,180,84,.4); }
  .live.on { background: linear-gradient(180deg, rgba(72,230,164,.24), rgba(72,230,164,.08)); color: #bff5df; box-shadow: inset 0 0 0 1px rgba(72,230,164,.4); }
</style>

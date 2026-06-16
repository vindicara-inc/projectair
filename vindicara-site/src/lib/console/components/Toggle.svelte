<script lang="ts">
  let { on = false, accent = 'teal', disabled = false, onchange }: {
    on?: boolean;
    accent?: 'teal' | 'vio';
    disabled?: boolean;
    onchange?: (next: boolean) => void;
  } = $props();
  function flip() { if (!disabled) onchange?.(!on); }
</script>

<button class="sw {accent} {on ? 'on' : ''}" class:disabled aria-pressed={on} aria-label="toggle" onclick={flip}></button>

<style>
  .sw { width: 38px; height: 22px; border-radius: 11px; background: rgba(255,255,255,.13); position: relative; cursor: pointer; transition: .18s; flex: 0 0 38px; border: 0; padding: 0; }
  .sw::after { content: ''; position: absolute; top: 2px; left: 2px; width: 18px; height: 18px; border-radius: 50%; background: #fff; transition: .18s; }
  .sw.on { background: linear-gradient(90deg, #48e6a4, #13c08a); }
  .sw.on::after { left: 18px; }
  .sw.vio.on { background: linear-gradient(90deg, #9b6bff, #6db5ff); }
  .sw.disabled { opacity: .5; cursor: not-allowed; }
</style>

<script lang="ts">
  let {
    chainIntegrity = 100, recordCount = 0, haltedCount = 0,
    agentCount = 0, isConnected = false, onHalted, onReset, onMenu,
  }: {
    chainIntegrity?: number; recordCount?: number; haltedCount?: number;
    agentCount?: number; isConnected?: boolean;
    onHalted?: () => void; onReset?: () => void;
    onMenu?: () => void;
  } = $props();

  const integrityColor = $derived(
    chainIntegrity > 80 ? 'var(--color-success)' :
    chainIntegrity > 50 ? 'var(--color-warning)' : 'var(--color-critical)'
  );
  const integrityGlow = $derived(
    chainIntegrity > 80 ? 'var(--color-success-glow)' :
    chainIntegrity > 50 ? 'var(--color-warning-glow)' : 'var(--color-critical-glow)'
  );
</script>

<div class="hud-bar fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-4 py-2">
  <div class="flex items-center gap-4">
    <div class="flex items-center gap-2.5">
      <div class="flex items-center justify-center rounded-sm font-bold text-white"
        style="width:20px;height:20px;font-size:11px;
          background:linear-gradient(135deg,var(--color-nebula-violet),var(--color-nebula-indigo));"
      >A</div>
      <span style="font-family:var(--font-display);font-size:11px;letter-spacing:0.2em;
        color:var(--color-nebula-accent);text-shadow:0 0 8px rgba(34,211,238,0.4);">AIR COMMAND</span>
    </div>

    <div class="flex items-center gap-1.5">
      <span class="severity-dot" style="width:6px;height:6px;
        background:{integrityColor};box-shadow:0 0 6px {integrityGlow};"></span>
      <span style="font-family:var(--font-mono);font-size:9px;letter-spacing:0.08em;
        color:{integrityColor};">{chainIntegrity}% INTEGRITY</span>
    </div>

    <span style="font-family:var(--font-mono);font-size:8px;letter-spacing:0.06em;
      color:rgba(240,240,255,0.3);">{recordCount} CAPSULES</span>

    <div class="flex items-center gap-1.5">
      <span class="severity-dot" style="width:5px;height:5px;
        background:{isConnected ? 'var(--color-success)' : 'var(--color-warning)'};
        box-shadow:0 0 6px {isConnected ? 'var(--color-success-glow)' : 'var(--color-warning-glow)'};"></span>
      <span style="font-family:var(--font-mono);font-size:8px;letter-spacing:0.08em;
        color:{isConnected ? 'var(--color-success)' : 'var(--color-warning)'};">{isConnected ? 'LIVE' : 'LOCAL'}</span>
    </div>
  </div>

  <div class="flex items-center gap-3">
    {#if haltedCount > 0}
      <button onclick={onHalted}
        class="flex items-center gap-1 px-2.5 py-1 rounded-sm cursor-pointer"
        style="font-family:var(--font-mono);font-size:9px;letter-spacing:0.06em;
          color:var(--color-critical);background:rgba(255,84,104,0.1);
          border:1px solid rgba(255,84,104,0.3);">
        &#9888; {haltedCount} HALTED
      </button>
    {/if}
    <button onclick={onReset}
      class="px-2 py-1 rounded-sm cursor-pointer"
      style="font-family:var(--font-mono);font-size:8px;letter-spacing:0.08em;
        color:rgba(240,240,255,0.25);background:transparent;border:1px solid rgba(240,240,255,0.08);">
      RESET
    </button>
    <button onclick={onMenu}
      class="flex flex-col gap-[3px] px-2 py-1.5 rounded-sm cursor-pointer hover:bg-white/5 transition-colors"
      title="Settings">
      <span class="w-4 h-[2px] bg-white/40"></span>
      <span class="w-4 h-[2px] bg-white/40"></span>
      <span class="w-4 h-[2px] bg-white/40"></span>
    </button>
  </div>
</div>

<script lang="ts">
  let {
    activeTab = 'monitor',
    onTabChange,
    onAskAir,
  }: {
    activeTab?: string;
    onTabChange?: (tab: string) => void;
    onAskAir?: () => void;
  } = $props();

  const tabs = ['Secure', 'Analyze', 'Monitor'] as const;
</script>

<div class="cmd-bar fixed bottom-0 left-0 right-0 z-50 px-8 pb-5 pt-10">
  <div class="flex items-center justify-center gap-3">
    <!-- Ask AIR button -->
    <button
      onclick={onAskAir}
      class="cmd-tab active flex items-center gap-2 rounded-xl"
      style="
        border-color: rgba(34, 211, 238, 0.5);
        background: linear-gradient(135deg, rgba(34, 211, 238, 0.15), rgba(99, 102, 241, 0.1));
        color: var(--color-nebula-accent);
        text-shadow: 0 0 10px rgba(34, 211, 238, 0.6);
        box-shadow: 0 0 20px rgba(34, 211, 238, 0.12), 0 0 60px rgba(34, 211, 238, 0.04);
      "
    >
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"/>
        <path d="M12 16v-4M12 8h.01"/>
      </svg>
      Ask AIR
    </button>

    {#each tabs as tab}
      <button
        onclick={() => onTabChange?.(tab.toLowerCase())}
        class="cmd-tab rounded-xl {activeTab === tab.toLowerCase() ? 'active' : ''}"
      >
        {tab}
      </button>
    {/each}
  </div>
</div>

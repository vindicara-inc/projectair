<script lang="ts">
  import { replayStore } from '$lib/stores/replay.svelte';
  import { findingsStore } from '$lib/stores/findings.svelte';

  interface AgentStatus {
    name: string;
    health: 'clean' | 'flagged' | 'critical';
    findingCount: number;
  }

  let collapsed = $state(false);
  let selectedAgent = $state<string | null>(null);

  const agents = $derived.by<AgentStatus[]>(() => {
    const map = new Map<string, number>();
    for (const f of findingsStore.all) {
      const rec = replayStore.emitted[f.step_index];
      const name = (rec?.payload?.source_agent_id as string) ?? 'unknown';
      map.set(name, (map.get(name) ?? 0) + 1);
    }
    const seen = new Set<string>();
    for (const rec of replayStore.emitted) {
      const name = (rec?.payload?.source_agent_id as string);
      if (name) seen.add(name);
    }
    for (const name of seen) {
      if (!map.has(name)) map.set(name, 0);
    }
    return [...map.entries()].map(([name, count]) => ({
      name,
      health: count === 0 ? 'clean' as const : count >= 3 ? 'critical' as const : 'flagged' as const,
      findingCount: count
    }));
  });

  interface Props {
    onFilterAgent?: (agent: string | null) => void;
  }
  let { onFilterAgent }: Props = $props();

  function toggleAgent(name: string): void {
    selectedAgent = selectedAgent === name ? null : name;
    onFilterAgent?.(selectedAgent);
  }
</script>

<div>
  <button class="section-label w-full text-left cursor-pointer" onclick={() => collapsed = !collapsed}>
    Fleet Status
    <span class="ml-auto" style="color: var(--color-text-dim);">{collapsed ? '+' : '-'}</span>
  </button>

  {#if !collapsed}
    <div class="stark-panel p-4 flex flex-col gap-1">
      {#if agents.length === 0}
        <p class="text-xs" style="color: var(--color-text-dim); font-family: var(--font-ui);">No agents detected</p>
      {:else}
        {#each agents as agent}
          <button
            class="flex items-center gap-3 px-3 py-2 w-full text-left cursor-pointer transition-all"
            style="background: {selectedAgent === agent.name ? 'rgba(220,38,38,0.08)' : 'transparent'};
                   border: 1px solid {selectedAgent === agent.name ? 'rgba(220,38,38,0.15)' : 'transparent'};"
            onclick={() => toggleAgent(agent.name)}
          >
            <span class="severity-dot {agent.health === 'clean' ? 'success' : agent.health === 'flagged' ? 'warning' : 'critical'}"></span>
            <span class="flex-1 text-sm truncate" style="color: var(--color-text); font-family: var(--font-ui);">{agent.name}</span>
            {#if agent.findingCount > 0}
              <span class="text-micro">{agent.findingCount}</span>
            {/if}
          </button>
        {/each}
      {/if}
    </div>
  {/if}
</div>

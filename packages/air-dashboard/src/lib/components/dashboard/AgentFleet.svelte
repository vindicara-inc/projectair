<script lang="ts">
  interface Agent {
    id: string;
    name: string;
    status: string;
    confidence: number;
    lastAction: string;
    timestamp: string;
  }

  let { agents = [] }: { agents: Agent[] } = $props();

  const displayedAgents = $derived(agents.length ? agents : []);

  function getStatusStyle(status: string): string {
    if (status === 'halted') return 'border-red-400 text-red-400';
    if (status === 'investigating') return 'border-amber-400 text-amber-400';
    return 'border-teal-400 text-teal-400';
  }
</script>

<div class="space-y-6">
  <div class="flex items-center justify-between mb-2">
    <h2 class="text-lg font-semibold tracking-wider text-violet-300">AGENT FLEET</h2>
    <div class="text-xs font-mono bg-teal-500/10 text-teal-400 px-3 py-1 rounded-full">
      {displayedAgents.length} ONLINE
    </div>
  </div>

  <div class="space-y-3 max-h-[calc(100vh-280px)] overflow-auto pr-2 custom-scroll">
    {#each displayedAgents as agent (agent.id)}
      <div class="glass-panel p-5 rounded-2xl border border-white/10 hover:border-violet-400/40 transition-all">
        <div class="flex justify-between items-start">
          <div>
            <div class="font-mono text-xs text-white/60">{agent.id}</div>
            <div class="font-medium text-white mt-1">{agent.name}</div>
          </div>

          <div class="px-3 py-1 text-xs font-medium rounded-full border {getStatusStyle(agent.status)}">
            {agent.status}
          </div>
        </div>

        <div class="mt-4 mb-2">
          <div class="h-1.5 bg-white/10 rounded-full overflow-hidden">
            <div
              class="h-full bg-gradient-to-r from-teal-400 via-cyan-400 to-violet-400 rounded-full transition-all duration-500"
              style="width: {agent.confidence ?? 85}%"
            ></div>
          </div>
        </div>

        <div class="text-xs flex justify-between text-white/60">
          <span>{agent.lastAction}</span>
          <span class="font-mono">{agent.timestamp}</span>
        </div>
      </div>
    {/each}
  </div>

  <button
    class="w-full py-3.5 text-sm font-medium border border-violet-400/30 hover:bg-violet-500/10 rounded-2xl transition-colors"
  >
    + Deploy New Agent
  </button>
</div>

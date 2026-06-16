<script lang="ts">
  interface Incident {
    id: string;
    title: string;
    agentId: string;
    severity: string;
    confidence: number;
    time: string;
    primaryAction?: string;
  }

  let {
    incidents = [],
    onIncidentAction,
  }: {
    incidents: Incident[];
    onIncidentAction?: (incident: Incident) => void;
  } = $props();

  function getSeverityStyle(severity: string): string {
    if (severity === 'Critical') return 'border-red-400 text-red-400 bg-red-500/10';
    if (severity === 'High') return 'border-orange-400 text-orange-400 bg-orange-500/10';
    return 'border-amber-400 text-amber-400 bg-amber-500/10';
  }
</script>

<div class="space-y-6">
  <div class="flex items-center justify-between">
    <h2 class="text-lg font-semibold tracking-wider text-violet-300">PRIORITIZED INCIDENTS</h2>
    <div class="px-3 py-1 text-xs bg-red-500/10 text-red-400 rounded-full font-mono">
      {incidents.length} ACTIVE
    </div>
  </div>

  <div class="space-y-4">
    {#each incidents as incident (incident.id)}
      <div class="glass-panel p-6 rounded-3xl border border-white/10 hover:border-violet-400/50 transition-all group">
        <div class="flex gap-4">
          <div class="flex-1 min-w-0">
            <div class="text-sm font-medium leading-snug text-white">
              {incident.title}
            </div>

            <div class="flex items-center gap-3 mt-3 text-xs">
              <span class="font-mono text-white/50">AGENT {incident.agentId}</span>

              <span class="px-3 py-0.5 rounded-full text-[10px] border uppercase tracking-widest {getSeverityStyle(incident.severity)}">
                {incident.severity}
              </span>
            </div>
          </div>

          <div class="text-right text-xs">
            <div class="text-teal-400 font-semibold">{incident.confidence}%</div>
            <div class="text-white/40 mt-1 font-mono">{incident.time}</div>
          </div>
        </div>

        <button
          onclick={() => onIncidentAction?.(incident)}
          class="mt-6 w-full py-3.5 bg-gradient-to-r from-indigo-600 via-violet-600 to-purple-600 hover:brightness-110 rounded-2xl text-sm font-medium transition-all active:scale-[0.985]"
        >
          {incident.primaryAction || 'Investigate'} &rarr;
        </button>
      </div>
    {/each}
  </div>

  <div class="text-center pt-2">
    <button class="text-violet-400 hover:text-violet-300 text-sm transition-colors">
      View Full Incident Log &rarr;
    </button>
  </div>
</div>

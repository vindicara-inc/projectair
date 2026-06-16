<script lang="ts">
  import RingGauge from './RingGauge.svelte';
  import WaveformPanel from './WaveformPanel.svelte';

  interface Agent {
    id: string;
    status: string;
    ops: number;
    lastAction: string;
  }

  let {
    agents = [],
    chainIntegrity = 0,
    fleetHealth = 0,
    riskScore = 0,
    detectorValues = [],
    recordValues = [],
    selectedAgentId = '',
    onSelectAgent = (_id: string) => {},
  }: {
    agents?: Agent[];
    chainIntegrity?: number;
    fleetHealth?: number;
    riskScore?: number;
    detectorValues?: number[];
    recordValues?: number[];
    selectedAgentId?: string;
    onSelectAgent?: (id: string) => void;
  } = $props();

  function chainColor(v: number): string {
    if (v >= 95) return '#22d3ee';
    if (v >= 80) return '#ffb547';
    return '#ff5468';
  }

  function safetyColor(v: number): string {
    if (v <= 25) return '#22d3ee';
    if (v <= 60) return '#ffb547';
    return '#ff5468';
  }

  function statusDotColor(status: string): string {
    if (status === 'halted' || status === 'critical') return '#ff5468';
    if (status === 'flagged') return '#ffb547';
    return '#22d3ee';
  }
</script>

<aside class="w-64 flex flex-col gap-2.5 h-full overflow-hidden">
  <!-- Gauge row: CHAIN + FLEET -->
  <div class="flex gap-2 justify-center">
    <RingGauge value={chainIntegrity} label="CHAIN" size={110} color={chainColor(chainIntegrity)} />
    <RingGauge value={fleetHealth} label="FLEET" size={110} color="#a855f7" />
  </div>

  <!-- SAFETY gauge -->
  <div class="flex justify-center">
    <RingGauge value={riskScore} label="SAFETY" size={110} color={safetyColor(riskScore)} />
  </div>

  <!-- Detector signal waveform -->
  <WaveformPanel title="DETECTOR SIGNAL" values={detectorValues} barCount={36} height={44} />

  <!-- Record stream waveform -->
  <WaveformPanel
    title="RECORD STREAM"
    values={recordValues}
    barCount={28}
    height={36}
    color="#a855f7"
  />

  <!-- Agent Fleet list -->
  <div class="glass-panel flex-1 overflow-hidden flex flex-col min-h-0">
    <div class="px-3 pt-3 pb-2">
      <span class="hud-label" style="font-size: 7px; color: #a855f7;">
        AGENT FLEET ({agents.length})
      </span>
    </div>
    <div class="flex-1 overflow-y-auto custom-scroll px-2 pb-2 space-y-1">
      {#each agents as agent (agent.id)}
        <button
          class="w-full flex items-center gap-2 px-2 py-1.5 rounded text-left transition-colors hover:bg-white/5 {selectedAgentId === agent.id ? 'bg-white/5' : ''}"
          onclick={() => onSelectAgent(agent.id)}
        >
          <!-- Status dot -->
          <span
            class="shrink-0 w-2 h-2 rounded-full"
            style="background: {statusDotColor(agent.status)}; box-shadow: 0 0 6px {statusDotColor(agent.status)};"
          ></span>

          <!-- Agent info -->
          <span class="flex-1 min-w-0">
            <span
              class="block font-mono truncate"
              style="font-size: 11px; color: rgba(255,255,255,0.85);"
            >
              {agent.id}
            </span>
          </span>

          <!-- Status + ops -->
          <span class="shrink-0 text-right">
            <span
              class="block font-mono"
              style="font-size: 9px; color: {statusDotColor(agent.status)};"
            >
              {agent.status}
            </span>
            <span
              class="block font-mono"
              style="font-size: 9px; color: rgba(255,255,255,0.4);"
            >
              {agent.ops} ops
            </span>
          </span>
        </button>
      {/each}
    </div>
  </div>
</aside>

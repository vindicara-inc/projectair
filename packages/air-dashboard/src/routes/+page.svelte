<script lang="ts">
  import AlertFeed from '$lib/panels/AlertFeed.svelte';
  import FleetStatus from '$lib/panels/FleetStatus.svelte';
  import ComplianceGauge from '$lib/panels/ComplianceGauge.svelte';
  import ChainHealth from '$lib/panels/ChainHealth.svelte';
  import DetailDrawer from '$lib/panels/DetailDrawer.svelte';
  import CloudConnect from '$lib/panels/CloudConnect.svelte';

  import { replayStore } from '$lib/stores/replay.svelte';
  import { verifierStore } from '$lib/stores/verifier.svelte';
  import { findingsStore } from '$lib/stores/findings.svelte';
  import { focusStore } from '$lib/stores/focus.svelte';
  import { modeStore } from '$lib/stores/mode.svelte';
  import { cloudSession } from '$lib/stores/cloud_session.svelte';
  import { drawerStore } from '$lib/stores/drawer.svelte';
  import { runDetectors } from '$lib/detectors';
  import { SCENARIOS, loadScenario } from '$lib/capsules/loader';
  import type { FindingTemplate } from '$lib/templates/types.ts';

  let lastDetectorRunSize = 0;
  let loading = $state(false);
  let agentFilter = $state<string | null>(null);
  let templateMap = $state(new Map<string, FindingTemplate>());

  $effect(() => {
    const unsub = modeStore.bindMediaQueries();
    return () => { unsub?.(); cloudSession.stopStream(); };
  });

  $effect(() => {
    loadTemplates();
  });

  async function loadTemplates(): Promise<void> {
    const ids = [
      'ASI01', 'ASI02', 'ASI03', 'ASI04', 'ASI05',
      'ASI06', 'ASI07', 'ASI08', 'ASI09', 'ASI10',
      'AIR-01', 'AIR-02', 'AIR-03', 'AIR-04', 'AIR-05', 'AIR-06'
    ];
    const map = new Map<string, FindingTemplate>();
    await Promise.allSettled(
      ids.map(async (id) => {
        try {
          const resp = await fetch(`/templates/${id}.json`);
          if (!resp.ok) return;
          const tpl = (await resp.json()) as FindingTemplate;
          map.set(id, tpl);
        } catch { /* skip */ }
      })
    );
    templateMap = map;
  }

  $effect(() => {
    if (cloudSession.isConnected) void loadCloudChain();
  });

  async function loadCloudChain(): Promise<void> {
    if (!cloudSession.isConnected) return;
    loading = true;
    try {
      const records = await cloudSession.loadCurrentChain({ limit: 1000 });
      verifierStore.reset();
      findingsStore.reset();
      focusStore.clear();
      replayStore.load(records, 'cloud');
      replayStore.play();
      cloudSession.startStream((record) => {
        replayStore.emitted = [...replayStore.emitted, record];
        replayStore.currentIndex = replayStore.emitted.length - 1;
      });
    } catch (err) {
      console.error('failed to load cloud chain:', err);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    const records = replayStore.records;
    const emitted = replayStore.emitted;
    const lastIngested = verifierStore.entries.length;
    for (let i = lastIngested; i < emitted.length; i++) {
      verifierStore.ingest(emitted[i]!, i);
    }
    if (emitted.length !== lastDetectorRunSize) {
      lastDetectorRunSize = emitted.length;
      findingsStore.reset();
      findingsStore.add(runDetectors(emitted, null));
    }
    if (emitted.length === 0 && lastDetectorRunSize > 0) {
      lastDetectorRunSize = 0;
    }
    void records;
  });

  async function selectAndPlay(scenarioId: string): Promise<void> {
    const scenario = SCENARIOS.find((s) => s.id === scenarioId);
    if (!scenario) return;
    loading = true;
    try {
      const records = await loadScenario(scenario);
      verifierStore.reset();
      findingsStore.reset();
      focusStore.clear();
      replayStore.load(records, scenario.id);
      replayStore.play();
    } finally {
      loading = false;
    }
  }
</script>

<svelte:head>
  <title>AIR Cloud — Command Center</title>
</svelte:head>

<div class="min-h-screen px-6 pb-20 max-w-[1600px] mx-auto grid items-start"
  style="grid-template-columns: 240px 1fr; gap: 24px;
         {drawerStore.isOpen ? 'padding-right: 384px;' : ''}">

  <!-- LEFT COLUMN -->
  <div class="flex flex-col gap-6 pt-6 sticky top-12">
    <FleetStatus onFilterAgent={(agent) => agentFilter = agent} />
    <ComplianceGauge />
    <ChainHealth />

    <div>
      <span class="section-label">Data Source</span>
      <div class="stark-panel p-4 flex flex-col gap-3">
        <CloudConnect onChainLoaded={loadCloudChain} />
        <div class="flex items-center gap-2 flex-wrap">
          <span class="text-micro">Scenario</span>
          {#each SCENARIOS as scenario (scenario.id)}
            <button
              class="text-xs px-2 py-1 cursor-pointer transition-all"
              style="font-family: var(--font-ui); font-weight: 600;
                     border: 1px solid {replayStore.scenarioId === scenario.id ? 'var(--color-amber)' : 'rgba(255,255,255,0.08)'};
                     background: {replayStore.scenarioId === scenario.id ? 'rgba(255,179,71,0.1)' : 'transparent'};
                     color: {replayStore.scenarioId === scenario.id ? 'var(--color-amber)' : 'var(--color-text-dim)'};"
              onclick={() => selectAndPlay(scenario.id)}
              disabled={loading}
              title={scenario.description}
            >{scenario.label}</button>
          {/each}
        </div>
        <div class="flex items-center gap-2">
          <button class="btn-secondary text-xs" onclick={() => replayStore.play()} disabled={replayStore.records.length === 0}>Play</button>
          <button class="btn-secondary text-xs" onclick={() => replayStore.pause()}>Pause</button>
          <button class="btn-secondary text-xs" onclick={() => { replayStore.reset(); verifierStore.reset(); findingsStore.reset(); focusStore.clear(); }}>Reset</button>
        </div>
      </div>
    </div>
  </div>

  <!-- CENTER COLUMN -->
  <div class="pt-6">
    <AlertFeed
      findings={findingsStore.all}
      records={replayStore.emitted}
      templates={templateMap}
      {agentFilter}
    />
  </div>
</div>

<DetailDrawer />

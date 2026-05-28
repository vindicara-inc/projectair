<script lang="ts">
  import AlertFeed from '$lib/panels/AlertFeed.svelte';
  import FleetStatus from '$lib/panels/FleetStatus.svelte';
  import ComplianceGauge from '$lib/panels/ComplianceGauge.svelte';
  import ChainHealth from '$lib/panels/ChainHealth.svelte';
  import DetailDrawer from '$lib/panels/DetailDrawer.svelte';
  import CloudConnect from '$lib/panels/CloudConnect.svelte';
  import ApprovalQueue from '$lib/panels/ApprovalQueue.svelte';
  import ReportExport from '$lib/panels/ReportExport.svelte';

  import { replayStore } from '$lib/stores/replay.svelte';
  import { verifierStore } from '$lib/stores/verifier.svelte';
  import { findingsStore } from '$lib/stores/findings.svelte';
  import { focusStore } from '$lib/stores/focus.svelte';
  import { modeStore } from '$lib/stores/mode.svelte';
  import { cloudSession } from '$lib/stores/cloud_session.svelte';
  import { drawerStore } from '$lib/stores/drawer.svelte';
  import { approvalStore } from '$lib/stores/approval.svelte';
  import { runDetectors } from '$lib/detectors';
  import type { FindingTemplate } from '$lib/templates/types';

  let lastDetectorRunSize = 0;
  let loading = $state(false);
  let agentFilter = $state<string | null>(null);
  let templateMap = $state(new Map<string, FindingTemplate>());

  const hasData = $derived(replayStore.emitted.length > 0);

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
      // Feed tool_start records with critical/high findings into the approval queue.
      // A tool_start with any critical or high severity finding is treated as a
      // containment-relevant action requiring human review.
      for (let i = 0; i < emitted.length; i++) {
        const rec = emitted[i]!;
        if (rec.kind !== 'tool_start') continue;
        const stepFindings = findingsStore.forStep(i);
        const hasSevere = stepFindings.some(f => f.severity === 'critical' || f.severity === 'high');
        if (hasSevere) {
          approvalStore.addPending(rec, i);
        }
      }
    }
    if (emitted.length === 0 && lastDetectorRunSize > 0) {
      lastDetectorRunSize = 0;
      approvalStore.reset();
    }
    void records;
  });
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
    <ApprovalQueue />
    <ReportExport />

    <div>
      <span class="section-label">Data Source</span>
      <div class="stark-panel p-4">
        <CloudConnect onChainLoaded={loadCloudChain} />
      </div>
    </div>
  </div>

  <!-- CENTER COLUMN -->
  <div class="pt-6">
    {#if !hasData && !cloudSession.isConnected}
      <div class="stark-panel p-12 flex flex-col items-center gap-6 text-center" style="min-height: 300px;">
        <div class="w-16 h-16 flex items-center justify-center"
          style="border: 2px solid rgba(220,38,38,0.2); background: rgba(220,38,38,0.04);">
          <span style="font-size: 28px; color: var(--color-red); text-shadow: 0 0 12px var(--color-red-glow);">&#9678;</span>
        </div>
        <div>
          <h2 class="text-lg font-semibold mb-2" style="font-family: var(--font-ui); color: var(--color-text);">
            No live data
          </h2>
          <p class="text-sm" style="color: var(--color-text-secondary); font-family: var(--font-ui); line-height: 1.6; max-width: 360px;">
            Connect to AIR Cloud to see live agent activity. Incidents, chain integrity, and compliance scores will populate automatically.
          </p>
        </div>
        <div class="mt-2">
          <CloudConnect onChainLoaded={loadCloudChain} />
        </div>
      </div>
    {:else if loading}
      <div class="stark-panel p-12 flex items-center justify-center" style="min-height: 200px;">
        <span class="text-sm" style="color: var(--color-text-dim); font-family: var(--font-ui);">Loading chain data...</span>
      </div>
    {:else}
      <AlertFeed
        findings={findingsStore.all}
        records={replayStore.emitted}
        templates={templateMap}
        {agentFilter}
      />
    {/if}
  </div>
</div>

<DetailDrawer />

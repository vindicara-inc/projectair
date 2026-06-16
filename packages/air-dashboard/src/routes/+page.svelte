<script lang="ts">
  import AirNetworkGraph from '$lib/components/dashboard/AirNetworkGraph.svelte';
  import AskAIR from '$lib/components/dashboard/AskAIR.svelte';
  import ApprovalInbox from '$lib/components/dashboard/ApprovalInbox.svelte';
  import StatusBar from '$lib/components/dashboard/StatusBar.svelte';
  import LeftSidebar from '$lib/components/dashboard/LeftSidebar.svelte';
  import MonitorTab from '$lib/components/dashboard/MonitorTab.svelte';
  import AnalyzeTab from '$lib/components/dashboard/AnalyzeTab.svelte';
  import SecureTab from '$lib/components/dashboard/SecureTab.svelte';
  import SettingsDrawer from '$lib/components/dashboard/SettingsDrawer.svelte';

  import { replayStore } from '$lib/stores/replay.svelte';
  import { verifierStore } from '$lib/stores/verifier.svelte';
  import { findingsStore } from '$lib/stores/findings.svelte';
  import { focusStore } from '$lib/stores/focus.svelte';
  import { modeStore } from '$lib/stores/mode.svelte';
  import { cloudSession } from '$lib/stores/cloud_session.svelte';
  import { approvalStore } from '$lib/stores/approval.svelte';
  import { authStore } from '$lib/stores/auth.svelte';
  import { drawerStore } from '$lib/stores/drawer.svelte';
  import { runDetectors } from '$lib/detectors';
  import { SCENARIOS, loadScenario } from '$lib/capsules/loader';
  import { fillTemplate } from '$lib/templates/fill';
  import { buildFleet, buildEdges, buildIncidents, waveformBins, findingBins } from '$lib/agents/derive';
  import type { IncidentVM } from '$lib/agents/derive';
  import type { FindingTemplate } from '$lib/templates/types';
  import type { AgDRRecord } from '$lib/agdr/types';
  import { base } from '$app/paths';

  // --- Local state ---
  let activeTab = $state<'monitor' | 'analyze' | 'secure'>('monitor');
  let showAskAir = $state(false);
  let showApprovalInbox = $state(false);
  let showSettings = $state(false);
  let selectedAgentId = $state<string | null>(null);
  let loading = $state(false);
  let lastDetectorRunSize = 0;
  let templateMap = $state(new Map<string, FindingTemplate>());

  // --- Derived data ---
  const records = $derived(replayStore.emitted as AgDRRecord[]);
  const hasData = $derived(records.length > 0);
  const recordCount = $derived(records.length);
  const pendingIndices = $derived(new Set(approvalStore.pending.map(p => p.recordIndex)));
  const agents = $derived(buildFleet(records, findingsStore.all, pendingIndices));
  const edges = $derived(buildEdges(records));
  const incidents = $derived(buildIncidents(findingsStore.all, records, templateMap));

  const verifiedCount = $derived(verifierStore.entries.filter(e => e.status === 'ok').length);
  const chainIntegrity = $derived(
    verifierStore.entries.length > 0
      ? Math.round((verifiedCount / verifierStore.entries.length) * 1000) / 10
      : hasData ? 100 : 0
  );
  const haltedCount = $derived(approvalStore.pending.length);
  const criticalCount = $derived(findingsStore.all.filter(f => f.severity === 'critical').length);
  const highCount = $derived(findingsStore.all.filter(f => f.severity === 'high').length);
  const mediumCount = $derived(findingsStore.all.filter(f => f.severity === 'medium').length);
  const riskScore = $derived(
    hasData ? Math.max(0, 100 - criticalCount * 20 - highCount * 10 - mediumCount * 3) : 100
  );
  const fleetHealth = $derived(
    agents.length > 0
      ? Math.round((agents.filter(a => a.status === 'active').length / agents.length) * 100)
      : hasData ? 100 : 0
  );

  // Waveform bins via derive.ts helpers
  const detectorValues = $derived(findingBins(findingsStore.all, recordCount, 36));
  const recordValues = $derived(waveformBins(records, 28));
  const agentActivityValues = $derived(
    waveformBins(records, 44, r => r.kind === 'tool_start' || r.kind === 'agent_message' || r.kind === 'llm_start')
  );

  // AnalyzeTab expects `finding: string` and `toolName: string`; IncidentVM has `finding: Finding` and `toolName: string | null`
  const analyzeIncidents = $derived(
    incidents.map(i => ({ ...i, finding: i.detector, toolName: i.toolName ?? '' }))
  );

  const approvalItems = $derived(approvalStore.pending.map(p => ({
    id: p.record.step_id,
    agent: agents.find(a => records[p.recordIndex] !== undefined)?.id ?? 'unknown',
    description: `access ${p.record.payload?.tool_name ?? 'resource'}`,
    policy: 'High-Privilege Action',
  })));

  // --- Incident selection (opens drawer) ---
  function selectIncident(inc: IncidentVM): void {
    focusStore.select(inc.stepIndex);
    const record = records[inc.stepIndex];
    if (!record) return;
    const tpl = templateMap.get(inc.detector);
    const filled = tpl ? fillTemplate(tpl, record) : null;
    drawerStore.open({
      finding: inc.finding, record, template: tpl,
      layer1Text: filled?.text ?? inc.title,
      slotValues: filled?.slotValues ?? {},
      entailmentPassed: true,
    });
  }

  function resetAll(): void {
    verifierStore.reset(); findingsStore.reset(); approvalStore.reset();
    focusStore.clear(); replayStore.reset(); lastDetectorRunSize = 0;
  }

  // --- Effects ---
  $effect(() => { const u = modeStore.bindMediaQueries(); return () => { u?.(); cloudSession.stopStream(); }; });
  $effect(() => { loadTemplates(); });
  $effect(() => { if (cloudSession.isConnected) void loadCloudChain(); });

  // Data pump: ingest records into verifier + run detectors
  $effect(() => {
    const _records = replayStore.records;
    const emitted = replayStore.emitted;
    const lastIngested = verifierStore.entries.length;
    for (let i = lastIngested; i < emitted.length; i++) verifierStore.ingest(emitted[i]!, i);
    if (emitted.length !== lastDetectorRunSize) {
      lastDetectorRunSize = emitted.length;
      findingsStore.reset();
      if (emitted.length === 0) approvalStore.reset();
      else {
        findingsStore.add(runDetectors(emitted, null));
        for (let i = 0; i < emitted.length; i++) {
          const rec = emitted[i]!;
          if (rec.kind !== 'tool_start') continue;
          if (findingsStore.forStep(i).some(f => f.severity === 'critical' || f.severity === 'high'))
            approvalStore.addPending(rec, i);
        }
      }
    }
    void _records;
  });

  // --- Template + chain loaders ---
  async function loadTemplates(): Promise<void> {
    const ids = ['ASI01','ASI02','ASI03','ASI04','ASI05','ASI06','ASI07','ASI08','ASI09','ASI10',
                 'AIR-01','AIR-02','AIR-03','AIR-04','AIR-05','AIR-06'];
    const map = new Map<string, FindingTemplate>();
    await Promise.allSettled(ids.map(async id => {
      try { const r = await fetch(`${base}/templates/${id}.json`); if (r.ok) map.set(id, await r.json() as FindingTemplate); } catch {}
    }));
    templateMap = map;
  }

  async function loadCloudChain(): Promise<void> {
    if (!cloudSession.isConnected) return;
    loading = true;
    try {
      const chain = await cloudSession.loadCurrentChain({ limit: 1000 });
      resetAll();
      replayStore.load(chain, 'cloud'); replayStore.play();
      cloudSession.startStream((record) => {
        replayStore.emitted = [...replayStore.emitted, record];
        replayStore.currentIndex = replayStore.emitted.length - 1;
      });
    } catch (err) { console.error('cloud chain:', err); } finally { loading = false; }
  }

  async function loadLocalScenario(id: string): Promise<void> {
    const s = SCENARIOS.find(x => x.id === id); if (!s) return;
    loading = true;
    try {
      const chain = await loadScenario(s);
      resetAll(); replayStore.load(chain, s.id); replayStore.play();
    } catch (e) { console.error('scenario:', e); } finally { loading = false; }
  }
</script>

<svelte:head><title>AIR Cloud - Command Center</title></svelte:head>

<div class="fixed inset-0 bg-nebula-bg text-white overflow-hidden">
  {#if !hasData && !loading}
    <!-- Empty state -->
    <div class="absolute inset-0 flex items-center justify-center z-20">
      <div class="glass-panel p-10 rounded-sm text-center max-w-md" style="animation: fade-up 0.6s ease;">
        <div class="w-14 h-14 mx-auto mb-5 flex items-center justify-center" style="border: 1px solid rgba(34,211,238,0.3);">
          <span class="neon-text-cyan text-2xl">&#9678;</span>
        </div>
        <h2 class="text-lg font-semibold mb-2">No live data</h2>
        <p class="text-white/40 text-sm mb-6">Connect to AIR Cloud or load a scenario.</p>
        {#if cloudSession.status === 'disconnected' || cloudSession.status === 'error'}
          <button onclick={() => authStore.login()} class="w-full py-3 mb-4 text-sm font-medium transition-all"
            style="background: rgba(34,211,238,0.1); border: 1px solid rgba(34,211,238,0.3); color: var(--color-nebula-accent);">
            Connect to AIR Cloud
          </button>
        {/if}
        <div class="flex flex-wrap gap-2 justify-center">
          {#each SCENARIOS as sc (sc.id)}
            <button onclick={() => loadLocalScenario(sc.id)} class="px-3 py-1.5 text-xs transition-all hover:bg-white/5"
              style="border: 1px solid rgba(168,85,247,0.2); color: rgba(168,85,247,0.7);" title={sc.description}>
              {sc.label}
            </button>
          {/each}
        </div>
      </div>
    </div>
  {:else if loading}
    <!-- Loading state -->
    <div class="absolute inset-0 flex items-center justify-center z-20">
      <div class="flex items-center gap-3">
        <div class="w-3 h-3 rounded-full animate-pulse" style="background:#22d3ee; box-shadow:0 0 12px rgba(34,211,238,0.5);"></div>
        <span class="text-sm text-white/60 font-mono">Loading...</span>
      </div>
    </div>
  {:else}
    <!-- 3D graph background (always mounted, opacity varies by tab) -->
    <div class="absolute inset-0 z-0 transition-opacity duration-300"
      style="opacity: {activeTab === 'monitor' ? 1 : 0.3};">
      <AirNetworkGraph {agents} {edges}
        onSelectAgent={(id) => selectedAgentId = selectedAgentId === id ? null : id} />
    </div>

    <!-- HUD overlay -->
    <div class="absolute inset-0 z-10 pointer-events-none">
      <!-- Status bar (top) -->
      <div class="pointer-events-auto">
        <StatusBar {chainIntegrity} {recordCount} {haltedCount}
          agentCount={agents.length} isConnected={cloudSession.isConnected}
          onHalted={() => showApprovalInbox = true} onReset={resetAll}
          onMenu={() => showSettings = !showSettings} />
      </div>

      <!-- Left sidebar + tab content area -->
      <div class="pointer-events-auto absolute left-3 top-14 bottom-16 right-3 flex gap-3 overflow-hidden">
        <!-- Left sidebar (264px) -->
        <div class="w-[264px] shrink-0">
          <LeftSidebar {agents} {chainIntegrity} {fleetHealth} {riskScore}
            {detectorValues} {recordValues}
            selectedAgentId={selectedAgentId ?? ''}
            onSelectAgent={(id) => selectedAgentId = selectedAgentId === id ? null : id} />
        </div>

        <!-- Tab content (fills remaining width) -->
        <div class="flex-1 min-w-0 overflow-hidden">
          {#if activeTab === 'monitor'}
            <MonitorTab {records} findings={findingsStore.all}
              verifierEntries={verifierStore.entries}
              {criticalCount} {highCount} {mediumCount}
              agentCount={agents.length} {recordCount} {agentActivityValues}
              focusedIndex={focusStore.manualIndex ?? -1}
              onSelectRecord={(i) => focusStore.select(i)} />
          {:else if activeTab === 'analyze'}
            <AnalyzeTab incidents={analyzeIncidents} {records}
              onSelectIncident={(sel) => {
                const inc = incidents.find(i => i.id === sel.id);
                if (inc) selectIncident(inc);
              }} />
          {:else}
            <SecureTab {approvalItems}
              onApprove={(id) => { const i = approvalStore.pending.find(p => p.record.step_id === id); if (i) approvalStore.approve(i.recordIndex, 'operator'); }}
              onDeny={(id) => { const i = approvalStore.pending.find(p => p.record.step_id === id); if (i) approvalStore.deny(i.recordIndex, 'Denied'); }} />
          {/if}
        </div>
      </div>

      <!-- Command bar (bottom) -->
      <div class="pointer-events-auto absolute bottom-0 left-0 right-0 flex items-center justify-center gap-2 pb-3 pt-8"
        style="background: linear-gradient(180deg, transparent 0%, rgba(6,6,16,0.95) 50%);">
        <button onclick={() => showAskAir = !showAskAir}
          class="cmd-tab {showAskAir ? 'active' : ''} flex items-center gap-1.5">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>
          </svg>
          Ask AIR
        </button>
        <button onclick={() => activeTab = 'monitor'} class="cmd-tab {activeTab === 'monitor' ? 'active' : ''}">Monitor</button>
        <button onclick={() => activeTab = 'analyze'} class="cmd-tab {activeTab === 'analyze' ? 'active' : ''}">Analyze</button>
        <button onclick={() => activeTab = 'secure'} class="cmd-tab {activeTab === 'secure' ? 'active' : ''}">Secure</button>
      </div>
    </div>

    <!-- Ask AIR overlay -->
    {#if showAskAir}
      <div class="fixed bottom-16 left-1/2 -translate-x-1/2 z-50" style="animation: fade-up 0.3s ease;">
        <AskAIR />
      </div>
    {/if}
  {/if}

  <!-- Approval inbox modal -->
  {#if showApprovalInbox}
    <ApprovalInbox items={approvalItems} onClose={() => showApprovalInbox = false}
      onApprove={(id) => { const i = approvalStore.pending.find(p => p.record.step_id === id); if (i) approvalStore.approve(i.recordIndex, 'operator'); }}
      onDeny={(id) => { const i = approvalStore.pending.find(p => p.record.step_id === id); if (i) approvalStore.deny(i.recordIndex, 'Denied'); }} />
  {/if}

  {#if showSettings}
    <SettingsDrawer onClose={() => showSettings = false} />
  {/if}
</div>

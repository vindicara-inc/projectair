<script lang="ts">
  import { siemStore, type SiemVendor } from '../../stores/siem.svelte.ts';
  import { cloudSession } from '../../stores/cloud_session.svelte.ts';
  import { authStore } from '../../stores/auth.svelte.ts';
  import { roleStore } from '../../stores/role.svelte.ts';
  import { replayStore } from '../../stores/replay.svelte.ts';
  import { findingsStore } from '../../stores/findings.svelte.ts';
  import { verifierStore } from '../../stores/verifier.svelte.ts';

  let { onClose }: { onClose: () => void } = $props();

  let activeSection = $state<string>('overview');
  let expandedVendor = $state<string | null>(null);

  const secretFields = new Set(['hec_token', 'api_key', 'shared_key', 'webhook_url', 'http_source_url']);

  const sections = [
    { id: 'overview', label: 'Overview', icon: '◎' },
    { id: 'siem', label: 'SIEM Integrations', icon: '⇄' },
    { id: 'api', label: 'API Keys', icon: '🔑' },
    { id: 'team', label: 'Team', icon: '👥' },
    { id: 'export', label: 'Export', icon: '↓' },
  ] as const;

  function testVendor(vendor: SiemVendor): void {
    if (cloudSession.isConnected && cloudSession.client) {
      void siemStore.testConnection(vendor.id, cloudSession.baseUrl, { Authorization: `Bearer ${cloudSession.client.apiKey}` });
    } else {
      const { valid, missing } = siemStore.validateConfig(vendor.id);
      siemStore.setStatus(vendor.id, valid ? 'ok' : 'error', valid ? null : `Missing: ${missing.join(', ')}`);
    }
  }

  function pushVendor(vendor: SiemVendor): void {
    if (!cloudSession.isConnected || !cloudSession.client) { siemStore.setStatus(vendor.id, 'error', 'Connect to AIR Cloud first'); return; }
    void siemStore.pushFindings(vendor.id, cloudSession.baseUrl, { Authorization: `Bearer ${cloudSession.client.apiKey}` }, findingsStore.all, replayStore.emitted.length);
  }

  function statusDot(s: string): string {
    if (s === 'ok') return 'bg-emerald-400 shadow-[0_0_4px_rgba(52,211,153,0.5)]';
    if (s === 'error') return 'bg-red-400 shadow-[0_0_4px_rgba(248,113,113,0.5)]';
    if (s === 'testing' || s === 'pushing') return 'bg-amber-400 animate-pulse';
    return 'bg-white/20';
  }

  function downloadBlob(blob: Blob, name: string): void {
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); URL.revokeObjectURL(a.href);
  }
  function exportJSON(): void {
    downloadBlob(new Blob([JSON.stringify({ exported_at: new Date().toISOString(), records: replayStore.emitted, findings: findingsStore.all }, null, 2)], { type: 'application/json' }), `air-evidence-${new Date().toISOString().slice(0, 10)}.json`);
  }
  function exportCSV(): void {
    const h = 'detector_id,severity,title,step_index,timestamp\n';
    const rows = findingsStore.all.map(f => { const r = replayStore.emitted[f.step_index]; return [f.detector_id, f.severity, `"${f.title}"`, f.step_index, r?.timestamp ?? ''].join(','); }).join('\n');
    downloadBlob(new Blob([h + rows], { type: 'text/csv' }), `air-findings-${new Date().toISOString().slice(0, 10)}.csv`);
  }
</script>

<!-- Backdrop -->
<div class="fixed inset-0 z-[90] bg-black/60 backdrop-blur-sm" onclick={onClose}></div>

<!-- Drawer -->
<div class="fixed top-0 right-0 bottom-0 z-[95] w-[420px] flex" style="animation: slide-in-right 0.2s ease;">
  <!-- Nav -->
  <div class="w-14 bg-nebula-bg border-r border-white/5 flex flex-col items-center pt-4 gap-1">
    {#each sections as s}
      <button onclick={() => activeSection = s.id}
        class="w-10 h-10 flex items-center justify-center text-sm rounded-lg transition-all {activeSection === s.id ? 'bg-white/10 text-nebula-accent' : 'text-white/90 hover:text-white/90 hover:bg-white/5'}"
        title={s.label}>{s.icon}</button>
    {/each}
    <div class="flex-1"></div>
    <button onclick={onClose} class="w-10 h-10 flex items-center justify-center text-white/90 hover:text-white/90 mb-4">&times;</button>
  </div>

  <!-- Content -->
  <div class="flex-1 bg-nebula-bg/95 backdrop-blur-xl border-l border-white/5 overflow-auto custom-scroll p-5">
    {#if activeSection === 'overview'}
      <h2 class="hud-label mb-4">WORKSPACE OVERVIEW</h2>
      <div class="space-y-3">
        <div class="glass-panel p-4">
          <div class="text-[9px] font-mono text-white/90 mb-1">CONNECTION</div>
          <div class="flex items-center gap-2">
            <div class="w-2 h-2 rounded-full {cloudSession.isConnected ? 'bg-emerald-400' : 'bg-white/20'}"></div>
            <span class="text-sm text-white">{cloudSession.isConnected ? 'Connected to AIR Cloud' : 'Offline / Local'}</span>
          </div>
          {#if cloudSession.workspace}
            <div class="mt-3 space-y-1.5 text-[11px]">
              <div class="flex justify-between"><span class="text-white/90">Workspace</span><span class="text-white/90 font-mono">{cloudSession.workspace.name}</span></div>
              <div class="flex justify-between"><span class="text-white/90">ID</span><span class="text-white font-mono text-[9px]">{cloudSession.workspace.workspace_id}</span></div>
              <div class="flex justify-between"><span class="text-white/90">Owner</span><span class="text-white/90">{cloudSession.workspace.owner_email}</span></div>
              <div class="flex justify-between"><span class="text-white/90">Created</span><span class="text-white font-mono">{cloudSession.workspace.created_at}</span></div>
            </div>
          {/if}
        </div>

        <div class="glass-panel p-4">
          <div class="text-[9px] font-mono text-white/90 mb-1">CURRENT USER</div>
          <div class="space-y-1.5 text-[11px]">
            <div class="flex justify-between"><span class="text-white/90">Email</span><span class="text-white/90">{authStore.user?.email ?? 'Not authenticated'}</span></div>
            <div class="flex justify-between"><span class="text-white/90">Role</span><span class="text-white/90 font-mono uppercase">{roleStore.current}</span></div>
            <div class="flex justify-between"><span class="text-white/90">Permissions</span><span class="text-white">{roleStore.isAdmin ? 'Full access' : 'View only'}</span></div>
          </div>
        </div>

        <div class="glass-panel p-4">
          <div class="text-[9px] font-mono text-white/90 mb-1">CHAIN STATUS</div>
          <div class="space-y-1.5 text-[11px]">
            <div class="flex justify-between"><span class="text-white/90">Records</span><span class="text-nebula-accent font-mono">{replayStore.emitted.length}</span></div>
            <div class="flex justify-between"><span class="text-white/90">Findings</span><span class="text-violet-400 font-mono">{findingsStore.all.length}</span></div>
            <div class="flex justify-between"><span class="text-white/90">Verified</span><span class="font-mono" style="color: {verifierStore.entries.filter(e => e.status === 'ok').length === verifierStore.entries.length ? '#6effb3' : '#ff5468'};">{verifierStore.entries.filter(e => e.status === 'ok').length}/{verifierStore.entries.length}</span></div>
            <div class="flex justify-between"><span class="text-white/90">Source</span><span class="text-white font-mono">{replayStore.scenarioId ?? 'live'}</span></div>
          </div>
        </div>

        <div class="glass-panel p-4">
          <div class="text-[9px] font-mono text-white/90 mb-1">ABOUT</div>
          <div class="text-[11px] text-white space-y-1">
            <div>Project AIR by Vindicara</div>
            <div>Forensic accountability for AI agents</div>
            <div class="font-mono text-[9px] text-white/90">Dashboard v0.1.0</div>
          </div>
        </div>
      </div>

    {:else if activeSection === 'siem'}
      <h2 class="hud-label mb-4">SIEM INTEGRATIONS</h2>
      <p class="text-[11px] text-white/75 mb-4">Forward findings to your security platform. Pushes go through the AIR Cloud backend.</p>
      {#each siemStore.vendors as vendor (vendor.id)}
        <div class="mb-3">
          <div onclick={() => expandedVendor = expandedVendor === vendor.id ? null : vendor.id}
            role="button" tabindex="0" onkeydown={(e: KeyboardEvent) => e.key === 'Enter' && (expandedVendor = expandedVendor === vendor.id ? null : vendor.id)}
            class="w-full flex items-center gap-3 px-3 py-3 rounded-lg bg-white/[0.03] hover:bg-white/[0.06] transition-colors cursor-pointer">
            <button onclick={(e: MouseEvent) => { e.stopPropagation(); siemStore.toggle(vendor.id); }}
              class="relative w-8 h-4 rounded-full transition-colors flex-shrink-0 {vendor.enabled ? 'bg-teal-500/70' : 'bg-white/10'}">
              <span class="absolute top-0.5 left-0.5 w-3 h-3 rounded-full bg-white transition-transform {vendor.enabled ? 'translate-x-4' : 'translate-x-0'}"></span>
            </button>
            <span class="text-sm text-white flex-1 text-left">{vendor.name}</span>
            <span class="w-2 h-2 rounded-full {statusDot(vendor.lastStatus)}"></span>
            {#if vendor.eventsSent > 0}<span class="text-[9px] font-mono text-white/90">{vendor.eventsSent} sent</span>{/if}
            <span class="text-white/20 text-xs {expandedVendor === vendor.id ? 'rotate-180' : ''} transition-transform">&#9662;</span>
          </div>
          {#if expandedVendor === vendor.id}
            <div class="px-3 pt-3 pb-2 space-y-2 border-l border-white/5 ml-4 mt-1">
              {#each Object.keys(vendor.config) as field}
                <label class="block">
                  <span class="text-[9px] font-mono text-white/75 uppercase tracking-wider">{field}</span>
                  <input type={secretFields.has(field) ? 'password' : 'text'} value={vendor.config[field]}
                    oninput={(e: Event) => siemStore.updateConfig(vendor.id, field, (e.target as HTMLInputElement).value)}
                    class="w-full mt-0.5 px-2.5 py-2 text-xs font-mono bg-black/40 border border-white/10 text-white focus:border-cyan-400/40 focus:outline-none transition-colors" placeholder={field} />
                </label>
              {/each}
              <div class="flex gap-2 mt-2">
                <button onclick={() => testVendor(vendor)} disabled={vendor.lastStatus === 'testing'}
                  class="flex-1 py-2 text-[10px] font-semibold uppercase border border-cyan-400/20 text-cyan-400/80 hover:bg-cyan-400/10 transition-all">{vendor.lastStatus === 'testing' ? 'Testing...' : 'Test'}</button>
                <button onclick={() => pushVendor(vendor)} disabled={vendor.lastStatus === 'pushing' || findingsStore.all.length === 0}
                  class="flex-1 py-2 text-[10px] font-semibold uppercase border border-violet-400/20 text-violet-400/80 hover:bg-violet-400/10 transition-all">{vendor.lastStatus === 'pushing' ? 'Pushing...' : 'Push'}</button>
              </div>
              {#if vendor.lastStatus === 'error' && vendor.lastError}<div class="text-[10px] text-red-400 font-mono mt-1">{vendor.lastError}</div>{/if}
              {#if vendor.lastStatus === 'ok'}<div class="text-[10px] text-emerald-400 font-mono mt-1">Connected{#if vendor.lastPushAt} &bull; Last: {new Date(vendor.lastPushAt).toLocaleTimeString()}{/if}</div>{/if}
            </div>
          {/if}
        </div>
      {/each}

    {:else if activeSection === 'api'}
      <h2 class="hud-label mb-4">API KEYS</h2>
      {#if cloudSession.isConnected}
        <div class="glass-panel p-4 mb-3">
          <div class="text-[9px] font-mono text-white/90 mb-2">CURRENT SESSION</div>
          <div class="space-y-1.5 text-[11px]">
            <div class="flex justify-between"><span class="text-white/90">Auth Mode</span><span class="text-white/90 font-mono">{cloudSession.client?.authMode ?? 'N/A'}</span></div>
            <div class="flex justify-between"><span class="text-white/90">Endpoint</span><span class="text-white font-mono text-[9px] truncate max-w-[200px]">{cloudSession.baseUrl}</span></div>
          </div>
        </div>
        <p class="text-[11px] text-white/75">API keys are managed in the AIR Cloud console. Use `air login` from the CLI to authenticate.</p>
      {:else}
        <p class="text-[11px] text-white/75">Connect to AIR Cloud to manage API keys.</p>
      {/if}

    {:else if activeSection === 'team'}
      <h2 class="hud-label mb-4">TEAM</h2>
      <div class="glass-panel p-4 mb-3">
        <div class="text-[9px] font-mono text-white/90 mb-2">YOUR ROLE</div>
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-violet-500 to-indigo-500 flex items-center justify-center text-xs font-bold">{(authStore.user?.email ?? 'U')[0]?.toUpperCase()}</div>
          <div>
            <div class="text-sm text-white">{authStore.user?.email ?? 'Not signed in'}</div>
            <div class="text-[10px] font-mono text-white/75 uppercase">{roleStore.current}</div>
          </div>
        </div>
      </div>
      <div class="glass-panel p-4">
        <div class="text-[9px] font-mono text-white/90 mb-2">ACCESS LEVELS</div>
        <div class="space-y-2 text-[11px]">
          <div class="flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-emerald-400"></span><span class="text-white/90">Owner</span><span class="text-white/90 flex-1 text-right">Full access, billing, delete workspace</span></div>
          <div class="flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-cyan-400"></span><span class="text-white/90">Admin</span><span class="text-white/90 flex-1 text-right">Manage keys, SIEM, approve/deny</span></div>
          <div class="flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-violet-400"></span><span class="text-white/90">Member</span><span class="text-white/90 flex-1 text-right">View chain, findings, timeline</span></div>
        </div>
      </div>

    {:else if activeSection === 'export'}
      <h2 class="hud-label mb-4">EXPORT</h2>
      {#if replayStore.emitted.length > 0}
        <p class="text-[11px] text-white/75 mb-4">{replayStore.emitted.length} records, {findingsStore.all.length} findings available for export.</p>
        <div class="space-y-2">
          <button onclick={exportJSON} class="w-full py-3 text-sm font-medium border border-cyan-400/20 text-cyan-300 hover:bg-cyan-500/10 transition-all">Export JSON Evidence Pack</button>
          <button onclick={exportCSV} class="w-full py-3 text-sm font-medium border border-violet-400/20 text-violet-300 hover:bg-violet-500/10 transition-all">Export CSV Findings</button>
        </div>
      {:else}
        <p class="text-[11px] text-white/75">Load chain data to enable exports.</p>
      {/if}
    {/if}
  </div>
</div>

<style>
  @keyframes slide-in-right {
    from { transform: translateX(100%); }
    to { transform: translateX(0); }
  }
</style>

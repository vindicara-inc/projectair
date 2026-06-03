<script lang="ts">
  import type { AgDRRecord, Finding, Severity } from '../../agdr/types.ts';
  import { inferAgentId, describeAction } from '../../agents/derive.ts';
  import type { LedgerEntry } from '../../stores/verifier.svelte.ts';

  let {
    records = [],
    findings = [],
    verifierEntries = [],
    focusedIndex = -1,
    onSelectRecord,
  }: {
    records: AgDRRecord[];
    findings: Finding[];
    verifierEntries: LedgerEntry[];
    focusedIndex?: number;
    onSelectRecord?: (index: number) => void;
  } = $props();

  let scrollEl: HTMLDivElement | undefined = $state(undefined);
  let stickToBottom = $state(true);
  let searchQuery = $state('');
  let rowEls = $state<Map<number, HTMLElement>>(new Map());

  const findingsByStep = $derived.by(() => {
    const m = new Map<number, Finding[]>();
    for (const f of findings) {
      const list = m.get(f.step_index);
      if (list) list.push(f); else m.set(f.step_index, [f]);
    }
    return m;
  });

  const verifierByIndex = $derived.by(() => {
    const m = new Map<number, LedgerEntry>();
    for (const e of verifierEntries) m.set(e.index, e);
    return m;
  });

  const matchedIndices = $derived.by(() => {
    if (!searchQuery.trim()) return new Set<number>();
    const q = searchQuery.toLowerCase();
    const result = new Set<number>();
    for (let i = 0; i < records.length; i++) {
      const rec = records[i]!;
      const rawTs = rec.timestamp?.toLowerCase() ?? '';
      const localTs = formatTime(rec.timestamp).toLowerCase();
      const fullTs = formatFullTime(rec.timestamp).toLowerCase();
      const agent = inferAgentId(rec, i).toLowerCase();
      const tool = rec.payload?.tool_name?.toLowerCase() ?? '';
      const kind = rec.kind.toLowerCase();
      const action = describeAction(rec).toLowerCase();
      if (rawTs.includes(q) || localTs.includes(q) || fullTs.includes(q) || agent.includes(q) || tool.includes(q) || kind.includes(q) || action.includes(q)) {
        result.add(i);
      }
    }
    return result;
  });

  const matchCount = $derived(searchQuery.trim() ? matchedIndices.size : records.length);
  const isSearching = $derived(searchQuery.trim().length > 0);

  $effect(() => {
    if (focusedIndex >= 0) {
      const el = rowEls.get(focusedIndex);
      if (el) {
        stickToBottom = false;
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }
  });

  function handleScroll(): void {
    if (!scrollEl) return;
    const { scrollHeight, scrollTop, clientHeight } = scrollEl;
    stickToBottom = scrollHeight - scrollTop - clientHeight < 40;
  }

  $effect(() => {
    const _len = records.length;
    void _len;
    if (stickToBottom && scrollEl && focusedIndex < 0) {
      scrollEl.scrollTop = scrollEl.scrollHeight;
    }
  });

  function jumpToFirstMatch(): void {
    if (matchedIndices.size === 0) return;
    const idx = Math.min(...matchedIndices);
    onSelectRecord?.(idx);
    const el = rowEls.get(idx);
    if (el) { stickToBottom = false; el.scrollIntoView({ behavior: 'smooth', block: 'center' }); }
  }

  function formatTime(ts: string): string {
    try { return new Date(ts).toTimeString().slice(0, 12); } catch { return '--:--:--'; }
  }

  function formatFullTime(ts: string): string {
    try { return new Date(ts).toISOString().replace('T', ' ').slice(0, 23); } catch { return ts; }
  }

  const KIND_COLORS: Record<string, string> = {
    tool_start: '#22d3ee', tool_end: '#22d3ee',
    llm_start: '#a855f7', llm_end: '#a855f7',
    agent_message: '#d946ef', human_approval: '#ff5468',
    intent_declaration: '#6effb3', anchor: '#ffb547',
  };

  function kindColor(kind: string): string { return KIND_COLORS[kind] ?? 'rgba(255,255,255,0.3)'; }

  function agentDotColor(agentId: string): string {
    let hash = 0;
    for (let i = 0; i < agentId.length; i++) hash = agentId.charCodeAt(i) + ((hash << 5) - hash);
    return `hsl(${((hash % 360) + 360) % 360}, 70%, 60%)`;
  }

  const SEV_ORDER: Record<Severity, number> = { critical: 3, high: 2, medium: 1 };
  function worstSev(list: Finding[]): Severity {
    let w: Severity = 'medium';
    for (const f of list) if (SEV_ORDER[f.severity] > SEV_ORDER[w]) w = f.severity;
    return w;
  }

  function registerRow(el: HTMLElement, i: number): { destroy: () => void } {
    rowEls.set(i, el);
    return { destroy() { rowEls.delete(i); } };
  }

  function isMatch(i: number): boolean {
    return !isSearching || matchedIndices.has(i);
  }
</script>

<div class="glass-panel flex flex-col h-full overflow-hidden">
  <div class="flex items-center gap-3 px-4 py-2.5 border-b border-white/8">
    <h2 class="hud-label shrink-0" style="font-size: 9px;">EVENT TIMELINE</h2>
    <div class="flex-1 relative">
      <input
        bind:value={searchQuery}
        onkeydown={(e: KeyboardEvent) => e.key === 'Enter' && jumpToFirstMatch()}
        placeholder="Search timestamp, agent, tool..."
        class="w-full bg-white/5 border border-white/10 px-3 py-1.5 text-[11px] font-mono text-white/80 placeholder:text-white/25 focus:outline-none focus:border-nebula-accent/40"
      />
      {#if searchQuery}
        <span class="absolute right-2 top-1/2 -translate-y-1/2 text-[9px] font-mono" style="color: {matchCount > 0 ? '#22d3ee' : '#ff5468'};">
          {matchCount} match{matchCount !== 1 ? 'es' : ''}
        </span>
      {/if}
    </div>
    <span class="font-mono text-[10px] text-nebula-accent shrink-0">{records.length}</span>
  </div>

  <div bind:this={scrollEl} onscroll={handleScroll} class="flex-1 overflow-y-auto custom-scroll">
    {#each records as record, i (record.step_id)}
        {@const agentId = inferAgentId(record, i)}
        {@const stepFindings = findingsByStep.get(i)}
        {@const vEntry = verifierByIndex.get(i)}
        {@const isFocused = focusedIndex === i}
        {@const matched = isMatch(i)}
        <button
          type="button"
          use:registerRow={i}
          onclick={() => onSelectRecord?.(i)}
          class="w-full text-left px-3 py-2 flex items-center gap-2 border-b border-white/5 hover:bg-white/[0.04] transition-colors cursor-pointer"
          style="{isFocused ? 'background: rgba(34,211,238,0.08); border-left: 2px solid #22d3ee;' : matched && isSearching ? 'background: rgba(168,85,247,0.06); border-left: 2px solid #a855f7;' : ''} {!matched ? 'opacity: 0.25;' : ''}"
          title={formatFullTime(record.timestamp)}
        >
          <span class="font-mono text-[10px] text-white/25 w-7 shrink-0 text-right">{i}</span>
          <span class="font-mono text-[10px] text-white/50 w-20 shrink-0">{formatTime(record.timestamp)}</span>
          <span class="flex items-center gap-1.5 shrink-0 min-w-[90px]">
            <span class="w-2 h-2 rounded-full shrink-0" style="background: {agentDotColor(agentId)};"></span>
            <span class="text-[10px] text-white/60 truncate max-w-[72px]">{agentId}</span>
          </span>
          <span class="text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 shrink-0"
            style="color: {kindColor(record.kind)}; background: color-mix(in srgb, {kindColor(record.kind)} 12%, transparent);">
            {record.kind.replace('_', ' ')}
          </span>
          <span class="text-xs text-white/70 truncate flex-1 min-w-0">{describeAction(record)}</span>
          <span class="flex items-center gap-1.5 shrink-0">
            {#if stepFindings && stepFindings.length > 0}
              <span class="severity-dot {worstSev(stepFindings)}"></span>
              <span class="text-[10px] font-mono text-white/50">{stepFindings.length}</span>
            {/if}
            {#if vEntry && vEntry.status !== 'ok'}
              <span class="w-2 h-2 rounded-full shrink-0" style="background: #ff5468; box-shadow: 0 0 6px rgba(255,84,104,0.5);" title={vEntry.reason ?? vEntry.status}></span>
            {/if}
          </span>
        </button>
    {/each}
    {#if records.length === 0}
      <div class="flex items-center justify-center h-full text-white/30 text-xs font-mono py-12">Awaiting records...</div>
    {/if}
  </div>
</div>

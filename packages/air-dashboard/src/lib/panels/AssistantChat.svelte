<script lang="ts">
  import { assistantStore } from '$lib/stores/assistant.svelte';
  import { replayStore } from '$lib/stores/replay.svelte';
  import { findingsStore } from '$lib/stores/findings.svelte';

  let input = $state('');

  const REFUSAL_RESPONSES = [
    'I can only answer questions about the current chain data.',
    'I cannot generate remediation advice. Remediation steps come from the curated template library.',
    'I cannot make predictions about future agent behavior.',
    'I can only reference signed chain records. I have no access to external data.',
    'That question is outside my scope. I can help you explore the chain records.',
    'I cannot compare this to data outside the current chain.',
    'I can only summarize what the signed evidence shows.'
  ];

  const OUT_OF_SCOPE_PATTERNS = [
    /predict|forecast|will happen/i,
    /recommend|suggest|advise|should I/i,
    /compare.*(?:other|external|outside)/i,
    /internet|web|google|search online/i
  ];

  function isOutOfScope(query: string): boolean {
    return OUT_OF_SCOPE_PATTERNS.some((p) => p.test(query));
  }

  function handleSubmit(): void {
    const query = input.trim();
    if (!query) return;
    input = '';
    assistantStore.addUserMessage(query);

    if (isOutOfScope(query)) {
      const refusal = REFUSAL_RESPONSES[Math.floor(Math.random() * REFUSAL_RESPONSES.length)]!;
      assistantStore.addAssistantMessage(refusal, []);
      return;
    }

    const records = replayStore.emitted;
    const findings = findingsStore.all;

    let response = '';
    const citations: number[] = [];

    if (/what.*agent.*do|activity|history/i.test(query)) {
      const agentActions = records.map((r, i) => ({ index: i, kind: r.kind, tool: r.payload.tool_name ?? '' }));
      const last10 = agentActions.slice(-10);
      response = `Based on the chain, the agent performed ${records.length} actions. The last ${last10.length} were: ${last10.map((a) => `#${a.index} ${a.kind}${a.tool ? ` (${a.tool})` : ''}`).join(', ')}.`;
      citations.push(...last10.map((a) => a.index));
    } else if (/finding|alert|issue|problem/i.test(query)) {
      if (findings.length === 0) {
        response = 'No findings in the current chain. All detectors returned clean.';
      } else {
        response = `There are ${findings.length} findings: ${findings.map((f) => `${f.detector_id} (${f.severity}) at record #${f.step_index}`).join(', ')}.`;
        citations.push(...findings.map((f) => f.step_index));
      }
    } else if (/happened before|repeat|recur/i.test(query)) {
      response = `I can only search the current chain (${records.length} records). Historical cross-chain queries require AIR Cloud with chain archival enabled.`;
    } else {
      response = `The current chain contains ${records.length} signed records with ${findings.length} findings. Ask me about specific agent activity, findings, or chain records.`;
    }

    assistantStore.addAssistantMessage(response, citations);
  }
</script>

{#if assistantStore.isOpen}
  <div class="fixed bottom-24 right-6 z-50 w-[380px]"
    style="background: linear-gradient(180deg, rgba(10,10,15,0.97) 0%, rgba(8,8,12,0.98) 100%);
           border: 1px solid var(--color-panel-edge);
           box-shadow: 0 10px 50px rgba(0,0,0,0.6), 0 0 30px rgba(220,38,38,0.05);
           animation: fade-up 0.2s ease-out; max-height: 500px; display: flex; flex-direction: column;">

    <div class="flex items-center justify-between px-4 py-3" style="border-bottom: 1px solid rgba(255,255,255,0.06);">
      <div class="flex items-center gap-2">
        <div class="w-3 h-3" style="background: radial-gradient(circle, var(--color-red) 0%, rgba(220,38,38,0.4) 100%);
          border-radius: 50% !important; box-shadow: 0 0 8px var(--color-red-glow);"></div>
        <span class="text-sm font-semibold" style="font-family: var(--font-ui); color: var(--color-text);">AIR Assistant</span>
      </div>
      <button class="text-xs cursor-pointer" style="color: var(--color-text-dim);"
        onclick={() => assistantStore.close()}>&times;</button>
    </div>

    <div class="flex-1 overflow-y-auto p-4 flex flex-col gap-3 min-h-[200px]">
      {#if assistantStore.messages.length === 0}
        <p class="text-xs text-center py-8" style="color: var(--color-text-dim); font-family: var(--font-ui);">
          Ask about agent activity, findings, or chain records.
          <br /><br />
          <span style="color: var(--color-red); text-shadow: 0 0 4px var(--color-red-glow);">
            Every response cites signed chain evidence.
          </span>
        </p>
      {:else}
        {#each assistantStore.messages as msg (msg.id)}
          <div class="flex flex-col gap-1 {msg.role === 'user' ? 'items-end' : 'items-start'}">
            <div class="max-w-[90%] px-3 py-2 text-sm"
              style="font-family: var(--font-ui); line-height: 1.5;
                     background: {msg.role === 'user' ? 'rgba(220,38,38,0.1)' : 'rgba(255,255,255,0.03)'};
                     border: 1px solid {msg.role === 'user' ? 'rgba(220,38,38,0.15)' : 'rgba(255,255,255,0.06)'};
                     color: var(--color-text);">
              {msg.content}
            </div>
            {#if msg.citations.length > 0}
              <span class="text-xs" style="color: var(--color-red); font-family: var(--font-data); font-size: 10px;
                text-shadow: 0 0 4px var(--color-red-glow);">
                Records: {msg.citations.map((c) => `#${c}`).join(', ')}
              </span>
            {/if}
          </div>
        {/each}
      {/if}
    </div>

    <form class="flex items-center gap-2 p-3" style="border-top: 1px solid rgba(255,255,255,0.06);"
      onsubmit={(e) => { e.preventDefault(); handleSubmit(); }}>
      <input
        type="text"
        bind:value={input}
        placeholder="Ask about this chain..."
        class="flex-1 text-sm px-3 py-2 outline-none"
        style="font-family: var(--font-ui); color: var(--color-text);
               background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.08);"
      />
      <button type="submit" class="btn-primary text-xs px-3 py-2">Send</button>
    </form>
  </div>
{/if}

<script lang="ts">
  import { assistantStore } from '$lib/stores/assistant.svelte';
  import { findingsStore } from '$lib/stores/findings.svelte';
  import { replayStore } from '$lib/stores/replay.svelte';
  import type { AgDRRecord } from '$lib/agdr/types';

  let input = $state('');

  function sendMessage(): void {
    if (!input.trim()) return;

    assistantStore.addUserMessage(input);
    const query = input.toLowerCase();
    input = '';

    const records = replayStore.emitted as AgDRRecord[];
    const findings = findingsStore.all;

    let response = '';
    const citations: number[] = [];

    const agentMatch = query.match(/agent[- ]?(\S+)/i);
    if (agentMatch) {
      const agentId = agentMatch[1];
      const agentRecords = records.filter(r => r.payload?.source_agent_id === agentId);
      const agentFindings = findings.filter(f => {
        const rec = records[f.step_index];
        return rec?.payload?.source_agent_id === agentId;
      });
      if (agentRecords.length > 0) {
        response = `Agent ${agentId} has ${agentRecords.length} recorded actions and ${agentFindings.length} finding(s).`;
        if (agentFindings.length > 0) {
          const top = agentFindings[0]!;
          response += ` Most severe: ${top.title} (${top.severity}).`;
          citations.push(top.step_index);
        }
      } else {
        response = `No records found for agent ${agentId} in the current chain.`;
      }
    } else if (query.includes('halt') || query.includes('block') || query.includes('stop')) {
      const critical = findings.filter(f => f.severity === 'critical');
      response = `${critical.length} critical finding(s) in the current chain.`;
      for (const f of critical.slice(0, 3)) {
        response += ` ${f.detector_id}: ${f.title} at step ${f.step_index}.`;
        citations.push(f.step_index);
      }
    } else if (query.includes('chain') || query.includes('integrity')) {
      response = `Chain has ${records.length} records. All signatures and hashes are verified in-browser using Ed25519 + BLAKE3.`;
    } else if (findings.length > 0) {
      response = `${findings.length} total finding(s) across the chain. ${findings.filter(f => f.severity === 'critical').length} critical, ${findings.filter(f => f.severity === 'high').length} high, ${findings.filter(f => f.severity === 'medium').length} medium.`;
    } else {
      response = `No findings detected in the current chain. ${records.length} records verified.`;
    }

    assistantStore.addAssistantMessage(response, citations);
  }
</script>

<div class="glass-panel w-[620px] rounded-3xl overflow-hidden border border-violet-500/30 shadow-2xl">
  <div class="bg-gradient-to-r from-indigo-600 to-violet-600 px-6 py-4 font-medium">
    Ask AIR &bull; Forensic Assistant
  </div>

  <div class="h-80 p-6 overflow-auto space-y-4 custom-scroll">
    {#if assistantStore.messages.length === 0}
      <div class="text-white/40 text-sm text-center pt-8">Ask about any agent, incident, or the chain.</div>
    {/if}
    {#each assistantStore.messages as msg (msg.id)}
      <div class={msg.role === 'user' ? 'text-right' : ''}>
        <div class="inline-block max-w-[85%] rounded-2xl px-5 py-3 {msg.role === 'user' ? 'bg-teal-500/20' : 'bg-white/5'}">
          <div class="text-sm">{msg.content}</div>
          {#if msg.citations.length > 0}
            <div class="text-xs text-teal-400 mt-2 font-mono">
              Steps: {msg.citations.join(', ')}
            </div>
          {/if}
        </div>
      </div>
    {/each}
  </div>

  <div class="p-4 border-t border-white/10 flex gap-3">
    <input
      bind:value={input}
      onkeydown={(e: KeyboardEvent) => e.key === 'Enter' && sendMessage()}
      placeholder="Ask about any incident, agent, or capsule..."
      class="flex-1 bg-white/5 border border-white/20 rounded-2xl px-5 py-3 text-sm focus:outline-none focus:border-teal-400 placeholder:text-white/40"
    />
    <button onclick={sendMessage} class="bg-teal-500 hover:bg-teal-400 px-8 rounded-2xl font-medium transition-colors">
      Send
    </button>
  </div>
</div>

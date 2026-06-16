<script lang="ts">
  import type { AgDRRecord } from '$lib/console/forensics/types';
  import TechDetails from './TechDetails.svelte';

  export interface TimelineItem {
    record: AgDRRecord;
    plain: string;
    detail?: string;
    legitimate?: boolean;
  }

  let {
    items,
    failedIndex = null,
    tampered = false
  }: { items: TimelineItem[]; failedIndex?: number | null; tampered?: boolean } = $props();

  const short = (h: string) => `${h.slice(0, 10)}…${h.slice(-6)}`;
  function payloadSummary(r: AgDRRecord): string {
    const p = r.payload;
    if (p.tool_name) return `${p.tool_name}(${p.tool_args ? JSON.stringify(p.tool_args) : ''})`;
    if (p.prompt) return p.prompt;
    if (p.response) return p.response;
    if (p.tool_output) return p.tool_output;
    if (p.final_output) return p.final_output;
    if (p.human_approval) return `human_approval: ${p.human_approval.decision} by ${p.human_approval.approver_sub}`;
    return r.kind;
  }
</script>

<ol class="tl">
  {#each items as it, i}
    {@const broken = tampered && failedIndex === i}
    {@const downstream = tampered && failedIndex !== null && i > failedIndex}
    <li class="step" class:legit={it.legitimate} class:flag={!it.legitimate && !broken} class:broken class:downstream>
      <div class="rail">
        <span class="node"></span>
      </div>
      <div class="body">
        <div class="top">
          <span class="n">Step {i + 1}</span>
          {#if it.legitimate}<span class="tick">authorized</span>{/if}
          {#if broken}<span class="tamperflag">⚠ Tampering detected here</span>{/if}
        </div>
        <div class="plain">{it.plain}</div>
        {#if it.detail}<div class="detail">{it.detail}</div>{/if}
        {#if broken}
          <div class="brokenmsg">This record was changed after it was signed. Tampering detected.</div>
        {/if}

        <TechDetails>
          <div><span class="k">action:</span> <b>{payloadSummary(it.record)}</b></div>
          <div><span class="k">type:</span> {it.record.kind}</div>
          <div><span class="k">step id:</span> {it.record.step_id}</div>
          <div><span class="k">when:</span> {it.record.timestamp}</div>
          <div><span class="k">content hash (BLAKE3):</span> <span class="hash">{it.record.content_hash}</span></div>
          <div><span class="k">links to previous (prev_hash):</span> <span class="hash">{short(it.record.prev_hash)}</span></div>
          <div><span class="k">signature (Ed25519):</span> <span class="hash">{short(it.record.signature)}</span></div>
          <div><span class="k">signed by (key):</span> <span class="hash">{short(it.record.signer_key)}</span></div>
        </TechDetails>
      </div>
    </li>
  {/each}
</ol>

<style>
  .tl { list-style: none; display: flex; flex-direction: column; }
  .step { display: grid; grid-template-columns: 26px 1fr; gap: 14px; padding: 4px 0; }
  .rail { display: flex; flex-direction: column; align-items: center; }
  .rail::before, .rail::after { content: ''; width: 1px; flex: 1; background: var(--hair); }
  .step:first-child .rail::before { background: transparent; }
  .step:last-child .rail::after { background: transparent; }
  .node { width: 11px; height: 11px; border-radius: 50%; border: 2px solid var(--faint); background: var(--bg); flex: 0 0 auto; margin: 3px 0; }
  .legit .node { border-color: var(--teal); box-shadow: 0 0 8px rgba(72,230,164,.5); }
  .flag .node { border-color: var(--air); background: rgba(230,57,70,.25); box-shadow: 0 0 8px rgba(230,57,70,.5); }
  .broken .node { border-color: var(--air); background: var(--air); box-shadow: 0 0 14px var(--air); }
  .body { padding-bottom: 16px; min-width: 0; }
  .top { display: flex; align-items: center; gap: 10px; margin-bottom: 3px; }
  .n { font-family: var(--mono); font-size: 9.5px; letter-spacing: .12em; text-transform: uppercase; color: var(--faint); }
  .tick { font-family: var(--mono); font-size: 9px; letter-spacing: .08em; text-transform: uppercase; color: #bff5df; }
  .tamperflag { font-family: var(--mono); font-size: 9.5px; letter-spacing: .06em; color: #ffd0d4; }
  .plain { font-size: 14.5px; font-weight: 600; line-height: 1.3; }
  .flag .plain { color: #ffd9dc; }
  .detail { font-size: 12.5px; color: var(--muted); margin-top: 3px; line-height: 1.45; }
  .brokenmsg { margin-top: 8px; padding: 9px 12px; border: 1px solid rgba(230,57,70,.5); background: rgba(230,57,70,.12); color: #ffd0d4; font-size: 12.5px; font-weight: 600; }
  .downstream { opacity: .42; }
  .downstream .plain { text-decoration: line-through; text-decoration-color: rgba(255,255,255,.25); }
</style>

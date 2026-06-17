<script lang="ts">
  import type { AgDRRecord, BuiltScenario, VerificationResult } from '$lib/console/forensics/types';
  import { verifyChain, tamperChain } from '$lib/console/forensics/crypto';
  import { recordReview } from '$lib/console/stores/sessionlog';
  import Panel from '$lib/console/components/Panel.svelte';
  import StatusPill from './StatusPill.svelte';
  import SeverityPill from './SeverityPill.svelte';
  import StepTimeline, { type TimelineItem } from './StepTimeline.svelte';
  import FindingsPanel from './FindingsPanel.svelte';
  import IntentVerdictPanel from './IntentVerdictPanel.svelte';
  import IntegrityPanel from './IntegrityPanel.svelte';
  import ContainmentPanel from './ContainmentPanel.svelte';
  import ExportBar from './ExportBar.svelte';

  let { scenario, onback }: { scenario: BuiltScenario; onback: () => void } = $props();

  // The live chain. Resets whenever the scenario changes (switching incidents).
  let chain = $state<AgDRRecord[]>([...scenario.records]);
  let tampered = $state(false);
  let verification = $state<VerificationResult | null>(null);

  $effect(() => {
    // re-seed when the selected scenario changes
    scenario.id;
    chain = [...scenario.records];
    tampered = false;
    verification = null;
    recordReview(scenario.id, scenario.title);
  });

  let displayChain = $derived(
    tampered && scenario.tamper
      ? tamperChain(chain, scenario.tamper.stepIndex, scenario.tamper.mutate)
      : chain
  );

  function plainFor(index: number, record: AgDRRecord): Omit<TimelineItem, 'record'> {
    const spec = scenario.steps[index];
    if (spec) return { plain: spec.plain, detail: spec.detail, legitimate: spec.legitimate };
    if (record.kind === 'human_approval') {
      const ha = record.payload.human_approval;
      const approve = ha?.decision === 'approve';
      return {
        plain: approve ? 'A clinician approved the change' : 'A clinician kept the change blocked',
        detail: `Decision recorded on-chain · authorized by ${ha?.approver_name ?? ha?.approver_sub ?? 'operator'}`,
        legitimate: true
      };
    }
    return { plain: record.kind, legitimate: true };
  }

  let items = $derived<TimelineItem[]>(
    displayChain.map((record, index) => ({ record, ...plainFor(index, record) }))
  );

  function verify() {
    tampered = false;
    verification = verifyChain(chain);
  }
  function simulateTamper() {
    if (!scenario.tamper) return;
    tampered = true;
    verification = verifyChain(tamperChain(chain, scenario.tamper.stepIndex, scenario.tamper.mutate));
  }
  function reset() {
    tampered = false;
    verification = null;
  }
  function onDecision(updated: AgDRRecord[]) {
    chain = updated;
    // keep integrity honest: a fresh decision invalidates any prior verify display
    verification = null;
    tampered = false;
  }
</script>

<div class="detail">
  <button class="back" onclick={onback}>← All incidents</button>

  <!-- Plain-English summary first, before any timeline or codes. -->
  <section class="hero glass hud" class:contained={scenario.status === 'contained'}>
    <div class="meta">
      <StatusPill status={scenario.status} />
      <SeverityPill severity={scenario.severity} />
      <span class="agent"><b>{scenario.agentLabel}</b> · {scenario.agentDescription}</span>
      <span class="dot">·</span>
      <span class="when">{new Date(scenario.occurredAt).toLocaleString()}</span>
    </div>
    <h1>{scenario.title}</h1>
    <p class="headline">{scenario.plainHeadline}</p>
  </section>

  {#if scenario.containment}
    <Panel klass="sec">
      <div class="ph"><h3>Action paused for a human</h3><span class="hint">human-in-the-loop</span></div>
      <ContainmentPanel {scenario} {chain} ondecision={onDecision} />
    </Panel>
  {/if}

  <Panel klass="sec">
    <div class="ph"><h3>What happened, step by step</h3><span class="hint">{items.length} signed steps</span></div>
    <StepTimeline {items} failedIndex={verification?.failed_index ?? null} {tampered} />
  </Panel>

  {#if scenario.findings.length}
    <Panel klass="sec">
      <div class="ph"><h3>What Project AIR caught</h3><span class="hint">{scenario.findings.length} findings</span></div>
      <FindingsPanel findings={scenario.findings} />
    </Panel>
  {/if}

  <Panel klass="sec">
    <div class="ph"><h3>Did it do what it was asked?</h3><span class="hint">intent verification</span></div>
    <IntentVerdictPanel verdict={scenario.verdict} />
  </Panel>

  <Panel klass="sec signature">
    <div class="ph"><h3>Proof the record can't be altered</h3><span class="hint">tamper-evident</span></div>
    <IntegrityPanel
      {verification}
      {tampered}
      canTamper={!!scenario.tamper}
      recordCount={displayChain.length}
      signerKey={scenario.signerKey}
      onverify={verify}
      ontamper={simulateTamper}
      onreset={reset}
    />
  </Panel>

  <Panel klass="sec">
    <div class="ph"><h3>Take this with you</h3><span class="hint">export · SIEM</span></div>
    <ExportBar {scenario} chain={displayChain} {verification} />
  </Panel>
</div>

<style>
  .detail { display: flex; flex-direction: column; gap: 18px; }
  .back { align-self: flex-start; background: none; border: 0; color: var(--muted); font-family: var(--ui); font-size: 13px; cursor: pointer; padding: 0; }
  .back:hover { color: var(--ink); }
  .hero { padding: 26px 28px; border-left: 3px solid var(--air); }
  .hero.contained { border-left-color: var(--blue); }
  .meta { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; color: var(--faint); font-size: 12px; }
  .meta .agent { color: var(--muted); }
  .hero h1 { font-family: var(--display); font-size: 27px; font-weight: 600; letter-spacing: -.02em; line-height: 1.15; margin: 14px 0 12px; }
  .headline { font-size: 16px; line-height: 1.6; color: #dfe3ea; max-width: 78ch; }
  :global(.detail .sec) { padding: 22px 24px; }
  :global(.detail .signature) { border-color: rgba(72,230,164,.28); }
</style>

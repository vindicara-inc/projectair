<script lang="ts">
  import type { AgDRRecord, BuiltScenario, HumanApproval } from '$lib/console/forensics/types';
  import { appendSignedStep } from '$lib/console/forensics/crypto';
  import { deterministicStepId } from '$lib/console/forensics/scenarios/build';
  import { operator, operatorSub } from '$lib/console/stores/operator';
  import { recordDecision } from '$lib/console/stores/sessionlog';
  import TechDetails from './TechDetails.svelte';

  let {
    scenario,
    chain,
    ondecision
  }: { scenario: BuiltScenario; chain: AgDRRecord[]; ondecision: (records: AgDRRecord[]) => void } = $props();

  let c = $derived(scenario.containment!);
  let decided = $state<'approve' | 'deny' | null>(null);
  let decidedBy = $state<{ name: string; org: string } | null>(null);

  // Whose name gets recorded. Uses the signed-in operator; falls back to a clearly
  // labelled demo clinician if no one has signed in yet.
  let authorizer = $derived(
    $operator.signedInAt
      ? { name: $operator.name, org: $operator.organization, role: $operator.role, sub: operatorSub($operator) }
      : { name: 'Dr. A. Rivera', org: 'Demo Health System', role: 'Attending physician', sub: 'auth0|a.rivera' }
  );

  function decide(decision: 'approve' | 'deny') {
    const nowIso = new Date().toISOString();
    const nowSec = Math.floor(Date.parse(nowIso) / 1000);
    const ha: HumanApproval = {
      challenge_id: c.challengeId,
      decision,
      approver_sub: authorizer.sub,
      approver_email: `${authorizer.sub.split('|')[1]}@${authorizer.org.toLowerCase().replace(/[^a-z0-9]+/g, '')}.example`,
      approver_name: authorizer.name,
      approver_org: authorizer.org,
      issuer: 'https://vindicara.us.auth0.com/',
      audience: 'projectair-console',
      issued_at: nowSec,
      expires_at: nowSec + 3600,
      signed_token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.demo-synthetic-token.sig'
    };
    const updated = appendSignedStep(
      chain,
      {
        kind: 'human_approval',
        step_id: deterministicStepId(scenario.id, chain.length),
        timestamp: nowIso,
        payload: { challenge_id: c.challengeId, human_approval: ha }
      },
      scenario.seedHex
    );
    decided = decision;
    decidedBy = { name: authorizer.name, org: authorizer.org };
    recordDecision({ incidentId: scenario.id, title: scenario.title, decision, approver: authorizer.name });
    ondecision(updated);
  }

  function resetDecision() {
    decided = null;
    decidedBy = null;
    ondecision([...scenario.records]);
  }
</script>

<div class="contain">
  <div class="blocked">
    <div class="bh">
      <span class="shield">⛔</span>
      <div>
        <div class="bt">Project AIR blocked this and paused for a human</div>
        <div class="bsub">No medication order was changed. Nothing happens until a clinician decides.</div>
      </div>
    </div>
    <dl class="facts">
      <div><dt>What the agent tried to do</dt><dd>{c.blockedAction}</dd></div>
      <div><dt>Why it was blocked</dt><dd>{c.blockedReasonPlain}</dd></div>
      <div><dt>Patient context</dt><dd>{c.patientContext}</dd></div>
    </dl>
  </div>

  {#if decided === null}
    <div class="ask">
      <div class="askh">Waiting for a human to approve or reject</div>
      <div class="who">Recorded as: <b>{authorizer.name}</b> · {authorizer.org}{#if !$operator.signedInAt}<span class="hintdemo"> (sign in to record your own name)</span>{/if}</div>
      <div class="ctrls">
        <button class="btn crit" onclick={() => decide('approve')}>Approve this change</button>
        <button class="btn ok" onclick={() => decide('deny')}>Keep it blocked</button>
      </div>
    </div>
  {:else}
    <div class="outcome o-{decided}">
      {#if decided === 'approve'}
        <div class="oh">✓ Change approved — and tied to the human who authorized it</div>
        <p>
          <b>{decidedBy?.name}</b> ({decidedBy?.org}) approved the order change. Project AIR recorded
          exactly who made the call, signed into the same tamper-evident record.
        </p>
      {:else}
        <div class="oh">✕ Kept blocked</div>
        <p>
          <b>{decidedBy?.name}</b> ({decidedBy?.org}) upheld the block. The agent’s attempted change
          was rejected, and that decision is recorded on-chain.
        </p>
      {/if}
      <button class="btn ghost" onclick={resetDecision}>Reset decision (show the other outcome)</button>
    </div>
  {/if}

  <TechDetails>
    <div><span class="k">challenge id:</span> {c.challengeId}</div>
    <div><span class="k">containment:</span> {c.blockedReasonTechnical}</div>
    {#if decided}
      <div><span class="k">decision:</span> <b>{decided}</b> recorded as kind=human_approval, signed into the chain</div>
      <div><span class="k">approver_sub:</span> {authorizer.sub}</div>
      <div><span class="k">issuer:</span> https://vindicara.us.auth0.com/ · audience: projectair-console</div>
    {/if}
  </TechDetails>
</div>

<style>
  .contain { display: flex; flex-direction: column; gap: 16px; }
  .blocked { border: 1px solid rgba(109,181,255,.3); background: rgba(109,181,255,.06); padding: 16px 18px; }
  .bh { display: flex; gap: 13px; align-items: flex-start; }
  .shield { font-size: 20px; line-height: 1; }
  .bt { font-size: 15px; font-weight: 600; }
  .bsub { font-size: 12.5px; color: var(--muted); margin-top: 3px; }
  .facts { margin-top: 15px; display: flex; flex-direction: column; gap: 10px; }
  .facts dt { font-family: var(--mono); font-size: 9.5px; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); margin-bottom: 3px; }
  .facts dd { font-size: 13.5px; line-height: 1.45; }
  .ask { border: 1px solid var(--hair); padding: 16px 18px; }
  .askh { font-size: 14px; font-weight: 600; }
  .who { font-size: 12.5px; color: var(--muted); margin-top: 6px; }
  .who b { color: var(--ink); }
  .hintdemo { color: var(--faint); }
  .ctrls { display: flex; gap: 11px; margin-top: 14px; }
  .ctrls .btn { padding: 10px 18px; font-size: 13px; }
  .outcome { padding: 16px 18px; border: 1px solid; }
  .o-approve { border-color: rgba(255,180,84,.42); background: rgba(255,180,84,.08); }
  .o-deny { border-color: rgba(72,230,164,.4); background: rgba(72,230,164,.08); }
  .oh { font-size: 15px; font-weight: 600; }
  .o-approve .oh { color: #ffd9a6; }
  .o-deny .oh { color: #bff5df; }
  .outcome p { font-size: 13px; line-height: 1.55; color: var(--muted); margin: 9px 0 14px; }
  .outcome b { color: var(--ink); }
</style>

<script lang="ts">
  import type { IntentVerification } from '$lib/console/forensics/types';
  import SeverityPill from './SeverityPill.svelte';
  import TechDetails from './TechDetails.svelte';
  let { verdict }: { verdict: IntentVerification } = $props();

  const verdictPlain: Record<string, string> = {
    failed: 'The agent did something it was never asked to do',
    verified: 'The agent stayed within what it was asked to do',
    inconclusive: 'Could not be determined automatically'
  };
</script>

<div class="verdict v-{verdict.verdict}">
  <div class="cols">
    <div class="col">
      <div class="lab">What the agent was asked to do</div>
      <div class="intent">{verdict.intent}</div>
    </div>
    <div class="arrow" aria-hidden="true">→</div>
    <div class="col">
      <div class="lab">What Project AIR found</div>
      <div class="vtitle">{verdictPlain[verdict.verdict]}</div>
    </div>
  </div>

  <div class="plainverdict">{verdict.plainVerdict}</div>

  {#if verdict.violations.length}
    <div class="vlist">
      {#each verdict.violations as v}
        <div class="viol">
          <div class="vh">
            <span class="vt">{v.plainTitle}</span>
            <SeverityPill severity={v.severity} />
          </div>
          <div class="why">{v.whyItMatters}</div>
          {#if v.causal_path.length}
            <div class="path">
              <span class="plab">How it happened:</span>
              {#each v.causal_path as ord, idx}
                <span class="node">Step {ord + 1}</span>{#if idx < v.causal_path.length - 1}<span class="conn">→</span>{/if}
              {/each}
            </div>
          {/if}
          <TechDetails>
            <div><span class="k">check:</span> <b>{v.check_id}</b> — {v.title}</div>
            <div><span class="k">expected:</span> {v.expected}</div>
            <div><span class="k">actual:</span> {v.actual}</div>
            <div><span class="k">causal path (step ordinals):</span> {v.causal_path.join(' → ')}</div>
          </TechDetails>
        </div>
      {/each}
    </div>
  {/if}

  <TechDetails label="Technical verdict">
    <div><b>{verdict.technicalVerdict}</b></div>
    <div class="k">{verdict.summary}</div>
  </TechDetails>
</div>

<style>
  .verdict { padding: 4px 0; }
  .cols { display: grid; grid-template-columns: 1fr 22px 1fr; align-items: center; gap: 14px; }
  .lab { font-family: var(--mono); font-size: 9.5px; letter-spacing: .12em; text-transform: uppercase; color: var(--faint); margin-bottom: 7px; }
  .intent { font-size: 14px; line-height: 1.4; color: var(--ink); }
  .vtitle { font-size: 14px; line-height: 1.4; font-weight: 600; }
  .arrow { text-align: center; color: var(--faint); font-size: 18px; }
  .v-failed .vtitle { color: #ffd0d4; }
  .v-verified .vtitle { color: #bff5df; }
  .plainverdict {
    margin-top: 16px; padding: 13px 15px; font-size: 14px; line-height: 1.5; font-weight: 500;
    border: 1px solid;
  }
  .v-failed .plainverdict { border-color: rgba(230,57,70,.42); background: rgba(230,57,70,.1); color: #ffdee0; }
  .v-verified .plainverdict { border-color: rgba(72,230,164,.4); background: rgba(72,230,164,.08); color: #d6f7e8; }
  .v-inconclusive .plainverdict { border-color: rgba(255,180,84,.4); background: rgba(255,180,84,.1); color: #ffe6c2; }
  .vlist { display: flex; flex-direction: column; gap: 11px; margin-top: 16px; }
  .viol { padding: 13px 15px; border: 1px solid var(--hair); background: rgba(255,255,255,.02); }
  .vh { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .vt { font-size: 13.5px; font-weight: 600; }
  .why { font-size: 12px; color: var(--muted); margin-top: 5px; line-height: 1.5; }
  .path { display: flex; align-items: center; flex-wrap: wrap; gap: 7px; margin-top: 10px; }
  .plab { font-family: var(--mono); font-size: 9.5px; letter-spacing: .08em; text-transform: uppercase; color: var(--faint); margin-right: 3px; }
  .node { font-family: var(--mono); font-size: 10px; padding: 3px 9px; border: 1px solid rgba(230,57,70,.4); background: rgba(230,57,70,.1); color: #ffc4c8; }
  .conn { color: var(--air); font-weight: 700; }
</style>

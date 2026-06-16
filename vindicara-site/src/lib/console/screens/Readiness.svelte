<script lang="ts">
  import { api } from '$lib/console/api/client';
  import Panel from '$lib/console/components/Panel.svelte';
  import StateBlock from '$lib/console/components/StateBlock.svelte';
  let load = $state(api.getReadiness());
  const ring = (pct: number) => 100 - pct; // dashoffset over dasharray 100
</script>

{#await load}
  <Panel><StateBlock kind="loading" /></Panel>
{:then d}
  <Panel reveal klass="score">
    <div class="ring">
      <svg width="104" height="104" viewBox="0 0 104 104"><circle cx="52" cy="52" r="44" fill="none" stroke="rgba(255,255,255,.1)" stroke-width="7"/><circle cx="52" cy="52" r="44" fill="none" stroke="#48e6a4" stroke-width="7" stroke-linecap="round" stroke-dasharray="276" stroke-dashoffset="0" transform="rotate(-90 52 52)"/></svg>
      <div class="n">{d.scoreYes}<span>/{d.scoreTotal}</span></div>
    </div>
    <div>
      <div class="st-big">All {d.scoreTotal === d.scoreYes ? 'four' : ''} answered: yes</div>
      <div class="st-sub">These are the questions a health system uses to decide whether your AI is HIPAA compliant. Every one is backed by evidence the deterministic floor produces, not a promise. Find your gaps before the buyer does, then close them here.</div>
    </div>
    <div class="acts">
      <button class="authbtn ok"><span class="key"></span>Export readiness report</button>
      <button class="btn">Share with buyer</button>
    </div>
  </Panel>

  <div class="yes4">
    {#each d.questions as q, i}
      <Panel reveal delay={0.06 + i * 0.04} klass="qcard">
        <div class="check">✓</div>
        <div><div class="qq">{q.question}</div><div class="qa">{@html q.proof}</div></div>
      </Panel>
    {/each}
  </div>

  <Panel reveal delay={0.3} klass="why">
    <div class="whygrid">
      <div>
        <div class="wt">Why every answer holds: the deterministic floor</div>
        <div class="wx">Each yes comes from structural checks that run as fixed logic over what the agent actually did, not an AI making a judgment call. They return the same verdict every time and <b>cannot be jailbroken or talked out of blocking</b>. That is what turns a compliance claim into evidence a buyer can verify for themselves, which is the whole point of the four questions above.</div>
      </div>
      <div class="rings">
        {#each d.compliance as c}
          <div class="rg">
            <svg width="40" height="40" viewBox="0 0 40 40"><circle cx="20" cy="20" r="16" fill="none" stroke="rgba(255,255,255,.1)" stroke-width="4"/><circle cx="20" cy="20" r="16" fill="none" stroke={c.state === 'good' ? '#48e6a4' : '#ffb454'} stroke-width="4" stroke-linecap="round" stroke-dasharray="100" stroke-dashoffset={ring(c.pct)} transform="rotate(-90 20 20)"/></svg>
            <div><div class="t">{c.framework}</div><div class="d">{c.detail}</div></div>
          </div>
        {/each}
      </div>
    </div>
  </Panel>
{:catch err}
  <Panel><StateBlock kind="error" message={err.message} /></Panel>
{/await}

<style>
  :global(.score) { display: flex; align-items: center; gap: 22px; padding: 22px 24px; flex-wrap: wrap; flex-direction: row; }
  .ring { position: relative; width: 104px; height: 104px; flex: 0 0 104px; }
  .ring .n { position: absolute; inset: 0; display: grid; place-items: center; font-family: var(--display); font-size: 26px; font-weight: 600; }
  .ring .n span { font-size: 14px; color: var(--faint); }
  .st-big { font-family: var(--display); font-size: 19px; font-weight: 600; color: #bff5df; }
  .st-sub { font-size: 12.5px; color: var(--muted); margin-top: 5px; max-width: 460px; line-height: 1.5; }
  .acts { margin-left: auto; display: flex; gap: 10px; flex-wrap: wrap; }
  .authbtn { display: flex; align-items: center; gap: 9px; padding: 9px 15px; border: 1px solid rgba(72,230,164,.35); background: linear-gradient(180deg, rgba(72,230,164,.18), rgba(72,230,164,.04)); color: #bff5df; font-weight: 600; font-size: 13px; cursor: pointer; }
  .key { width: 14px; height: 14px; border-radius: 3px; background: radial-gradient(circle at 30% 30%, #fff, #7af0c0); }

  .yes4 { display: grid; grid-template-columns: repeat(2, 1fr); gap: 18px; }
  :global(.qcard) { padding: 18px 20px; display: flex; flex-direction: row; align-items: flex-start; gap: 14px; }
  .check { width: 30px; height: 30px; border-radius: 50%; flex: 0 0 30px; display: grid; place-items: center; background: linear-gradient(135deg, #19b27a, #48e6a4); color: #04140d; font-weight: 800; font-size: 15px; box-shadow: 0 0 16px rgba(72,230,164,.35); }
  .qq { font-size: 14px; font-weight: 600; }
  .qa { font-size: 11.5px; color: var(--muted); margin-top: 5px; line-height: 1.55; }
  .qa :global(b) { color: #bff5df; font-weight: 600; }

  :global(.why) { padding: 22px 24px; }
  .whygrid { display: grid; grid-template-columns: 1.25fr 1fr; gap: 26px; align-items: center; }
  .wt { font-family: var(--display); font-size: 16px; font-weight: 600; margin-bottom: 8px; }
  .wx { font-size: 12.5px; color: var(--muted); line-height: 1.65; }
  .wx :global(b) { color: #cfe9ff; font-weight: 600; }
  .rings { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; }
  .rg { display: flex; align-items: center; gap: 11px; }
  .rg .t { font-size: 12px; font-weight: 600; } .rg .d { font-family: var(--mono); font-size: 9.5px; color: var(--faint); margin-top: 2px; }

  @media (max-width: 980px) { .yes4 { grid-template-columns: 1fr; } .whygrid { grid-template-columns: 1fr; } }
</style>

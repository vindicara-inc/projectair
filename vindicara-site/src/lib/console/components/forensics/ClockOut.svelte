<script lang="ts">
  import { operator, signOut } from '$lib/console/stores/operator';
  import { clockOutOpen, reviewed, decisions, resetSession, departmentHead } from '$lib/console/stores/sessionlog';
  import SessionReportDoc from '$lib/console/components/report/SessionReportDoc.svelte';

  let clockOutAt = $state('');
  let reportId = $state('');

  $effect(() => {
    if ($clockOutOpen && !clockOutAt) {
      const now = new Date().toISOString();
      clockOutAt = now;
      reportId = `AIR-SESS-${now.slice(0, 16).replace(/[-:T]/g, '')}`;
    }
    if (!$clockOutOpen) {
      clockOutAt = '';
      reportId = '';
    }
  });

  function printReport() {
    setTimeout(() => window.print(), 60);
  }

  function finish() {
    clockOutOpen.set(false);
    resetSession();
    signOut();
  }
</script>

{#if $clockOutOpen}
  <div class="co-backdrop" role="presentation">
    <div class="co-panel">
      <div class="co-head no-print">
        <div class="co-badge">✓ Clocked out — report sealed</div>
        <p class="co-sub">
          A signed session report has been filed and routed to <b>{departmentHead.name}</b>,
          {departmentHead.title} · {$operator.organization}.
        </p>
        <div class="co-actions">
          <button class="btn" onclick={printReport}>Print / Save as PDF</button>
          <button class="btn ok" onclick={finish}>Done — sign out</button>
        </div>
      </div>

      <SessionReportDoc
        operatorName={$operator.name}
        organization={$operator.organization}
        role={$operator.role}
        authMethod={$operator.authMethod}
        signInAt={$operator.signedInAt ?? ''}
        {clockOutAt}
        reviewed={$reviewed}
        decisions={$decisions}
        {reportId}
        deptHead={departmentHead}
      />
    </div>
  </div>
{/if}

<style>
  .co-backdrop { position: fixed; inset: 0; z-index: 80; overflow: auto; background: radial-gradient(circle at 50% 18%, rgba(8,9,14,.9), rgba(4,5,8,.96)); backdrop-filter: blur(4px); padding: 28px 18px 60px; animation: fade .25s ease; }
  @keyframes fade { from { opacity: 0; } to { opacity: 1; } }
  .co-panel { max-width: 760px; margin: 0 auto; display: flex; flex-direction: column; gap: 18px; }
  .co-head { text-align: center; }
  .co-badge { display: inline-block; font-family: var(--mono); font-size: 11px; letter-spacing: .12em; text-transform: uppercase; font-weight: 600; color: #bff5df; border: 1px solid rgba(72,230,164,.4); background: rgba(72,230,164,.1); padding: 6px 14px; }
  .co-sub { font-size: 13.5px; color: var(--muted); margin: 13px auto 0; max-width: 56ch; line-height: 1.55; }
  .co-sub b { color: var(--ink); }
  .co-actions { display: flex; gap: 11px; justify-content: center; margin-top: 16px; }
  .co-actions .btn { padding: 10px 18px; font-size: 12.5px; }
</style>

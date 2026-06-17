<script lang="ts">
  import './book.css';
  import { goto } from '$app/navigation';
  import BookmarkRail from '$components/BookmarkRail.svelte';

  // P · Protect — the deterministic floor (Enforce): stop before harm, not after.
  const items = [
    { name: 'Structural Verification', meta: 'Fixed logic over the causal graph' },
    { name: 'Real-time Halt & Step-up', meta: 'Stops the action before harm, not after' },
    { name: 'Human-in-the-loop Approvals', meta: 'No agent acts without a delegation' },
    { name: 'Kill-switch', meta: 'Revoke agent authority instantly' }
  ];

  let toast = $state('');
  let toastTimer: ReturnType<typeof setTimeout> | undefined;
  function inquire(p: (typeof items)[number]) {
    toast = `Let's talk — ${p.name}`;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (toast = ''), 3200);
  }
</script>

<div class="vx vx--protect">
  <button class="bk-brand" type="button" onclick={() => goto('/')}>
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M12 2 L22 21 L12 16 L2 21 Z" fill="#ffd5d9" />
      <path d="M12 2 L22 21 L12 16 Z" fill="#e63946" />
    </svg>
    AIR
  </button>

  <div class="bk-page">
    <header class="bk-hero">
      <div class="eyebrow">Project AIR · Vindicara, Inc.</div>
      <h1 class="bk-title">Stops the agent<br />before it acts.</h1>
      <p class="lead bk-lead">
        Not evidence after the fact — enforcement in the moment. The deterministic floor halts an
        uncovered agent the instant it breaches policy. Before harm, not after.
      </p>

      <div class="bk-seal">
        <span class="bk-seal-dot" aria-hidden="true"></span>
        <span class="bk-seal-label">Deterministic floor</span>
        <span class="bk-seal-chip">SV-SECRET</span>
        <span class="bk-seal-chip">SV-NET</span>
        <span class="bk-seal-chip">SV-SCOPE</span>
        <span class="bk-seal-chip">SV-ENTITY</span>
        <span class="bk-seal-chip">SV-EXFIL</span>
      </div>
    </header>

    <section class="bk-panel">
      <div class="bk-fn">
        <div class="bk-tag">P</div>
        <div>
          <h3>Protect</h3>
          <div class="bk-pk">deterministic enforcement</div>
        </div>
      </div>

      <p class="bk-body">
        Structural Verification runs as fixed logic over the causal graph. It returns the same
        verdict every time and cannot be prompt-injected or talked out of blocking. No agent acts
        without a human delegation.
      </p>

      <div class="bk-products">
        {#each items as p}
          <div class="bk-prod">
            <span class="bk-prod-name">{p.name}</span>
            <span class="bk-prod-meta">{p.meta}</span>
            <button class="bk-prod-cta" type="button" onclick={() => inquire(p)}>Talk to us →</button>
          </div>
        {/each}
      </div>

      <p class="bk-fnote">
        We produce the stop, not the policy. You set the rules;
        <b>the floor enforces them every time.</b>
      </p>
    </section>
  </div>

  <BookmarkRail active="protect" />

  {#if toast}
    <div class="bk-toast" role="status">{toast}</div>
  {/if}
</div>

<script lang="ts">
  import './book.css';
  import { goto } from '$app/navigation';
  import BookmarkRail from '$lib/console/components/BookmarkRail.svelte';

  // M · Monitor — the 16 detectors: every action read the moment it happens.
  const items = [
    { name: 'OWASP Agentic Top 10', meta: 'All 10 agentic-app signatures' },
    { name: 'OWASP LLM categories', meta: 'Three LLM-layer detectors' },
    { name: 'AIR-native checks', meta: 'Three checks no GRC tool ships' },
    { name: 'Offline, zero-config', meta: '14 of 16 run with no setup' }
  ];

  let toast = $state('');
  let toastTimer: ReturnType<typeof setTimeout> | undefined;
  function inquire(p: (typeof items)[number]) {
    toast = `Let's talk — ${p.name}`;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (toast = ''), 3200);
  }
</script>

<div class="vx vx--monitor">
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
      <h1 class="bk-title">Every agent in flight,<br />watched live.</h1>
      <p class="lead bk-lead">
        Continuous visibility — not a quarterly report. Every action is read against 16 detectors the
        moment it happens, so you see the incident as it happens, not in the post-mortem.
      </p>

      <div class="bk-seal">
        <span class="bk-seal-dot" aria-hidden="true"></span>
        <span class="bk-seal-label">16 detectors</span>
        <span class="bk-seal-chip">10 OWASP Agentic</span>
        <span class="bk-seal-chip">3 OWASP LLM</span>
        <span class="bk-seal-chip">3 AIR-native</span>
      </div>
    </header>

    <section class="bk-panel">
      <div class="bk-fn">
        <div class="bk-tag">M</div>
        <div>
          <h3>Monitor</h3>
          <div class="bk-pk">16 detectors</div>
        </div>
      </div>

      <p class="bk-body">
        Every agent action is read against all 10 OWASP Top 10 for Agentic Applications signatures, 3
        OWASP LLM categories, and 3 AIR-native checks. 14 run offline with zero config.
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
        We produce the signal, not the staffing. The watch never blinks;
        <b>the response is yours to run.</b>
      </p>
    </section>
  </div>

  <BookmarkRail active="monitor" />

  {#if toast}
    <div class="bk-toast" role="status">{toast}</div>
  {/if}
</div>

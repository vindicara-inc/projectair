<script lang="ts">
  import './book.css';
  import { goto } from '$app/navigation';
  import BookmarkRail from '$components/BookmarkRail.svelte';

  // P · Prove — the forensic spine: signed + anchored, independently verifiable.
  const items = [
    { name: 'Proof & Admissibility', meta: 'Court- and insurer-ready evidence' },
    { name: 'Self-authenticating records', meta: 'Hold up without trusting the operator' },
    { name: 'Independently verifiable', meta: 'Re-check the integrity yourself' }
  ];

  let toast = $state('');
  let toastTimer: ReturnType<typeof setTimeout> | undefined;
  function inquire(p: (typeof items)[number]) {
    toast = `Let's talk — ${p.name}`;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (toast = ''), 3200);
  }
</script>

<div class="vx vx--prove">
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
      <h1 class="bk-title">Turn <span class="air">AIR</span> on.</h1>
      <p class="lead bk-lead">
        And from this moment, every action is on the record — sealed the instant it happens,
        tamper-evident, independently verifiable, yours to take into any room.
      </p>

      <div class="bk-seal">
        <span class="bk-seal-dot" aria-hidden="true"></span>
        <span class="bk-seal-label">Signed · post-quantum ready</span>
        <span class="bk-seal-chip">BLAKE3</span>
        <span class="bk-seal-chip">Ed25519</span>
        <span class="bk-seal-chip">ML-DSA-65</span>
        <span class="bk-seal-chip">Sigstore Rekor</span>
      </div>
    </header>

    <section class="bk-panel">
      <div class="bk-fn">
        <div class="bk-tag">P</div>
        <div>
          <h3>Prove</h3>
          <div class="bk-pk">signed + anchored</div>
        </div>
      </div>

      <p class="bk-body">
        Each action is sealed into a tamper-evident, independently verifiable record. Its integrity,
        timing, and origin hold up without trusting the operator, the cloud, or us. This is the
        forensic evidence an insurer, regulator, or court will accept.
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
        We produce the proof, not the verdict. The integrity is undeniable;
        <b>the meaning is yours to argue.</b>
      </p>
    </section>
  </div>

  <BookmarkRail active="prove" />

  {#if toast}
    <div class="bk-toast" role="status">{toast}</div>
  {/if}
</div>

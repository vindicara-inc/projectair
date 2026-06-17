<script lang="ts">
  import './book.css';
  import { goto } from '$app/navigation';
  import BookmarkRail from '$components/BookmarkRail.svelte';

  // A · Audit — the audit trail + delegated-authority record, and the evidence packs you sell.
  const packs = [
    { name: 'SOC 2 Agent Evidence', meta: 'Control evidence · CC7.2 / CC7.3', file: 'soc2-agent-evidence.json' },
    { name: 'HIPAA Audit-Trail', meta: 'Activity records · 45 CFR 164.312(b)', file: 'hipaa-audit-trail.json' },
    { name: 'ISO 42001 / EU AI Act', meta: 'AI management + Article 12 logging', file: 'iso42001-euaiact.json' },
    { name: 'Agent Audit Trail', meta: 'Full signed timeline, in order', file: 'agent-audit-trail.json' }
  ];

  let toast = $state('');
  let toastTimer: ReturnType<typeof setTimeout> | undefined;
  function inquire(p: (typeof packs)[number]) {
    toast = `Let's talk — scoping your ${p.name}`;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (toast = ''), 3200);
  }
</script>

<div class="vx vx--audit">
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
      <h1 class="bk-title">The audit trail your<br />assessor actually asks for.</h1>
      <p class="lead bk-lead">
        Every action your agents take — bound to the human who authorized it — sealed into a complete
        record. The agent-level evidence SOC 2, HIPAA, and ISO 42001 now require, and that generic GRC
        tools do not produce.
      </p>

      <div class="bk-seal">
        <span class="bk-seal-dot" aria-hidden="true"></span>
        <span class="bk-seal-label">Sealed · real cryptography</span>
        <span class="bk-seal-chip">BLAKE3</span>
        <span class="bk-seal-chip">Ed25519</span>
        <span class="bk-seal-chip">RFC 3161</span>
        <span class="bk-seal-chip">Sigstore Rekor</span>
      </div>
    </header>

    <section class="bk-panel">
      <div class="bk-fn">
        <div class="bk-tag">A</div>
        <div>
          <h3>Audit</h3>
          <div class="bk-pk">the record you take into your audit</div>
        </div>
      </div>

      <p class="bk-body">
        We capture every action, who authorized it, and whether that authority was ever exceeded —
        the system of record for delegated authority. It is evidence you can hand an assessor, not a
        promise you ask them to take on faith.
      </p>

      <div class="bk-products">
        {#each packs as p}
          <div class="bk-prod">
            <span class="bk-prod-name">{p.name}</span>
            <span class="bk-prod-meta">{p.meta}</span>
            <button class="bk-prod-cta" type="button" onclick={() => inquire(p)}>Talk to us →</button>
          </div>
        {/each}
      </div>

      <p class="bk-fnote">
        We produce the record, not the attestation. <b>You are not buying an auditor.</b>
      </p>
    </section>
  </div>

  <BookmarkRail active="audit" />

  {#if toast}
    <div class="bk-toast" role="status">{toast}</div>
  {/if}
</div>

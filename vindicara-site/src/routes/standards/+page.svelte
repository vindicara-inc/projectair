<script>
  import AppShell from '$components/AppShell.svelte';
  const cards = [
    { k: 'OWASP', t: 'Top 10 for Agentic Applications 2026', d: 'All 10 Agentic ASIs (ASI01 through ASI10), plus 3 OWASP LLM categories (LLM01, LLM04, LLM06) and 3 AIR-native detectors, for 16 total.',
      ic: '<path d="M12 3l7 3v5c0 4-3 7-7 9-4-2-7-5-7-9V6z"/>' },
    { k: 'AgDR', t: 'AI Decision Records', d: 'BLAKE3 content hashing, Ed25519 signatures, opt-in ML-DSA-65 (FIPS 204) post-quantum signing, forward-chained hash integrity, UUIDv7 for monotonic ordering.',
      ic: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>' },
    { k: 'EU AI Act', t: 'Articles 12 & 72', d: 'Audit trail retention and post-market monitoring evidence. Exportable as conformity artifacts.',
      ic: '<path d="M12 4v16M6 8h12M6 8l-2.5 5a2.5 2.5 0 0 0 5 0zM18 8l-2.5 5a2.5 2.5 0 0 0 5 0zM8 20h8"/>' },
    { k: 'HIPAA', t: 'Security Rule (2025 NPRM, proposed)', d: 'Cryptographic evidence for 45 CFR 164.312 audit controls, integrity controls, and person authentication. Auth0-verified clinician identity in the chain.',
      ic: '<path d="M12 20s-7-4.5-7-10a4 4 0 0 1 7-2.5A4 4 0 0 1 19 10c0 5.5-7 10-7 10z"/>' },
    { k: 'California', t: 'AB 316', d: 'Removes the defense that an AI system acted on its own. The record of who authorized the agent, and provable evidence of what it did.',
      ic: '<path d="M13 5l6 6M16 8l-8 8M5 13l6 6M3 21h8"/>' },
    { k: 'NIST', t: 'AI RMF', d: 'Map, Measure, Manage, and Govern functions backed by runtime evidence rather than policy PDFs.',
      ic: '<path d="M10 6h9M10 12h9M10 18h9M4 6l1.4 1.4L7.5 5M4 12l1.4 1.4L7.5 11M4 18l1.4 1.4L7.5 17"/>' }
  ];
</script>
<svelte:head><title>Vindicara · Standards Alignment</title></svelte:head>

<AppShell active="standards" title="standards alignment" scroll={true}>
  <div class="wrap">
    <div class="head">
      <div class="eyebrow">Standards Alignment</div>
      <h1><span class="air">AIR</span> speaks the frameworks<br>your auditor already does.</h1>
    </div>

    <div class="grid">
      {#each cards as c}
        <div class="card">
          <div class="k">
            <svg class="ki" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{@html c.ic}</svg>
            {c.k}
          </div>
          <div class="t">{c.t}</div>
          <div class="d">{c.d}</div>
        </div>
      {/each}
    </div>

    <div class="closer">
      <div class="c1">Your next incident is already on its way.</div>
      <div class="c2">Make sure you can <span class="grad">prove what happened.</span></div>
    </div>
  </div>
</AppShell>

<style>
  .head{text-align:center;max-width:720px;margin:8px auto 0}
  .head .eyebrow{font-weight:700;color:var(--air2)}
  .head h1{font-size:32px;margin:12px 0 0}
  .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:34px 0 0}
  .card{border:1px solid var(--line);background:var(--panel);box-shadow:var(--shadow);border-radius:12px;padding:16px 18px}
  .k{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--air2);font-weight:700}
  .ki{width:17px;height:17px;flex:none}
  .t{font-size:15px;font-weight:700;color:var(--white);margin-top:9px}
  .d{font-size:12.5px;color:#CBD5E8;line-height:1.55;margin-top:6px}
  .closer{text-align:center;margin:44px 0 8px}
  .c1{font-family:var(--display);font-size:26px;font-weight:600;color:var(--white)}
  .c2{font-family:var(--display);font-size:26px;font-weight:600;margin-top:2px}
  .grad{color:var(--air2)}
  @media (max-width:1080px){ .grid{grid-template-columns:1fr 1fr} }
  @media (max-width:680px){ .grid{grid-template-columns:1fr} }
</style>

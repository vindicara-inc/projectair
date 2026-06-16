<script>
  import AppShell from '$components/AppShell.svelte';
  import { goto } from '$app/navigation';

  const get = [
    { t: 'White-glove SDK integration', d: 'We wire Project AIR into your agents across major frameworks: LangChain, OpenAI, Anthropic, LlamaIndex, Gemini, and Google ADK.' },
    { t: 'Cryptographically signed, replayable forensic chain', d: 'For every agent session, with 16 detectors across the OWASP Top 10 for Agentic Applications, OWASP LLM, and AIR-native checks.' },
    { t: 'Deterministic enforcement floor', d: 'An uncovered agent cannot cross it. Enforcement runs as fixed logic, not a model that can be jailbroken.' },
    { t: 'Compliance-ready exports', d: 'EU AI Act Article 72 and Article 12 artifacts, plus HIPAA audit-control evidence (45 CFR 164.312(b)).' },
    { t: 'Direct line to the founder', d: 'Real influence over the roadmap, and a BAA where PHI is involved.' }
  ];
  const ask = [
    { t: 'A production or near-production deployment', d: 'A real agent workload we can instrument.' },
    { t: 'Two or three short feedback sessions', d: 'Over the course of the partnership.' },
    { t: 'A case-study commitment', d: 'Anonymized at launch is fine; named when you are comfortable, plus a quote we can use.' }
  ];
  const why = [
    { t: 'EU AI Act Article 72', d: 'Applies August 2, 2026 for high-risk systems under Annex III (HR, credit, essential services, and more), requiring continuous post-market monitoring you can hand to a regulator.' },
    { t: 'HIPAA is tightening', d: 'It already requires audit controls (45 CFR 164.312(b)); the 2025 Security Rule NPRM (proposed) signals stricter requirements ahead.' },
    { t: 'Your agents are in production now', d: 'And standard logs are mutable, gapped, and cannot prove they were not tampered with.' }
  ];
</script>
<svelte:head><title>Vindicara · Design Partner Program</title></svelte:head>

<AppShell active="design-partner" title="design partners" scroll={true}>
  <div class="prose">
    <div class="eyebrow">Design Partner Program</div>
    <h1>Become one of three founding design partners.</h1>
    <p class="lede">Project AIR is the system of record for human accountability over AI agents. It monitors every action, enforces a deterministic floor an uncovered agent cannot cross, proves the result with signed and anchored evidence, and ties every action back to a named human. Evidence-grade infrastructure is the foundation, not the whole story.</p>
    <p>We will integrate Project AIR into your production agents, hands-on and free. In return, we ask for structured feedback and an anonymized case study. You keep direct influence over the roadmap and can verify the technology before committing.</p>

    <div class="prove">
      <div class="ph">Prove it before you sign anything</div>
      <ul>
        <li><code>pip install projectair</code> then <code>air demo</code>: a real signed chain in under 30 seconds, no account, offline.</li>
        <li>Verify our own production ops chain yourself on public Sigstore Rekor. Zero Vindicara infrastructure in the verification path.</li>
        <li>Read the admissibility architecture, designed for FRE 902(13) self-authentication and eIDAS mapping with honest disclosures, at <a href="/admissibility">/admissibility</a>.</li>
      </ul>
    </div>

    <div class="cols">
      <div class="col">
        <div class="ch">What you get</div>
        {#each get as g}<div class="item"><div class="it">{g.t}</div><div class="id">{g.d}</div></div>{/each}
      </div>
      <div class="col">
        <div class="ch">What we ask</div>
        {#each ask as a}<div class="item"><div class="it">{a.t}</div><div class="id">{a.d}</div></div>{/each}
      </div>
      <div class="col">
        <div class="ch">Why now</div>
        {#each why as w}<div class="item"><div class="it">{w.t}</div><div class="id">{w.d}</div></div>{/each}
      </div>
    </div>

    <div class="outcome">
      <div class="oh">The outcome</div>
      <p>Independently verifiable, tamper-evident evidence for every agent decision, with enforcement that holds and authority that traces to a person. Built for regulators, auditors, customers, and your own risk team.</p>
    </div>

    <div class="cta">
      <button class="apply" onclick={() => goto('/contact')}>Apply to be a design partner</button>
      <span class="note">Free during the design-partner period. BAA available. About a 30-minute kickoff to start.</span>
    </div>
  </div>
</AppShell>

<style>
  .prose h1{font-size:34px;margin:14px 0 0;max-width:20ch}
  .lede{font-size:15.5px;color:var(--white);line-height:1.6;margin:18px 0 6px;font-family:var(--display)}
  .prose p{font-size:13.5px;color:var(--soft);line-height:1.65;margin-top:8px}
  .prove{border:1px solid rgba(230,57,70,.35);background:var(--airbg,rgba(230,57,70,.06));padding:18px 20px;margin:20px 0}
  .prove .ph{font-family:var(--mono);font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--air2);font-weight:700;margin-bottom:10px}
  .prove ul{list-style:none;display:grid;gap:9px}
  .prove li{font-size:13px;color:var(--soft);line-height:1.55;padding-left:18px;position:relative}
  .prove li::before{content:'›';position:absolute;left:0;color:var(--air2);font-weight:700}
  .prove code{font-family:var(--mono);font-size:12px;color:var(--white);background:rgba(255,255,255,.06);padding:1px 5px}
  .prove a{color:var(--air2);text-decoration:none} .prove a:hover{text-decoration:underline}
  .cols{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin:22px 0}
  .ch{font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--air2);border-bottom:1px solid var(--line);padding-bottom:8px;margin-bottom:12px}
  .item{margin-bottom:13px}
  .item .it{font-size:13px;font-weight:700;color:var(--white);line-height:1.3}
  .item .id{font-size:12px;color:#CBD5E8;line-height:1.5;margin-top:3px}
  .outcome{background:#0a1326;border:1px solid var(--line);padding:18px 20px;margin-top:8px}
  .outcome .oh{font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--air2);margin-bottom:6px}
  .outcome p{font-size:13.5px;color:var(--soft);line-height:1.6}
  .cta{display:flex;align-items:center;gap:16px;margin-top:22px;flex-wrap:wrap}
  .apply{background:var(--air);color:#fff;border:0;padding:13px 22px;font-family:var(--ui);font-weight:700;font-size:14px;cursor:pointer}
  .apply:hover{filter:brightness(1.08)}
  .note{font-size:11.5px;color:var(--faint);font-family:var(--mono)}
  @media (max-width:1080px){ .cols{grid-template-columns:1fr} }
</style>

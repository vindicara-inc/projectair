<script>
  import AppShell from '$components/AppShell.svelte';
  const posts = [
    { t: 'Introducing Axiisium', d: "Vindicara's healthcare initiative: multimodal AI for acute myeloid leukemia that fuses pathology, flow, cytogenetics, molecular, and clinical data, with every decision a signed, audit-ready record.", tag: 'Initiative', href: '/blog/introducing-axiisium', date: 'June 26, 2026' },
    { t: 'An NVIDIA-backed second opinion, signed', d: 'How NemoGuard NIM classifier verdicts become signed detector findings in the AIR evidence chain.', tag: 'Engineering', href: '/blog/nvidia-inception-nemoguard-second-opinion', date: '2026-06-10' },
    { t: '88% of AI Agent Deployments Had a Security Incident. 6% Have a Budget to Fix It.', d: 'The state of AI agent accountability in 2026: the incidents, the converging regulatory deadlines, and the evidence infrastructure gap.', tag: 'Strategy', href: '/blog/ai-agent-accountability-crisis-2026', date: 'May 27, 2026' },
    { t: 'Introducing Project AIR', d: 'Evidence-grade infrastructure for accountable AI agents: signed intent capsules, 16 OWASP-mapped detectors, causal explanation, Auth0 containment, and cross-agent chain of custody.', tag: 'Launch', href: '/blog/introducing-project-air', date: 'May 26, 2026' },
    { t: 'They Check Messages. We Check Missions.', d: 'Structural Verification: a deterministic floor that checks whether the agent’s actual trajectory served its declared intent, and cannot be prompt-injected.', tag: 'Engineering', href: '/blog/structural-verification', date: 'May 13, 2026' },
    { t: 'The New HIPAA AI Audit Problem (and How to Solve It)', d: 'The HIPAA Security Rule NPRM makes audit controls mandatory. AI agents touching PHI need cryptographic evidence chains, not application logs.', tag: 'Compliance', href: '/blog/hipaa-ai-audit-problem', date: 'May 12, 2026' },
    { t: 'Forensic Evidence for NemoClaw: HIPAA Audit Trails for Sandboxed Clinical AI', d: 'NVIDIA NemoClaw controls what clinical AI agents can do. Project AIR proves what they did. Prevention plus evidence for regulated healthcare.', tag: 'Engineering', href: '/blog/nemoclaw-forensic-evidence', date: 'May 12, 2026' },
    { t: 'What happens after an AI agent does something it shouldn’t?', d: 'A map of AI agent security tooling, and the post-incident forensic layer most teams don’t realize they’re missing.', tag: 'Strategy', href: '/blog/forensic-layer-market-map', date: 'May 2, 2026' },
    { t: 'Implementing Trustworthy Agents: A Forensic Evidence Layer for Production', d: 'Anthropic’s paper on trustworthy agents names three ecosystem gaps. Project AIR is our answer to evidence sharing and open standards.', tag: 'Strategy', href: '/blog/trustworthy-agents-forensic-evidence', date: 'April 24, 2026' },
    { t: 'Run your first air trace in 5 minutes', d: 'From pip install projectair to a signed forensic timeline of your LangChain agent in under five minutes.', tag: 'Engineering', href: '/blog/secure-ai-agents-5-minutes', date: 'April 2, 2026' },
    { t: 'EU AI Act Article 72: A Developer’s Guide to Post-Market Monitoring', d: 'What post-market monitoring evidence actually has to contain by August 2, 2026, and how to automate producing it.', tag: 'Compliance', href: '/blog/eu-ai-act-article-72-guide', date: 'April 2, 2026' },
    { t: 'The State of MCP Security in 2026', d: '92% of MCP servers lack proper OAuth. We scanned real configurations and found critical vulnerabilities across authentication and authorization.', tag: 'Engineering', href: '/blog/mcp-security-2026', date: 'April 2, 2026' }
  ];
</script>
<svelte:head><title>Vindicara · Blog</title></svelte:head>

<AppShell active="blog" title="blog" scroll={true}>
  <div class="prose">
    <div class="eyebrow">Blog</div>
    <h1>Notes from the evidence layer.</h1>
    <p>Engineering, compliance, and strategy from the team building Project AIR.</p>

    <div class="posts">
      {#each posts as p}
        <a class="post" href={p.href}>
          <div class="ptag">{p.tag} · {p.date}</div>
          <div class="ptitle">{p.t}</div>
          <div class="pdesc">{p.d}</div>
          <div class="pmore">Read →</div>
        </a>
      {/each}
    </div>
  </div>
</AppShell>

<style>
  .prose h1{font-size:36px;margin:14px 0 0}
  .posts{display:flex;flex-direction:column;gap:14px;margin:24px 0 14px}
  .post{display:block;border:1px solid var(--line);background:var(--panel);box-shadow:var(--shadow);padding:20px;text-decoration:none;color:var(--white);transition:.15s}
  .post:hover{border-color:var(--air);transform:translateY(-2px)}
  .ptag{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--air2)}
  .ptitle{font-family:var(--display);font-size:20px;font-weight:600;margin:8px 0 6px}
  .pdesc{font-size:13px;color:var(--soft);line-height:1.5}
  .pmore{font-family:var(--mono);font-size:11px;color:var(--air2);margin-top:12px}
</style>

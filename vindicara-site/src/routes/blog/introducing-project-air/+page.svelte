<script>
  import AppShell from '$components/AppShell.svelte';
</script>

<svelte:head>
  <title>Introducing Project AIR: Evidence-Grade Infrastructure for Accountable AI Agents | Vindicara Blog</title>
  <meta name="description" content="Project AIR 1.0 ships a five-layer forensic stack for AI agents: signed intent capsules, 16 OWASP-mapped detectors, causal explanation, Auth0 containment, and cross-agent chain of custody. MIT-licensed, open source, on PyPI today." />
  <link rel="canonical" href="https://vindicara.io/blog/introducing-project-air" />
  <meta property="og:type" content="article" />
  <meta property="og:url" content="https://vindicara.io/blog/introducing-project-air" />
  <meta property="og:title" content="Introducing Project AIR: Evidence-Grade Infrastructure for Accountable AI Agents" />
  <meta property="og:description" content="Signed forensic chains, 16 OWASP-mapped detectors, causal explanation, Auth0 containment, and cross-agent trust. Open source on PyPI today." />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="Introducing Project AIR: Evidence-Grade Infrastructure for Accountable AI Agents" />
  <meta name="twitter:description" content="Signed forensic chains, 16 OWASP-mapped detectors, causal explanation, Auth0 containment, and cross-agent trust. Open source on PyPI today." />
  <meta name="keywords" content="AI agent security, AI agent audit trail, AI agent accountability, AI agent forensics, OWASP agentic security, AI governance, signed intent capsule, AI compliance, AI agent monitoring" />
  {@html `<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@type": "Article",
    "headline": "Introducing Project AIR: Evidence-Grade Infrastructure for Accountable AI Agents",
    "description": "Project AIR 1.0 ships a five-layer forensic stack for AI agents: signed intent capsules, 16 OWASP-mapped detectors, causal explanation, Auth0 containment, and cross-agent chain of custody.",
    "datePublished": "2026-05-26",
    "dateModified": "2026-05-26",
    "author": {
      "@type": "Person",
      "name": "Kevin Minn",
      "url": "https://vindicara.io"
    },
    "publisher": {
      "@type": "Organization",
      "name": "Vindicara",
      "url": "https://vindicara.io",
      "logo": {
        "@type": "ImageObject",
        "url": "https://vindicara.io/vindicara-logo.png"
      }
    },
    "mainEntityOfPage": "https://vindicara.io/blog/introducing-project-air",
    "keywords": ["AI agent security", "AI agent audit trail", "OWASP agentic", "AI forensics", "signed intent capsule"]
  })}</script>`}
</svelte:head>

<AppShell active="blog" title="blog" scroll={true}>
  <article class="prose">
    <div class="eyebrow">Launch · Open Source</div>
    <h1>Introducing Project <span class="air">AIR</span></h1>
    <p class="sub">Evidence-grade infrastructure for accountable AI agents.</p>
    <p class="muted">May 26, 2026 · Kevin Minn</p>
    <p>Every agent decision, signed. Every action, tamper-evident. Every chain, anchored to public infrastructure anyone can verify. MIT-licensed and on PyPI today.</p>

    <h2>What Project <span class="air">AIR</span> is</h2>
    <p>Project <span class="air">AIR</span> writes a <strong>Signed Intent Capsule</strong> for every AI agent decision. Each capsule carries a BLAKE3 content hash and an Ed25519 signature, chained to the previous step. The chain root is anchored to <a href="https://docs.sigstore.dev/">Sigstore Rekor</a> (a public transparency log) and RFC 3161 trusted timestamps. The result is evidence that survives subpoena, survives the vendor, and survives the auditor's first question.</p>
    <pre class="code">pip install projectair
air demo</pre>
    <p>That is the entire cold start. Two commands, ten seconds, and you have a signed forensic chain with 16 detectors running over it. No API keys, no cloud account, no agent wiring required.</p>

    <h2>The problem: AI agents act without evidence</h2>
    <p>When an AI agent breaks something in production, three questions follow: what happened, who authorized it, and can you prove it? Today the answer to all three is usually "we think so, based on logs." Application logs are mutable, unsigned, and vendor-controlled. They are not evidence. They are claims.</p>
    <p>The gap is not detection (the security industry has that covered). The gap is <strong>proof</strong>. Proof that the agent was told to do X and did Y. Proof that no one altered the record after the fact. Proof that a human authorized the sensitive action, verified by a third-party identity provider, recorded in a chain that neither the agent vendor nor the customer can backdate.</p>
    <p>That is what <span class="air">AIR</span> builds. Not another detection layer. An evidence layer.</p>

    <h2>What shipped in 1.0: the five-layer stack</h2>
    <table>
      <thead><tr><th>Layer</th><th>What it does</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td class="mono red">Detection</td><td>16 detectors mapped to OWASP Top 10 for Agentic + LLM Applications</td><td>shipped</td></tr>
        <tr><td class="mono red">Trust Anchor</td><td>RFC 3161 timestamps + Sigstore Rekor transparency log</td><td>shipped</td></tr>
        <tr><td class="mono red">Causal Reasoning</td><td><code>air explain</code> walks the chain, explains why a step happened</td><td>shipped</td></tr>
        <tr><td class="mono red">Containment</td><td>Halt agent actions; require Auth0-verified human approval</td><td>shipped</td></tr>
        <tr><td class="mono red">Handoff Protocol</td><td>Cross-agent chain of custody with W3C Trace Context + Rekor attestation</td><td>shipped</td></tr>
      </tbody>
    </table>
    <p>Each layer is independently adoptable. A team can start with detection only and add anchoring, containment, or cross-agent trust as their deployment matures. The layers compose; they do not require each other.</p>

    <h2>16 detectors, mapped to public taxonomies</h2>
    <p><span class="air">AIR</span> ships <strong>10 of 10</strong> detectors from the <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/">OWASP Top 10 for Agentic Applications</a>, 3 detectors from the OWASP Top 10 for LLM Applications, and 3 <span class="air">AIR</span>-native detectors including NemoGuard cross-corroboration with NVIDIA NIM classifiers.</p>
    <p>Every detector maps to a public taxonomy. No proprietary severity scales, no vague "risk scores." When <span class="air">AIR</span> flags ASI02 (Tool Misuse), that is the same ASI02 your compliance team reads in the OWASP spec. The mapping is the documentation.</p>

    <h2>Works with the frameworks you already use</h2>
    <table>
      <thead><tr><th>Framework</th><th>Integration</th></tr></thead>
      <tbody>
        <tr><td>LangChain</td><td class="mono">AIRCallbackHandler</td></tr>
        <tr><td>OpenAI SDK</td><td class="mono">instrument_openai</td></tr>
        <tr><td>Anthropic SDK</td><td class="mono">instrument_anthropic</td></tr>
        <tr><td>Google Gemini SDK</td><td class="mono">instrument_gemini</td></tr>
        <tr><td>Google ADK</td><td class="mono">instrument_adk</td></tr>
        <tr><td>LlamaIndex</td><td class="mono">instrument_llamaindex</td></tr>
        <tr><td>NVIDIA NeMo Guardrails</td><td class="mono">instrument_nemo_guardrails</td></tr>
        <tr><td>NVIDIA NIM / vLLM / Groq / Together / Fireworks</td><td class="mono">instrument_openai</td></tr>
        <tr><td>Custom code</td><td class="mono">AIRRecorder</td></tr>
      </tbody>
    </table>
    <p>Any OpenAI-compatible endpoint works through <code>instrument_openai</code>, including self-hosted models on NVIDIA NIM, vLLM, and TGI. One integration covers the entire OpenAI-compatible ecosystem.</p>

    <h2>Structural verification: did the agent do what it was told?</h2>
    <p>Detection tells you what went wrong. Structural verification tells you whether the agent honored its declared intent. Declare what the agent is authorized to do (which tools, which paths, which network targets, whether secret access is allowed), and <span class="air">AIR</span> verifies the chain against that declaration deterministically.</p>
    <pre class="code">from airsdk import AIRRecorder, IntentSpec

spec = IntentSpec(
    goal="Refactor the auth module",
    allowed_tools=["read_file", "write_file"],
    allowed_paths=["src/auth/"],
    secret_access=False,
)
recorder = AIRRecorder("chain.jsonl", intent_spec=spec)</pre>
    <pre class="code">$ air verify-intent chain.jsonl

FAILED: 2 violations against declared intent
  SV-SECRET-01  CRITICAL  step 6: Secret material accessed outside declared scope
  SV-NET-01     CRITICAL  step 8: Network egress to undeclared destination</pre>
    <p>Four symbolic checks ship today: SV-SECRET (secret access), SV-NET (network egress), SV-SCOPE (tool scope), and SV-EXFIL (data exfiltration patterns with causal path tracing). The verdict is VERIFIED, FAILED, or INCONCLUSIVE. CI-friendly: <code>air verify-intent</code> exits with code 2 on FAILED.</p>

    <h2>We run it on our own infrastructure</h2>
    <p>Every API request to <code>vindicara.io</code> is recorded as a signed AgDR chain using the same <code>airsdk</code> library customers use, anchored to public Sigstore Rekor every 60 seconds, and published as redacted JSONL.</p>
    <p><a href="/evidence">Verify it yourself</a>. The chain catalog, manifest, and every Rekor anchor are independently verifiable with zero Vindicara infrastructure in the path. If we stopped existing tomorrow, the proof would still stand.</p>

    <h2>Post-quantum ready (experimental)</h2>
    <p><span class="air">AIR</span> supports <strong>ML-DSA-65 (FIPS 204)</strong> post-quantum signatures as an opt-in experimental feature. Ed25519 remains the default. Mixed-algorithm chains (some records Ed25519, some ML-DSA-65) verify correctly. When quantum computing threatens Ed25519, your chains are already migration-ready.</p>

    <h2>What comes next</h2>
    <p>1.0 is the foundation. The roadmap includes HL7v2 + FHIR R4 clinical interop for healthcare deployments, learned-baseline behavioral detection, cross-tenant federation via Sigstore Fulcio, and framework-level containment interceptors for LangChain and OpenAI so step-up approval happens automatically. Each of these gets its own news cycle; we do not rush features to pad launch day.</p>

    <div class="card callout">
      <h3>Try it now</h3>
      <pre class="code">pip install projectair &amp;&amp; air demo</pre>
      <div class="ctas">
        <a class="btn" href="https://github.com/vindicara-inc/vindicara">View on GitHub</a>
        <a class="btn ghost" href="/pricing">Pricing</a>
        <a class="btn ghost" href="/blog/secure-ai-agents-5-minutes">5-Minute Quickstart</a>
      </div>
    </div>
  </article>
</AppShell>

<style>
  .prose h1{font-size:36px;margin:14px 0 0}
  .prose .sub{font-size:19px;font-weight:600;color:var(--white);margin:6px 0 8px}
  .prose a{color:var(--air2)}
  code{font-family:var(--mono);font-size:.92em;color:var(--air2)}
  .code{font-family:var(--mono);font-size:12.5px;background:rgba(0,0,0,.35);border:1px solid var(--line);padding:14px;overflow-x:auto;line-height:1.6;margin:18px 0;color:var(--soft)}
  table{width:100%;border-collapse:collapse;font-size:13px;margin:18px 0;color:var(--soft)}
  th{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.08em;text-align:left;color:var(--faint);padding:8px 10px;border-bottom:1px solid var(--line)}
  td{padding:8px 10px;border-bottom:1px solid var(--line);line-height:1.5;vertical-align:top}
  td.mono{font-family:var(--mono);font-size:11.5px}
  td.red{color:var(--air2)}
  .callout{padding:18px 20px;margin:22px 0}
  .callout h3{margin-top:0}
  .ctas{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
</style>

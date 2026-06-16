<script lang="ts">
  import ShareButtons from '$lib/components/ShareButtons.svelte';

  const shareUrl = 'https://vindicara.io/blog/introducing-project-air';
  const shareTitle = 'Introducing Project AIR: Evidence-Grade Infrastructure for Accountable AI Agents';
  const shareDesc = 'Signed forensic chains, OWASP-mapped detection, causal reasoning, Auth0-verified containment, and cross-agent trust. Open source on PyPI today.';
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

<article class="max-w-3xl mx-auto px-6 py-16">
  <header class="mb-12">
    <div class="flex items-center gap-3 mb-6">
      <span class="text-[10px] font-bold uppercase tracking-wider bg-brand-red/10 text-brand-red border border-brand-red/20 rounded-full px-2.5 py-0.5">Launch</span>
      <span class="text-[10px] font-bold uppercase tracking-wider bg-brand-cyan/10 text-brand-cyan border border-brand-cyan/20 rounded-full px-2.5 py-0.5">Open Source</span>
      <span class="text-[10px]" style="color: var(--text-faint);">12 min read</span>
    </div>
    <h1 class="text-4xl sm:text-5xl font-bold tracking-tight leading-tight" style="color: var(--text-primary);">Introducing Project AIR</h1>
    <p class="text-2xl mt-2 font-semibold tracking-tight" style="color: var(--text-secondary);">Evidence-grade infrastructure for accountable AI agents.</p>
    <p class="text-lg mt-4" style="color: var(--text-muted);">Every agent decision, signed. Every action, tamper-evident. Every chain, anchored to public infrastructure anyone can verify. MIT-licensed and on PyPI today.</p>
    <div class="flex items-center gap-3 mt-6 text-sm" style="color: var(--text-muted);">
      <span>Kevin Minn</span>
      <span style="color: var(--text-faint);">|</span>
      <span>May 26, 2026</span>
    </div>
  </header>

  <!-- Section 1: What AIR is -->
  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">What Project AIR is</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Project AIR writes a <strong>Signed Intent Capsule</strong> for every AI agent decision. Each capsule carries a BLAKE3 content hash and an Ed25519 signature, chained to the previous step. The chain root is anchored to <a href="https://docs.sigstore.dev/" class="text-brand-red hover:underline">Sigstore Rekor</a> (a public transparency log) and RFC 3161 trusted timestamps. The result is evidence that survives subpoena, survives the vendor, and survives the auditor's first question.
  </p>

  <div class="dark-embed rounded-lg p-6 font-mono text-sm leading-relaxed mt-6 mb-6">
    <pre class="text-zinc-300 overflow-x-auto">pip install projectair
air demo</pre>
  </div>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    That is the entire cold start. Two commands, ten seconds, and you have a signed forensic chain with 16 detectors running over it. No API keys, no cloud account, no agent wiring required.
  </p>

  <!-- Section 2: The problem -->
  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">The problem: AI agents act without evidence</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    When an AI agent breaks something in production, three questions follow: what happened, who authorized it, and can you prove it? Today the answer to all three is usually "we think so, based on logs." Application logs are mutable, unsigned, and vendor-controlled. They are not evidence. They are claims.
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    The gap is not detection (the security industry has that covered). The gap is <strong>proof</strong>. Proof that the agent was told to do X and did Y. Proof that no one altered the record after the fact. Proof that a human authorized the sensitive action, verified by a third-party identity provider, recorded in a chain that neither the agent vendor nor the customer can backdate.
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    That is what AIR builds. Not another detection layer. An evidence layer.
  </p>

  <!-- Section 3: What shipped -->
  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">What shipped in 1.0: the five-layer stack</h2>

  <div class="overflow-x-auto mt-6 mb-6">
    <table class="w-full text-sm" style="color: var(--text-secondary);">
      <thead>
        <tr style="border-bottom: 2px solid var(--border-subtle);">
          <th class="text-left p-3 font-semibold" style="color: var(--text-primary);">Layer</th>
          <th class="text-left p-3 font-semibold" style="color: var(--text-primary);">What it does</th>
          <th class="text-left p-3 font-semibold" style="color: var(--text-primary);">Status</th>
        </tr>
      </thead>
      <tbody>
        <tr style="border-bottom: 1px solid var(--border-subtle);">
          <td class="p-3 font-mono text-brand-red">Detection</td>
          <td class="p-3">16 detectors mapped to OWASP Top 10 for Agentic + LLM Applications</td>
          <td class="p-3"><span class="text-green-400">shipped</span></td>
        </tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);">
          <td class="p-3 font-mono text-brand-red">Trust Anchor</td>
          <td class="p-3">RFC 3161 timestamps + Sigstore Rekor transparency log</td>
          <td class="p-3"><span class="text-green-400">shipped</span></td>
        </tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);">
          <td class="p-3 font-mono text-brand-red">Causal Reasoning</td>
          <td class="p-3"><code class="text-brand-cyan">air explain</code> walks the chain, explains why a step happened</td>
          <td class="p-3"><span class="text-green-400">shipped</span></td>
        </tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);">
          <td class="p-3 font-mono text-brand-red">Containment</td>
          <td class="p-3">Halt agent actions; require Auth0-verified human approval</td>
          <td class="p-3"><span class="text-green-400">shipped</span></td>
        </tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);">
          <td class="p-3 font-mono text-brand-red">Handoff Protocol</td>
          <td class="p-3">Cross-agent chain of custody with W3C Trace Context + Rekor attestation</td>
          <td class="p-3"><span class="text-green-400">shipped</span></td>
        </tr>
      </tbody>
    </table>
  </div>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Each layer is independently adoptable. A team can start with detection only and add anchoring, containment, or cross-agent trust as their deployment matures. The layers compose; they do not require each other.
  </p>

  <!-- Section 4: Detector coverage -->
  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">16 detectors, mapped to public taxonomies</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    AIR ships <strong>10 of 10</strong> detectors from the <a href="https://owasp.org/www-project-top-10-for-large-language-model-applications/" class="text-brand-red hover:underline">OWASP Top 10 for Agentic Applications</a>, 3 detectors from the OWASP Top 10 for LLM Applications, and 3 AIR-native detectors including NemoGuard cross-corroboration with NVIDIA NIM classifiers.
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Every detector maps to a public taxonomy. No proprietary severity scales, no vague "risk scores." When AIR flags ASI02 (Tool Misuse), that is the same ASI02 your compliance team reads in the OWASP spec. The mapping is the documentation.
  </p>

  <!-- Section 5: Framework integrations -->
  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">Works with the frameworks you already use</h2>

  <div class="overflow-x-auto mt-6 mb-6">
    <table class="w-full text-sm" style="color: var(--text-secondary);">
      <thead>
        <tr style="border-bottom: 2px solid var(--border-subtle);">
          <th class="text-left p-3 font-semibold" style="color: var(--text-primary);">Framework</th>
          <th class="text-left p-3 font-semibold" style="color: var(--text-primary);">Integration</th>
        </tr>
      </thead>
      <tbody>
        <tr style="border-bottom: 1px solid var(--border-subtle);"><td class="p-3">LangChain</td><td class="p-3 font-mono text-brand-cyan">AIRCallbackHandler</td></tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);"><td class="p-3">OpenAI SDK</td><td class="p-3 font-mono text-brand-cyan">instrument_openai</td></tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);"><td class="p-3">Anthropic SDK</td><td class="p-3 font-mono text-brand-cyan">instrument_anthropic</td></tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);"><td class="p-3">Google Gemini SDK</td><td class="p-3 font-mono text-brand-cyan">instrument_gemini</td></tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);"><td class="p-3">Google ADK</td><td class="p-3 font-mono text-brand-cyan">instrument_adk</td></tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);"><td class="p-3">LlamaIndex</td><td class="p-3 font-mono text-brand-cyan">instrument_llamaindex</td></tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);"><td class="p-3">NVIDIA NeMo Guardrails</td><td class="p-3 font-mono text-brand-cyan">instrument_nemo_guardrails</td></tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);"><td class="p-3">NVIDIA NIM / vLLM / Groq / Together / Fireworks</td><td class="p-3 font-mono text-brand-cyan">instrument_openai</td></tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);"><td class="p-3">Custom code</td><td class="p-3 font-mono text-brand-cyan">AIRRecorder</td></tr>
      </tbody>
    </table>
  </div>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Any OpenAI-compatible endpoint works through <code class="text-brand-cyan bg-brand-cyan/10 px-1.5 py-0.5 rounded text-sm">instrument_openai</code>, including self-hosted models on NVIDIA NIM, vLLM, and TGI. One integration covers the entire OpenAI-compatible ecosystem.
  </p>

  <!-- Section 6: Structural Verification -->
  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">Structural verification: did the agent do what it was told?</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Detection tells you what went wrong. Structural verification tells you whether the agent honored its declared intent. Declare what the agent is authorized to do (which tools, which paths, which network targets, whether secret access is allowed), and AIR verifies the chain against that declaration deterministically.
  </p>

  <div class="dark-embed rounded-lg p-6 font-mono text-sm leading-relaxed mt-6 mb-6">
    <pre class="text-zinc-300 overflow-x-auto"><span class="text-brand-cyan">from</span> airsdk <span class="text-brand-cyan">import</span> AIRRecorder, IntentSpec

spec = IntentSpec(
    goal=<span class="text-green-400">"Refactor the auth module"</span>,
    allowed_tools=[<span class="text-green-400">"read_file"</span>, <span class="text-green-400">"write_file"</span>],
    allowed_paths=[<span class="text-green-400">"src/auth/"</span>],
    secret_access=<span class="text-brand-cyan">False</span>,
)
recorder = AIRRecorder(<span class="text-green-400">"chain.jsonl"</span>, intent_spec=spec)</pre>
  </div>

  <div class="dark-embed rounded-lg p-6 font-mono text-sm leading-relaxed mt-4 mb-6">
    <pre class="text-zinc-300 overflow-x-auto">$ air verify-intent chain.jsonl

FAILED: 2 violations against declared intent
  SV-SECRET-01  CRITICAL  step 6: Secret material accessed outside declared scope
  SV-NET-01     CRITICAL  step 8: Network egress to undeclared destination</pre>
  </div>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Four symbolic checks ship today: SV-SECRET (secret access), SV-NET (network egress), SV-SCOPE (tool scope), and SV-EXFIL (data exfiltration patterns with causal path tracing). The verdict is VERIFIED, FAILED, or INCONCLUSIVE. CI-friendly: <code class="text-brand-cyan bg-brand-cyan/10 px-1.5 py-0.5 rounded text-sm">air verify-intent</code> exits with code 2 on FAILED.
  </p>

  <!-- Section 7: We self-host it -->
  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">We run it on our own infrastructure</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Every API request to <code class="text-brand-cyan bg-brand-cyan/10 px-1.5 py-0.5 rounded text-sm">vindicara.io</code> is recorded as a signed AgDR chain using the same <code class="text-brand-cyan bg-brand-cyan/10 px-1.5 py-0.5 rounded text-sm">airsdk</code> library customers use, anchored to public Sigstore Rekor every 60 seconds, and published as redacted JSONL.
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    <a href="/ops-chain" class="text-brand-red hover:underline">Verify it yourself</a>. The chain catalog, manifest, and every Rekor anchor are independently verifiable with zero Vindicara infrastructure in the path. If we stopped existing tomorrow, the proof would still stand.
  </p>

  <!-- Section 8: Post-quantum -->
  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">Post-quantum ready (experimental)</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    AIR supports <strong>ML-DSA-65 (FIPS 204)</strong> post-quantum signatures as an opt-in experimental feature. Ed25519 remains the default. Mixed-algorithm chains (some records Ed25519, some ML-DSA-65) verify correctly. When quantum computing threatens Ed25519, your chains are already migration-ready.
  </p>

  <!-- Section 9: What's next -->
  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">What comes next</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    1.0 is the foundation. The roadmap includes HL7v2 + FHIR R4 clinical interop for healthcare deployments, learned-baseline behavioral detection, cross-tenant federation via Sigstore Fulcio, and framework-level containment interceptors for LangChain and OpenAI so step-up approval happens automatically. Each of these gets its own news cycle; we do not rush features to pad launch day.
  </p>

  <!-- CTA -->
  <div class="glass-panel rounded-xl p-8 mt-12 text-center">
    <h2 class="text-2xl font-bold mb-4" style="color: var(--text-primary);">Try it now</h2>
    <div class="dark-embed rounded-lg p-4 font-mono text-sm inline-block mb-6">
      <pre class="text-zinc-300">pip install projectair && air demo</pre>
    </div>
    <div class="flex items-center justify-center gap-4 mt-4">
      <a href="https://github.com/vindicara-inc/vindicara" class="btn-primary text-sm px-6 py-2.5">View on GitHub</a>
      <a href="/pricing" class="btn-secondary text-sm px-6 py-2.5">Pricing</a>
      <a href="/blog/secure-ai-agents-5-minutes" class="btn-secondary text-sm px-6 py-2.5">5-Minute Quickstart</a>
    </div>
  </div>

  <!-- Share -->
  <div class="mt-12 pt-8" style="border-top: 1px solid var(--border-subtle);">
    <ShareButtons url={shareUrl} title={shareTitle} description={shareDesc} />
  </div>
</article>

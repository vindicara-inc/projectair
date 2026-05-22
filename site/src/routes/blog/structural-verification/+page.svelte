<script lang="ts">
  import ShareButtons from '$lib/components/ShareButtons.svelte';

  const shareUrl = 'https://vindicara.io/blog/structural-verification';
  const shareTitle = 'They Check Messages. We Check Missions.';
  const shareDesc = 'Intent Capsules are the signed promise. Structural Verification is the proof the promise was kept. A new category in AI agent security.';
</script>

<svelte:head>
  <title>They Check Messages. We Check Missions. | Vindicara Blog</title>
  <meta name="description" content="Intent Capsules record what the agent declared it would do. Structural Verification checks whether the agent's actual behavior served that declaration. The deterministic floor cannot be prompt-injected." />
  <link rel="canonical" href="https://vindicara.io/blog/structural-verification" />
  <meta property="og:type" content="article" />
  <meta property="og:url" content="https://vindicara.io/blog/structural-verification" />
  <meta property="og:title" content="They Check Messages. We Check Missions." />
  <meta property="og:description" content="Intent Capsules are the signed promise. Structural Verification is the proof the promise was kept." />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="They Check Messages. We Check Missions." />
  <meta name="twitter:description" content="Structural Verification: the deterministic proof that your AI agent honored its declared intent." />
  <meta name="keywords" content="structural verification, intent capsule, AI agent security, agent accountability, trajectory verification, OWASP ASI01, AI safety, prompt injection defense, deterministic verification, agent compliance" />
  {@html `<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@type": "Article",
    "headline": "They Check Messages. We Check Missions.",
    "description": "Intent Capsules record what the agent declared it would do. Structural Verification checks whether the agent's actual behavior served that declaration.",
    "datePublished": "2026-05-13",
    "dateModified": "2026-05-13",
    "author": {
      "@type": "Person",
      "name": "Kevin Minn",
      "url": "https://vindicara.io"
    },
    "publisher": {
      "@type": "Organization",
      "name": "Vindicara",
      "url": "https://vindicara.io",
      "logo": { "@type": "ImageObject", "url": "https://vindicara.io/og-image.png" }
    },
    "mainEntityOfPage": "https://vindicara.io/blog/structural-verification",
    "keywords": ["structural verification", "intent capsule", "AI agent security", "trajectory verification", "OWASP ASI01"]
  })}</script>`}
</svelte:head>

<article class="max-w-3xl mx-auto px-6 py-16">
  <header class="mb-12">
    <div class="flex items-center gap-3 mb-6">
      <span class="text-[10px] font-bold uppercase tracking-wider bg-brand-red/10 text-brand-red border border-brand-red/20 rounded-full px-2.5 py-0.5">Product</span>
      <span class="text-[10px] font-bold uppercase tracking-wider bg-brand-cyan/10 text-brand-cyan border border-brand-cyan/20 rounded-full px-2.5 py-0.5">Engineering</span>
      <span class="text-[10px]" style="color: var(--text-faint);">8 min read</span>
    </div>
    <h1 class="text-4xl sm:text-5xl font-bold tracking-tight leading-tight" style="color: var(--text-primary);">They Check Messages. We Check Missions.</h1>
    <p class="text-lg mt-4" style="color: var(--text-muted);">Intent Capsules are the signed promise. Structural Verification is the proof the promise was kept. Together, they are the accountability standard for autonomous AI agents.</p>
    <div class="flex items-center gap-3 mt-6 text-sm" style="color: var(--text-muted);">
      <span>Kevin Minn</span>
      <span style="color: var(--text-faint);">|</span>
      <span>May 13, 2026</span>
    </div>
  </header>

  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">The promise gap</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Every Signed Intent Capsule records what the agent declared it would do. "Refactor the auth module." "Review patient labs and recommend treatment." "Generate a quarterly compliance report." The capsule is signed, chained, anchored to a public transparency log.
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    But until today, nothing in the stack checked whether the agent's actual behavior served that declaration. The capsule was a signed promise. Nobody verified whether the promise was kept.
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    This is the credibility gap. The market reads "Intent Capsule" and assumes verification is happening. It was not. Now it is.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">What Structural Verification does</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    After a chain completes (or continuously during execution), Structural Verification traces the causal graph from the declared intent through every decision to the final outcome. It answers one question: <strong style="color: var(--text-primary);">did this agent's actions logically serve what it said it was doing?</strong>
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    The SSH-exfiltration demo makes this concrete. An agent declares intent: "refactor the auth module." It reads a README, reads <code class="font-mono text-brand-red">~/.ssh/id_rsa</code>, and POSTs the key to an external URL. Today's pattern-matching detectors (ASI01, ASI02) catch this via known attack signatures. Structural Verification catches it at a higher level:
  </p>

  <div class="glass-panel rounded-xl p-6 mt-6 border-brand-red/20">
    <p class="text-sm text-brand-red font-mono font-bold mb-2">STRUCTURAL VERIFICATION: FAILED</p>
    <div class="space-y-2 text-sm" style="color: var(--text-secondary);">
      <p><span class="text-brand-red font-mono">SV-SECRET</span> Secret material accessed at step 5 (<code class="font-mono" style="color: var(--text-muted);">~/.ssh/id_rsa</code>). IntentSpec does not declare <code class="font-mono" style="color: var(--text-muted);">secret_access: true</code>.</p>
      <p><span class="text-brand-red font-mono">SV-NET</span> HTTP POST to <code class="font-mono" style="color: var(--text-muted);">attacker.example.com</code> at step 7. Destination not in <code class="font-mono" style="color: var(--text-muted);">allowed_network</code>.</p>
      <p><span class="text-brand-red font-mono">SV-EXFIL</span> Causal path from secret read (step 5) to network egress (step 7) via Layer 2 causal graph. Data exfiltration trajectory detected.</p>
    </div>
  </div>

  <p class="leading-relaxed mt-6" style="color: var(--text-secondary);">
    Pattern matching asks: "does this step look like a known attack?" Structural Verification asks: "does this trajectory serve the declared mission?" A novel attack pattern that no detector has a signature for still fails structural verification if the actions do not serve the goal.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">The hybrid architecture</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    There is a critical technical risk in any verification system: if the verifier is an LLM, the same prompt injection that fooled the agent can fool the judge. A well-crafted adversarial input that bypasses per-call guardrails would also bypass an LLM-based verifier. The verification collapses into "another AI judging AI."
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Project AIR's Structural Verification ships with a <strong style="color: var(--text-primary);">deterministic symbolic floor</strong> that cannot be prompt-injected. Four checks, all operating over the causal graph and the declared IntentSpec:
  </p>

  <div class="glass-panel rounded-xl p-6 mt-6 space-y-4">
    <div>
      <h3 class="text-sm font-bold text-brand-red uppercase tracking-wider font-mono">SV-SECRET</h3>
      <p class="text-sm mt-1" style="color: var(--text-muted);">Detects access to secret material (SSH keys, API tokens, credentials, environment secrets) when the IntentSpec does not declare <code class="font-mono text-brand-red">secret_access: true</code>. Deterministic pattern matching over tool arguments and outputs.</p>
    </div>
    <div>
      <h3 class="text-sm font-bold text-brand-red uppercase tracking-wider font-mono">SV-NET</h3>
      <p class="text-sm mt-1" style="color: var(--text-muted);">Flags network egress to destinations not in the IntentSpec's <code class="font-mono text-brand-red">allowed_network</code> list. Catches undeclared data exfiltration, C2 callbacks, and unexpected API calls.</p>
    </div>
    <div>
      <h3 class="text-sm font-bold text-brand-red uppercase tracking-wider font-mono">SV-SCOPE</h3>
      <p class="text-sm mt-1" style="color: var(--text-muted);">Verifies filesystem access stays within the <code class="font-mono text-brand-red">allowed_paths</code> declared in the IntentSpec. An agent scoped to <code class="font-mono" style="color: var(--text-muted);">src/auth/</code> that reads <code class="font-mono" style="color: var(--text-muted);">~/.ssh/</code> triggers immediately.</p>
    </div>
    <div>
      <h3 class="text-sm font-bold text-brand-red uppercase tracking-wider font-mono">SV-EXFIL</h3>
      <p class="text-sm mt-1" style="color: var(--text-muted);">Uses the Layer 2 causal graph to detect causal paths from secret reads to network egress. This is the trajectory check: it does not just flag individual steps, it proves the <em>relationship</em> between them. A secret read that never leaves the machine is not exfiltration. A secret read that flows into an HTTP POST is.</p>
    </div>
  </div>

  <p class="leading-relaxed mt-6" style="color: var(--text-secondary);">
    The symbolic floor is the guarantee. If a competitor demonstrates a prompt-injected LLM judge, the deterministic layer still catches it. The LLM reasoning ceiling (v2) will add nuance for the ambiguous middle, with the LLM's judgment itself capsule-signed and reviewable. Sell the floor as the guarantee. Sell the ceiling as defense in depth.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">The IntentSpec schema</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Free-text intent ("refactor the auth module") is hard to verify precisely. Structural Verification introduces a structured <code class="font-mono text-brand-red">IntentSpec</code> that defines what the agent is authorized to do:
  </p>

  <div class="bg-obsidian-lighter rounded-xl p-5 mt-6 font-mono text-sm overflow-x-auto border border-white/10">
    <pre class="text-zinc-300"><span class="text-brand-red">from</span> airsdk <span class="text-brand-red">import</span> AIRRecorder
<span class="text-brand-red">from</span> airsdk.types <span class="text-brand-red">import</span> IntentSpec

recorder = AIRRecorder(
    <span class="text-green-400">"agent-chain.jsonl"</span>,
    intent_spec=IntentSpec(
        goal=<span class="text-green-400">"Refactor the auth module"</span>,
        allowed_tools=[<span class="text-green-400">"read_file"</span>, <span class="text-green-400">"write_file"</span>, <span class="text-green-400">"run_tests"</span>],
        allowed_paths=[<span class="text-green-400">"src/auth/"</span>, <span class="text-green-400">"tests/auth/"</span>],
        allowed_network=[],
        secret_access=<span class="text-brand-purple">False</span>,
        non_goals=[<span class="text-green-400">"deploy"</span>, <span class="text-green-400">"access credentials"</span>],
    ),
)</pre>
  </div>

  <p class="leading-relaxed mt-6" style="color: var(--text-secondary);">
    The IntentSpec is recorded as an <code class="font-mono text-brand-red">INTENT_DECLARATION</code> step in the chain. It is signed, chained, and tamper-evident like every other capsule. The structural verifier checks every subsequent step against these constraints.
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    If no IntentSpec is provided, the verifier falls back to the <code class="font-mono text-brand-red">user_intent</code> free-text field. This gives weaker verification (the symbolic checks still run, but without scope constraints). The verdict is still useful; the IntentSpec makes it precise.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">Try it</h2>

  <div class="bg-obsidian-lighter rounded-xl p-5 mt-6 font-mono text-sm overflow-x-auto border border-white/10">
    <pre class="text-zinc-300"><span class="text-brand-red">$</span> pip install projectair
<span class="text-brand-red">$</span> air demo
<span class="text-zinc-500"># Step 6/9 runs structural verification on the SSH-exfil chain</span>
<span class="text-zinc-500"># SV-SECRET, SV-NET, SV-EXFIL all fire. Verdict: FAILED.</span>

<span class="text-brand-red">$</span> air verify-intent my-chain.jsonl
<span class="text-zinc-500"># Run structural verification on any chain. Exit code 2 = FAILED.</span></pre>
  </div>

  <p class="leading-relaxed mt-6" style="color: var(--text-secondary);">
    <code class="font-mono text-brand-red">air verify-intent</code> reads any AgDR chain, extracts the intent (from an IntentSpec record or from the <code class="font-mono text-brand-red">user_intent</code> field), runs the four symbolic checks, and outputs a verdict. Exit code 0 is VERIFIED. Exit code 2 is FAILED. Exit code 3 is INCONCLUSIVE. Wire it into CI, run it in a post-deploy hook, or use it in forensic review.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">Why this is different</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Every other tool in the AI safety stack checks individual messages. NVIDIA NemoGuard classifies content per-call. Guardrails AI validates inputs and outputs. Bedrock Guardrails wraps model responses. These are useful. They are also scoped to the step level. None of them ask: "given everything this agent did across its entire session, did the trajectory serve the declared mission?"
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Structural Verification operates at the trajectory level. It has the full causal graph. It knows the relationship between steps. It can prove that reading a secret at step 5 and posting to an external URL at step 7 constitutes a causal exfiltration path, even if neither step in isolation looks malicious. No per-call classifier can make that determination.
  </p>

  <div class="glass-panel rounded-xl p-6 mt-6" style="border-color: var(--border);">
    <table class="w-full text-sm">
      <thead>
        <tr class="text-left uppercase tracking-wider text-xs" style="color: var(--text-muted); border-bottom: 1px solid var(--border);">
          <th class="pb-3">Approach</th>
          <th class="pb-3">Scope</th>
          <th class="pb-3">Limitation</th>
        </tr>
      </thead>
      <tbody style="color: var(--text-secondary);">
        <tr style="border-bottom: 1px solid var(--border-subtle);">
          <td class="py-3 font-medium" style="color: var(--text-primary);">Per-call guardrails</td>
          <td class="py-3">Single input/output</td>
          <td class="py-3" style="color: var(--text-muted);">Cannot see relationships between steps</td>
        </tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);">
          <td class="py-3 font-medium" style="color: var(--text-primary);">Content classifiers</td>
          <td class="py-3">Single message</td>
          <td class="py-3" style="color: var(--text-muted);">Cannot reason about trajectory intent</td>
        </tr>
        <tr style="border-bottom: 1px solid var(--border-subtle);">
          <td class="py-3 font-medium" style="color: var(--text-primary);">LLM judge</td>
          <td class="py-3">Session (prompt-injectable)</td>
          <td class="py-3" style="color: var(--text-muted);">Same attack surface as the agent itself</td>
        </tr>
        <tr>
          <td class="py-3 text-brand-red font-semibold">Structural Verification</td>
          <td class="py-3">Full trajectory (deterministic)</td>
          <td class="py-3" style="color: var(--text-muted);">Requires intent declaration for full precision</td>
        </tr>
      </tbody>
    </table>
  </div>

  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">HIPAA: "prove it works"</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    The 2026 HIPAA Security Rule NPRM requires covered entities to <strong style="color: var(--text-primary);">prove every control exists, has a designated owner, and actually works</strong>. Structural Verification is the "actually works" part. The audit trail (Layer 1) proves the agent was monitored. The containment policy (Layer 3) proves the agent was constrained. Structural Verification proves the agent <em>honored</em> its constraints.
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    In the healthcare demo, a clinical AI agent declares intent to review patient labs and recommend treatment. It accesses lab results, imaging, and medications (all within scope). It attempts to access restricted psychiatric records (blocked by containment policy, flagged by ASI02). Structural Verification adds the trajectory-level proof: "every PHI access in this chain served the declared clinical review intent. Verdict: VERIFIED."
  </p>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    A signed capsule chain that says "the agent ran." A structural verification result that says "the agent honored its declared purpose." Together, they satisfy 45 CFR 164.312(b) audit controls and 164.502(b) minimum necessary in a way no log file can.
  </p>

  <div class="glass-panel rounded-xl p-8 my-12 text-center border-brand-red/20">
    <h3 class="text-xl font-bold mb-2" style="color: var(--text-primary);">Signed promise. Verified proof.</h3>
    <p class="text-sm mb-6" style="color: var(--text-muted);">Project AIR is open source. Structural Verification ships in the latest release.</p>
    <div class="flex flex-col sm:flex-row items-center justify-center gap-3">
      <a href="https://github.com/vindicara-inc/projectair" class="btn-primary text-sm px-6 py-3">
        <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        View on GitHub
      </a>
      <a href="https://pypi.org/project/projectair/" class="btn-secondary text-sm px-6 py-3">pip install projectair</a>
    </div>
  </div>

  <h2 class="text-2xl font-bold mt-12 mb-4" style="color: var(--text-primary);">The 24-month arc</h2>

  <p class="leading-relaxed mt-4" style="color: var(--text-secondary);">
    Structural Verification is not the destination. It is the foundation.
  </p>

  <ol class="list-decimal list-inside leading-relaxed mt-4 space-y-3 ml-4" style="color: var(--text-secondary);">
    <li><strong style="color: var(--text-primary);">Now:</strong> Ship structural verification. Define the category. Prove that intent capsules are not just records but enforceable contracts.</li>
    <li><strong style="color: var(--text-primary);">Months 3-6:</strong> Establish the capsule + verification schema as an open standard. Defend the category. Make IntentSpec the format other tools consume.</li>
    <li><strong style="color: var(--text-primary);">Months 6-12:</strong> Layer a Verifiable Agent Trust Score on top. Monetize the category. A trust score that includes "this agent has verified intent compliance across 10,000 sessions" is a substantially stronger signal than one that only counts detector findings.</li>
  </ol>

  <p class="leading-relaxed mt-6" style="color: var(--text-secondary);">
    We are building a primitive, then a standard, then a market.
  </p>

  <div class="mt-16 pt-8" style="border-top: 1px solid var(--border-subtle);">
    <h2 class="text-lg font-semibold mb-6" style="color: var(--text-primary);">Related Posts</h2>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-6">
      <a href="/blog/hipaa-ai-audit-problem" class="glass-panel rounded-lg p-4 hover:border-brand-red/30 transition-colors block">
        <span class="text-[10px] font-bold uppercase tracking-wider text-brand-red">Healthcare</span>
        <p class="text-sm font-medium mt-1" style="color: var(--text-primary);">The New HIPAA AI Audit Problem (and How to Solve It)</p>
      </a>
      <a href="/blog/trustworthy-agents-forensic-evidence" class="glass-panel rounded-lg p-4 hover:border-brand-red/30 transition-colors block">
        <span class="text-[10px] font-bold uppercase tracking-wider text-brand-red">Perspective</span>
        <p class="text-sm font-medium mt-1" style="color: var(--text-primary);">Implementing Trustworthy Agents: A Forensic Evidence Layer for Production</p>
      </a>
    </div>
  </div>

  <div class="mt-8">
    <ShareButtons url={shareUrl} title={shareTitle} description={shareDesc} />
  </div>
</article>

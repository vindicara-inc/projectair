<script>
  import AppShell from '$components/AppShell.svelte';
</script>

<svelte:head>
  <title>They Check Messages. We Check Missions. | Vindicara Blog</title>
  <meta name="description" content="Intent Capsules record what the agent declared it would do. Structural Verification checks whether the agent's actual behavior served that declaration. The deterministic floor cannot be prompt-injected." />
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

<AppShell active="blog" title="blog" scroll={true}>
  <article class="prose">
    <div class="eyebrow">Product · Engineering</div>
    <h1>They Check Messages. We Check Missions.</h1>
    <p class="muted">May 13, 2026 · Kevin Minn</p>
    <p>Intent Capsules are the signed promise. Structural Verification is the proof the promise was kept. Together, they are the accountability standard for autonomous AI agents.</p>

    <h2>The promise gap</h2>
    <p>Every Signed Intent Capsule records what the agent declared it would do. "Refactor the auth module." "Review patient labs and recommend treatment." "Generate a quarterly compliance report." The capsule is signed, chained, anchored to a public transparency log.</p>
    <p>But until today, nothing in the stack checked whether the agent's actual behavior served that declaration. The capsule was a signed promise. Nobody verified whether the promise was kept.</p>
    <p>This is the credibility gap. The market reads "Intent Capsule" and assumes verification is happening. It was not. Now it is.</p>

    <h2>What Structural Verification does</h2>
    <p>After a chain completes (or continuously during execution), Structural Verification traces the causal graph from the declared intent through every decision to the final outcome. It answers one question: <strong>did this agent's actions logically serve what it said it was doing?</strong></p>
    <p>The SSH-exfiltration demo makes this concrete. An agent declares intent: "refactor the auth module." It reads a README, reads <code>~/.ssh/id_rsa</code>, and POSTs the key to an external URL. Today's pattern-matching detectors (ASI01, ASI02) catch this via known attack signatures. Structural Verification catches it at a higher level:</p>
    <div class="card callout">
      <p class="redhead mono">STRUCTURAL VERIFICATION: FAILED</p>
      <p><span class="sv">SV-SECRET</span> Secret material accessed at step 5 (<code>~/.ssh/id_rsa</code>). IntentSpec does not declare <code>secret_access: true</code>.</p>
      <p><span class="sv">SV-NET</span> HTTP POST to <code>attacker.example.com</code> at step 7. Destination not in <code>allowed_network</code>.</p>
      <p><span class="sv">SV-EXFIL</span> Causal path from secret read (step 5) to network egress (step 7) via Layer 2 causal graph. Data exfiltration trajectory detected.</p>
    </div>
    <p>Pattern matching asks: "does this step look like a known attack?" Structural Verification asks: "does this trajectory serve the declared mission?" A novel attack pattern that no detector has a signature for still fails structural verification if the actions do not serve the goal.</p>

    <h2>The hybrid architecture</h2>
    <p>There is a critical technical risk in any verification system: if the verifier is an LLM, the same prompt injection that fooled the agent can fool the judge. A well-crafted adversarial input that bypasses per-call guardrails would also bypass an LLM-based verifier. The verification collapses into "another AI judging AI."</p>
    <p>Project <span class="air">AIR</span>'s Structural Verification ships with a <strong>deterministic symbolic floor</strong> that cannot be prompt-injected. Four checks, all operating over the causal graph and the declared IntentSpec:</p>
    <div class="card callout">
      <h3 class="sv">SV-SECRET</h3>
      <p>Detects access to secret material (SSH keys, API tokens, credentials, environment secrets) when the IntentSpec does not declare <code>secret_access: true</code>. Deterministic pattern matching over tool arguments and outputs.</p>
      <h3 class="sv">SV-NET</h3>
      <p>Flags network egress to destinations not in the IntentSpec's <code>allowed_network</code> list. Catches undeclared data exfiltration, C2 callbacks, and unexpected API calls.</p>
      <h3 class="sv">SV-SCOPE</h3>
      <p>Verifies filesystem access stays within the <code>allowed_paths</code> declared in the IntentSpec. An agent scoped to <code>src/auth/</code> that reads <code>~/.ssh/</code> triggers immediately.</p>
      <h3 class="sv">SV-EXFIL</h3>
      <p>Uses the Layer 2 causal graph to detect causal paths from secret reads to network egress. This is the trajectory check: it does not just flag individual steps, it proves the <em>relationship</em> between them. A secret read that never leaves the machine is not exfiltration. A secret read that flows into an HTTP POST is.</p>
    </div>
    <p>The symbolic floor is the guarantee. If a competitor demonstrates a prompt-injected LLM judge, the deterministic layer still catches it. The LLM reasoning ceiling (v2) will add nuance for the ambiguous middle, with the LLM's judgment itself capsule-signed and reviewable. Sell the floor as the guarantee. Sell the ceiling as defense in depth.</p>

    <h2>The IntentSpec schema</h2>
    <p>Free-text intent ("refactor the auth module") is hard to verify precisely. Structural Verification introduces a structured <code>IntentSpec</code> that defines what the agent is authorized to do:</p>
    <pre class="code">from airsdk import AIRRecorder
from airsdk.types import IntentSpec

recorder = AIRRecorder(
    "agent-chain.jsonl",
    intent_spec=IntentSpec(
        goal="Refactor the auth module",
        allowed_tools=["read_file", "write_file", "run_tests"],
        allowed_paths=["src/auth/", "tests/auth/"],
        allowed_network=[],
        secret_access=False,
        non_goals=["deploy", "access credentials"],
    ),
)</pre>
    <p>The IntentSpec is recorded as an <code>INTENT_DECLARATION</code> step in the chain. It is signed, chained, and tamper-evident like every other capsule. The structural verifier checks every subsequent step against these constraints.</p>
    <p>If no IntentSpec is provided, the verifier falls back to the <code>user_intent</code> free-text field. This gives weaker verification (the symbolic checks still run, but without scope constraints). The verdict is still useful; the IntentSpec makes it precise.</p>

    <h2>Try it</h2>
    <pre class="code">$ pip install projectair
$ air demo
# Step 6/9 runs structural verification on the SSH-exfil chain
# SV-SECRET, SV-NET, SV-EXFIL all fire. Verdict: FAILED.

$ air verify-intent my-chain.jsonl
# Run structural verification on any chain. Exit code 2 = FAILED.</pre>
    <p><code>air verify-intent</code> reads any AgDR chain, extracts the intent (from an IntentSpec record or from the <code>user_intent</code> field), runs the four symbolic checks, and outputs a verdict. Exit code 0 is VERIFIED. Exit code 2 is FAILED. Exit code 3 is INCONCLUSIVE. Wire it into CI, run it in a post-deploy hook, or use it in forensic review.</p>

    <h2>Why this is different</h2>
    <p>Every other tool in the AI safety stack checks individual messages. NVIDIA NemoGuard classifies content per-call. Guardrails AI validates inputs and outputs. Bedrock Guardrails wraps model responses. These are useful. They are also scoped to the step level. None of them ask: "given everything this agent did across its entire session, did the trajectory serve the declared mission?"</p>
    <p>Structural Verification operates at the trajectory level. It has the full causal graph. It knows the relationship between steps. It can prove that reading a secret at step 5 and posting to an external URL at step 7 constitutes a causal exfiltration path, even if neither step in isolation looks malicious. No per-call classifier can make that determination.</p>
    <table>
      <thead><tr><th>Approach</th><th>Scope</th><th>Limitation</th></tr></thead>
      <tbody>
        <tr><td>Per-call guardrails</td><td>Single input/output</td><td>Cannot see relationships between steps</td></tr>
        <tr><td>Content classifiers</td><td>Single message</td><td>Cannot reason about trajectory intent</td></tr>
        <tr><td>LLM judge</td><td>Session (prompt-injectable)</td><td>Same attack surface as the agent itself</td></tr>
        <tr><td class="red"><strong>Structural Verification</strong></td><td>Full trajectory (deterministic)</td><td>Requires intent declaration for full precision</td></tr>
      </tbody>
    </table>

    <h2>HIPAA: "prove it works"</h2>
    <p>The 2025 HIPAA Security Rule NPRM (proposed) would require covered entities to <strong>prove every control exists, has a designated owner, and actually works</strong>. Structural Verification is the "actually works" part. The audit trail (Layer 1) proves the agent was monitored. The containment policy (Layer 3) proves the agent was constrained. Structural Verification proves the agent <em>honored</em> its constraints.</p>
    <p>In the healthcare demo, a clinical AI agent declares intent to review patient labs and recommend treatment. It accesses lab results, imaging, and medications (all within scope). It attempts to access restricted psychiatric records (blocked by containment policy, flagged by ASI02). Structural Verification adds the trajectory-level proof: "every PHI access in this chain served the declared clinical review intent. Verdict: VERIFIED."</p>
    <p>A signed capsule chain that says "the agent ran." A structural verification result that says "the agent honored its declared purpose." Together, they satisfy 45 CFR 164.312(b) audit controls and 164.502(b) minimum necessary in a way no log file can.</p>

    <div class="card callout">
      <h3>Signed promise. Verified proof.</h3>
      <p>Project <span class="air">AIR</span> is open source. Structural Verification ships in the latest release.</p>
      <div class="ctas">
        <a class="btn" href="https://github.com/vindicara-inc/projectair">View on GitHub</a>
        <a class="btn ghost" href="https://pypi.org/project/projectair/">pip install projectair</a>
      </div>
    </div>

    <h2>The 24-month arc</h2>
    <p>Structural Verification is not the destination. It is the foundation.</p>
    <ol>
      <li><strong>Now:</strong> Ship structural verification. Define the category. Prove that intent capsules are not just records but enforceable contracts.</li>
      <li><strong>Months 3-6:</strong> Establish the capsule + verification schema as an open standard. Defend the category. Make IntentSpec the format other tools consume.</li>
      <li><strong>Months 6-12:</strong> Layer a Verifiable Agent Trust Score on top. Monetize the category. A trust score that includes "this agent has verified intent compliance across 10,000 sessions" is a substantially stronger signal than one that only counts detector findings.</li>
    </ol>
    <p>We are building a primitive, then a standard, then a market.</p>

    <h2>Related posts</h2>
    <ul>
      <li><a href="/blog/hipaa-ai-audit-problem">The New HIPAA AI Audit Problem (and How to Solve It)</a></li>
      <li><a href="/blog/trustworthy-agents-forensic-evidence">Implementing Trustworthy Agents: A Forensic Evidence Layer for Production</a></li>
    </ul>
  </article>
</AppShell>

<style>
  .prose h1{font-size:36px;margin:14px 0 0}
  .prose a{color:var(--air2)}
  code{font-family:var(--mono);font-size:.92em;color:var(--air2)}
  .code{font-family:var(--mono);font-size:12.5px;background:rgba(0,0,0,.35);border:1px solid var(--line);padding:14px;overflow-x:auto;line-height:1.6;margin:18px 0;color:var(--soft)}
  ol{color:var(--soft);line-height:1.7;font-size:14.5px;margin:0 0 12px 20px}
  ol li{margin-bottom:8px}
  .callout{padding:18px 20px;margin:22px 0}
  .callout h3{margin-top:14px}
  .callout h3:first-child{margin-top:0}
  .redhead{color:var(--air);font-weight:700}
  .mono{font-family:var(--mono)}
  .sv{font-family:var(--mono);font-size:12px;color:var(--air2);font-weight:700;letter-spacing:.06em}
  h3.sv{font-size:12px;text-transform:uppercase}
  table{width:100%;border-collapse:collapse;font-size:13px;margin:18px 0;color:var(--soft)}
  th{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.08em;text-align:left;color:var(--faint);padding:8px 10px;border-bottom:1px solid var(--line)}
  td{padding:8px 10px;border-bottom:1px solid var(--line);line-height:1.5;vertical-align:top}
  td.red{color:var(--air2)}
  .ctas{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
</style>

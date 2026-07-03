<script>
  import AppShell from '$components/AppShell.svelte';
</script>

<svelte:head>
  <title>An NVIDIA-Backed Second Opinion, Signed: NemoGuard Verdicts as Forensic Evidence | Vindicara Blog</title>
  <meta name="description" content="Vindicara is an NVIDIA Inception program member. Project AIR ships NVIDIA integrations today: NeMo Guardrails decisions captured as signed records, NemoGuard NIM classifier verdicts recorded as detector findings, and any OpenAI-compatible NIM endpoint instrumented in-process." />
  <meta property="og:type" content="article" />
  <meta property="og:url" content="https://vindicara.io/blog/nvidia-inception-nemoguard-second-opinion" />
  <meta property="og:title" content="An NVIDIA-Backed Second Opinion, Signed: NemoGuard Verdicts as Forensic Evidence" />
  <meta property="og:description" content="How Project AIR records NVIDIA NemoGuard classifier verdicts into a tamper-evident, independently verifiable evidence chain. Shipped, on PyPI, MIT-licensed." />
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="An NVIDIA-Backed Second Opinion, Signed: NemoGuard Verdicts as Forensic Evidence" />
  <meta name="twitter:description" content="How Project AIR records NVIDIA NemoGuard classifier verdicts into a tamper-evident, independently verifiable evidence chain." />
  <meta name="keywords" content="NVIDIA Inception, NeMo Guardrails, NemoGuard NIM, AI agent accountability, AI agent forensics, jailbreak detection, content safety, NIM microservices, signed intent capsule" />
  {@html `<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@type": "Article",
    "headline": "An NVIDIA-Backed Second Opinion, Signed: NemoGuard Verdicts as Forensic Evidence",
    "description": "Vindicara, an NVIDIA Inception program member, ships NVIDIA integrations in Project AIR: NeMo Guardrails capture, NemoGuard NIM classifier verdicts as detector findings, and in-process NIM instrumentation.",
    "datePublished": "2026-06-10",
    "dateModified": "2026-06-10",
    "author": { "@type": "Person", "name": "Kevin Minn", "url": "https://vindicara.io" },
    "publisher": { "@type": "Organization", "name": "Vindicara", "url": "https://vindicara.io" },
    "mainEntityOfPage": "https://vindicara.io/blog/nvidia-inception-nemoguard-second-opinion",
    "keywords": ["NVIDIA Inception", "NeMo Guardrails", "NemoGuard NIM", "AI agent forensics"]
  })}</script>`}
</svelte:head>

<AppShell active="blog" title="blog" scroll={true}>
  <article class="prose">
    <div class="eyebrow">Engineering</div>
    <h1>An NVIDIA-backed second opinion, signed</h1>
    <p class="muted">June 10, 2026 · Kevin Minn</p>

    <p>Vindicara is a member of the NVIDIA Inception program, and Project <span class="air">AIR</span> ships real NVIDIA integrations today. Not a roadmap slide: code on PyPI, runnable with one API key. This post explains what those integrations do and why a safety classifier's verdict belongs inside a forensic evidence chain, not just in a log line.</p>

    <h2>The problem with verdicts that vanish</h2>
    <p>Safety rails make decisions constantly: this prompt looks like a jailbreak, this output violates content policy, this conversation drifted off its allowed topic. In most stacks those verdicts gate the action and then disappear. Six months later, when an auditor asks why the agent was allowed to proceed, the answer is a shrug. The rail did its job in the moment and left nothing for the record.</p>
    <p>Project <span class="air">AIR</span> treats every verdict as evidence. Whatever the rail decides, the decision itself is captured as a signed, hash-chained record: what was checked, what the verdict was, what happened next, and which human cleared it if a step-up was raised.</p>

    <h2>What ships today</h2>
    <h3>NeMo Guardrails capture</h3>
    <p><code>instrument_nemo_guardrails</code> wraps an existing NeMo Guardrails deployment so that every guardrail decision lands in the <span class="air">AIR</span> chain as a signed record. No change to how the rails work; they simply stop being amnesiac.</p>

    <h3>NemoGuard NIM classifiers as detector findings</h3>
    <p><code>NemoGuardClient</code> calls NVIDIA's NemoGuard NIM microservices, JailbreakDetect, ContentSafety, and TopicControl, and records each verdict as a detector finding. Two of <span class="air">AIR</span>'s 16 detectors exist specifically for this: AIR-05 scales NemoGuard safety classifications by severity, and AIR-06 cross-corroborates NemoGuard verdicts against <span class="air">AIR</span>'s own heuristic detectors.</p>
    <p>That corroboration is the point. When an <span class="air">AIR</span> heuristic and an NVIDIA-served classifier independently agree that a prompt was a jailbreak attempt, the evidence chain no longer says "our detector flagged it." It says two independent systems agreed, and both verdicts are signed into the same tamper-evident record.</p>

    <h3>Any NIM endpoint, instrumented in-process</h3>
    <p>Any OpenAI-compatible NIM endpoint works through <code>instrument_openai</code>, so inference served from build.nvidia.com is captured the same way as any other provider. This is verified by a network-gated end-to-end test and a runnable demo that needs only an <code>NVIDIA_API_KEY</code>.</p>

    <pre class="code">pip install projectair
export NVIDIA_API_KEY=nvapi-...
python examples/nim_demo.py</pre>

    <h2>Framing discipline</h2>
    <p>NemoGuard rails are inference-backed safety classifiers. They sit alongside <span class="air">AIR</span>'s 16 detectors (10 OWASP Agentic, 3 OWASP LLM, 3 <span class="air">AIR</span>-native) as a second opinion, not a replacement. And they are distinct from ASI10, which is declared-scope Zero-Trust enforcement rather than anomaly detection. Precision about what each layer does is half the value of an accountability product.</p>

    <h2>Where this goes</h2>
    <p>The integration we are building toward binds NVIDIA's hardware root of trust into the same evidence chain: an NRAS-signed GPU attestation token recorded inside the Signed Intent Capsule, so the record proves not only what an agent did and who authorized it, but that it ran on verified NVIDIA confidential-computing hardware. That work is on the roadmap and labeled experimental until a reference workload runs end to end.</p>

    <div class="card callout">
      <p><b>Try it.</b> The SDK and CLI are MIT-licensed and on PyPI. <code>pip install projectair && air demo</code> runs in under a minute.</p>
      <a class="btn" href="/overview">Get started</a>
    </div>

    <p class="muted nvlegal">&copy; 2026 NVIDIA, the NVIDIA logo, NeMo, NemoGuard, NIM, and NVIDIA Inception are trademarks and/or registered trademarks of NVIDIA Corporation in the U.S. and other countries.</p>
  </article>
</AppShell>

<style>
  .prose h1{font-size:36px;margin:14px 0 0}
  .prose code{font-family:var(--mono);font-size:12.5px;background:rgba(0,0,0,.35);border:1px solid var(--line);padding:1px 6px}
  .code{font-family:var(--mono);font-size:12.5px;background:rgba(0,0,0,.35);border:1px solid var(--line);padding:14px;overflow-x:auto;color:var(--soft);line-height:1.6;margin:0 0 12px}
  .callout{padding:20px;margin:26px 0}
  .callout .btn{margin-top:6px}
  .nvlegal{margin-top:34px;opacity:.6}
</style>

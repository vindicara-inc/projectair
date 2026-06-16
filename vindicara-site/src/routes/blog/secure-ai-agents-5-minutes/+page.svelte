<script>
  import AppShell from '$components/AppShell.svelte';
</script>

<svelte:head>
  <title>Run your first `air trace` in 5 minutes | Vindicara Blog</title>
  <meta name="description" content="From pip install projectair to a signed forensic timeline of your LangChain agent in under five minutes. The air CLI and airsdk are MIT-licensed and open source today." />
  <link rel="canonical" href="https://vindicara.io/blog/secure-ai-agents-5-minutes" />
  <meta property="og:type" content="article" />
  <meta property="og:url" content="https://vindicara.io/blog/secure-ai-agents-5-minutes" />
  <meta property="og:title" content="Run your first `air trace` in 5 minutes" />
  <meta property="og:description" content="From pip install projectair to a signed forensic timeline of your LangChain agent in under five minutes. The air CLI and airsdk are MIT-licensed and open source today." />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="Run your first `air trace` in 5 minutes" />
  <meta name="twitter:description" content="From pip install projectair to a signed forensic timeline of your LangChain agent in under five minutes." />
  {@html `<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@type": "Article",
    "headline": "Run your first `air trace` in 5 minutes",
    "description": "From pip install projectair to a signed forensic timeline of your LangChain agent in under five minutes. The air CLI and airsdk are MIT-licensed and open source today.",
    "datePublished": "2026-04-02",
    "dateModified": "2026-04-18",
    "author": {
      "@type": "Organization",
      "name": "Vindicara Security Research",
      "url": "https://vindicara.io"
    },
    "publisher": {
      "@type": "Organization",
      "name": "Vindicara",
      "url": "https://vindicara.io"
    },
    "mainEntityOfPage": "https://vindicara.io/blog/secure-ai-agents-5-minutes"
  })}</script>`}
</svelte:head>

<AppShell active="blog" title="blog" scroll={true}>
  <article class="prose">
    <div class="eyebrow">Quickstart</div>
    <h1>Run your first <code>air trace</code> in 5 minutes</h1>
    <p class="muted">April 18, 2026 · Kevin Minn</p>
    <p>From <code>pip install projectair</code> to a signed forensic timeline of your LangChain agent. The <code>air</code> CLI and <code>airsdk</code> are MIT-licensed and open source today.</p>

    <h2>Why run <code>air</code> before you have an incident</h2>
    <p>Most teams reach for forensics after something breaks. By then, the trace is incomplete, the reasoning is gone, and the on-call engineer is stitching together logs from five systems at 2am. The teams that recover fast are the ones that were already writing a signed record of every agent decision before the incident.</p>
    <p>Project <span class="air">AIR</span>&#8482; is the forensic reconstruction layer for AI agents. The <code>air</code> CLI ingests an agent trace, runs detectors across two public OWASP taxonomies (all 10 OWASP Top 10 for Agentic Applications categories from ASI01 through ASI10; plus 3 OWASP Top 10 for LLM Applications categories: LLM01, LLM04, LLM06), plus 3 <span class="air">AIR</span>-native detectors (16 detectors in total), and outputs a timeline you can hand to security, legal, or insurance. The <code>airsdk</code> Python package is what writes the trace in the first place, as a chain of AgDR (AI Decision Record) entries, each with a BLAKE3 content hash and an Ed25519 signature.</p>
    <p>This guide walks through five steps that take roughly one minute each. The prerequisite is one LangChain agent you can run once. That is it.</p>

    <h2>Step 1: Install</h2>
    <pre class="code">pip install projectair</pre>
    <p>One package installs both the <code>air</code> CLI and the <code>airsdk</code> Python library. No torch, no heavy model downloads, no GPU. The CLI works on any trace file the SDK emits, and the SDK is a standard LangChain callback handler. If your agent runs today, this installs clean alongside it.</p>

    <h2>Step 2: Wire the AgDR callback into your agent</h2>
    <p>Add the callback handler to your LangChain <code>AgentExecutor</code>. Every tool call, every model response, every intermediate reasoning step becomes an AgDR entry, signed and chained to the previous one:</p>
    <pre class="code">{`from airsdk import AIRCallbackHandler
from langchain.agents import AgentExecutor

handler = AIRCallbackHandler(key="...")
agent = AgentExecutor(callbacks=[handler], ...)`}</pre>
    <p>The handler is drop-in. You do not need to restructure your agent, your prompts, or your tool definitions. The signing key can be a local Ed25519 key pair you generate once, or a key ID that points at a cloud KMS if you already have one. Your existing LangChain agent behavior does not change. What changes is that every step now has a cryptographic receipt.</p>

    <h2>Step 3: Run your agent once</h2>
    <p>Run your agent the way you always do. A single conversation, a scripted test, a short session, any of it is enough to produce a trace file. The handler writes AgDR entries as the run progresses, so if the agent crashes mid-run you still get a partial, valid chain up to the point of failure. Partial evidence is still evidence.</p>
    <p>The output is a structured log file, by default named after the run. We will use <code>my-app.log</code> in the next step.</p>

    <div class="card callout">
      <h3>Start the forensic record before the incident</h3>
      <p><code>air</code> and <code>airsdk</code> are MIT-licensed and open source. One <code>pip install</code> and you have a signed chain.</p>
      <div class="ctas">
        <a class="btn" href="https://github.com/vindicara-inc/projectair?utm_source=blog&utm_medium=cta&utm_campaign=secure-ai-agents-5-minutes">View on GitHub</a>
        <a class="btn ghost" href="https://vindicara.io/#how-it-works?utm_source=blog&utm_medium=cta&utm_campaign=secure-ai-agents-5-minutes">How <span class="air">AIR</span> works</a>
      </div>
    </div>

    <h2>Step 4: Run <code>air trace</code></h2>
    <pre class="code">air trace my-app.log</pre>
    <p>The CLI walks the signed chain, verifies each hash and signature, and runs the trace against the OWASP Top 10 for Agentic Applications detection set. You get a console report that looks like this:</p>
    <pre class="code">{`[AIR v0.1] Analyzing 247 agent steps across 3 conversations...

  ASI01 Agent Goal Hijack detected at step 47
  ASI02 Tool Misuse detected at step 51

[Export] forensic-report.json | forensic-report.pdf | forensic-report.siem`}</pre>
    <p>Each finding ties back to a specific step in the signed chain. ASI01 (Agent Goal Hijack) flags steps where the agent's behavior drifted from the task it was given. ASI02 (Tool Misuse) flags steps where the agent invoked a tool in a way the threat model says it should not. The mapping is to the OWASP Top 10 for Agentic Applications 2026, the same taxonomy your security team is already standardizing on.</p>
    <p>If nothing triggers, the run is clean. You still have a signed record that says so, timestamped, reproducible, and auditable.</p>

    <h2>Step 5: Export the forensic report</h2>
    <p>The same scan emits three export formats out of the box:</p>
    <p><strong><code>forensic-report.json</code></strong>. The full decision chain with every AgDR entry, every hash, every signature, and every detection. This is the canonical evidence artifact. Any downstream tool can consume it.</p>
    <p><strong><code>forensic-report.pdf</code></strong>. A human-readable incident summary with the timeline, detections, and verification status. This is what legal, insurance, and executive stakeholders actually read.</p>
    <p><strong><code>forensic-report.siem</code></strong>. A normalized event stream ready for ingestion by your SIEM. Findings become alerts, the decision chain becomes queryable events, and your SOC analysts see agent incidents alongside the rest of your security telemetry.</p>
    <p>Five minutes in, you have a signed forensic record, ASI detections against OWASP Top 10 for Agentic Applications, and three export formats that plug into the tools security, legal, and the SOC already use. None of that existed before you installed <code>projectair</code>.</p>

    <h2>What comes next</h2>
    <p>The OSS path is enough to get a signed record of every agent run, detect ASI violations, and export evidence packs. That is the floor. The ceiling is <span class="air">AIR</span> Cloud: the hosted incident response layer where the forensic record streams into a real-time dashboard, incident workflows and alerting fire on detection, and the compliance engine projects the same chain into <a href="/blog/eu-ai-act-article-72-guide">EU AI Act Article 72</a> exports, California SB 53 incident reports, SOC 2 evidence, and insurance carrier formats.</p>
    <p>Before any of that, the question is the record. If your agent ran today and something went wrong tomorrow, could you prove what happened? Five minutes from now, the answer is yes.</p>

    <div class="card callout">
      <h3>Your next incident is already on its way.</h3>
      <p>Make sure you can prove what happened. <code>pip install projectair</code> and the record starts now.</p>
      <div class="ctas">
        <a class="btn" href="https://github.com/vindicara-inc/projectair?utm_source=blog&utm_medium=cta&utm_campaign=secure-ai-agents-5-minutes">View on GitHub</a>
        <a class="btn ghost" href="https://vindicara.io/#how-it-works?utm_source=blog&utm_medium=cta&utm_campaign=secure-ai-agents-5-minutes">How <span class="air">AIR</span> works</a>
      </div>
    </div>

    <h2>Related posts</h2>
    <ul>
      <li><a href="/blog/mcp-security-2026">The State of MCP Security in 2026</a></li>
      <li><a href="/blog/eu-ai-act-article-72-guide">EU AI Act Article 72: A Developer's Guide</a></li>
    </ul>
  </article>
</AppShell>

<style>
  .prose h1{font-size:36px;margin:14px 0 0}
  .prose a{color:var(--air2)}
  code{font-family:var(--mono);font-size:.92em;color:var(--air2)}
  .code{font-family:var(--mono);font-size:12.5px;background:rgba(0,0,0,.35);border:1px solid var(--line);padding:14px;overflow-x:auto;line-height:1.6;margin:18px 0;color:var(--soft)}
  .callout{padding:18px 20px;margin:22px 0}
  .callout h3{margin-top:0}
  .ctas{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
</style>

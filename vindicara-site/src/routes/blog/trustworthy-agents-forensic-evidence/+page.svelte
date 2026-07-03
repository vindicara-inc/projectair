<script>
  import AppShell from '$components/AppShell.svelte';
</script>

<svelte:head>
  <title>Implementing Trustworthy Agents: A Forensic Evidence Layer for Production | Vindicara Blog</title>
  <meta name="description" content="Anthropic's April 9 paper on trustworthy agents names three ecosystem gaps. Project AIR is our answer to evidence sharing and open standards." />
  <meta property="og:type" content="article" />
  <meta property="og:url" content="https://vindicara.io/blog/trustworthy-agents-forensic-evidence" />
  <meta property="og:title" content="Implementing Trustworthy Agents: A Forensic Evidence Layer for Production" />
  <meta property="og:description" content="Anthropic's April 9 paper on trustworthy agents names three ecosystem gaps. Project AIR is our answer to evidence sharing and open standards." />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="Implementing Trustworthy Agents: A Forensic Evidence Layer for Production" />
  <meta name="twitter:description" content="Anthropic's April 9 paper on trustworthy agents names three ecosystem gaps. Project AIR is our answer to evidence sharing and open standards." />
  {@html `<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@type": "Article",
    "headline": "Implementing Trustworthy Agents: A Forensic Evidence Layer for Production",
    "description": "Anthropic's April 9 paper on trustworthy agents names three ecosystem gaps. Project AIR is our answer to evidence sharing and open standards.",
    "datePublished": "2026-04-24",
    "author": {
      "@type": "Person",
      "name": "Kevin Minn",
      "jobTitle": "Founder",
      "affiliation": {
        "@type": "Organization",
        "name": "Vindicara",
        "url": "https://vindicara.io"
      }
    },
    "publisher": {
      "@type": "Organization",
      "name": "Vindicara",
      "url": "https://vindicara.io"
    },
    "mainEntityOfPage": "https://vindicara.io/blog/trustworthy-agents-forensic-evidence"
  })}</script>`}
</svelte:head>

<AppShell active="blog" title="blog" scroll={true}>
  <article class="prose">
    <div class="eyebrow">Perspective</div>
    <h1>Implementing Trustworthy Agents: A Forensic Evidence Layer for Production</h1>
    <p class="muted">April 24, 2026 · Kevin Minn, Founder, Vindicara</p>
    <p>Anthropic's April 9 paper on trustworthy agents names three places the ecosystem must step up. Project <span class="air">AIR</span> is our answer to evidence sharing and open standards, and a concrete contribution to a problem no single company can solve alone.</p>

    <p>On April 9, Anthropic published <em>Trustworthy Agents in Practice</em>. It is the most honest thing I have read from a frontier lab about where agent security actually stands.</p>
    <p>Two lines from the paper have been sitting with me for two weeks:</p>
    <blockquote>
      <p>"The security and reliability of agents cannot be achieved by any single company working alone."</p>
      <p>"This is the kind of infrastructure no single company can build alone."</p>
    </blockquote>
    <p>That is not marketing. That is an admission. And it is a direct invitation to the rest of us building in this space.</p>
    <p>What is missing today is not another prevention layer. It is a way to answer, after an incident: what did the agent actually do, and can you prove it?</p>
    <p>Anthropic names three places where the ecosystem needs to step up: <strong>shared benchmarks, evidence sharing, and open standards.</strong> Project <span class="air">AIR</span> is our answer to the second one, and a down payment on the third.</p>

    <h2>The four components, and where the gap is</h2>
    <p>The paper identifies four components that determine how any agent behaves: the <strong>model</strong>, the <strong>harness</strong> (instructions and guardrails), the <strong>tools</strong> it can call, and the <strong>environment</strong> it runs in. Anthropic is upfront that most industry conversation centers on the model, "and understandably so," but that agent behavior depends on all four layers working together.</p>
    <p>That is where the gap is.</p>
    <p>The model layer has Anthropic, OpenAI, Google. The harness layer has LangChain, LlamaIndex, CrewAI. The tools layer has MCP, which Anthropic created and donated to the Linux Foundation. The environment layer has every cloud provider on earth.</p>
    <p>What none of those layers produce is a <strong>signed, classified, exportable record of what the agent actually did when something went wrong.</strong></p>
    <p>That is the gap <span class="air">AIR</span> fills.</p>

    <h2>What <span class="air">AIR</span> is</h2>
    <p><span class="air">AIR</span> stands for Agent Incident Response. It ships as three surfaces sharing one evidence chain:</p>
    <p><strong><code>air</code></strong>: the CLI. MIT-licensed. Ingests any agent trace, runs all 16 detectors (10 OWASP ASI, 3 OWASP LLM categories, and 3 <span class="air">AIR</span>-native), and produces a signed forensic timeline. <code>pip install projectair</code>, then <code>air trace my-app.log</code>.</p>
    <p><strong><code>airsdk</code></strong>: the Python SDK. MIT-licensed. Drop-in LangChain callback handler. Every agent decision written as an <strong>AgDR record</strong> (AI Decision Record), with BLAKE3 content hashing, Ed25519 signatures, and UUIDv7 ordering, forward-chained for tamper evidence.</p>
    <p><strong><span class="air">AIR</span> Cloud</strong>: hosted incident response. Real-time dashboards, SIEM integrations, compliance exports, insurance-ready evidence packs. Coming soon.</p>
    <p>The SDK integration is three lines:</p>
    <pre class="code">{`from airsdk import AIRCallbackHandler

handler = AIRCallbackHandler(key="...")
agent = AgentExecutor(callbacks=[handler])`}</pre>
    <p>Every tool call, every environment interaction, every refusal or acceptance gets hashed into a forward-chain. The chain is cryptographically verifiable. The classification is based on an open, shared taxonomy. The exports are in formats that legal teams, SOC analysts, and insurance underwriters already accept.</p>

    <h2>Why this matters for the four-layer framework</h2>
    <p>Anthropic's paper is specific about where the model layer can and cannot help. Prompt injection, they write, has "no single line of defense" that is sufficient. They train the model, monitor traffic, red-team their systems. And still, as the paper puts it: "even together, these safeguards are not a guarantee."</p>
    <p>That is honest. And it means when something does go wrong, the response layer matters as much as the prevention layer.</p>
    <p><span class="air">AIR</span> operates across the <strong>tools</strong> and <strong>environment</strong> layers. When an agent calls a tool it should not have had access to, <span class="air">AIR</span> signs and classifies that call. When an environment transitions, a new MCP server registered, a permission escalated, a file written to a sensitive path, <span class="air">AIR</span> records the transition. When the agent completes a task or fails one, <span class="air">AIR</span> produces evidence you can verify.</p>
    <p>In the framework's language: <span class="air">AIR</span> is how the <strong>transparency</strong> principle gets made real after the fact. You can claim transparency. Or you can prove it.</p>

    <div class="card callout">
      <h3>The forensic evidence layer is open source today</h3>
      <p><code>air</code> and <code>airsdk</code> are MIT-licensed. <code>pip install projectair</code> and the signed chain starts now.</p>
      <div class="ctas">
        <a class="btn" href="https://github.com/vindicara-inc/projectair?utm_source=blog&utm_medium=cta&utm_campaign=trustworthy-agents">View on GitHub</a>
        <a class="btn ghost" href="https://vindicara.io/#how-it-works?utm_source=blog&utm_medium=cta&utm_campaign=trustworthy-agents">How <span class="air">AIR</span> works</a>
      </div>
    </div>

    <h2>Why OWASP ASI, not a vendor taxonomy</h2>
    <p>The classification layer matters almost as much as the signing layer. A signed blob of data nobody can interpret is just encrypted noise.</p>
    <p><span class="air">AIR</span> classifies every recorded event against the <strong>OWASP Top 10 for Agentic Applications 2026</strong> (ASI01 through ASI10), plus three OWASP LLM categories (LLM01, LLM04, LLM06) and three <span class="air">AIR</span>-native detectors, 16 in total.</p>
    <p>OWASP ASI is an open, shared taxonomy, vendor-neutral, and already on the radar of every security team paying attention. We did not invent a taxonomy because there is no reason to fragment the field further.</p>
    <p>The same reasoning Anthropic used when they donated MCP to the Linux Foundation applies here: open protocols let security properties be designed in once, rather than patched together one deployment at a time. Open protocols also keep competition focused on the quality and safety of the agent, rather than on who controls the integrations.</p>

    <h2>Real incidents, real mappings</h2>
    <p>Every public agent breach in the last eighteen months maps to an ASI signature. ForcedLeak (Salesforce Agentforce) was ASI01: goal hijack via indirect prompt injection in trusted CRM records. The Salesloft Drift breach was ASI03: inherited OAuth credentials reused to escalate access into systems the operator never authorised the agent to reach. GitHub Copilot YOLO mode was ASI02: tool misuse through auto-approved destructive shell calls. ServiceNow Now Assist was ASI01 + ASI03: indirect injection from user-supplied ticket fields driving the agent into actions outside its authorised scope.</p>
    <p>Each of those incidents left behind fragmented, unsigned traces scattered across logs. None of them produced a single evidence bundle a legal team, SOC analyst, or insurance carrier could act on without weeks of reconstruction.</p>
    <p>The <a href="/home">incidents table on vindicara.io</a> walks through what <span class="air">AIR</span>'s detection signatures would have caught at the step the breach actually happened. Every mapping is against the OWASP 2026 taxonomy.</p>

    <h2>What we are doing, and what we are asking for</h2>
    <p><code>projectair</code> ships on PyPI today. The MIT SDK and CLI are live. The design partner program for <span class="air">AIR</span> Cloud opens May 4: three production LangChain deployments, sixty days of feedback, preferred pricing in return.</p>
    <p>But the larger ask is for the ecosystem. Anthropic's paper names the three gaps: benchmarks, evidence sharing, open standards.</p>
    <p><span class="air">AIR</span> contributes to <strong>evidence sharing</strong> and <strong>open standards</strong>. We would like to work with labs, standards bodies, and infrastructure providers on making the evidence format interoperable, so an incident detected in a LangChain agent on AWS produces the same AgDR record as one detected in a CrewAI agent on Azure, verifiable by any downstream consumer.</p>
    <p>If you are running agents in production, try it. <code>pip install projectair</code> and run <code>air demo</code>. You will see exactly what your current tooling does not capture.</p>
    <p>The paper is right. This is not infrastructure one company can build alone.</p>

    <div class="card callout">
      <h3>Build the evidence layer with us.</h3>
      <p><code>pip install projectair</code> to start. Open issues, PRs, and threat-model contributions welcome on GitHub.</p>
      <div class="ctas">
        <a class="btn" href="https://github.com/vindicara-inc/projectair?utm_source=blog&utm_medium=cta&utm_campaign=trustworthy-agents-end">View on GitHub</a>
        <a class="btn ghost" href="https://vindicara.io/#how-it-works?utm_source=blog&utm_medium=cta&utm_campaign=trustworthy-agents-end">How <span class="air">AIR</span> works</a>
      </div>
    </div>

    <p><strong>Kevin Minn</strong> is the founder of Vindicara. <span class="air">AIR</span> is MIT-licensed at <a href="https://vindicara.io">vindicara.io</a>. The CLI and SDK are on PyPI: <code>pip install projectair</code>. Source at <a href="https://github.com/vindicara-inc/projectair">github.com/vindicara-inc/projectair</a>.</p>
    <h3>References</h3>
    <ul>
      <li>Anthropic, <em>Trustworthy Agents in Practice</em> (April 9, 2026): <a href="https://www.anthropic.com/research/trustworthy-agents">anthropic.com/research/trustworthy-agents</a></li>
      <li>OWASP Top 10 for Agentic Applications 2026 (ASI01 through ASI10)</li>
      <li>Model Context Protocol (Linux Foundation Agentic AI Foundation): <a href="https://modelcontextprotocol.io">modelcontextprotocol.io</a></li>
    </ul>

    <h2>Related posts</h2>
    <ul>
      <li><a href="/blog/secure-ai-agents-5-minutes">Run your first <code>air trace</code> in 5 minutes</a></li>
      <li><a href="/blog/eu-ai-act-article-72-guide">EU AI Act Article 72: A Developer's Guide</a></li>
    </ul>
  </article>
</AppShell>

<style>
  .prose h1{font-size:36px;margin:14px 0 0}
  .prose a{color:var(--air2)}
  code{font-family:var(--mono);font-size:.92em;color:var(--air2)}
  .code{font-family:var(--mono);font-size:12.5px;background:rgba(0,0,0,.35);border:1px solid var(--line);padding:14px;overflow-x:auto;line-height:1.6;margin:18px 0;color:var(--soft)}
  blockquote{border-left:2px solid var(--air);margin:24px 0;padding:4px 0 4px 20px;color:var(--white);font-style:italic}
  blockquote p{color:var(--white);margin-bottom:8px}
  .callout{padding:18px 20px;margin:22px 0}
  .callout h3{margin-top:0}
  .ctas{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
</style>

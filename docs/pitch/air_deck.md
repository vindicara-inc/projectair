---
marp: true
paginate: true
size: 16:9
title: Vindicara AIR · Pre-Seed · April 2026
author: Kevin Minn · kevin.minn@vindicara.io
style: |
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

  :root {
    --paper: #FAFAF5;
    --ink: #0A0A0F;
    --muted: #52525B;
    --hair: #D4D4D0;
    --red: #E63946;
    --deep: #1A1A2E;
  }

  section {
    background: var(--paper);
    color: var(--ink);
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    padding: 56px 72px;
    font-size: 20px;
    letter-spacing: -0.005em;
  }

  section::after {
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    letter-spacing: 0.15em;
    text-transform: uppercase;
  }

  h1 {
    font-size: 52px;
    font-weight: 900;
    letter-spacing: -0.02em;
    line-height: 1.05;
    margin: 0 0 16px;
    color: var(--ink);
  }

  h2 {
    font-size: 36px;
    font-weight: 800;
    letter-spacing: -0.015em;
    line-height: 1.1;
    margin: 0 0 18px;
    color: var(--ink);
  }

  h3 {
    font-size: 17px;
    font-weight: 700;
    letter-spacing: -0.005em;
    margin: 0 0 8px;
    color: var(--ink);
  }

  .eyebrow {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    color: var(--red);
    margin-bottom: 18px;
  }

  .lede {
    font-size: 19px;
    color: var(--muted);
    max-width: 900px;
    line-height: 1.45;
  }

  .mono { font-family: 'JetBrains Mono', monospace; }
  .red { color: var(--red); }
  .muted { color: var(--muted); }

  strong { font-weight: 700; color: var(--ink); }

  hr {
    border: none;
    border-top: 1px solid var(--hair);
    margin: 18px 0;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
    margin-top: 10px;
  }

  th {
    text-align: left;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
    padding: 10px 12px;
    border-bottom: 1px solid var(--deep);
  }

  td {
    padding: 12px 12px;
    border-bottom: 1px solid var(--hair);
    vertical-align: top;
    line-height: 1.4;
  }

  .grid {
    display: grid;
    gap: 0;
    border: 1px solid var(--deep);
  }

  .grid-2 { grid-template-columns: 1fr 1fr; }
  .grid-3 { grid-template-columns: 1fr 1fr 1fr; }
  .grid-4 { grid-template-columns: 1fr 1fr 1fr 1fr; }
  .grid-5 { grid-template-columns: 1fr 1fr 1fr 1fr 1fr; }

  .cell {
    padding: 20px 22px;
    border-right: 1px solid var(--hair);
    border-bottom: 1px solid var(--hair);
  }
  .grid-2 .cell:nth-child(even) { border-right: none; }
  .grid-3 .cell { border-right: 1px solid var(--hair); }
  .grid-3 .cell:nth-child(3n) { border-right: none; }
  .grid-4 .cell { border-right: 1px solid var(--hair); }
  .grid-4 .cell:nth-child(4n) { border-right: none; }
  .grid-5 .cell { border-right: 1px solid var(--hair); }
  .grid-5 .cell:nth-child(5n) { border-right: none; }

  .stat {
    font-family: 'JetBrains Mono', monospace;
    font-size: 44px;
    font-weight: 800;
    color: var(--ink);
    line-height: 1;
  }

  .stat-red { color: var(--red); }

  .cite {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
    margin-top: 10px;
  }

  .label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
  }

  .pill {
    display: inline-block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--red);
    border: 1px solid var(--red);
    padding: 3px 8px;
  }

  .pill-ink {
    display: inline-block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--ink);
    border: 1px solid var(--deep);
    padding: 3px 8px;
  }

  .terminal {
    background: var(--ink);
    color: #E4E4E7;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    line-height: 1.55;
    padding: 20px 24px;
    margin-top: 12px;
  }
  .terminal .cmd { color: #FAFAF5; }
  .terminal .warn { color: #F59E0B; }
  .terminal .crit { color: #EF4444; }
  .terminal .info { color: #22D3EE; }
  .terminal .ok { color: #34D399; }
  .terminal .dim { color: #71717A; }

  .foot {
    position: absolute;
    bottom: 22px;
    left: 72px;
    right: 72px;
    display: flex;
    justify-content: space-between;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--muted);
  }

  .hero-rule {
    height: 4px;
    width: 80px;
    background: var(--red);
    margin: 28px 0 24px;
  }
---

<!-- _paginate: false -->

<div class="eyebrow">Vindicara · Pre-Seed · April 2026</div>

# Forensic reconstruction<br/>and incident response<br/><span class="red">for AI agents.</span>

<div class="hero-rule"></div>

<div class="lede">

Project AIR is the OSS SDK developers install in five minutes, and the signed Intent Capsule chain that produces evidence SOC, legal, and insurance can act on.

</div>

<div class="foot">
<span>Kevin Minn · Founder · kevin.minn@vindicara.io</span>
<span>vindicara.io · pip install projectair</span>
</div>

---

<div class="eyebrow">01 · The World That Just Arrived</div>

## Agents went to production.<br/>The audit layer didn't.

<div class="grid grid-3" style="margin-top: 22px;">
  <div class="cell">
    <div class="stat stat-red">362</div>
    <p style="margin: 10px 0 0; font-size: 14px; line-height: 1.4;">AI security incidents in 2025, +55% YoY</p>
    <div class="cite">AI Incident Database</div>
  </div>
  <div class="cell">
    <div class="stat">73%</div>
    <p style="margin: 10px 0 0; font-size: 14px; line-height: 1.4;">of production AI deployments contain prompt injection</p>
    <div class="cite">OWASP / Lakera · 2025</div>
  </div>
  <div class="cell">
    <div class="stat stat-red">0</div>
    <p style="margin: 10px 0 0; font-size: 14px; line-height: 1.4;">evidence-grade audit logs produced by today's agent stack</p>
    <div class="cite">Vindicara analysis · 2026</div>
  </div>
</div>

<p class="label" style="margin-top: 28px;">Real agent incidents, 2025–2026</p>

<div class="grid grid-5" style="margin-top: 10px;">
  <div class="cell">
    <h3>EchoLeak</h3>
    <p class="mono muted" style="font-size: 11px;">M365 Copilot · May 2025</p>
  </div>
  <div class="cell">
    <h3>ForcedLeak</h3>
    <p class="mono muted" style="font-size: 11px;">Salesforce Agentforce · Sep 2025</p>
  </div>
  <div class="cell">
    <h3>Replit Vibe Meltdown</h3>
    <p class="mono muted" style="font-size: 11px;">Jul 2025</p>
  </div>
  <div class="cell">
    <h3>Amazon Q Poisoning</h3>
    <p class="mono muted" style="font-size: 11px;">Jul 2025</p>
  </div>
  <div class="cell">
    <h3>Mexico 195M records</h3>
    <p class="mono muted" style="font-size: 11px;">Dec 2025 – Feb 2026</p>
  </div>
</div>

<div class="foot">
<span>vindicara.io · pip install projectair</span>
<span>github.com/vindicara-inc/projectair</span>
</div>

---

<div class="eyebrow">02 · The Missing Layer</div>

## Prevention has it. Observability has it. Governance has it.<br/>The forensic-evidence layer is empty.

<div class="grid grid-4" style="margin-top: 22px;">
  <div class="cell">
    <span class="pill-ink">Prevent</span>
    <h3 style="margin-top: 10px;">Lakera · NeMo · Bedrock</h3>
    <p style="font-size: 14px; color: var(--muted); margin-top: 6px;">Stops bad things before they happen.</p>
  </div>
  <div class="cell">
    <span class="pill-ink">Observe</span>
    <h3 style="margin-top: 10px;">LangSmith · Langfuse · Arize · Datadog LLM</h3>
    <p style="font-size: 14px; color: var(--muted); margin-top: 6px;">Shows what happened, for debugging.</p>
  </div>
  <div class="cell">
    <span class="pill-ink">Govern</span>
    <h3 style="margin-top: 10px;">Credo AI · Fiddler · watsonx.governance</h3>
    <p style="font-size: 14px; color: var(--muted); margin-top: 6px;">Manages policy at the program level.</p>
  </div>
  <div class="cell" style="background: #FEF2F3;">
    <span class="pill">Prove</span>
    <h3 style="margin-top: 10px;">AIR · the layer this deck is about</h3>
    <p style="font-size: 14px; color: var(--muted); margin-top: 6px;">Produces signed evidence SOC, legal, and insurance can act on.</p>
  </div>
</div>

<p style="margin-top: 26px; font-size: 16px;">AIR runs behind the prevention, observability, and governance layers, not against them.</p>

---

<div class="eyebrow">03 · What AIR Is</div>

## When an agent goes off-script,<br/>AIR tells you what happened, and proves it.

<div class="grid grid-2" style="margin-top: 20px;">
  <div class="cell">
    <span class="label">Three lines. One callback.</span>
<pre class="mono" style="background: var(--ink); color: #E4E4E7; padding: 16px 18px; margin-top: 10px; font-size: 11px; line-height: 1.55;">
<span style="color:#A78BFA;">from</span> airsdk <span style="color:#A78BFA;">import</span> AIRCallbackHandler
<span style="color:#A78BFA;">from</span> langchain.agents <span style="color:#A78BFA;">import</span> AgentExecutor

handler = <span style="color:#22D3EE;">AIRCallbackHandler</span>(
    log_path=<span style="color:#34D399;">"my-agent.log"</span>,
    user_intent=<span style="color:#34D399;">"Process Q3 sales report"</span>,
)
agent = <span style="color:#22D3EE;">AgentExecutor</span>(callbacks=[handler])
</pre>
    <p style="font-size: 13px; color: var(--muted); margin-top: 10px;">Also ships first-party <span class="mono">instrument_openai()</span> and <span class="mono">instrument_anthropic()</span>.</p>
  </div>
  <div class="cell">
    <h3>Sign every decision</h3>
    <p style="font-size: 14px; color: var(--muted); margin: 4px 0 14px;">BLAKE3 content hash, Ed25519 signature, chained. OWASP's Intent Capsule pattern (ASI01 mitigation #5).</p>
    <h3>Replay and verify</h3>
    <p style="font-size: 14px; color: var(--muted); margin: 4px 0 14px;"><span class="mono">air trace my-agent.log</span> verifies signatures and runs OWASP-aligned detectors.</p>
    <h3>Export forensic report</h3>
    <p style="font-size: 14px; color: var(--muted); margin: 4px 0 0;">JSON for the dev. PDF for legal and insurance. SIEM (ArcSight CEF) for the SOC. One command.</p>
  </div>
</div>

<p style="margin-top: 20px; font-size: 14px;">Implements OWASP's own recommended Intent Capsule pattern at decision-level granularity.</p>

---

<div class="eyebrow">04 · Live in 30 Seconds</div>

## From <span class="mono">pip install</span> to signed forensic report,<br/>in one command.

<div class="terminal">
<span class="dim">$</span> <span class="cmd">pip install projectair</span><br/>
<span class="dim">Successfully installed projectair-0.2.4</span><br/>
<br/>
<span class="dim">$</span> <span class="cmd">air demo</span><br/>
<span class="dim">[AIR v0.2.4] Loaded 47 agent steps across 1 conversation.</span><br/>
<span class="ok">[Chain verified] 47 records, Ed25519 signatures valid, BLAKE3 chain intact.</span><br/>
<br/>
<span class="warn">  ASI01 Agent Goal Hijack at step 8   <span class="dim">admin_delete_records outside declared goal</span></span><br/>
<span class="crit">  ASI02 Tool Misuse at step 34        <span class="dim">shell_exec with unescaped metacharacters</span></span><br/>
<span class="warn">  ASI04 Supply Chain at step 6        <span class="dim">mcp_analytics invocation, MCP inventory check</span></span><br/>
<span class="crit">  ASI05 Unexpected Code Execution     <span class="dim">python_eval on generated code (critical)</span></span><br/>
<span class="warn">  ASI06 Memory Poisoning at step 13   <span class="dim">rag_retrieve returned injection-shaped content</span></span><br/>
<span class="crit">  ASI07 Inter-Agent Communication     <span class="dim">A2A descriptor forgery, signer-key mismatch</span></span><br/>
<span class="crit">  ASI08 Cascading Failures at step 46 <span class="dim">alpha fanned out to 5 distinct agents</span></span><br/>
<span class="warn">  ASI09 Human-Agent Trust at step 17  <span class="dim">fabricated authority before wire_transfer</span></span><br/>
<span class="warn">  AIR-01 / AIR-02 / AIR-03 / AIR-04   <span class="dim">LLM01 / LLM06 / LLM04 / chain-integrity</span></span><br/>
<br/>
<span class="info">[Export] forensic-report.json · --format pdf · --format siem</span>
</div>

<p style="margin-top: 16px; font-size: 14px; color: var(--muted);">8 of 10 OWASP Agentic detectors plus 3 OWASP LLM plus 1 AIR-native, surfaced in the first run.</p>

---

<div class="eyebrow">05 · Why Now</div>

## Five things that did not exist<br/>12 months ago.

<div class="grid grid-5" style="margin-top: 20px;">
  <div class="cell">
    <div class="label">Dec 2025</div>
    <h3 style="margin-top: 10px;">OWASP Top 10 for Agentic Applications v12.6</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 6px;">First formal taxonomy. ASI01–ASI10. The framework AIR maps to 1:1.</p>
  </div>
  <div class="cell">
    <div class="label">Jan 2026</div>
    <h3 style="margin-top: 10px;">Armilla closes $25M Series B</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 6px;">AI liability insurance with explicit coverage for agent failures. The buyer for AIR's evidence.</p>
  </div>
  <div class="cell">
    <div class="label">Mar 2026</div>
    <h3 style="margin-top: 10px;">Public AgDR signed-decision spec</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 6px;">BLAKE3, Ed25519, Merkle-tree chaining. AIR's on-disk format is compatible.</p>
  </div>
  <div class="cell">
    <div class="label">Apr 2026</div>
    <h3 style="margin-top: 10px;">OWASP names "Intent Capsule"</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 6px;">ASI01 mitigation #5. Exactly what AIR ships at decision-level granularity.</p>
  </div>
  <div class="cell" style="background: #FEF2F3;">
    <div class="label">Aug 2, 2026</div>
    <h3 style="margin-top: 10px;">EU AI Act Article 72 enforcement begins</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 6px;">High-risk AI requires post-market monitoring with audit trails. €15M / 3% global turnover penalties.</p>
  </div>
</div>

---

<div class="eyebrow">06 · Market</div>

## Where the security spend<br/>is going.

<div class="grid grid-2" style="margin-top: 20px;">
  <div class="cell">
    <div class="stat">$3–5B</div>
    <p style="margin: 10px 0 0; font-size: 15px;">AI security TAM in 2026. $15–35B by 2028, 35% CAGR.</p>
    <div class="cite">Industry analyst consensus</div>
  </div>
  <div class="cell" style="background: #FEF2F3;">
    <div class="stat stat-red">$500M – $5B</div>
    <p style="margin: 10px 0 0; font-size: 15px;">Agent IR sub-segment. Specifically addressable for the forensic-evidence layer.</p>
    <div class="cite">Vindicara sizing</div>
  </div>
</div>

<div class="grid grid-3" style="margin-top: 20px;">
  <div class="cell">
    <div class="stat">$25M</div>
    <p style="margin: 10px 0 0; font-size: 14px; line-height: 1.4;">Armilla Series B (Jan 2026). AI insurance market is funded.</p>
  </div>
  <div class="cell">
    <div class="stat">$300M</div>
    <p style="margin: 10px 0 0; font-size: 14px; line-height: 1.4;">Check Point acquired Lakera (Sep 2025). Adjacent-layer consolidation.</p>
  </div>
  <div class="cell">
    <div class="stat">$18B</div>
    <p style="margin: 10px 0 0; font-size: 14px; line-height: 1.4;">Salesforce acquired Wiz (Apr 2026). Enterprise security spend at scale.</p>
  </div>
</div>

<p style="margin-top: 22px; font-size: 15px; color: var(--muted);">Pricing benchmark: $30K–$300K ACV enterprise security tools, $15K–$50K mid-market.</p>

---

<div class="eyebrow">06 · What Ships Today</div>

## Verified on PyPI.<br/>No promises, code.

<div class="grid grid-2" style="margin-top: 20px;">
  <div class="cell">
    <span class="pill-ink">projectair · MIT · v0.2.4</span>
    <p style="font-size: 14px; color: var(--muted); margin: 8px 0 14px;">The OSS developer surface. <span class="mono">pip install projectair</span>.</p>
    <ul style="font-size: 14px; line-height: 1.55; margin: 0; padding-left: 18px;">
      <li><strong>8 OWASP Agentic detectors</strong> (ASI01, ASI02, ASI04 partial, ASI05, ASI06, ASI07, ASI08, ASI09)</li>
      <li><strong>3 OWASP LLM detectors</strong> (AIR-01 → LLM01 Prompt Injection, AIR-02 → LLM06 Sensitive Data, AIR-03 → LLM04 DoS)</li>
      <li><strong>1 AIR-native detector</strong> (AIR-04 Untraceable Action, chain integrity)</li>
      <li>LangChain callback + OpenAI SDK + Anthropic SDK first-party integrations</li>
      <li>BLAKE3 + Ed25519 Signed Intent Capsule chain (AgDR-format compatible)</li>
      <li>JSON, PDF, and SIEM (ArcSight CEF) exports from one command</li>
    </ul>
  </div>
  <div class="cell">
    <span class="pill-ink">vindicara · Apache-2.0 · v0.2.0</span>
    <p style="font-size: 14px; color: var(--muted); margin: 8px 0 14px;">Engine substrate behind AIR Cloud. Not for direct install.</p>
    <ul style="font-size: 14px; line-height: 1.55; margin: 0; padding-left: 18px;">
      <li>FastAPI on AWS Lambda, DynamoDB, S3</li>
      <li>MCP Security Scanner</li>
      <li>Agent IAM (per-agent identities, scoped tokens)</li>
      <li>Behavioral Drift Detection</li>
      <li>Compliance-as-Code (EU AI Act Article 72, NIST AI RMF, SOC 2 AI, ISO 42001)</li>
    </ul>
  </div>
</div>

<p style="margin-top: 18px; font-size: 14px;"><strong>9 PyPI releases across April 20–21, 2026.</strong> Velocity, not slides.</p>

---

<div class="eyebrow">07 · Next 90 Days</div>

## Concrete milestones.<br/>Tied to capital.

<div class="grid grid-4" style="margin-top: 22px;">
  <div class="cell">
    <div class="label">Week 1</div>
    <h3 style="margin-top: 10px;">10 of 10 OWASP Agentic shipped</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px;">ASI03 Identity & Privilege Abuse (agent-identity registry design plus detector). ASI10 Rogue Agents (behavioral-integrity baselines). OWASP Q3 Solutions Landscape submission live.</p>
  </div>
  <div class="cell">
    <div class="label">Week 4</div>
    <h3 style="margin-top: 10px;">AIR Cloud private alpha</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px;">Hosted dashboard, SIEM pipeline, /playground page. EchoLeak case-study blog (HN + LangChain Discord). 3 design partner LOIs in EU + US.</p>
  </div>
  <div class="cell">
    <div class="label">Week 8</div>
    <h3 style="margin-top: 10px;">First paid pilot. 500 GitHub stars.</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px;">$5K–$15K/mo pilot live with one design partner. Armilla insurance partnership first call. OWASP contributor status on the ASI initiative.</p>
  </div>
  <div class="cell" style="background: #FEF2F3;">
    <div class="label red">Week 12</div>
    <h3 style="margin-top: 10px;">$40K–$75K MRR run-rate. Seed open.</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px;">90-second demo video (real exploit, real export). 5 paying customers. Seed conversations with the believer-filter narrative.</p>
  </div>
</div>

---

<div class="eyebrow">08 · GTM</div>

## Free tool lands.<br/>Paid engine expands.

<p class="lede" style="margin-bottom: 20px;">The Snyk OSS-to-enterprise playbook, retuned for agent IR.</p>

<div class="grid grid-3">
  <div class="cell">
    <div class="label">Wedge</div>
    <h3 style="margin-top: 6px;">One ICP. Real urgency.</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px; line-height: 1.5;">Security engineer at a Series A–C LangChain shop with at least one EU customer demanding Article 72 readiness. ~500–1,200 reachable buyers through LangChain Discord and company directories.</p>
  </div>
  <div class="cell">
    <div class="label">Land</div>
    <h3 style="margin-top: 6px;">Free <span class="mono">pip install projectair</span></h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px; line-height: 1.5;">Five-minute install. One callback. Signed Intent Capsule chain producing real forensic reports. The buyer demos it to their EU customer the same afternoon.</p>
  </div>
  <div class="cell" style="background: #FEF2F3;">
    <div class="label red">Expand</div>
    <h3 style="margin-top: 6px;">AIR Cloud, paid engine</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px; line-height: 1.5;">$49 Dev, $149 Team self-serve. Enterprise ACV $25K–$100K. Hosted dashboards, SIEM pipelines, premium detectors, compliance evidence at scale, insurance-workflow exports.</p>
  </div>
</div>

---

<div class="eyebrow">09 · Competition</div>

## There is a category.<br/>Here is who is in it.

<table>
  <thead>
    <tr>
      <th style="width: 18%;">Layer</th>
      <th style="width: 35%;">Who</th>
      <th style="width: 30%;">What AIR does</th>
      <th style="width: 17%;">They do not</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Prevention</strong></td>
      <td>Lakera (Check Point), NeMo Guardrails, Bedrock Guardrails</td>
      <td>Records what they could not stop, signed and admissible.</td>
      <td>Produce forensic evidence.</td>
    </tr>
    <tr>
      <td><strong>Observability</strong></td>
      <td>LangSmith, Langfuse, Arize, Datadog LLM</td>
      <td>Signs the trace so it is evidence, not just a log.</td>
      <td>Produce evidence.</td>
    </tr>
    <tr>
      <td><strong>Forensic claimants</strong></td>
      <td>Vorlon (RSA Mar 2026), Oktsec (Apr 2026), AgDR spec</td>
      <td>LangChain / OpenAI / Anthropic-native. MIT OSS wedge. Three-audience export.</td>
      <td>Ship a developer OSS wedge.</td>
    </tr>
    <tr>
      <td><strong>Insurance</strong></td>
      <td>Armilla, Vouch, Munich Re aiSure</td>
      <td>Supplies the underwriting evidence those carriers need.</td>
      <td>Sit in the agent runtime.</td>
    </tr>
  </tbody>
</table>

<p style="margin-top: 18px; font-size: 14px;"><strong>AIR's seat:</strong> LangChain-native, MIT, Intent-Capsule-signed, three-audience export. Still empty.</p>

---

<div class="eyebrow">10 · Why Kevin</div>

## Solo founder. Shipped 9 PyPI releases in two days.<br/>Knows regulated-market buyers from 1099Pass.

<div class="grid grid-3" style="margin-top: 20px;">
  <div class="cell">
    <div class="label">1099Pass · Plaid review</div>
    <h3 style="margin-top: 10px;">Built fintech live in production.</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px; line-height: 1.5;">Gig-worker income verification, cleared Plaid's production review. Taught me what regulated-market buyers actually want: signed, replayable evidence, not "trust me."</p>
  </div>
  <div class="cell">
    <div class="label">projectair velocity</div>
    <h3 style="margin-top: 10px;">v0.1.0 → v0.2.4 in two days.</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px; line-height: 1.5;">9 PyPI releases April 20–21, 2026. 8 OWASP Agentic detectors, 3 OWASP LLM detectors, 1 AIR-native check. LangChain, OpenAI SDK, Anthropic SDK integrations. BLAKE3 + Ed25519 signed Intent Capsule chain. Velocity is the moat.</p>
  </div>
  <div class="cell">
    <div class="label">OWASP + standards</div>
    <h3 style="margin-top: 10px;">Grounded, not vibes.</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px; line-height: 1.5;">Every claim maps 1:1 to OWASP Top 10 for Agentic Applications v12.6 and the Solutions Landscape framework. Engaging Scott Clinton's project directly. Stack: Python 3.12, AWS Lambda + CDK, BLAKE3 + Ed25519, LangChain / OpenAI / Anthropic.</p>
  </div>
</div>

---

<!-- _paginate: false -->

<div class="eyebrow">The Ask</div>

## <span class="red">$500K</span> SAFE at $5M cap.<br/>12 months to design partner revenue.

<div class="grid grid-3" style="margin-top: 28px;">
  <div class="cell">
    <div class="label">Product</div>
    <h3 style="margin-top: 10px;">Ship the remaining 2 OWASP Agentic detectors.</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px; line-height: 1.5;">ASI03 Identity & Privilege Abuse (needs agent-identity registry, v0.3.0). ASI10 Rogue Agents (behavioral-integrity baselines). Reach 10 of 10 by Month 2.</p>
  </div>
  <div class="cell">
    <div class="label">Revenue</div>
    <h3 style="margin-top: 10px;">Land 5 paying customers plus Armilla partnership.</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px; line-height: 1.5;">$25K–$100K ACV mid-market through the LangChain ecosystem. First insurance-workflow JSON Schema. Insurance carrier as distribution moat.</p>
  </div>
  <div class="cell" style="background: #FEF2F3;">
    <div class="label red">Team</div>
    <h3 style="margin-top: 10px;">First engineer plus cybersecurity advisor.</h3>
    <p style="font-size: 13px; color: var(--muted); margin-top: 8px; line-height: 1.5;">Senior engineer to take AIR Cloud plus ASI03 and ASI10 in parallel. CISO-title advisor to pressure-test messaging against real buyer scrutiny.</p>
  </div>
</div>

<div class="hero-rule" style="margin-top: 40px;"></div>

<p style="font-size: 22px; font-weight: 600; margin-top: 6px;">Kevin Minn · Founder, Vindicara</p>
<p class="mono" style="font-size: 14px; color: var(--muted);">kevin.minn@vindicara.io · vindicara.io · pip install projectair · github.com/vindicara-inc/projectair</p>

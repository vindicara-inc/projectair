<script lang="ts">
  import ShareButtons from '$lib/components/ShareButtons.svelte';

  const shareUrl = 'https://vindicara.io/blog/forensic-layer-market-map';
  const shareTitle = "What happens after an AI agent does something it shouldn't?";
  const shareDesc = "A map of AI agent security tooling, and the layer most teams don't realize they're missing.";
</script>

<svelte:head>
  <title>What happens after an AI agent does something it shouldn't? | Vindicara Blog</title>
  <meta name="description" content="A map of AI agent security tooling, and the layer most teams don't realize they're missing. Pre-incident, during-incident, post-incident: who builds what, and where the gaps are." />
  <link rel="canonical" href="https://vindicara.io/blog/forensic-layer-market-map" />
  <meta property="og:type" content="article" />
  <meta property="og:url" content="https://vindicara.io/blog/forensic-layer-market-map" />
  <meta property="og:title" content="What happens after an AI agent does something it shouldn't?" />
  <meta property="og:description" content="A map of AI agent security tooling, and the layer most teams don't realize they're missing." />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="What happens after an AI agent does something it shouldn't?" />
  <meta name="twitter:description" content="A map of AI agent security tooling, and the layer most teams don't realize they're missing." />
  {@html `<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@type": "Article",
    "headline": "What happens after an AI agent does something it shouldn't?",
    "description": "A map of AI agent security tooling, and the layer most teams don't realize they're missing.",
    "datePublished": "2026-05-02",
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
    "mainEntityOfPage": "https://vindicara.io/blog/forensic-layer-market-map"
  })}</script>`}
</svelte:head>

<article class="max-w-3xl mx-auto px-6 py-16">
  <header class="mb-12">
    <div class="flex items-center gap-3 mb-6">
      <span class="text-[10px] font-bold uppercase tracking-wider bg-brand-red/10 text-brand-red border border-brand-red/20 rounded-full px-2.5 py-0.5">Perspective</span>
      <span class="text-[10px] text-zinc-600">10 min read</span>
    </div>
    <h1 class="text-4xl sm:text-5xl font-bold tracking-tight leading-tight">What happens after an AI agent does something it shouldn't?</h1>
    <p class="text-lg text-zinc-400 mt-4">A map of AI agent security tooling, and the layer most teams don't realize they're missing.</p>
    <div class="flex items-center gap-3 mt-6 text-sm text-zinc-500">
      <span>Kevin Minn, Founder, Vindicara</span>
      <span class="text-zinc-700">|</span>
      <span>May 2, 2026</span>
    </div>
  </header>

  <p class="text-zinc-300 leading-relaxed mt-4">
    It is 2:14 AM. A multi-agent customer support system has been running for six months, handling 40,000 conversations a day. Tonight one of the agents called a refund tool 31 times in 90 seconds, all to the same customer account, none of which a human approved. The customer notices in the morning and calls in. The SOC opens the trace.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    What the SOC has is a JSON file in whatever shape LangSmith, or Arize, or Datadog, or your own logger, writes. The trace is mutable. It is in your application's own format. It is unsigned. It contains the prompt, the model output, the tool call arguments, the tool return value. It does not contain a cryptographically verifiable chain that says "this exact decision was made by this exact agent at this exact time, before anyone could touch it."
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    So what do you tell the customer? What do you tell the bank? What do you tell the regulator who shows up six months later because three of those refunds got flagged as money laundering?
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    The AI agent security market has spent two years building tools that prevent bad things from happening. A smaller wedge of the market has built tools that observe bad things happening. The third part of the lifecycle, what happens after, is where the tooling thins out. This post is a map of who builds what, where the gaps are, and what we built to fill one of them.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4">Three layers</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    Classic enterprise security has a three-layer shape that has been stable since the 1990s.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    A WAF blocks malicious requests before they reach the app. A SIEM aggregates logs and alerts on suspicious patterns. Forensic imaging captures disk and memory state when an incident is being investigated, in a chain-of-custody form that a regulator, court, or insurer will accept.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    These three layers do different jobs. They compose: a mature security stack runs all three. Removing any one of them breaks the others. Without prevention you drown in incidents. Without observability you cannot tell prevention is working. Without forensics you cannot prove what happened, contest a finding, file an insurance claim, or comply with post-incident regulatory obligations.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    AI agent security is going through the same evolution. The pre-incident and during-incident layers have multiple credible vendors. The post-incident layer, for agent semantics specifically, is sparse.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    Three layers, mapped to AI agents:
  </p>

  <ol class="list-decimal pl-6 mt-4 space-y-2 text-zinc-300 leading-relaxed">
    <li><strong class="text-white">Pre-incident.</strong> Prevention. Block prompts, gate tool calls, scan inputs, enforce output schemas.</li>
    <li><strong class="text-white">During-incident.</strong> Observability. Traces, evals, dashboards, latency, prompt versioning, cost.</li>
    <li><strong class="text-white">Post-incident.</strong> Forensics. Reconstruct what happened. Sign it. Verify it against an authorization scope. Hand it to legal, regulators, or insurers in a form that holds up.</li>
  </ol>

  <p class="text-zinc-300 leading-relaxed mt-4">
    The rest of this post walks through each layer, names the vendors that operate in it, says honestly what the layer does well and what it cannot do, and ends at the third layer, which is where Project AIR ships.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4">Pre-incident: runtime defense</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    The first layer is prevention. Tools here intercept prompts, outputs, or tool calls in real time and decide whether to allow them through.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    The names: <strong class="text-white">Lakera Guard</strong> sits in front of LLM endpoints and classifies prompt-injection attempts. <strong class="text-white">Protect AI Guardian</strong> does runtime model scanning and policy enforcement. <strong class="text-white">HiddenLayer</strong> focuses on ML supply-chain risk and runtime detection. <strong class="text-white">NeMo Guardrails</strong> (NVIDIA) is a declarative input/output gating framework you wire into LangChain or LlamaIndex agents. <strong class="text-white">Guardrails AI</strong> enforces structured output schemas and policy violations on LLM responses. <strong class="text-white">CalypsoAI</strong> and <strong class="text-white">Robust Intelligence</strong> sit adjacent, broadening into governance and red-teaming respectively.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    What this layer does well: it stops the obvious bad things before they reach a tool call. Prompt injection, PII leakage, jailbreak attempts, schema violations, the easy 80%. Anyone deploying agents to production should be running something at this layer. The cost of not running prevention is paid in incidents that should never have happened.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    What this layer cannot do: tell you what happened after a block decision was logged. The block fires, the request is denied, the log entry is a row in a stream nobody designed for evidentiary use. The log is mutable, in the application's own format, and signed by no one. When a regulator or insurer asks "show me what your agent did at 2:14 AM," the prevention log answers part of the question, "we blocked these requests," but does not produce a record that can be independently verified against tampering.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    This is not a criticism. WAFs do not solve every security problem either. The point is that prevention is the first layer of a stack, not the whole stack. When prevention fails, and prevention fails, you need the next layers to be there.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4">During-incident: observability</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    The second layer is observability. Traces, evals, dashboards, latency, prompt versioning.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    The names: <strong class="text-white">LangSmith</strong> (LangChain's hosted observability), <strong class="text-white">Arize Phoenix</strong> (open source agent traces with LLM-eval primitives), <strong class="text-white">Langfuse</strong> (open source LLM observability and prompt management), <strong class="text-white">Helicone</strong> (LLM proxy with built-in tracing), <strong class="text-white">Weights & Biases Weave</strong> (the W&B extension into LLM observability), <strong class="text-white">Datadog LLM Observability</strong> (the obvious enterprise default for shops already on Datadog), <strong class="text-white">New Relic AI Monitoring</strong> (same play for the New Relic shops), <strong class="text-white">Honeycomb</strong> for teams using it for general distributed tracing.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    What this layer does well: ops visibility on a complex stack. You can see what your agent did, how long each step took, which prompts were used, what the model returned, what the cost was, and which evals fired. This is what your platform team needs to keep the system running. The vendors here are good at what they do, the open source options are mature, and the hosted offerings have reasonable pricing for the value.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    What this layer cannot do: produce evidence with integrity guarantees. A trace is mutable. It can be edited, truncated, replayed in a different order, or dropped entirely. Nothing in the schema enforces "this is what actually happened, signed by the agent's runtime, before anyone could tamper with it." The trace tells operations "the system is healthy, here is what it is doing." It does not tell legal "here is signed, tamper-evident evidence the agent did X at time T." Those are different questions and they require different artifacts.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    A trace is the output of an observability layer. A signed forensic record is the output of a forensics layer. The fact that both contain similar fields, prompt, output, tool calls, latency, does not make them interchangeable for the use case post-incident workflows actually need.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4">Post-incident: forensics</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    The third layer is where it gets thinner.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    You can pipe LLM traces into general SIEM tooling. <strong class="text-white">Splunk</strong>, <strong class="text-white">Datadog Cloud SIEM</strong>, <strong class="text-white">Elastic Security</strong>, <strong class="text-white">Sumo Logic</strong>, all of them ingest application logs and apply detection rules. They are mature, they are battle-tested, they have integrations with everything. What they do not do is model agent semantics at the schema level. They treat an agent trace as one more application log stream. The concepts that matter for agent forensics, capsules, tool authorization scope, signed envelope chains, multi-agent coordination, are not first-class in any general SIEM today. You can build them on top, the same way you can build anything on top of Splunk, but you are doing schema work the SIEM does not help with.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    Below the SIEM layer is <strong class="text-white">AWS CloudTrail</strong>, <strong class="text-white">GuardDuty</strong>, and equivalents from GCP and Azure. These are infrastructure-level. They tell you a Lambda invoked another Lambda. They are agent-blind by design.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    In the agent-aware corner, there are two pieces worth naming.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    First, <strong class="text-white">AgDR</strong> (the Agent Data Record format), originated by accountability.ai and the work of Mahmoud Mohamed Anwar (me2resh). AgDR is an open schema specification for signed agent records. It defines a record envelope, a payload structure, a signing primitive, and a verification model designed specifically for agent forensics. It is the closest thing the field has to a canonical schema for this layer. We adopted it.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    Second, <strong class="text-white">Project AIR</strong>, the open source SDK and CLI we ship as <code class="font-mono text-brand-red">projectair</code> on PyPI under MIT. AIR is the reference implementation that produces AgDR-format Signed Intent Capsules from running agents. The capsule is signed with Ed25519 over a BLAKE3-hashed payload, chained to the previous capsule in the session, verifiable with a published key, and emitted in real time as the agent runs. AIR ships 14 detectors out of the box: 10 covering the OWASP Top 10 for Agentic Applications (ASI01 through ASI10), 3 covering the OWASP Top 10 for LLM Applications categories most relevant to agent runtimes (LLM01 prompt injection, LLM06 sensitive information disclosure, LLM04 model denial of service), and 1 AIR-native detector for forensic chain integrity. ASI10 is implemented as Zero-Trust behavioral-scope enforcement against an operator-declared scope, which is what the OWASP spec mitigation describes. It is not anomaly detection. The learned-baseline anomaly variant is on the roadmap.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    AIR also ships <code class="font-mono text-brand-red">air report article72</code>, an EU AI Act Article 72 post-market monitoring evidence generator. We believe we are the only OSS project shipping that today.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    That is the layer. SIEMs that do not model agent semantics. Infrastructure logs that are agent-blind. AgDR as the open schema. AIR as the OSS reference SDK that produces it.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4">Why this matters</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    Three forcing functions are converging on the third layer in 2026.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    <strong class="text-white">Compliance.</strong> The EU AI Act came into force in stages through 2025 and 2026. Article 72 specifically obligates providers of high-risk AI systems to maintain a post-market monitoring system that documents incidents, behavioral changes, and corrective actions. NIST AI RMF organizes its MEASURE and MANAGE functions around evidence that an AI system's behavior is being monitored, documented, and acted on. SOC 2 AI controls, in the form they are starting to take in 2026 audits, ask for the same thing in different language: "show me the records." The records have to come from somewhere.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    <strong class="text-white">Insurance.</strong> Cyber insurance carriers underwriting AI workloads are starting to ask reconstructibility questions during renewal. "If your agent caused damage at 2:14 AM, can you produce a record that holds up to subrogation?" The answer "we have a LangSmith trace" is being followed up by "is the trace signed?" If the answer is no, the carrier either prices the risk higher or excludes the workload from the policy.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    <strong class="text-white">Litigation.</strong> When an agent causes damage to a customer or counterparty, the question of who decided what, when, with what authorization, becomes a legal question. Signed records are the difference between "we have logs that suggest the agent did X" and "here is tamper-evident evidence, verifiable by anyone holding our public key, that the agent did X at time T under authorization scope Y." One of those is a story. The other is a fact pattern in a legal sense.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    These three are not theoretical. They are showing up in renewal questionnaires, audit findings, and regulator letters today. The teams building production agents in 2026 will have answers ready or be caught flat-footed when the first incident lands.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4">How the layers compose</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    The three layers are not competing. They compose.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    A mature stack runs all three:
  </p>

  <ol class="list-decimal pl-6 mt-4 space-y-2 text-zinc-300 leading-relaxed">
    <li>Prevention sits in front, blocking the easy 80% before they become incidents.</li>
    <li>Observability runs continuously, telling ops the system is healthy and triaging the live anomalies prevention let through.</li>
    <li>Forensics records every agent action in a signed, tamper-evident form, so when prevention misses something and observability flags it late, there is a record that holds up to scrutiny.</li>
  </ol>

  <p class="text-zinc-300 leading-relaxed mt-4">
    In conversations with teams running agents in production, most have layers 1 and 2 in some form. Layer 3, for agent semantics specifically, is the one most teams have not built. Some have nothing. Some have application logs they assume will hold up if needed. A small number have built bespoke signing on top of their observability, which is good but expensive to maintain.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    Project AIR is our contribution to making the third layer cheap to adopt. MIT license. Pip install. Sixty-second demo. Drop the callback into your LangChain agent or wrap your OpenAI client and you are emitting signed records.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4">What we shipped</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    <code class="font-mono text-brand-red">projectair</code> 0.3.2 is live on PyPI under MIT license. Ten detectors covering the full OWASP Top 10 for Agentic Applications shipped in 0.3.0 on April 22, alongside the Article 72 evidence generator. 0.3.1 added a LlamaIndex integration. 0.3.2 added the Google Gemini SDK and Google ADK integrations.
  </p>

  <pre class="bg-zinc-900/50 border border-white/5 rounded-lg p-4 mt-6 overflow-x-auto"><code class="font-mono text-sm text-zinc-300">pip install projectair
air demo</code></pre>

  <p class="text-zinc-300 leading-relaxed mt-4">
    Sixty seconds, end to end. You see signed Intent Capsules emitted as the demo agent runs, the chain verified, and a forensic report generated. From there, drop the callback into your real agent: one line for LangChain, a wrap for OpenAI, Anthropic, LlamaIndex, Gemini, or ADK, and you are recording.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    The schema is AgDR-compatible, with credit to accountability.ai and Mahmoud Mohamed Anwar (me2resh). The reference implementation is open source under MIT, open contribution, open standard.
  </p>

  <h2 class="text-2xl font-bold mt-12 mb-4">Try it</h2>

  <pre class="bg-zinc-900/50 border border-white/5 rounded-lg p-4 mt-6 overflow-x-auto"><code class="font-mono text-sm text-zinc-300">pip install projectair
air demo</code></pre>

  <p class="text-zinc-300 leading-relaxed mt-4">
    Source: <a href="https://github.com/vindicara-inc/projectair" class="text-brand-red hover:underline">github.com/vindicara-inc/projectair</a>. Issues, PRs, and security disclosures welcome. If you are evaluating for a regulated workload, the Article 72 generator is in the OSS package today.
  </p>

  <ShareButtons url={shareUrl} title={shareTitle} description={shareDesc} />
</article>

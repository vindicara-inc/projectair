<script lang="ts">
  import ShareButtons from '$lib/components/ShareButtons.svelte';

  const shareUrl = 'https://vindicara.io/blog/nemoclaw-forensic-evidence';
  const shareTitle = 'Forensic Evidence for NemoClaw: HIPAA Audit Trails for Sandboxed Clinical AI';
  const shareDesc = 'NVIDIA NemoClaw controls what clinical AI agents can do. Project AIR proves what they did. Together: prevention + evidence for HIPAA-regulated healthcare.';
</script>

<svelte:head>
  <title>Forensic Evidence for NemoClaw: HIPAA Audit Trails for Sandboxed Clinical AI | Vindicara Blog</title>
  <meta name="description" content="NVIDIA NemoClaw controls what clinical AI agents can do. Project AIR proves what they did. Together they deliver both prevention and cryptographic evidence for HIPAA-regulated healthcare AI deployments." />
  <link rel="canonical" href="https://vindicara.io/blog/nemoclaw-forensic-evidence" />
  <meta property="og:type" content="article" />
  <meta property="og:url" content="https://vindicara.io/blog/nemoclaw-forensic-evidence" />
  <meta property="og:title" content="Forensic Evidence for NemoClaw: HIPAA Audit Trails for Sandboxed Clinical AI" />
  <meta property="og:description" content="NVIDIA NemoClaw controls what clinical AI agents can do. Project AIR proves what they did. Prevention + evidence for HIPAA-regulated healthcare." />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="Forensic Evidence for NemoClaw: HIPAA Audit Trails for Sandboxed Clinical AI" />
  <meta name="twitter:description" content="NemoClaw sandboxes. AIR signs. Together: HIPAA-grade clinical AI you can prove to an auditor." />
  <meta name="keywords" content="NVIDIA NemoClaw, NemoClaw HIPAA, OpenClaw AIR integration, clinical AI audit trail, NemoClaw forensic evidence, healthcare AI sandbox, OpenShell HIPAA, NVIDIA healthcare AI, NemoClaw security, AI agent sandbox audit, NemoClaw OpenShell Project AIR, clinical decision support compliance" />
  {@html `<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@type": "Article",
    "headline": "Forensic Evidence for NemoClaw: HIPAA Audit Trails for Sandboxed Clinical AI",
    "description": "NVIDIA NemoClaw controls what clinical AI agents can do. Project AIR proves what they did. Together they deliver prevention and cryptographic evidence for HIPAA-regulated healthcare.",
    "datePublished": "2026-05-12",
    "dateModified": "2026-05-12",
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
    "mainEntityOfPage": "https://vindicara.io/blog/nemoclaw-forensic-evidence",
    "keywords": ["NVIDIA NemoClaw", "HIPAA", "clinical AI", "forensic evidence", "OpenShell", "OpenClaw", "Project AIR", "healthcare AI audit"]
  })}</script>`}
</svelte:head>

<article class="max-w-3xl mx-auto px-6 py-16">
  <header class="mb-12">
    <div class="flex items-center gap-3 mb-6">
      <span class="text-[10px] font-bold uppercase tracking-wider bg-green-500/10 text-green-500 border border-green-500/20 rounded-full px-2.5 py-0.5">NVIDIA</span>
      <span class="text-[10px] font-bold uppercase tracking-wider bg-brand-red/10 text-brand-red border border-brand-red/20 rounded-full px-2.5 py-0.5">Healthcare</span>
      <span class="text-[10px] text-zinc-600">10 min read</span>
    </div>
    <h1 class="text-4xl sm:text-5xl font-bold tracking-tight leading-tight">Forensic Evidence for NemoClaw: HIPAA Audit Trails for Sandboxed Clinical AI</h1>
    <p class="text-lg text-zinc-400 mt-4">NemoClaw controls what your clinical AI agent can do. Project AIR proves what it did. One vendor for the cage. One for the camera. Together: the first HIPAA-grade deployment model for autonomous healthcare agents.</p>
    <div class="flex items-center gap-3 mt-6 text-sm text-zinc-500">
      <span>Kevin Minn</span>
      <span class="text-zinc-700">|</span>
      <span>May 12, 2026</span>
    </div>
  </header>

  <!-- SECTION: The two-layer problem -->
  <h2 class="text-2xl font-bold mt-12 mb-4">Healthcare has a two-layer problem</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    When a health system deploys an AI agent that reads patient records, generates treatment recommendations, and writes to the chart, two questions arise that no single tool answers:
  </p>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
    <div class="glass-panel rounded-xl p-5">
      <h3 class="text-sm font-bold text-green-400 uppercase tracking-wider mb-2">Prevention</h3>
      <p class="text-sm text-zinc-400">"Can we stop the agent from accessing psychiatric records, exfiltrating data, or calling tools it should not touch?"</p>
    </div>
    <div class="glass-panel rounded-xl p-5">
      <h3 class="text-sm font-bold text-brand-red uppercase tracking-wider mb-2">Evidence</h3>
      <p class="text-sm text-zinc-400">"Can we prove to an auditor, a regulator, or a court exactly what the agent did, in a record that nobody can alter after the fact?"</p>
    </div>
  </div>

  <p class="text-zinc-300 leading-relaxed mt-6">
    Guardrails solve the first. They do not solve the second. Application logs attempt the second, but they are mutable, unsigned, and lack cryptographic identity. A tampered log is indistinguishable from an original. That is not evidence. That is a text file.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    NVIDIA's NemoClaw and Vindicara's Project AIR solve each layer independently, and snap together cleanly because their boundaries do not overlap.
  </p>

  <!-- SECTION: What NemoClaw brings -->
  <h2 class="text-2xl font-bold mt-12 mb-4">What NemoClaw brings: the hardened sandbox</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    <a href="https://www.nvidia.com/en-us/ai/nemoclaw/" class="text-green-400 hover:text-green-400/80 underline" target="_blank" rel="noopener noreferrer">NemoClaw</a> combines NVIDIA's OpenClaw agent platform with the OpenShell runtime to create a sandboxed execution environment for autonomous AI agents. The agent runs inside a hardened container with declarative policies governing:
  </p>

  <ul class="list-disc list-inside text-zinc-300 leading-relaxed mt-4 space-y-2 ml-4">
    <li><strong>Network access:</strong> which endpoints the agent can reach, enforced by eBPF at the kernel level. No policy, no connection.</li>
    <li><strong>Filesystem access:</strong> which paths are readable, writable, or invisible. Locked at sandbox creation via Linux Landlock.</li>
    <li><strong>Inference routing:</strong> which models the agent can call, through NemoClaw's L7 proxy. No model substitution attacks.</li>
    <li><strong>Process isolation:</strong> seccomp + cgroups contain the agent's system calls and resource consumption.</li>
  </ul>

  <p class="text-zinc-300 leading-relaxed mt-4">
    For healthcare, this means a clinical decision support agent can be structurally prevented from accessing psychiatric records (42 CFR Part 2 protected), calling external APIs not in the approved list, or consuming more compute than budgeted. The sandbox is the cage.
  </p>

  <!-- SECTION: What AIR brings -->
  <h2 class="text-2xl font-bold mt-12 mb-4">What Project AIR brings: the cryptographic camera</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    <a href="https://pypi.org/project/projectair/" class="text-brand-red hover:text-brand-red/80 underline" target="_blank" rel="noopener noreferrer">Project AIR</a> instruments the agent inside the sandbox. Every action the agent takes becomes a <strong>Signed Intent Capsule</strong>: a JSON record content-hashed with BLAKE3 and signed with Ed25519. Each capsule's signature covers both its own content and the previous capsule's hash, forming a tamper-evident chain that breaks if anyone alters a single byte.
  </p>

  <p class="text-zinc-300 leading-relaxed mt-4">
    The chain is the evidence. Not logs. Evidence. The distinction matters in healthcare:
  </p>

  <div class="glass-panel rounded-xl p-6 mt-6 space-y-3">
    <div class="flex items-start gap-3">
      <span class="text-brand-red font-mono text-xs font-bold mt-0.5">LOG</span>
      <p class="text-sm text-zinc-500">"Our Splunk dashboard shows the agent did not access the psychiatric records." An insider with logging access can delete or alter entries. Splunk cannot prove this did not happen.</p>
    </div>
    <div class="flex items-start gap-3">
      <span class="text-green-400 font-mono text-xs font-bold mt-0.5">AIR</span>
      <p class="text-sm text-zinc-300">"The signed forensic chain contains 14 capsules. Capsule 8 shows an <code class="font-mono text-brand-red">ehr_query</code> for psychiatric records that returned <code class="font-mono text-brand-red">[RESTRICTED: 42 CFR Part 2]</code>. The chain verifies end-to-end. Altering any capsule breaks the chain at that record. The chain is anchored to public Sigstore Rekor at log index 1465403522. Verify it yourself."</p>
    </div>
  </div>

  <!-- SECTION: How they connect -->
  <h2 class="text-2xl font-bold mt-12 mb-4">How they connect: four lines of Python</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    The <code class="font-mono text-brand-red">instrument_nemoclaw</code> integration hooks into the OpenClaw agent lifecycle inside NemoClaw's sandbox. Every execution, every tool call, every inference request, and every OpenShell policy decision is captured as a signed capsule.
  </p>

  <div class="bg-obsidian-lighter rounded-xl p-5 mt-6 font-mono text-sm overflow-x-auto border border-white/10">
    <pre class="text-zinc-300"><span class="text-brand-red">from</span> openclaw_sdk <span class="text-brand-red">import</span> OpenClawClient
<span class="text-brand-red">from</span> airsdk <span class="text-brand-red">import</span> AIRRecorder
<span class="text-brand-red">from</span> airsdk.integrations.nemoclaw <span class="text-brand-red">import</span> instrument_nemoclaw

recorder = AIRRecorder(<span class="text-green-400">"clinical-chain.jsonl"</span>)
client = OpenClawClient(api_key=<span class="text-green-400">"..."</span>)
instrumented = instrument_nemoclaw(client, recorder)

<span class="text-zinc-500"># Every execution now produces signed forensic evidence</span>
result = instrumented.execute(
    pipeline=<span class="text-green-400">"clinical-cds"</span>,
    input=&#123;<span class="text-green-400">"mrn"</span>: <span class="text-green-400">"20260511-0042"</span>&#125;,
)</pre>
  </div>

  <p class="text-zinc-300 leading-relaxed mt-6">
    The instrumented client captures six event types:
  </p>

  <div class="glass-panel rounded-xl p-6 mt-4">
    <table class="w-full text-sm">
      <thead>
        <tr class="text-left text-zinc-500 uppercase tracking-wider text-xs border-b border-white/10">
          <th class="pb-3">Event</th>
          <th class="pb-3">Source</th>
          <th class="pb-3">What it captures</th>
        </tr>
      </thead>
      <tbody class="text-zinc-300">
        <tr class="border-b border-white/5">
          <td class="py-2.5 font-mono text-xs text-brand-red">execution_start</td>
          <td class="py-2.5">OpenClaw</td>
          <td class="py-2.5">Pipeline name, input data, agent identity</td>
        </tr>
        <tr class="border-b border-white/5">
          <td class="py-2.5 font-mono text-xs text-brand-red">execution_end</td>
          <td class="py-2.5">OpenClaw</td>
          <td class="py-2.5">Pipeline output, final result</td>
        </tr>
        <tr class="border-b border-white/5">
          <td class="py-2.5 font-mono text-xs text-brand-red">tool_start/end</td>
          <td class="py-2.5">OpenClaw</td>
          <td class="py-2.5">Tool name, arguments, output (e.g. EHR queries)</td>
        </tr>
        <tr class="border-b border-white/5">
          <td class="py-2.5 font-mono text-xs text-brand-red">inference_start/end</td>
          <td class="py-2.5">NIM / L7 proxy</td>
          <td class="py-2.5">Model name, prompt, response</td>
        </tr>
        <tr>
          <td class="py-2.5 font-mono text-xs text-green-400">sandbox_policy</td>
          <td class="py-2.5">OpenShell</td>
          <td class="py-2.5">Action, resource, decision (allow/deny), reason</td>
        </tr>
      </tbody>
    </table>
  </div>

  <p class="text-zinc-300 leading-relaxed mt-6">
    The last row is the bridge. When OpenShell denies a network egress or blocks a filesystem read, that enforcement decision is captured in the same signed chain as the agent's clinical actions. An auditor sees both what the agent tried and what the sandbox stopped, in one tamper-evident record.
  </p>

  <!-- SECTION: HIPAA mapping -->
  <h2 class="text-2xl font-bold mt-12 mb-4">HIPAA mapping: which layer covers which control</h2>

  <div class="glass-panel rounded-xl p-6 mt-4">
    <table class="w-full text-sm">
      <thead>
        <tr class="text-left text-zinc-500 uppercase tracking-wider text-xs border-b border-white/10">
          <th class="pb-3">HIPAA Control</th>
          <th class="pb-3">NemoClaw</th>
          <th class="pb-3">Project AIR</th>
        </tr>
      </thead>
      <tbody class="text-zinc-300">
        <tr class="border-b border-white/5">
          <td class="py-2.5 font-mono text-xs">164.312(a) Access Control</td>
          <td class="py-2.5"><span class="text-green-400">&#10003;</span> OpenShell policies</td>
          <td class="py-2.5"><span class="text-zinc-600">&#8212;</span></td>
        </tr>
        <tr class="border-b border-white/5">
          <td class="py-2.5 font-mono text-xs">164.312(b) Audit Controls</td>
          <td class="py-2.5"><span class="text-zinc-600">&#8212;</span></td>
          <td class="py-2.5"><span class="text-brand-red">&#10003;</span> Signed capsules</td>
        </tr>
        <tr class="border-b border-white/5">
          <td class="py-2.5 font-mono text-xs">164.312(c) Integrity</td>
          <td class="py-2.5"><span class="text-zinc-600">&#8212;</span></td>
          <td class="py-2.5"><span class="text-brand-red">&#10003;</span> BLAKE3 + Ed25519 chain</td>
        </tr>
        <tr class="border-b border-white/5">
          <td class="py-2.5 font-mono text-xs">164.312(d) Authentication</td>
          <td class="py-2.5"><span class="text-green-400">&#10003;</span> Agent identity</td>
          <td class="py-2.5"><span class="text-brand-red">&#10003;</span> Auth0 JWT in chain</td>
        </tr>
        <tr class="border-b border-white/5">
          <td class="py-2.5 font-mono text-xs">164.312(e) Transmission</td>
          <td class="py-2.5"><span class="text-green-400">&#10003;</span> Network policies</td>
          <td class="py-2.5"><span class="text-brand-red">&#10003;</span> Rekor public anchor</td>
        </tr>
        <tr>
          <td class="py-2.5 font-mono text-xs">164.502(b) Minimum Necessary</td>
          <td class="py-2.5"><span class="text-green-400">&#10003;</span> Filesystem scope</td>
          <td class="py-2.5"><span class="text-brand-red">&#10003;</span> Zero-Trust enforcement</td>
        </tr>
      </tbody>
    </table>
  </div>

  <p class="text-zinc-300 leading-relaxed mt-6">
    No overlap. No redundancy. NemoClaw fills the access control and transmission security columns. AIR fills the audit, integrity, and authentication columns. The minimum necessary row is the only shared concern, and even there the mechanisms are complementary: NemoClaw enforces at the infrastructure level (filesystem paths), AIR enforces at the application level (declared behavioral scope per agent).
  </p>

  <!-- SECTION: What the auditor sees -->
  <h2 class="text-2xl font-bold mt-12 mb-4">What the auditor sees</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    A HIPAA auditor reviewing a NemoClaw + AIR deployment gets three artifacts:
  </p>

  <ol class="list-decimal list-inside text-zinc-300 leading-relaxed mt-4 space-y-4 ml-4">
    <li>
      <strong>The OpenShell policy YAML:</strong> a declarative specification of what the agent is allowed to access. Readable by a non-engineer. "This agent can reach the EHR API at <code class="font-mono text-zinc-400">ehr.internal:443</code> and the NIM endpoint at <code class="font-mono text-zinc-400">nim.internal:8000</code>. Nothing else."
    </li>
    <li>
      <strong>The signed forensic chain:</strong> every action the agent took, in order, signed and tamper-evident. The auditor can verify independently using <code class="font-mono text-brand-red">air verify-public</code> with zero Vindicara API calls. The math is the trust anchor, not the vendor.
    </li>
    <li>
      <strong>The Sigstore Rekor anchor:</strong> a public, immutable timestamp proving the chain existed at a specific point in time. The auditor does not need to trust Vindicara, NVIDIA, or the hospital. The entry is at <a href="https://search.sigstore.dev" class="text-brand-red hover:text-brand-red/80 underline" target="_blank" rel="noopener noreferrer">search.sigstore.dev</a>, run by the Linux Foundation.
    </li>
  </ol>

  <p class="text-zinc-300 leading-relaxed mt-4">
    Three independent verification paths. No single point of trust. That is what HIPAA 164.312(c) integrity controls look like when you take them seriously.
  </p>

  <!-- SECTION: A real clinical scenario -->
  <h2 class="text-2xl font-bold mt-12 mb-4">A real scenario: clinical decision support on NemoClaw</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    A health system deploys a clinical decision support agent on NemoClaw. The agent reads patient labs, imaging reports, and medication history, then generates a treatment recommendation for a clinician to review.
  </p>

  <div class="bg-obsidian-lighter rounded-xl p-5 mt-6 font-mono text-sm overflow-x-auto border border-white/10">
    <pre class="text-zinc-300"><span class="text-brand-red">$</span> air demo --healthcare

  <span class="text-white font-bold">Project AIR: Healthcare Demo (HIPAA-Aligned)</span>

  <span class="text-zinc-500">STEP 2/8</span>  <span class="text-white">AIR captures every EHR access</span>
    PHI accesses captured: <span class="text-brand-red">14</span>

      [ 2] tool_start     <span class="text-zinc-400">ehr_query (lab_results)</span>
      [ 3] tool_end       <span class="text-zinc-400">HbA1c: 8.4%, Glucose: 186</span>
      [ 4] tool_start     <span class="text-zinc-400">ehr_query (imaging)</span>
      [ 5] tool_end       <span class="text-zinc-400">12mm RUL pulmonary nodule</span>
      [ 8] tool_start     <span class="text-zinc-400">ehr_query (psychiatric_notes)</span>
      [ 9] tool_end       <span class="text-brand-red">[RESTRICTED: 42 CFR Part 2]</span>
      [11] llm_end        <span class="text-zinc-400">Recommend GLP-1 agonist, PET-CT</span>

  <span class="text-zinc-500">STEP 3/8</span>  <span class="text-green-400">&#10003; Chain integrity verified</span>
  <span class="text-zinc-500">STEP 7/8</span>  <span class="text-red-400">&#10007; Tamper detected at index 3</span>

  <span class="text-green-400 font-bold">HIPAA 164.312(b): SATISFIED</span>
  <span class="text-green-400 font-bold">HIPAA 164.312(c): SATISFIED</span></pre>
  </div>

  <p class="text-zinc-300 leading-relaxed mt-6">
    Record 8 shows the agent attempted to access psychiatric records. OpenShell's filesystem policy blocked the underlying data access. AIR captured the attempt in the signed chain. The auditor sees both the prevention (sandbox policy denied) and the evidence (signed capsule recording the denied attempt). Neither layer alone gives this picture.
  </p>

  <!-- SECTION: Getting started -->
  <h2 class="text-2xl font-bold mt-12 mb-4">Getting started</h2>

  <p class="text-zinc-300 leading-relaxed mt-4">
    If you are running clinical AI on NemoClaw, or evaluating NemoClaw for a healthcare deployment:
  </p>

  <ol class="list-decimal list-inside text-zinc-300 leading-relaxed mt-4 space-y-3 ml-4">
    <li>
      <strong>Install Project AIR:</strong> <code class="font-mono text-brand-red">pip install projectair</code>. MIT-licensed, runs locally, no cloud dependency required.
    </li>
    <li>
      <strong>Instrument your NemoClaw agent:</strong> four lines. <code class="font-mono text-brand-red">instrument_nemoclaw(client, recorder)</code> handles the rest.
    </li>
    <li>
      <strong>Run the healthcare demo:</strong> <code class="font-mono text-brand-red">air demo --healthcare</code>. Show it to your compliance officer. The output maps directly to the HIPAA CFR sections they review.
    </li>
    <li>
      <strong>Connect to AIR Cloud:</strong> stream capsules to <a href="https://cloud.vindicara.io" class="text-brand-red hover:text-brand-red/80 underline">cloud.vindicara.io</a> for a live forensic dashboard your security team monitors without touching the agent or the sandbox.
    </li>
  </ol>

  <p class="text-zinc-300 leading-relaxed mt-6">
    NemoClaw is the cage. AIR is the camera. The health system gets both, and the auditor gets evidence that neither vendor can fabricate.
  </p>

  <div class="glass-panel rounded-xl p-6 mt-8 border-brand-red/20">
    <p class="text-sm text-zinc-400">
      <strong class="text-white">Project AIR</strong> is open source at
      <a href="https://github.com/vindicara-inc/projectair" class="text-brand-red hover:text-brand-red/80 underline" target="_blank" rel="noopener noreferrer">github.com/vindicara-inc/projectair</a>.
      The NemoClaw integration ships in <code class="font-mono text-brand-red">airsdk.integrations.nemoclaw</code>.
      Questions? <a href="mailto:support@vindicara.io" class="text-brand-red hover:text-brand-red/80 underline">support@vindicara.io</a>.
    </p>
    <p class="text-sm text-zinc-500 mt-3">
      Vindicara is a member of the
      <a href="https://www.nvidia.com/en-us/startups/" class="text-green-400 hover:text-green-400/80 underline" target="_blank" rel="noopener noreferrer">NVIDIA Inception program</a>
      and the NVIDIA Healthcare Developer Program.
    </p>
  </div>

  <div class="mt-8">
    <ShareButtons url={shareUrl} title={shareTitle} description={shareDesc} />
  </div>
</article>

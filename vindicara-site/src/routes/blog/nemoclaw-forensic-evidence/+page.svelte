<script>
  import AppShell from '$components/AppShell.svelte';
</script>

<svelte:head>
  <title>Forensic Evidence for NemoClaw: HIPAA Audit Trails for Sandboxed Clinical AI | Vindicara Blog</title>
  <meta name="description" content="NVIDIA NemoClaw controls what clinical AI agents can do. Project AIR proves what they did. Together they deliver both prevention and cryptographic evidence for HIPAA-regulated healthcare AI deployments." />
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

<AppShell active="blog" title="blog" scroll={true}>
  <article class="prose">
    <div class="eyebrow">NVIDIA · Healthcare</div>
    <h1>Forensic Evidence for NemoClaw: HIPAA Audit Trails for Sandboxed Clinical AI</h1>
    <p class="muted">May 12, 2026 · Kevin Minn</p>
    <p>NemoClaw controls what your clinical AI agent can do. Project <span class="air">AIR</span> proves what it did. One vendor for the cage. One for the camera. Together: the first HIPAA-grade deployment model for autonomous healthcare agents.</p>

    <h2>Healthcare has a two-layer problem</h2>
    <p>When a health system deploys an AI agent that reads patient records, generates treatment recommendations, and writes to the chart, two questions arise that no single tool answers:</p>
    <div class="card callout">
      <h3>Prevention</h3>
      <p>"Can we stop the agent from accessing psychiatric records, exfiltrating data, or calling tools it should not touch?"</p>
      <h3 class="redhead">Evidence</h3>
      <p>"Can we prove to an auditor, a regulator, or a court exactly what the agent did, in a record that nobody can alter after the fact?"</p>
    </div>
    <p>Guardrails solve the first. They do not solve the second. Application logs attempt the second, but they are mutable, unsigned, and lack cryptographic identity. A tampered log is indistinguishable from an original. That is not evidence. That is a text file.</p>
    <p>NVIDIA's NemoClaw and Vindicara's Project <span class="air">AIR</span> solve each layer independently, and snap together cleanly because their boundaries do not overlap.</p>

    <h2>What NemoClaw brings: the hardened sandbox</h2>
    <p><a href="https://www.nvidia.com/en-us/ai/nemoclaw/" target="_blank" rel="noopener noreferrer">NemoClaw</a> combines NVIDIA's OpenClaw agent platform with the OpenShell runtime to create a sandboxed execution environment for autonomous AI agents. The agent runs inside a hardened container with declarative policies governing:</p>
    <ul>
      <li><strong>Network access:</strong> which endpoints the agent can reach, enforced by eBPF at the kernel level. No policy, no connection.</li>
      <li><strong>Filesystem access:</strong> which paths are readable, writable, or invisible. Locked at sandbox creation via Linux Landlock.</li>
      <li><strong>Inference routing:</strong> which models the agent can call, through NemoClaw's L7 proxy. No model substitution attacks.</li>
      <li><strong>Process isolation:</strong> seccomp + cgroups contain the agent's system calls and resource consumption.</li>
    </ul>
    <p>For healthcare, this means a clinical decision support agent can be structurally prevented from accessing psychiatric records (42 CFR Part 2 protected), calling external APIs not in the approved list, or consuming more compute than budgeted. The sandbox is the cage.</p>

    <h2>What Project <span class="air">AIR</span> brings: the cryptographic camera</h2>
    <p><a href="https://pypi.org/project/projectair/" target="_blank" rel="noopener noreferrer">Project <span class="air">AIR</span></a> instruments the agent inside the sandbox. Every action the agent takes becomes a <strong>Signed Intent Capsule</strong>: a JSON record content-hashed with BLAKE3 and signed with Ed25519. Each capsule's signature covers both its own content and the previous capsule's hash, forming a tamper-evident chain that breaks if anyone alters a single byte.</p>
    <p>The chain is the evidence. Not logs. Evidence. The distinction matters in healthcare:</p>
    <div class="card callout">
      <p><span class="tag">LOG</span> "Our Splunk dashboard shows the agent did not access the psychiatric records." An insider with logging access can delete or alter entries. Splunk cannot prove this did not happen.</p>
      <p><span class="tag green">AIR</span> "The signed forensic chain contains 14 capsules. Capsule 8 shows an <code>ehr_query</code> for psychiatric records that returned <code>[RESTRICTED: 42 CFR Part 2]</code>. The chain verifies end-to-end. Altering any capsule breaks the chain at that record. The chain is anchored to public Sigstore Rekor at log index 1465403522. Verify it yourself."</p>
    </div>

    <h2>How they connect: four lines of Python</h2>
    <p>The <code>instrument_nemoclaw</code> integration hooks into the OpenClaw agent lifecycle inside NemoClaw's sandbox. Every execution, every tool call, every inference request, and every OpenShell policy decision is captured as a signed capsule.</p>
    <pre class="code">from openclaw_sdk import OpenClawClient
from airsdk import AIRRecorder
from airsdk.integrations.nemoclaw import instrument_nemoclaw

recorder = AIRRecorder("clinical-chain.jsonl")
client = OpenClawClient(api_key="...")
instrumented = instrument_nemoclaw(client, recorder)

# Every execution now produces signed forensic evidence
result = instrumented.execute(
    pipeline="clinical-cds",
    input=&#123;"mrn": "20260511-0042"&#125;,
)</pre>
    <p>The instrumented client captures six event types:</p>
    <table>
      <thead><tr><th>Event</th><th>Source</th><th>What it captures</th></tr></thead>
      <tbody>
        <tr><td class="mono red">execution_start</td><td>OpenClaw</td><td>Pipeline name, input data, agent identity</td></tr>
        <tr><td class="mono red">execution_end</td><td>OpenClaw</td><td>Pipeline output, final result</td></tr>
        <tr><td class="mono red">tool_start/end</td><td>OpenClaw</td><td>Tool name, arguments, output (e.g. EHR queries)</td></tr>
        <tr><td class="mono red">inference_start/end</td><td>NIM / L7 proxy</td><td>Model name, prompt, response</td></tr>
        <tr><td class="mono">sandbox_policy</td><td>OpenShell</td><td>Action, resource, decision (allow/deny), reason</td></tr>
      </tbody>
    </table>
    <p>The last row is the bridge. When OpenShell denies a network egress or blocks a filesystem read, that enforcement decision is captured in the same signed chain as the agent's clinical actions. An auditor sees both what the agent tried and what the sandbox stopped, in one tamper-evident record.</p>

    <h2>HIPAA mapping: which layer covers which control</h2>
    <table>
      <thead><tr><th>HIPAA Control</th><th>NemoClaw</th><th>Project AIR</th></tr></thead>
      <tbody>
        <tr><td class="mono">164.312(a) Access Control</td><td>&#10003; OpenShell policies</td><td class="faint">·</td></tr>
        <tr><td class="mono">164.312(b) Audit Controls</td><td class="faint">·</td><td>&#10003; Signed capsules</td></tr>
        <tr><td class="mono">164.312(c) Integrity</td><td class="faint">·</td><td>&#10003; BLAKE3 + Ed25519 chain</td></tr>
        <tr><td class="mono">164.312(d) Authentication</td><td>&#10003; Agent identity</td><td>&#10003; Auth0 JWT in chain</td></tr>
        <tr><td class="mono">164.312(e) Transmission</td><td>&#10003; Network policies</td><td>&#10003; Rekor public anchor</td></tr>
        <tr><td class="mono">164.502(b) Minimum Necessary</td><td>&#10003; Filesystem scope</td><td>&#10003; Zero-Trust enforcement</td></tr>
      </tbody>
    </table>
    <p>No overlap. No redundancy. NemoClaw fills the access control and transmission security columns. <span class="air">AIR</span> fills the audit, integrity, and authentication columns. The minimum necessary row is the only shared concern, and even there the mechanisms are complementary: NemoClaw enforces at the infrastructure level (filesystem paths), <span class="air">AIR</span> enforces at the application level (declared behavioral scope per agent).</p>

    <h2>What the auditor sees</h2>
    <p>A HIPAA auditor reviewing a NemoClaw + <span class="air">AIR</span> deployment gets three artifacts:</p>
    <ol>
      <li><strong>The OpenShell policy YAML:</strong> a declarative specification of what the agent is allowed to access. Readable by a non-engineer. "This agent can reach the EHR API at <code>ehr.internal:443</code> and the NIM endpoint at <code>nim.internal:8000</code>. Nothing else."</li>
      <li><strong>The signed forensic chain:</strong> every action the agent took, in order, signed and tamper-evident. The auditor can verify independently using <code>air verify-public</code> with zero Vindicara API calls. The math is the trust anchor, not the vendor.</li>
      <li><strong>The Sigstore Rekor anchor:</strong> a public, immutable timestamp proving the chain existed at a specific point in time. The auditor does not need to trust Vindicara, NVIDIA, or the hospital. The entry is at <a href="https://search.sigstore.dev" target="_blank" rel="noopener noreferrer">search.sigstore.dev</a>, run by the Linux Foundation.</li>
    </ol>
    <p>Three independent verification paths. No single point of trust. That is what HIPAA 164.312(c) integrity controls look like when you take them seriously.</p>

    <h2>A real scenario: clinical decision support on NemoClaw</h2>
    <p>A health system deploys a clinical decision support agent on NemoClaw. The agent reads patient labs, imaging reports, and medication history, then generates a treatment recommendation for a clinician to review.</p>
    <pre class="code">$ air demo --healthcare

  Project AIR: Healthcare Demo (HIPAA-Aligned)

  STEP 2/8  AIR captures every EHR access
    PHI accesses captured: 14

      [ 2] tool_start     ehr_query (lab_results)
      [ 3] tool_end       HbA1c: 8.4%, Glucose: 186
      [ 4] tool_start     ehr_query (imaging)
      [ 5] tool_end       12mm RUL pulmonary nodule
      [ 8] tool_start     ehr_query (psychiatric_notes)
      [ 9] tool_end       [RESTRICTED: 42 CFR Part 2]
      [11] llm_end        Recommend GLP-1 agonist, PET-CT

  STEP 3/8  &#10003; Chain integrity verified
  STEP 7/8  &#10007; Tamper detected at index 3

  HIPAA 164.312(b): SATISFIED
  HIPAA 164.312(c): SATISFIED</pre>
    <p>Record 8 shows the agent attempted to access psychiatric records. OpenShell's filesystem policy blocked the underlying data access. <span class="air">AIR</span> captured the attempt in the signed chain. The auditor sees both the prevention (sandbox policy denied) and the evidence (signed capsule recording the denied attempt). Neither layer alone gives this picture.</p>

    <h2>Getting started</h2>
    <p>If you are running clinical AI on NemoClaw, or evaluating NemoClaw for a healthcare deployment:</p>
    <ol>
      <li><strong>Install Project <span class="air">AIR</span>:</strong> <code>pip install projectair</code>. MIT-licensed, runs locally, no cloud dependency required.</li>
      <li><strong>Instrument your NemoClaw agent:</strong> four lines. <code>instrument_nemoclaw(client, recorder)</code> handles the rest.</li>
      <li><strong>Run the healthcare demo:</strong> <code>air demo --healthcare</code>. Show it to your compliance officer. The output maps directly to the HIPAA CFR sections they review.</li>
      <li><strong>Connect to <span class="air">AIR</span> Cloud:</strong> stream capsules to <a href="https://cloud.vindicara.io">cloud.vindicara.io</a> for a live forensic dashboard your security team monitors without touching the agent or the sandbox.</li>
    </ol>
    <p>NemoClaw is the cage. <span class="air">AIR</span> is the camera. The health system gets both, and the auditor gets evidence that neither vendor can fabricate.</p>

    <div class="card callout">
      <p><strong>Project <span class="air">AIR</span></strong> is open source at <a href="https://github.com/vindicara-inc/projectair" target="_blank" rel="noopener noreferrer">github.com/vindicara-inc/projectair</a>. The NemoClaw integration ships in <code>airsdk.integrations.nemoclaw</code>. Questions? <a href="mailto:support@vindicara.io">support@vindicara.io</a>.</p>
      <p>Vindicara is a member of the <a href="https://www.nvidia.com/en-us/startups/" target="_blank" rel="noopener noreferrer">NVIDIA Inception program</a> and the NVIDIA Healthcare Developer Program.</p>
    </div>
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
  .redhead{color:var(--air)}
  .tag{font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.08em;color:var(--air2);margin-right:6px}
  .tag.green{color:var(--white)}
  table{width:100%;border-collapse:collapse;font-size:13px;margin:18px 0;color:var(--soft)}
  th{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.08em;text-align:left;color:var(--faint);padding:8px 10px;border-bottom:1px solid var(--line)}
  td{padding:8px 10px;border-bottom:1px solid var(--line);line-height:1.5;vertical-align:top}
  td.mono{font-family:var(--mono);font-size:11.5px}
  td.red{color:var(--air2)}
  td.faint{color:var(--faint)}
</style>

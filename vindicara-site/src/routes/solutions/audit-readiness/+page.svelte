<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import SiteHeader from '$lib/components/SiteHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';
  onMount(setupReveal);
</script>

<svelte:head>
  <title>Audit readiness · Project AIR — walk into the assessment with the agent layer covered</title>
  <meta name="description" content="Mid-prep for SOC 2, HIPAA, ISO 42001 or EU AI Act? Your tooling logs humans and infrastructure but goes dark on what the agents did. Project AIR collects that evidence continuously, so readiness is a posture, not a fire drill." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind uc">
  <div class="dotfield"></div>
  <SiteHeader />

  <section class="hero">
    <div class="hl">
      <div class="eyebrow">Use case / Audit readiness</div>
      <h1>Walk into the assessment with the agent layer already covered.<br><em>Not scrambling two weeks out.</em></h1>
      <p class="sub">You're mid-prep for a SOC 2 Type II window, a HIPAA risk assessment, ISO 42001, or EU AI Act conformity — and your tooling logs humans and infrastructure but goes dark on what the agents did. <span class="air">AIR</span> collects that evidence continuously, so readiness is a posture, not a fire drill.</p>
      <div class="tagrow"><span>SOC 2</span><span>HIPAA</span><span>ISO 42001</span><span>EU AI Act</span></div>
      <div class="ctarow">
        <a class="btn-red" href="/contact">Book an agent audit</a>
        <a class="bookd" href="#evidence">See the evidence ↓</a>
      </div>
      <div class="trustline">Continuous · always current · mapped to your controls</div>
    </div>
    <div class="hfx">
      <div class="hglow"></div>
      <div class="capsule">
        <div class="cap-h"><span class="d"></span> Assessment-ready · live</div>
        <div class="cap-row res"><span class="k">Coverage</span><span class="v">agent layer · continuous</span></div>
        <div class="cap-row res"><span class="k">SOC 2</span><span class="v">CC7.2 / CC7.3 mapped</span></div>
        <div class="cap-row res"><span class="k">HIPAA</span><span class="v">164.312(b) mapped</span></div>
        <div class="cap-row res"><span class="k">EU AI Act</span><span class="v">Article 12 log</span></div>
        <div class="cap-sign">collected in-process · signed · always current</div>
        <div class="cap-verify">✓ ready today, not in two weeks</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">01</span><span class="bk">The stakes</span></div>
  <div class="scene rv">
    <div class="ts">T-14 days · auditor kickoff scheduled</div>
    <div class="big">Two weeks out, you realize nothing captured what the agents did.</div>
    <div class="sub">Your GRC stack covers people and infrastructure, but the autonomous agents are a blind spot you're now backfilling under a deadline. With <span class="air">AIR</span> that evidence was already being collected, signed, and mapped to each control while the work happened.</div>
  </div>

  <div class="breaker rv"><span class="bn">02</span><span class="bk">What "ready" means</span></div>
  <section class="wrap">
    <h2 class="rv">Ready is a posture, not a scramble.</h2>
    <div class="mcards">
      <div class="mc rv">
        <div class="mt">Continuous</div>
        <div class="ml">not retroactive</div>
        <p>Evidence is signed in-process the moment each agent acts, so the record exists before anyone asks for it.</p>
        <div class="mf">No reconstructing the week before the auditor arrives.</div>
      </div>
      <div class="mc rv">
        <div class="mt">The agent layer</div>
        <div class="ml">the gap others leave</div>
        <p>Your existing tools cover humans and infrastructure. <span class="air">AIR</span> fills the agent gap every framework now expects you to close.</p>
        <div class="mf">14 of the 16 detectors run offline with zero config.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Mapped to the control</div>
        <div class="ml">not raw logs</div>
        <p>Each record maps to the named requirement — SOC 2 CC7.2 / CC7.3, HIPAA 164.312(b), ISO 42001, EU AI Act Art. 12.</p>
        <div class="mf">The assessor sees coverage, not a data dump.</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">03</span><span class="bk">How <span class="air">AIR</span> answers</span></div>
  <section class="wrap">
    <h2 class="rv">Everything an assessment asks of the agent layer.</h2>
    <div class="maprows">
      <div class="mr rv"><div class="demand">Is the agent layer covered for this assessment?</div><div class="answer"><span class="layer">Audit</span>16 detectors read every agent action against OWASP and framework signatures, continuously.</div></div>
      <div class="mr rv"><div class="demand">Is the evidence current, or already stale?</div><div class="answer"><span class="layer">Prove</span>Signed in-process the moment each action happens — always assessment-ready.</div></div>
      <div class="mr rv"><div class="demand">Does it map to my controls?</div><div class="answer"><span class="layer">Report</span>One record → SOC 2 · HIPAA · ISO 42001 · EU AI Act evidence.</div></div>
      <div class="mr rv"><div class="demand">Can the assessor trust it wasn't edited?</div><div class="answer"><span class="layer">Prove</span>BLAKE3 + Ed25519, anchored to a public transparency log.</div></div>
      <div class="mr rv"><div class="demand">Across every agent and framework at once?</div><div class="answer"><span class="layer">One chain</span>A single signed chain covers them all — no per-framework rework.</div></div>
    </div>
  </section>

  <div class="breaker rv" id="evidence"><span class="bn">04</span><span class="bk">The evidence</span></div>
  <section class="evsec">
    <div class="evtext rv">
      <h2>Hand the assessor coverage, not a data dump.</h2>
      <p>A control-mapped, signed, timestamped record of what the agents did — produced in the form an assessor recognizes and can verify independently under <b>FRE 902(13)–(14)</b>.</p>
      <a class="flink" href="/standards">See the framework mapping →</a>
    </div>
    <div class="record rv">
      <div class="rec-h">Evidence pack · agent layer</div>
      <div class="chainrow"><b>Control</b> · SOC 2 CC7.2 — agent action logging</div>
      <div class="chainrow"><b>Action</b> · agent read — in scope, signed</div>
      <div class="chainrow"><b>Maps to</b> · HIPAA 164.312(b) · EU AI Act Art. 12</div>
      <div class="rec-sign">signed in-process · blake3 · ed25519 · anchored Rekor</div>
      <div class="verify">✓ assessment-ready · verify on search.sigstore.dev</div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">05</span><span class="bk">What you get</span></div>
  <section class="wrap">
    <h2 class="rv">The tiers teams in audit prep choose.</h2>
    <div class="tiers">
      <div class="tier feat rv">
        <div class="tn">Enterprise</div><div class="tl">most teams here</div>
        <ul>
          <li>Continuous agent-layer evidence</li>
          <li>Framework reports — SOC 2 · HIPAA · ISO 42001 · EU AI Act</li>
          <li>Causal graph, query &amp; replay</li>
          <li>SIEM: Splunk · Datadog · Sentinel · Sumo</li>
          <li>SSO / OIDC, SLA</li>
        </ul>
        <a class="pb" href="/contact">Book an agent audit</a>
      </div>
      <div class="tier rv">
        <div class="tn">Air-gapped</div><div class="tl">regulated · sovereign</div>
        <div class="plus2">Everything in Enterprise, plus</div>
        <ul>
          <li>On-prem / offline anchoring</li>
          <li>No phone-home — records never leave</li>
          <li>Extended retention + PQ re-anchoring</li>
          <li>Admissibility Pack — FRE 902 + expert support</li>
        </ul>
        <a class="pb" href="/contact">Talk to us</a>
      </div>
    </div>
  </section>

  <section class="close rv">
    <h2>Be ready before the auditor schedules the kickoff.</h2>
    <p>A free agent audit shows exactly where your agent-layer evidence stands today — and what an assessor would find.</p>
    <a class="btn-red big" href="/contact">Book an agent audit →</a>
    <div class="pills"><span>SOC 2</span><span>HIPAA</span><span>ISO 42001</span><span>EU AI Act Art. 12</span><span>FRE 902(13)–(14)</span></div>
  </section>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

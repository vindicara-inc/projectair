<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import IndustryHeader from '$lib/components/IndustryHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';
  onMount(setupReveal);
</script>

<svelte:head>
  <title>ISO 42001 · Project AIR — operational evidence for your AI management system</title>
  <meta name="description" content="ISO/IEC 42001:2023 asks for operational controls, monitoring, and records over your AI systems. For autonomous agents, Project AIR supplies the operational evidence — continuous monitoring and a signed record of what each agent did." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind fw">
  <div class="dotfield"></div>
  <IndustryHeader />

  <section class="hero">
    <div class="hl">
      <div class="eyebrow">Framework / ISO 42001</div>
      <h1>ISO 42001 certifies your AI management system.<br><em>Prove the agents are managed.</em></h1>
      <p class="sub"><b>ISO/IEC 42001:2023</b> asks for operational controls, monitoring, and records over your AI systems. For autonomous agents, <span class="air">AIR</span> supplies the operational evidence — continuous monitoring and a signed record of what each agent did.</p>
      <div class="tagrow"><span>ISO/IEC 42001:2023</span><span>AI management system</span><span>operational controls</span><span>monitoring</span></div>
      <div class="ctarow">
        <a class="btn-red" href="/contact">Book an agent audit</a>
        <a class="bookd" href="#evidence">See the evidence ↓</a>
      </div>
      <div class="trustline">Records the controls operate · tamper-evident · durable</div>
    </div>
    <div class="hfx">
      <div class="hglow"></div>
      <div class="capsule">
        <div class="cap-h"><span class="d"></span> AIMS evidence · live</div>
        <div class="cap-row res"><span class="k">Monitored</span><span class="v">agent action · 16 detectors</span></div>
        <div class="cap-row res"><span class="k">Accountable</span><span class="v">bound to a named human</span></div>
        <div class="cap-row res"><span class="k">Recorded</span><span class="v">signed, continuous</span></div>
        <div class="cap-row res"><span class="k">Lifecycle</span><span class="v">durable, anchored chain</span></div>
        <div class="cap-sign">operational evidence · anchored Rekor</div>
        <div class="cap-verify">✓ the controls operate, on the record</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">01</span><span class="bk">The stakes</span></div>
  <div class="scene rv">
    <div class="ts">ISO 42001 certification audit</div>
    <div class="big">Your AIMS is documented. The certifier asks for proof the agents are actually managed.</div>
    <div class="sub">ISO 42001 is a management-system standard: policy on paper isn't enough, the auditor wants records that the controls operate. For autonomous agents, that operational evidence is usually missing — <span class="air">AIR</span> produces it continuously and signs it.</div>
  </div>

  <div class="breaker rv"><span class="bn">02</span><span class="bk">The standard</span></div>
  <section class="wrap">
    <h2 class="rv">A management system, not a policy binder.</h2>
    <div class="mcards">
      <div class="mc rv">
        <div class="mt">A management system</div>
        <div class="ml">first of its kind</div>
        <p>ISO/IEC 42001:2023 is the first certifiable AI management system standard. It expects operational controls over your AI systems, not just policy.</p>
        <div class="mf">Agents are the part of "your AI systems" hardest to evidence.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Operate the controls</div>
        <div class="ml">monitoring &amp; records</div>
        <p>Certification tests that controls operate over time — monitoring, logging, records. <span class="air">AIR</span> runs the monitoring and signs the records for the agent layer.</p>
        <div class="mf">16 detectors, every agent action.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Across the lifecycle</div>
        <div class="ml">durable evidence</div>
        <p>The AIMS spans the AI lifecycle. A signed, anchored chain gives you durable, tamper-evident records the certifier can trust.</p>
        <div class="mf">Re-anchored to your retention floor.</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">03</span><span class="bk">How <span class="air">AIR</span> answers</span></div>
  <section class="wrap">
    <h2 class="rv">What an AIMS audit asks of the agent layer.</h2>
    <div class="maprows">
      <div class="mr rv"><div class="demand">Are your AI systems monitored in operation?</div><div class="answer"><span class="layer">Monitor</span>16 detectors on every agent action, continuously.</div></div>
      <div class="mr rv"><div class="demand">Do you keep records that the controls operate?</div><div class="answer"><span class="layer">Prove</span>Signed in-process, every action, over time.</div></div>
      <div class="mr rv"><div class="demand">Can you show accountability for agent actions?</div><div class="answer"><span class="layer">Account</span>Each action bound to a named human or service.</div></div>
      <div class="mr rv"><div class="demand">Are the records tamper-evident for the certifier?</div><div class="answer"><span class="layer">Prove</span>Anchored to a public transparency log.</div></div>
      <div class="mr rv"><div class="demand">Mapped to your AIMS, not raw logs?</div><div class="answer"><span class="layer">Report</span>Records map to your operational controls.</div></div>
    </div>
  </section>

  <div class="breaker rv" id="evidence"><span class="bn">04</span><span class="bk">The evidence</span></div>
  <section class="evsec">
    <div class="evtext rv">
      <h2>Operational evidence your certifier can trust.</h2>
      <p>A signed, monitored, accountable record of what each agent did — durable across the lifecycle and tamper-evident, so the AIMS controls are demonstrably operating, not just documented.</p>
      <a class="flink" href="/standards">See all framework mappings →</a>
    </div>
    <div class="record rv">
      <div class="rec-h">AIMS operational record · agdr/v2</div>
      <div class="chainrow"><b>Monitored</b> · agent action read against 16 detectors</div>
      <div class="chainrow"><b>Accountable</b> · bound to a named human</div>
      <div class="chainrow"><b>Recorded</b> · signed in-process, continuous</div>
      <div class="chainrow"><b>Durable</b> · anchored, re-anchored to retention</div>
      <div class="rec-sign">operational evidence · blake3 · ed25519 · anchored Rekor</div>
      <div class="verify">✓ controls operating, on the record · search.sigstore.dev</div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">05</span><span class="bk">What you get</span></div>
  <section class="wrap">
    <h2 class="rv">The tiers AIMS owners choose.</h2>
    <div class="tiers">
      <div class="tier feat rv">
        <div class="tn">Enterprise</div><div class="tl">most teams here</div>
        <ul>
          <li>Continuous agent-layer monitoring &amp; records</li>
          <li>Framework reports — ISO 42001 · SOC 2 · EU AI Act</li>
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
    <h2>Make the agent layer part of your AIMS.</h2>
    <p>A free agent audit shows the operational evidence you'd bring to an ISO 42001 certification today.</p>
    <a class="btn-red big" href="/contact">Book an agent audit →</a>
    <div class="pills"><span>ISO/IEC 42001:2023</span><span>operational controls</span><span>monitoring</span><span>FRE 902(13)–(14)</span></div>
  </section>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

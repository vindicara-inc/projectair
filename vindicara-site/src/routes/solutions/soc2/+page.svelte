<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import SiteHeader from '$lib/components/SiteHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';
  onMount(setupReveal);
</script>

<svelte:head>
  <title>SOC 2 · Project AIR — CC7.2 and CC7.3 evidence for the agent layer</title>
  <meta name="description" content="A SOC 2 Type II tests whether you monitor for anomalies (CC7.2) and respond to incidents (CC7.3). Project AIR produces that evidence for autonomous agents — signed, continuous across the window, and verifiable by your auditor." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind fw">
  <div class="dotfield"></div>
  <SiteHeader />

  <section class="hero">
    <div class="hl">
      <div class="eyebrow">Framework / SOC 2</div>
      <h1>SOC 2 covers your systems.<br><em>Does it cover your agents?</em></h1>
      <p class="sub">A SOC 2 Type II tests whether you monitor for anomalies (<b>CC7.2</b>) and respond to incidents (<b>CC7.3</b>). Your tooling does that for infrastructure and people — <span class="air">AIR</span> does it for autonomous agents, with signed evidence your auditor can verify.</p>
      <div class="tagrow"><span>SOC 2 Type II</span><span>CC7.2</span><span>CC7.3</span><span>agent evidence</span></div>
      <div class="ctarow">
        <a class="btn-red" href="/contact">Book an agent audit</a>
        <a class="bookd" href="#evidence">See the evidence ↓</a>
      </div>
      <div class="trustline">Continuous across the window · auditor-verifiable</div>
    </div>
    <div class="hfx">
      <div class="hglow"></div>
      <div class="capsule">
        <div class="cap-h"><span class="d"></span> SOC 2 evidence · live</div>
        <div class="cap-row res"><span class="k">CC7.2</span><span class="v">anomaly detected · 16 detectors</span></div>
        <div class="cap-row res"><span class="k">CC7.3</span><span class="v">evaluated &amp; responded</span></div>
        <div class="cap-row res"><span class="k">Type II</span><span class="v">signed across the window</span></div>
        <div class="cap-row halt"><span class="k">Agent action</span><span class="v">halted · SV-SCOPE</span></div>
        <div class="cap-sign">signed in-process · anchored Rekor</div>
        <div class="cap-verify">✓ auditor-verifiable · FRE 902(13)–(14)</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">01</span><span class="bk">The stakes</span></div>
  <div class="scene rv">
    <div class="ts">SOC 2 Type II · observation window</div>
    <div class="big">Your SOC 2 covers the infrastructure. The agents acting on it slipped out of scope.</div>
    <div class="sub">CC7.2 asks how you detect anomalies and CC7.3 how you respond. For servers and people you have answers; for autonomous agents, the control owner usually doesn't. <span class="air">AIR</span> produces that evidence continuously, across the whole observation window.</div>
  </div>

  <div class="breaker rv"><span class="bn">02</span><span class="bk">The criteria</span></div>
  <section class="wrap">
    <h2 class="rv">Two criteria the agent layer keeps failing quietly.</h2>
    <div class="mcards">
      <div class="mc rv">
        <div class="mt">CC7.2</div>
        <div class="ml">detect</div>
        <p>Monitor for anomalies and security events. <span class="air">AIR</span> reads every agent action against 16 detectors (OWASP Agentic + LLM + AIR-native), continuously.</p>
        <div class="mf">14 of the 16 run offline with zero config.</div>
      </div>
      <div class="mc rv">
        <div class="mt">CC7.3</div>
        <div class="ml">evaluate &amp; respond</div>
        <p>Evaluate and respond to security events. The causal graph and replay reconstruct what an agent did and why, so response is evidence-backed.</p>
        <div class="mf">Containment can halt an agent before harm, signed.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Type II</div>
        <div class="ml">over time</div>
        <p>Type II tests controls across a window, not a snapshot. <span class="air">AIR</span> signs each action in-process, so the evidence spans the whole period.</p>
        <div class="mf">No backfilling the week before the report is due.</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">03</span><span class="bk">How <span class="air">AIR</span> answers</span></div>
  <section class="wrap">
    <h2 class="rv">Every question a SOC 2 asks of the agent layer.</h2>
    <div class="maprows">
      <div class="mr rv"><div class="demand">How do you detect anomalous agent behavior? (CC7.2)</div><div class="answer"><span class="layer">Monitor</span>16 detectors on every agent action, continuously.</div></div>
      <div class="mr rv"><div class="demand">How do you respond to an agent incident? (CC7.3)</div><div class="answer"><span class="layer">Investigate</span>Causal graph and counterfactual replay reconstruct what happened.</div></div>
      <div class="mr rv"><div class="demand">Is the evidence continuous over the window?</div><div class="answer"><span class="layer">Prove</span>Signed in-process, every action, across the period.</div></div>
      <div class="mr rv"><div class="demand">Can the auditor verify it independently?</div><div class="answer"><span class="layer">Prove</span>Anchored to a public transparency log.</div></div>
      <div class="mr rv"><div class="demand">Mapped to the criteria, not raw logs?</div><div class="answer"><span class="layer">Report</span>Records map to CC7.2 / CC7.3.</div></div>
    </div>
  </section>

  <div class="breaker rv" id="evidence"><span class="bn">04</span><span class="bk">The evidence</span></div>
  <section class="evsec">
    <div class="evtext rv">
      <h2>Evidence mapped to the criterion, not a log dump.</h2>
      <p>A signed, timestamped record that names the criterion it satisfies — independently verifiable, and admissible under <b>FRE 902(13)–(14)</b> if the question ever leaves the audit room.</p>
      <a class="flink" href="/standards">See all framework mappings →</a>
    </div>
    <div class="record rv">
      <div class="rec-h">SOC 2 evidence · agent layer</div>
      <div class="chainrow"><b>CC7.2</b> · anomaly detected — ASI02 tool misuse</div>
      <div class="chainrow"><b>CC7.3</b> · evaluated &amp; responded — agent halted</div>
      <div class="chainrow"><b>Window</b> · signed across the Type II period</div>
      <div class="rec-sign">signed in-process · blake3 · ed25519 · anchored Rekor</div>
      <div class="verify">✓ auditor-verifiable · search.sigstore.dev</div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">05</span><span class="bk">What you get</span></div>
  <section class="wrap">
    <h2 class="rv">The tiers SOC 2 teams choose.</h2>
    <div class="tiers">
      <div class="tier feat rv">
        <div class="tn">Enterprise</div><div class="tl">most teams here</div>
        <ul>
          <li>CC7.2 / CC7.3 agent-layer evidence</li>
          <li>Causal graph, query &amp; replay</li>
          <li>Containment — halt agents before harm</li>
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
    <h2>Bring the agent layer into your SOC 2.</h2>
    <p>A free agent audit shows exactly what CC7.2 / CC7.3 evidence you'd have for your agents today.</p>
    <a class="btn-red big" href="/contact">Book an agent audit →</a>
    <div class="pills"><span>SOC 2 Type II</span><span>CC7.2</span><span>CC7.3</span><span>FRE 902(13)–(14)</span></div>
  </section>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

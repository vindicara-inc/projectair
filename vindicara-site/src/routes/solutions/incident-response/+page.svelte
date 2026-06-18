<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import IndustryHeader from '$lib/components/IndustryHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';
  onMount(setupReveal);
</script>

<svelte:head>
  <title>Incident response · Project AIR — reconstruct and prove an agent incident in minutes</title>
  <meta name="description" content="An agent misfired and a clock is running. Project AIR's causal graph and counterfactual replay reconstruct the chain of agent actions in minutes, and the signed log proves the reconstruction wasn't edited after the fact." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind uc">
  <div class="dotfield"></div>
  <IndustryHeader />

  <section class="hero">
    <div class="hl">
      <div class="eyebrow">Use case / Incident response</div>
      <h1>An agent did something wrong. Reconstruct exactly what happened, in minutes.<br><em>Not days of log-spelunking.</em></h1>
      <p class="sub">A customer escalation, a regulator inquiry, a reporting clock — and you need to know what the agent did and prove it before time runs out. <span class="air">AIR</span>'s causal graph and counterfactual replay reconstruct the chain, and the signed log proves the reconstruction wasn't edited after the fact.</p>
      <div class="tagrow"><span>Causal graph</span><span>Counterfactual replay</span><span>Signed timeline</span><span>Reporting deadlines</span></div>
      <div class="ctarow">
        <a class="btn-red" href="/contact">Book an agent audit</a>
        <a class="bookd" href="#evidence">See the evidence ↓</a>
      </div>
      <div class="trustline">Minutes, not weeks · reconstruction you can defend</div>
    </div>
    <div class="hfx">
      <div class="hglow"></div>
      <div class="capsule">
        <div class="cap-h"><span class="d"></span> Incident reconstruction · live</div>
        <div class="cap-row"><span class="k">Agent</span><span class="v">payments-agent-09</span></div>
        <div class="cap-row halt"><span class="k">Trigger</span><span class="v">exceeded scope @ 13:02</span></div>
        <div class="cap-row res"><span class="k">Cause</span><span class="v">causal graph → step 4</span></div>
        <div class="cap-row res"><span class="k">Replay</span><span class="v">counterfactual resolved</span></div>
        <div class="cap-sign">reconstructed in minutes · signed in-process</div>
        <div class="cap-verify">✓ original record · not edited after</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">01</span><span class="bk">The stakes</span></div>
  <div class="scene rv">
    <div class="ts">13:02 · incident: payments-agent-09</div>
    <div class="big">An agent did something it shouldn't have, and the clock to report just started.</div>
    <div class="sub">Across systems never built to attribute agent behavior, answering "what exactly happened" is normally days or weeks of log-spelunking. With <span class="air">AIR</span> the causal chain reconstructs in minutes, and the signed record proves it's the truth, not an after-the-fact edit.</div>
  </div>

  <div class="breaker rv"><span class="bn">02</span><span class="bk">What it takes</span></div>
  <section class="wrap">
    <h2 class="rv">Answer fast, and prove the answer.</h2>
    <div class="mcards">
      <div class="mc rv">
        <div class="mt">Reconstruct the chain</div>
        <div class="ml">causal graph</div>
        <p>The causal graph links each agent action to what caused it, so you read the path, not scattered logs across systems.</p>
        <div class="mf">Hard edges at confidence 1.0; soft edges scored.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Replay the counterfactual</div>
        <div class="ml">what if it hadn't</div>
        <p>Counterfactual replay shows the branch that didn't happen, so you can establish intent and impact, not just sequence.</p>
        <div class="mf">The "why," not only the "what."</div>
      </div>
      <div class="mc rv">
        <div class="mt">Prove it wasn't edited</div>
        <div class="ml">signed timeline</div>
        <p>The signed, anchored log proves your reconstruction is the original record, admissible under <span class="air">FRE&nbsp;902</span>.</p>
        <div class="mf">Reconstructed from signed records, not rebuilt from editable logs.</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">03</span><span class="bk">How <span class="air">AIR</span> answers</span></div>
  <section class="wrap">
    <h2 class="rv">Everything the clock demands, in order.</h2>
    <div class="maprows">
      <div class="mr rv"><div class="demand">What exactly did the agent do?</div><div class="answer"><span class="layer">Investigate</span>The signed timeline of every action, in order, attributed to the agent.</div></div>
      <div class="mr rv"><div class="demand">What caused it?</div><div class="answer"><span class="layer">Causal</span>The causal graph links each step to its trigger upstream.</div></div>
      <div class="mr rv"><div class="demand">What would have happened otherwise?</div><div class="answer"><span class="layer">Replay</span>Counterfactual replay runs over the same graph.</div></div>
      <div class="mr rv"><div class="demand">Can I prove the reconstruction is real?</div><div class="answer"><span class="layer">Prove</span>Signed in-process and anchored — not rebuilt from editable logs.</div></div>
      <div class="mr rv"><div class="demand">Before the reporting deadline?</div><div class="answer"><span class="layer">Minutes</span>Minutes, against the days of cross-system log-spelunking it replaces.</div></div>
    </div>
  </section>

  <div class="breaker rv" id="evidence"><span class="bn">04</span><span class="bk">The evidence</span></div>
  <section class="evsec">
    <div class="evtext rv">
      <h2>The timeline you file, and can defend.</h2>
      <p>A reconstructed, signed, timestamped chain of exactly what happened and why — independently verifiable, and admissible under <b>FRE 902(13)–(14)</b> when the inquiry escalates.</p>
      <a class="flink" href="/structural-verification">See structural verification →</a>
    </div>
    <div class="record rv">
      <div class="rec-h">Incident reconstruction · agdr/v2</div>
      <div class="chainrow"><b>Trigger</b> · agent exceeded scope @ 13:02:04Z</div>
      <div class="chainrow"><b>Cause</b> · causal graph → poisoned input at step 4</div>
      <div class="chainrow"><b>Replay</b> · counterfactual: blocked path shown</div>
      <div class="chainrow halt"><b>Halt</b> · action stopped — SV-SCOPE</div>
      <div class="rec-sign">signed in-process · reconstructed in minutes · anchored Rekor</div>
      <div class="verify">✓ original, not edited after · verify on search.sigstore.dev</div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">05</span><span class="bk">What you get</span></div>
  <section class="wrap">
    <h2 class="rv">The tiers incident teams choose.</h2>
    <div class="tiers">
      <div class="tier feat rv">
        <div class="tn">Enterprise</div><div class="tl">most teams here</div>
        <ul>
          <li>Causal graph, query &amp; counterfactual replay</li>
          <li>Signed, attributable agent timeline</li>
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
          <li>On-prem / offline reconstruction</li>
          <li>No phone-home — records never leave</li>
          <li>Extended retention + PQ re-anchoring</li>
          <li>Admissibility Pack — FRE 902 + expert support</li>
        </ul>
        <a class="pb" href="/contact">Talk to us</a>
      </div>
    </div>
  </section>

  <section class="close rv">
    <h2>When the clock starts, have the answer already.</h2>
    <p>A free agent audit shows how fast you could reconstruct an incident today, and what the signed record would prove.</p>
    <a class="btn-red big" href="/contact">Book an agent audit →</a>
    <div class="pills"><span>Causal graph</span><span>Counterfactual replay</span><span>EU AI Act Art. 73</span><span>FRE 902(13)–(14)</span></div>
  </section>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

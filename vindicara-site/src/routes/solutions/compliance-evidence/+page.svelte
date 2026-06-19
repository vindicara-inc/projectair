<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import SiteHeader from '$lib/components/SiteHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';
  onMount(setupReveal);
</script>

<svelte:head>
  <title>Compliance evidence · Project AIR — the record assessors actually ask for</title>
  <meta name="description" content="Raw logs aren't evidence. Project AIR produces a signed, timestamped, attributable record that maps to a named requirement — the SEC 17a-4 audit-trail alternative, the HIPAA 164.312(b) record, the EU AI Act Article 12 log — in the form an assessor recognizes." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind uc">
  <div class="dotfield"></div>
  <SiteHeader />

  <section class="hero">
    <div class="hl">
      <div class="eyebrow">Use case / Compliance evidence</div>
      <h1>Hand the assessor the record they actually asked for.<br><em>Not a data dump to interpret.</em></h1>
      <p class="sub">Raw logs aren't evidence. A signed, timestamped, attributable record that maps to a named requirement is — the 17a-4 audit-trail alternative, the HIPAA 164.312(b) record, the EU AI Act Article 12 log, produced in the form an assessor recognizes.</p>
      <div class="tagrow"><span>SEC 17a-4</span><span>HIPAA 164.312(b)</span><span>EU AI Act Art. 12</span><span>self-authenticating</span></div>
      <div class="ctarow">
        <a class="btn-red" href="/contact">Book an agent audit</a>
        <a class="bookd" href="#evidence">See the evidence ↓</a>
      </div>
      <div class="trustline">The artifact, not the export · verifiable by anyone</div>
    </div>
    <div class="hfx">
      <div class="hglow"></div>
      <div class="capsule">
        <div class="cap-h"><span class="d"></span> Compliance record · live</div>
        <div class="cap-row res"><span class="k">Requirement</span><span class="v">SEC 17a-4 alternative</span></div>
        <div class="cap-row res"><span class="k">Maps to</span><span class="v">HIPAA 164.312(b)</span></div>
        <div class="cap-row res"><span class="k">Maps to</span><span class="v">EU AI Act Art. 12</span></div>
        <div class="cap-row"><span class="k">Attributed</span><span class="v">agent + authorizing human</span></div>
        <div class="cap-sign">signed in-process · time-stamped · anchored Rekor</div>
        <div class="cap-verify">✓ self-authenticating · FRE 902(13)–(14)</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">01</span><span class="bk">The stakes</span></div>
  <div class="scene rv">
    <div class="ts">request · evidence for control 7.2</div>
    <div class="big">The assessor asked for one specific record. You sent a 40,000-line log export.</div>
    <div class="sub">Raw logs put the interpreting on the assessor and slow the whole review. <span class="air">AIR</span> produces the exact artifact — signed, timestamped, attributable, mapped to the named requirement — so what you hand over is evidence, not homework.</div>
  </div>

  <div class="breaker rv"><span class="bn">02</span><span class="bk">What counts</span></div>
  <section class="wrap">
    <h2 class="rv">A log is not evidence. This is.</h2>
    <div class="mcards">
      <div class="mc rv">
        <div class="mt">Signed, not just stored</div>
        <div class="ml">tamper-evident</div>
        <p>A record signed in-process and anchored is tamper-evident. A log anyone on the team could edit is not.</p>
        <div class="mf">BLAKE3 content hash, Ed25519 signature, public anchor.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Attributable</div>
        <div class="ml">who, and under whose authority</div>
        <p>Each record names the agent, the action, and the human who authorized it. "Someone did something" doesn't pass.</p>
        <div class="mf">Bound to a named human via Auth0, Entra, Okta or SPIFFE.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Mapped to the requirement</div>
        <div class="ml">the assessor's clause</div>
        <p>Each record points at the named clause — 17a-4, HIPAA 164.312(b), EU AI Act Art. 12 — so the assessor sees the answer.</p>
        <div class="mf">The form they recognize, not raw data to interpret.</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">03</span><span class="bk">How <span class="air">AIR</span> answers</span></div>
  <section class="wrap">
    <h2 class="rv">Everything that turns a log into evidence.</h2>
    <div class="maprows">
      <div class="mr rv"><div class="demand">Is this the record the requirement asks for?</div><div class="answer"><span class="layer">Prove</span>Each record maps to the named clause it satisfies.</div></div>
      <div class="mr rv"><div class="demand">Can you prove it wasn't edited?</div><div class="answer"><span class="layer">Prove</span>BLAKE3 + Ed25519, anchored to a public transparency log.</div></div>
      <div class="mr rv"><div class="demand">Who and what did it?</div><div class="answer"><span class="layer">Account</span>The agent and the authorizing human, on every record.</div></div>
      <div class="mr rv"><div class="demand">Will it hold outside our walls?</div><div class="answer"><span class="layer">Admissible</span>Self-authenticating under FRE 902(13)–(14).</div></div>
      <div class="mr rv"><div class="demand">For 17a-4, HIPAA and the EU AI Act at once?</div><div class="answer"><span class="layer">One record</span>One record, mapped to each requirement.</div></div>
    </div>
  </section>

  <div class="breaker rv" id="evidence"><span class="bn">04</span><span class="bk">The evidence</span></div>
  <section class="evsec">
    <div class="evtext rv">
      <h2>This is the artifact, not the export.</h2>
      <p>A signed, timestamped, attributable record that maps to the exact requirement the assessor cited — independently verifiable, with zero Vindicara infrastructure in the path.</p>
      <a class="flink" href="/evidence">See the full evidence model →</a>
    </div>
    <div class="record rv">
      <div class="rec-h">Compliance record · agdr/v2</div>
      <div class="chainrow"><b>Requirement</b> · SEC 17a-4 audit-trail alternative</div>
      <div class="chainrow"><b>Action</b> · agent action — time-stamped, attributed</div>
      <div class="chainrow"><b>Maps to</b> · HIPAA 164.312(b) · EU AI Act Art. 12</div>
      <div class="rec-sign">signed in-process · blake3 · ed25519 · anchored Rekor</div>
      <div class="verify">✓ self-authenticating · FRE 902(13)–(14)</div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">05</span><span class="bk">What you get</span></div>
  <section class="wrap">
    <h2 class="rv">The tiers compliance teams choose.</h2>
    <div class="tiers">
      <div class="tier feat rv">
        <div class="tn">Enterprise</div><div class="tl">most teams here</div>
        <ul>
          <li>Signed, attributable, requirement-mapped records</li>
          <li>Framework reports — SOC 2 · HIPAA · ISO 42001 · EU AI Act</li>
          <li>Causal graph, query &amp; replay</li>
          <li>SIEM: Splunk · Datadog · Sentinel · Sumo</li>
          <li>Retention to your regulatory floor</li>
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
    <h2>Send evidence, not a data dump.</h2>
    <p>A free agent audit shows the exact records you could hand an assessor today — and which requirements they already satisfy.</p>
    <a class="btn-red big" href="/contact">Book an agent audit →</a>
    <div class="pills"><span>SEC 17a-4</span><span>HIPAA 164.312(b)</span><span>EU AI Act Art. 12</span><span>FRE 902(13)–(14)</span></div>
  </section>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

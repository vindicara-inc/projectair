<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import IndustryHeader from '$lib/components/IndustryHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';
  onMount(setupReveal);
</script>

<svelte:head>
  <title>EU AI Act · Project AIR — Article 12 logging and Article 73 incident reporting for agents</title>
  <meta name="description" content="High-risk AI must keep automatic logs (Article 12) and report serious incidents (Article 73). Project AIR produces the Article 12 log for the agent layer — signed, attributable — and reconstructs incidents in minutes when Article 73's clock starts." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind fw">
  <div class="dotfield"></div>
  <IndustryHeader />

  <section class="hero">
    <div class="hl">
      <div class="eyebrow">Framework / EU AI Act</div>
      <h1>High-risk AI must keep logs.<br><em>Article 12, for your agents.</em></h1>
      <p class="sub">For high-risk systems, the EU AI Act requires automatic record-keeping (<b>Article 12</b>) and incident reporting (<b>Article 73</b>). <span class="air">AIR</span> produces the Article 12 log for the agent layer — signed, attributable — and is ready when Article 73's clock starts.</p>
      <div class="tagrow"><span>Article 12</span><span>Article 73</span><span>high-risk</span><span>Annex III</span></div>
      <div class="ctarow">
        <a class="btn-red" href="/contact">Book an agent audit</a>
        <a class="bookd" href="#evidence">See the evidence ↓</a>
      </div>
      <div class="trustline">Automatic logging · incident-ready · tamper-evident</div>
    </div>
    <div class="hfx">
      <div class="hglow"></div>
      <div class="capsule">
        <div class="cap-h"><span class="d"></span> Article 12 log · live</div>
        <div class="cap-row res"><span class="k">Logged</span><span class="v">agent action · automatic</span></div>
        <div class="cap-row res"><span class="k">Attributed</span><span class="v">agent + authorizing human</span></div>
        <div class="cap-row res"><span class="k">Art. 73 ready</span><span class="v">reconstruct in minutes</span></div>
        <div class="cap-row halt"><span class="k">Out-of-scope</span><span class="v">blocked · SV-SCOPE</span></div>
        <div class="cap-sign">signed in-process · anchored Rekor</div>
        <div class="cap-verify">✓ lifetime log · tamper-evident</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">01</span><span class="bk">The stakes</span></div>
  <div class="scene rv">
    <div class="ts">Annex III high-risk · agent system</div>
    <div class="big">Your high-risk system runs on agents. Article 12 wants the logs; Article 73 wants the incident report.</div>
    <div class="sub">Article 12 requires automatic logging over the system's lifetime, and Article 73 requires reporting serious incidents on a deadline. <span class="air">AIR</span> keeps the log continuously, and reconstructs the incident in minutes when the clock starts.</div>
  </div>

  <div class="breaker rv"><span class="bn">02</span><span class="bk">The articles</span></div>
  <section class="wrap">
    <h2 class="rv">Two obligations, and an honest date.</h2>
    <div class="mcards">
      <div class="mc rv">
        <div class="mt">Article 12</div>
        <div class="ml">record-keeping</div>
        <p>High-risk systems must automatically record events over their lifetime. <span class="air">AIR</span> signs each agent action in-process — the Article 12 log, for the agent layer.</p>
        <div class="mf">Automatic, not reconstructed after the fact.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Article 73</div>
        <div class="ml">incident reporting</div>
        <p>Serious incidents must be reported on a deadline. The causal graph and replay reconstruct what happened, fast, with a signed record.</p>
        <div class="mf">Minutes, against days of cross-system log-spelunking.</div>
      </div>
      <div class="mc rv">
        <div class="mt">The timeline</div>
        <div class="ml">Digital Omnibus</div>
        <p>The Digital Omnibus (provisional agreement May 7, 2026) defers high-risk Annex III obligations from Aug 2, 2026 to <em>Dec 2, 2027</em>.</p>
        <div class="mf flag">Provisional until adopted and published in the Official Journal; until then Aug 2, 2026 stays active. Article 5 prohibitions apply since Feb 2025.</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">03</span><span class="bk">How <span class="air">AIR</span> answers</span></div>
  <section class="wrap">
    <h2 class="rv">What the high-risk obligations ask of the agent layer.</h2>
    <div class="maprows">
      <div class="mr rv"><div class="demand">Automatic logging over the system's lifetime? (Art. 12)</div><div class="answer"><span class="layer">Prove</span>Signed in-process, every action, retained and re-anchored.</div></div>
      <div class="mr rv"><div class="demand">Who and what acted?</div><div class="answer"><span class="layer">Account</span>Each action bound to a named human or service.</div></div>
      <div class="mr rv"><div class="demand">Report a serious incident on deadline? (Art. 73)</div><div class="answer"><span class="layer">Investigate</span>Causal graph and replay reconstruct it in minutes.</div></div>
      <div class="mr rv"><div class="demand">Tamper-evident for a regulator?</div><div class="answer"><span class="layer">Prove</span>Anchored to a public transparency log.</div></div>
      <div class="mr rv"><div class="demand">Across cross-agent handoffs?</div><div class="answer"><span class="layer">Handoff</span>A chain of custody survives delegation.</div></div>
    </div>
  </section>

  <div class="breaker rv" id="evidence"><span class="bn">04</span><span class="bk">The evidence</span></div>
  <section class="evsec">
    <div class="evtext rv">
      <h2>The Article 12 log, and the Article 73 report under it.</h2>
      <p>An automatic, signed, attributable record of every agent action over the system's lifetime — and, when an incident hits, the reconstruction that backs the Article 73 report, admissible under <b>FRE 902(13)–(14)</b>.</p>
      <a class="flink" href="/standards">See all framework mappings →</a>
    </div>
    <div class="record rv">
      <div class="rec-h">Article 12 log · agdr/v2</div>
      <div class="chainrow"><b>Logged</b> · agent action — automatic, time-stamped</div>
      <div class="chainrow"><b>Attributed</b> · agent + authorizing human</div>
      <div class="chainrow"><b>Art. 73</b> · reconstructable in minutes</div>
      <div class="chainrow halt"><b>Halt</b> · out-of-scope call blocked — SV-SCOPE</div>
      <div class="rec-sign">signed in-process · blake3 · ed25519 · anchored Rekor</div>
      <div class="verify">✓ lifetime log, tamper-evident · search.sigstore.dev</div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">05</span><span class="bk">What you get</span></div>
  <section class="wrap">
    <h2 class="rv">The tiers high-risk providers choose.</h2>
    <div class="tiers">
      <div class="tier feat rv">
        <div class="tn">Enterprise</div><div class="tl">most teams here</div>
        <ul>
          <li>Article 12 logging for the agent layer</li>
          <li>Article 73 incident reconstruction</li>
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
    <h2>Be ready for Article 12, before the date moves again.</h2>
    <p>A free agent audit shows the lifetime log you'd already have for your high-risk agents — and how fast you could file under Article 73.</p>
    <a class="btn-red big" href="/contact">Book an agent audit →</a>
    <div class="pills"><span>Article 12</span><span>Article 73</span><span>Annex III</span><span>FRE 902(13)–(14)</span></div>
  </section>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

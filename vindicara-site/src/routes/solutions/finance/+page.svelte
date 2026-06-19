<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import SiteHeader from '$lib/components/SiteHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';
  onMount(setupReveal);
</script>

<svelte:head>
  <title>Finance &amp; insurance · Project AIR — the SEC 17a-4 audit trail for AI agents</title>
  <meta name="description" content="When agents recommend or execute trades, FINRA 4511 and SEC Rule 17a-4 demand a complete, time-stamped, identity-bound, reconstructable audit trail. Project AIR is that audit-trail alternative for the agent layer — immutable by cryptography, not WORM." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind">
  <div class="dotfield"></div>
  <SiteHeader />

  <!-- hero -->
  <section class="hero">
    <div class="hl">
      <div class="eyebrow">Solutions / Finance &amp; insurance</div>
      <h1>An agent recommended a trade.<br><em>Can you reproduce exactly what it saw?</em></h1>
      <p class="sub">When agents recommend or execute trades, <b>SEC Rule 17a-4</b> and <b>FINRA 4511</b> demand a complete, time-stamped, identity-bound audit trail you can reconstruct on demand. <span class="air">AIR</span> produces exactly that for the agent layer, made immutable by cryptography instead of WORM media.</p>
      <div class="tagrow">
        <span>FINRA 4511</span><span>SEC 17a-4</span><span>6-year retention</span><span>WORM-alternative</span>
      </div>
      <div class="ctarow">
        <a class="btn-red" href="/contact">Book an agent audit</a>
        <a class="bookd" href="#evidence">See the evidence ↓</a>
      </div>
      <div class="trustline">Free eval · nothing deployed · verify every record yourself</div>
    </div>

    <div class="hfx">
      <div class="hglow"></div>
      <div class="capsule">
        <div class="cap-h"><span class="d"></span> Signed Intent Capsule · live</div>
        <div class="cap-row"><span class="k">Agent</span><span class="v">order-router-04</span></div>
        <div class="cap-row"><span class="k">Delegated by</span><span class="v">pm.chen · Okta</span></div>
        <div class="cap-row res"><span class="k">Order</span><span class="v">BUY AAPL ×4,000</span></div>
        <div class="cap-row res"><span class="k">Limit check</span><span class="v">within mandate</span></div>
        <div class="cap-row halt"><span class="k">Off-book transfer</span><span class="v">blocked · SV-SCOPE</span></div>
        <div class="cap-sign">BLAKE3 · Ed25519 · time-stamped · anchored Rekor</div>
        <div class="cap-verify">✓ reconstructable · verify on search.sigstore.dev</div>
      </div>
    </div>
  </section>

  <!-- 01 the stakes -->
  <div class="breaker rv"><span class="bn">01</span><span class="bk">The stakes</span></div>
  <div class="scene rv">
    <div class="ts">09:41:58 · agent: order-router-04</div>
    <div class="big">An agent just placed 240 orders across 18 accounts in four minutes.</div>
    <div class="sub"><b>SEC Rule 17a-4</b> says you must show a complete, time-stamped trail of who did what, and recreate any record that changed. For a desk trader you have it; for an autonomous agent, that record usually doesn't exist until a regulator asks.</div>
  </div>

  <!-- 02 the mandate -->
  <div class="breaker rv"><span class="bn">02</span><span class="bk">The mandate</span></div>
  <section class="wrap">
    <h2 class="rv">What 17a-4 requires.</h2>
    <div class="mcards">
      <div class="mc rv">
        <div class="mt">FINRA Rule 4511</div>
        <div class="ml">recordkeeping baseline</div>
        <p>Members must preserve books and records for <em>at least six years</em>, in a format and on media that comply with SEC Rule 17a-4.</p>
        <div class="mf">Cryptographic, re-anchored retention is how <span class="air">AIR</span> meets the six-year obligation.</div>
      </div>
      <div class="mc rv">
        <div class="mt">SEC Rule 17a-4</div>
        <div class="ml">the audit-trail alternative</div>
        <p>The 2022 amendment added an alternative to WORM: a complete, time-stamped record of every create, modify and delete — who did it, when, and enough to recreate the original.</p>
        <div class="mf"><span class="air">AIR</span>'s signed log is exactly that, made immutable by cryptography instead of WORM media.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Insurance</div>
        <div class="ml">a distinct buyer</div>
        <p>The EU AI Act names insurance directly: life and health insurance risk and pricing are <em>Annex III high-risk</em> uses.</p>
        <div class="mf">Provable agent records are what both the regulator and the reinsurer ask to see.</div>
      </div>
    </div>
  </section>

  <!-- 03 how AIR answers -->
  <div class="breaker rv"><span class="bn">03</span><span class="bk">How <span class="air">AIR</span> answers</span></div>
  <section class="wrap">
    <h2 class="rv">17a-4, clause by clause, mapped to what already ships.</h2>
    <div class="maprows">
      <div class="mr rv"><div class="demand">A complete time-stamped trail of every create / modify / delete?</div><div class="answer"><span class="layer">Monitor</span>Every agent action is a signed, time-stamped AgDR record, forward-chained with BLAKE3.</div></div>
      <div class="mr rv"><div class="demand">The identity of who performed each action?</div><div class="answer"><span class="layer">Account</span>Each action bound to a named human (PM, desk, approver) through Okta, Entra, Auth0 or SPIFFE.</div></div>
      <div class="mr rv"><div class="demand">Recreate the original record if it changed?</div><div class="answer"><span class="layer">Prove</span>The forward-chain is tamper-evident; any edit breaks it, and the original state reconstructs.</div></div>
      <div class="mr rv"><div class="demand">Immutability without WORM media?</div><div class="answer"><span class="layer">Prove</span>Cryptographic immutability — Ed25519 signatures anchored to public Sigstore Rekor.</div></div>
      <div class="mr rv"><div class="demand">Six-year, and longer, retention?</div><div class="answer"><span class="layer">Enterprise</span>Signed and re-anchored to your regulatory floor, with post-quantum re-anchoring.</div></div>
    </div>
  </section>

  <!-- 04 the evidence -->
  <div class="breaker rv" id="evidence"><span class="bn">04</span><span class="bk">The evidence</span></div>
  <section class="evsec">
    <div class="evtext rv">
      <h2>The 17a-4 audit-trail alternative, in your hands.</h2>
      <p>Not a vendor attestation and not a log your team could have rewritten. A signed, time-stamped, identity-bound record of every agent action, reconstructable and independently verifiable, self-authenticating under <b>FRE 902(13)–(14)</b>.</p>
      <a class="flink" href="/admissibility">See the admissibility model →</a>
    </div>
    <div class="record rv">
      <div class="rec-h">AgDR record · agdr/v2</div>
      <div class="chainrow"><b>Delegation</b> · pm.chen authorized order-router-04</div>
      <div class="chainrow"><b>Action</b> · BUY AAPL ×4,000 @ 09:41:58.204Z</div>
      <div class="chainrow"><b>Check</b> · within mandate — in scope</div>
      <div class="chainrow halt"><b>Halt</b> · off-book transfer blocked — SV-SCOPE</div>
      <div class="rec-sign">sig: ed25519 · hash: blake3 · anchor: Rekor #1466351923</div>
      <div class="verify">✓ chain intact · reconstructable · verify on search.sigstore.dev</div>
    </div>
  </section>

  <!-- 05 what you get -->
  <div class="breaker rv"><span class="bn">05</span><span class="bk">What you get</span></div>
  <section class="wrap">
    <h2 class="rv">The tiers trading desks and insurers choose.</h2>
    <div class="tiers">
      <div class="tier feat rv">
        <div class="tn">Enterprise</div><div class="tl">most teams here</div>
        <ul>
          <li>Containment — halt agents before harm</li>
          <li>Causal graph, query &amp; replay</li>
          <li>SIEM: Splunk · Datadog · Sentinel · Sumo</li>
          <li>6-year+ retention, re-anchored to your floor</li>
          <li>SOC 2 · ISO 42001 · EU AI Act · NIST</li>
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
          <li>Dedicated, single-tenant deployment</li>
        </ul>
        <a class="pb" href="/contact">Talk to us</a>
      </div>
    </div>
    <p class="payline">Retention is the lever: you don't pay us to store records, you pay us to keep them provable, signed, tamper-evident, and re-anchored, for as long as the SEC and a courtroom require.</p>
  </section>

  <!-- close -->
  <section class="close rv">
    <h2>See what your agents traded, and prove it.</h2>
    <p>A free agent audit. Nothing deployed. You walk away with a 17a-4-style record of what your agents did, whether or not you ever buy.</p>
    <a class="btn-red big" href="/contact">Book an agent audit →</a>
    <div class="pills">
      <span>FINRA 4511</span><span>SEC 17a-4</span><span>6-year retention</span><span>EU AI Act Annex III</span><span>SOC 2</span><span>FRE 902(13)–(14)</span>
    </div>
  </section>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

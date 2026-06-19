<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import SiteHeader from '$lib/components/SiteHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';
  onMount(setupReveal);
</script>

<svelte:head>
  <title>Healthcare · Project AIR — prove what your AI agents did to ePHI</title>
  <meta name="description" content="Healthcare AI agents touch ePHI through FHIR. Project AIR signs every agent action, binds it to the authorizing clinician, and anchors it — the audit trail 45 CFR 164.312(b) asks for, for autonomous agents." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind">
  <div class="dotfield"></div>
  <SiteHeader />

  <!-- hero -->
  <section class="hero">
    <div class="hl">
      <div class="eyebrow">Solutions / Healthcare</div>
      <h1>An agent opened a patient's chart.<br><em>Can you prove it was allowed to?</em></h1>
      <p class="sub">Healthcare AI agents touch ePHI through FHIR. When one acts on its own, your EHR's audit log can't say <b>which agent</b> touched <b>which patient</b>, or under <b>whose authority</b> — <span class="air">AIR</span> can, and signs the proof.</p>
      <div class="tagrow">
        <span>FHIR R4 / R5</span><span>HIPAA 164.312(b)</span><span>BAA</span><span>Air-gapped</span>
      </div>
      <div class="ctarow">
        <a class="btn-red" href="/contact">Book an agent audit</a>
        <a class="bookd" href="#evidence">See the evidence ↓</a>
      </div>
      <div class="trustline">Free eval · nothing deployed · ePHI never leaves your boundary</div>
    </div>

    <div class="hfx">
      <div class="hglow"></div>
      <div class="capsule">
        <div class="cap-h"><span class="d"></span> Signed Intent Capsule · live</div>
        <div class="cap-row"><span class="k">Agent</span><span class="v">discharge-summarizer-03</span></div>
        <div class="cap-row"><span class="k">Delegated by</span><span class="v">dr.okafor · Auth0</span></div>
        <div class="cap-row res"><span class="k">FHIR read</span><span class="v">Patient/8841</span></div>
        <div class="cap-row res"><span class="k">FHIR read</span><span class="v">Observation/22907</span></div>
        <div class="cap-row halt"><span class="k">Bulk export</span><span class="v">blocked · SV-EXFIL</span></div>
        <div class="cap-sign">BLAKE3 · Ed25519 · anchored Rekor #1466351923</div>
        <div class="cap-verify">✓ chain intact · verify on search.sigstore.dev</div>
      </div>
    </div>
  </section>

  <!-- 01 the stakes -->
  <div class="breaker rv"><span class="bn">01</span><span class="bk">The stakes</span></div>
  <div class="scene rv">
    <div class="ts">02:14:07 · agent: discharge-summarizer-03</div>
    <div class="big">An autonomous agent just read 1,400 patient charts to draft discharge summaries.</div>
    <div class="sub">Under <b>45 CFR 164.312(b)</b> you must be able to say which patients, under whose authority, and prove the record was never changed. Your EHR answers that for a human at a workstation; for an autonomous agent, it can't.</div>
  </div>

  <!-- 02 the mandate -->
  <div class="breaker rv"><span class="bn">02</span><span class="bk">The mandate</span></div>
  <section class="wrap">
    <h2 class="rv">What the rules require, and where they're heading.</h2>
    <div class="mcards">
      <div class="mc rv">
        <div class="mt">FHIR / HL7</div>
        <div class="ml">the data substrate</div>
        <p>Agents read and write ePHI as FHIR <em>resources</em> over SMART-on-FHIR / OAuth. Since the 2020 ONC Cures Act, FHIR (R4 / R5) is the US standard for exchanging health data.</p>
        <div class="mf">The question your EHR can't answer: which agent touched which resource, for which patient.</div>
      </div>
      <div class="mc rv">
        <div class="mt">HIPAA 164.312(b)</div>
        <div class="ml">audit controls</div>
        <p>Audit logging is "addressable" today, and for autonomous agents it's routinely skipped. The 2025 Security Rule NPRM would make it mandatory.</p>
        <div class="mf flag">Proposed, not final — OCR hasn't issued a final rule. Either way, agents are the uncovered gap.</div>
      </div>
      <div class="mc rv">
        <div class="mt">BAA</div>
        <div class="ml">the contract</div>
        <p>Any vendor touching ePHI signs a Business Associate Agreement, with annual certification under the proposed rule.</p>
        <div class="mf">With air-gapped <span class="air">AIR</span> the ePHI never leaves your boundary, so there's nothing to phone home.</div>
      </div>
    </div>
  </section>

  <!-- 03 how AIR answers -->
  <div class="breaker rv"><span class="bn">03</span><span class="bk">How <span class="air">AIR</span> answers</span></div>
  <section class="wrap">
    <h2 class="rv">Every demand, mapped to a capability that already ships.</h2>
    <div class="maprows">
      <div class="mr rv"><div class="demand">Which agent touched which patient's record?</div><div class="answer"><span class="layer">Monitor</span>Per-agent identity with <code>DataSubjectRef</code> / <code>DataAssetRef</code> stamped on every action.</div></div>
      <div class="mr rv"><div class="demand">Under whose authority did it act?</div><div class="answer"><span class="layer">Account</span>Every agent bound to a named human through Auth0, Microsoft Entra, Okta, or SPIFFE.</div></div>
      <div class="mr rv"><div class="demand">Prove the log was not edited afterward.</div><div class="answer"><span class="layer">Prove</span>Each action signed in-process (BLAKE3 + Ed25519) and anchored to a public transparency log.</div></div>
      <div class="mr rv"><div class="demand">Stop an agent before it over-reaches.</div><div class="answer"><span class="layer">Protect</span>Structural Verification halts out-of-scope access deterministically: SV-EXFIL, SV-SCOPE.</div></div>
      <div class="mr rv"><div class="demand">Keep ePHI inside the boundary.</div><div class="answer"><span class="layer">Air-gapped</span>On-prem deployment with private anchoring; the transparency log runs inside your enclave.</div></div>
    </div>
  </section>

  <!-- 04 the evidence -->
  <div class="breaker rv" id="evidence"><span class="bn">04</span><span class="bk">The evidence</span></div>
  <section class="evsec">
    <div class="evtext rv">
      <h2>This is what you hand the auditor.</h2>
      <p>Not a screenshot of a dashboard, and not a log your team could have edited. A signed, anchored record of exactly what the agent did, who authorized it, and proof the chain is intact, self-authenticating under <b>FRE 902(13)–(14)</b>.</p>
      <a class="flink" href="/evidence">See the full evidence model →</a>
    </div>
    <div class="record rv">
      <div class="rec-h">AgDR record · agdr/v2</div>
      <div class="chainrow"><b>Delegation</b> · dr.okafor authorized discharge-summarizer-03</div>
      <div class="chainrow"><b>Subject</b> · DataSubjectRef = Patient/8841</div>
      <div class="chainrow"><b>Action</b> · FHIR read Observation/22907 — in scope</div>
      <div class="chainrow halt"><b>Halt</b> · bulk export blocked — SV-EXFIL</div>
      <div class="rec-sign">sig: ed25519 · hash: blake3 · anchor: Rekor #1466351923</div>
      <div class="verify">✓ chain intact · verify on search.sigstore.dev</div>
    </div>
  </section>

  <!-- 05 what you get -->
  <div class="breaker rv"><span class="bn">05</span><span class="bk">What you get</span></div>
  <section class="wrap">
    <h2 class="rv">The tiers regulated healthcare teams choose.</h2>
    <div class="tiers">
      <div class="tier rv">
        <div class="tn">Enterprise</div><div class="tl">most teams here</div>
        <ul>
          <li>Containment — halt agents before harm</li>
          <li>Causal graph, query &amp; replay</li>
          <li>SIEM: Splunk · Datadog · Sentinel · Sumo</li>
          <li>SSO / OIDC, SLA</li>
          <li>SOC 2 · HIPAA · ISO 42001 · EU AI Act · NIST</li>
        </ul>
        <a class="pb" href="/contact">Book an agent audit</a>
      </div>
      <div class="tier feat rv">
        <div class="tn">Air-gapped</div><div class="tl">regulated · sovereign</div>
        <div class="plus2">Everything in Enterprise, plus</div>
        <ul>
          <li>Air-gapped license — no phone-home</li>
          <li>Signed BAA</li>
          <li>HL7v2 / FHIR R4 interop</li>
          <li>On-prem / offline anchoring</li>
          <li>Admissibility Pack — FRE 902 + expert support</li>
        </ul>
        <a class="pb" href="/contact">Talk to us</a>
      </div>
    </div>
    <p class="payline">Retention is the lever: you don't pay us to store records, you pay us to keep them provable, signed, tamper-evident, and re-anchored, for as long as the law and a courtroom require.</p>
  </section>

  <!-- close -->
  <section class="close rv">
    <h2>See what your agents did to ePHI.</h2>
    <p>A free agent audit. Nothing deployed, nothing leaves your boundary. You walk away with the record, whether or not you ever buy.</p>
    <a class="btn-red big" href="/contact">Book an agent audit →</a>
    <div class="pills">
      <span>HIPAA 164.312(b)</span><span>45 CFR</span><span>FHIR R4 / R5</span><span>BAA</span><span>FRE 902(13)–(14)</span><span>SOC 2</span><span>ISO 42001</span>
    </div>
  </section>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

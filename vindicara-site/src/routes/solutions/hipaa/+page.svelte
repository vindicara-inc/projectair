<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import SiteHeader from '$lib/components/SiteHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';
  onMount(setupReveal);
</script>

<svelte:head>
  <title>HIPAA · Project AIR — 45 CFR 164.312(b) audit controls for AI agents</title>
  <meta name="description" content="HIPAA 164.312(b) requires audit controls over ePHI access. Your EHR logs the humans; the autonomous agents touching FHIR resources are the gap. Project AIR records every agent action against ePHI, signed and attributable." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind fw">
  <div class="dotfield"></div>
  <SiteHeader />

  <section class="hero">
    <div class="hl">
      <div class="eyebrow">Framework / HIPAA</div>
      <h1>HIPAA wants an audit trail.<br><em>Your agents aren't in it.</em></h1>
      <p class="sub"><b>45 CFR 164.312(b)</b> requires audit controls over who accessed ePHI. Your EHR logs the humans; the autonomous agents touching FHIR resources are the gap. <span class="air">AIR</span> records every agent action against ePHI, signed and attributable.</p>
      <div class="tagrow"><span>45 CFR 164.312(b)</span><span>audit controls</span><span>ePHI</span><span>BAA</span></div>
      <div class="ctarow">
        <a class="btn-red" href="/contact">Book an agent audit</a>
        <a class="bookd" href="#evidence">See the evidence ↓</a>
      </div>
      <div class="trustline">Per-agent · attributable · ePHI stays in your boundary</div>
    </div>
    <div class="hfx">
      <div class="hglow"></div>
      <div class="capsule">
        <div class="cap-h"><span class="d"></span> HIPAA audit · live</div>
        <div class="cap-row"><span class="k">Agent</span><span class="v">notes-summarizer-02</span></div>
        <div class="cap-row res"><span class="k">ePHI access</span><span class="v">Patient/8841 · read</span></div>
        <div class="cap-row res"><span class="k">Authorized by</span><span class="v">dr.okafor · Auth0</span></div>
        <div class="cap-row halt"><span class="k">Bulk export</span><span class="v">blocked · SV-EXFIL</span></div>
        <div class="cap-sign">164.312(b) record · signed · anchored Rekor</div>
        <div class="cap-verify">✓ attributable · who, what, when</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">01</span><span class="bk">The stakes</span></div>
  <div class="scene rv">
    <div class="ts">OCR inquiry · ePHI access review</div>
    <div class="big">An agent accessed ePHI. 164.312(b) wants the audit trail. Your EHR's stops at humans.</div>
    <div class="sub">Audit logging is "addressable" today and routinely skipped for agents; the 2025 Security Rule NPRM would make it mandatory. Either way the autonomous agents are the uncovered gap, and <span class="air">AIR</span> closes it with a signed, attributable record of every agent access.</div>
  </div>

  <div class="breaker rv"><span class="bn">02</span><span class="bk">The rule</span></div>
  <section class="wrap">
    <h2 class="rv">What 164.312(b) requires, stated straight.</h2>
    <div class="mcards">
      <div class="mc rv">
        <div class="mt">164.312(b)</div>
        <div class="ml">audit controls</div>
        <p>Implement mechanisms that record and examine activity in systems containing ePHI. For humans your EHR does; for agents, it doesn't.</p>
        <div class="mf">The forensic question: which agent touched which patient's record.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Addressable → mandatory</div>
        <div class="ml">the 2025 NPRM</div>
        <p>Today it's "addressable," and routinely skipped. The 2025 Security Rule NPRM would remove the addressable-vs-required split.</p>
        <div class="mf flag">Proposed, not final — as of mid-2026 OCR has issued no final rule.</div>
      </div>
      <div class="mc rv">
        <div class="mt">BAA</div>
        <div class="ml">the contract</div>
        <p>A vendor touching ePHI signs a Business Associate Agreement, with annual certification under the proposed rule.</p>
        <div class="mf">Air-gapped <span class="air">AIR</span> keeps the ePHI inside your boundary — nothing to phone home.</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">03</span><span class="bk">How <span class="air">AIR</span> answers</span></div>
  <section class="wrap">
    <h2 class="rv">Every audit-control question, for the agent layer.</h2>
    <div class="maprows">
      <div class="mr rv"><div class="demand">Which agent accessed which patient's ePHI?</div><div class="answer"><span class="layer">Monitor</span>Per-agent identity with <code>DataSubjectRef</code> / <code>DataAssetRef</code> on every action.</div></div>
      <div class="mr rv"><div class="demand">Under whose authority?</div><div class="answer"><span class="layer">Account</span>Bound to a named human via Auth0, Entra, Okta or SPIFFE.</div></div>
      <div class="mr rv"><div class="demand">Can you prove the record wasn't edited?</div><div class="answer"><span class="layer">Prove</span>BLAKE3 + Ed25519, anchored to a public log.</div></div>
      <div class="mr rv"><div class="demand">Does it satisfy 164.312(b)?</div><div class="answer"><span class="layer">Report</span>Records map to the audit-controls requirement.</div></div>
      <div class="mr rv"><div class="demand">Keep ePHI inside the boundary?</div><div class="answer"><span class="layer">Air-gapped</span>On-prem deployment; the record never leaves.</div></div>
    </div>
  </section>

  <div class="breaker rv" id="evidence"><span class="bn">04</span><span class="bk">The evidence</span></div>
  <section class="evsec">
    <div class="evtext rv">
      <h2>The 164.312(b) record, for an autonomous agent.</h2>
      <p>A signed, attributable, timestamped record of an agent's ePHI access — who, what, when, under whose authority — verifiable independently and admissible under <b>FRE 902(13)–(14)</b>.</p>
      <a class="flink" href="/solutions/healthcare">See the healthcare view →</a>
    </div>
    <div class="record rv">
      <div class="rec-h">HIPAA 164.312(b) record · agdr/v2</div>
      <div class="chainrow"><b>Delegation</b> · dr.okafor authorized notes-summarizer-02</div>
      <div class="chainrow"><b>Subject</b> · DataSubjectRef = Patient/8841</div>
      <div class="chainrow"><b>Action</b> · FHIR read — in scope, signed</div>
      <div class="chainrow halt"><b>Halt</b> · bulk export blocked — SV-EXFIL</div>
      <div class="rec-sign">signed in-process · blake3 · ed25519 · anchored Rekor</div>
      <div class="verify">✓ attributable · search.sigstore.dev</div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">05</span><span class="bk">What you get</span></div>
  <section class="wrap">
    <h2 class="rv">The tiers HIPAA-covered teams choose.</h2>
    <div class="tiers">
      <div class="tier feat rv">
        <div class="tn">Enterprise</div><div class="tl">most teams here</div>
        <ul>
          <li>164.312(b) agent-layer audit records</li>
          <li>Containment — halt agents before harm</li>
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
          <li>Signed BAA</li>
          <li>HL7v2 / FHIR R4 interop</li>
          <li>On-prem / offline anchoring</li>
          <li>Admissibility Pack — FRE 902 + expert support</li>
        </ul>
        <a class="pb" href="/contact">Talk to us</a>
      </div>
    </div>
  </section>

  <section class="close rv">
    <h2>Put your agents in the audit trail.</h2>
    <p>A free agent audit shows exactly what 164.312(b) evidence you'd have for your agents today — nothing deployed, ePHI never leaves your boundary.</p>
    <a class="btn-red big" href="/contact">Book an agent audit →</a>
    <div class="pills"><span>45 CFR 164.312(b)</span><span>BAA</span><span>FHIR R4 / R5</span><span>FRE 902(13)–(14)</span></div>
  </section>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

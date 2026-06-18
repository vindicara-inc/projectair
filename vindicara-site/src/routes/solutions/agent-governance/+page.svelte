<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import IndustryHeader from '$lib/components/IndustryHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';
  onMount(setupReveal);
</script>

<svelte:head>
  <title>Agent governance · Project AIR — who authorized what, proven</title>
  <meta name="description" content="An access-control dashboard asserts policy. Project AIR proves it held: this agent was permitted to act, here is who or what granted permission, and cryptographic proof the grant was real and never modified — across cross-agent handoffs." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind uc">
  <div class="dotfield"></div>
  <IndustryHeader />

  <section class="hero">
    <div class="hl">
      <div class="eyebrow">Use case / Agent governance</div>
      <h1>Who authorized what — proven.<br><em>Not just tracked.</em></h1>
      <p class="sub">An access-control dashboard asserts policy. <span class="air">AIR</span> proves it held: this agent was permitted to act, here's who or what granted permission, and here's cryptographic proof the grant was real and never modified.</p>
      <div class="tagrow"><span>Delegated authority</span><span>Cross-agent handoff</span><span>SPIFFE / Fulcio</span><span>proven, not claimed</span></div>
      <div class="ctarow">
        <a class="btn-red" href="/contact">Book an agent audit</a>
        <a class="bookd" href="#evidence">See the evidence ↓</a>
      </div>
      <div class="trustline">Bound to a human · scoped · proven across handoffs</div>
    </div>
    <div class="hfx">
      <div class="hglow"></div>
      <div class="capsule">
        <div class="cap-h"><span class="d"></span> Authorization chain · live</div>
        <div class="cap-row res"><span class="k">Granted by</span><span class="v">dr.okafor · Auth0</span></div>
        <div class="cap-row res"><span class="k">Agent</span><span class="v">claims-agent-A</span></div>
        <div class="cap-row res"><span class="k">Handoff</span><span class="v">A → B · PTID validated</span></div>
        <div class="cap-row halt"><span class="k">Out-of-scope</span><span class="v">blocked · SV-SCOPE</span></div>
        <div class="cap-sign">signed grant · counter-attested · anchored Rekor</div>
        <div class="cap-verify">✓ authority held · never exceeded</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">01</span><span class="bk">The stakes</span></div>
  <div class="scene rv">
    <div class="ts">review · agent privilege question</div>
    <div class="big">Did this agent even have the right to do that, and can you prove the permission was real?</div>
    <div class="sub">Tracking who has access is policy. Proving the authority was granted, scoped, and never exceeded — across cross-agent handoffs — is evidence. <span class="air">AIR</span> binds every agent to the human or service that authorized it, and signs the chain so no grant can be claimed after the fact.</div>
  </div>

  <div class="breaker rv"><span class="bn">02</span><span class="bk">Proven beats tracked</span></div>
  <section class="wrap">
    <h2 class="rv">The word that carries the card is "proven."</h2>
    <div class="mcards">
      <div class="mc rv">
        <div class="mt">Delegated, not assumed</div>
        <div class="ml">bound to a human</div>
        <p>Every agent is bound to a named human or service identity, and no action runs without a delegation behind it.</p>
        <div class="mf">Auth0, Microsoft Entra, Okta, or SPIFFE.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Scoped, and enforced</div>
        <div class="ml">Zero-Trust</div>
        <p>Declared scope is enforced deterministically. An out-of-scope action halts, and the halt is signed.</p>
        <div class="mf">Enforcement, not a policy that merely asserts itself.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Proven across handoffs</div>
        <div class="ml">chain of custody</div>
        <p>When Agent A delegates to Agent B, a cryptographic chain of custody carries the proof with the capability token.</p>
        <div class="mf">AgDR Handoff Protocol · SPIFFE / Fulcio identity.</div>
      </div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">03</span><span class="bk">How <span class="air">AIR</span> answers</span></div>
  <section class="wrap">
    <h2 class="rv">Every authorization question, answered with proof.</h2>
    <div class="maprows">
      <div class="mr rv"><div class="demand">Did this agent have the right to act?</div><div class="answer"><span class="layer">Account</span>Bound to a named human or service via Auth0, Entra, Okta or SPIFFE.</div></div>
      <div class="mr rv"><div class="demand">Who or what granted it?</div><div class="answer"><span class="layer">Account</span>The delegation record names the grantor, signed.</div></div>
      <div class="mr rv"><div class="demand">Was the grant real, not just claimed?</div><div class="answer"><span class="layer">Prove</span>The delegation is signed and anchored — not a config asserting policy.</div></div>
      <div class="mr rv"><div class="demand">Did the authority survive a handoff?</div><div class="answer"><span class="layer">Handoff</span>A cross-agent chain of custody carries it (AgDR Handoff).</div></div>
      <div class="mr rv"><div class="demand">Was it ever exceeded?</div><div class="answer"><span class="layer">Protect</span>Out-of-scope actions halt deterministically, and are signed.</div></div>
    </div>
  </section>

  <div class="breaker rv" id="evidence"><span class="bn">04</span><span class="bk">The evidence</span></div>
  <section class="evsec">
    <div class="evtext rv">
      <h2>Proof the authority held, end to end.</h2>
      <p>The grant, the scope, the handoff, and every action — signed, anchored, and counter-attested, so "this agent was permitted to act" is a record you can produce, not a claim a dashboard makes.</p>
      <a class="flink" href="/platform">See the layered platform →</a>
    </div>
    <div class="record rv">
      <div class="rec-h">Authorization chain · agdr/v2</div>
      <div class="chainrow"><b>Grant</b> · dr.okafor delegated claims-agent-A (Auth0)</div>
      <div class="chainrow"><b>Scope</b> · declared scope — enforced</div>
      <div class="chainrow"><b>Handoff</b> · agent-A → agent-B · PTID validated</div>
      <div class="chainrow halt"><b>Halt</b> · out-of-scope call blocked — SV-SCOPE</div>
      <div class="rec-sign">signed grant · counter-attested · anchored Rekor</div>
      <div class="verify">✓ authority held, never exceeded · search.sigstore.dev</div>
    </div>
  </section>

  <div class="breaker rv"><span class="bn">05</span><span class="bk">What you get</span></div>
  <section class="wrap">
    <h2 class="rv">The tiers governance owners choose.</h2>
    <div class="tiers">
      <div class="tier feat rv">
        <div class="tn">Enterprise</div><div class="tl">most teams here</div>
        <ul>
          <li>Human-bound delegation, signed</li>
          <li>Containment — halt out-of-scope actions</li>
          <li>Cross-agent handoff (AgDR Handoff)</li>
          <li>Causal graph, query &amp; replay</li>
          <li>SSO / OIDC, SLA</li>
        </ul>
        <a class="pb" href="/contact">Book an agent audit</a>
      </div>
      <div class="tier rv">
        <div class="tn">Air-gapped</div><div class="tl">regulated · sovereign</div>
        <div class="plus2">Everything in Enterprise, plus</div>
        <ul>
          <li>SPIFFE / Fulcio identity inside the enclave</li>
          <li>No phone-home — records never leave</li>
          <li>Extended retention + PQ re-anchoring</li>
          <li>Admissibility Pack — FRE 902 + expert support</li>
        </ul>
        <a class="pb" href="/contact">Talk to us</a>
      </div>
    </div>
  </section>

  <section class="close rv">
    <h2>Stop asserting policy. Prove it held.</h2>
    <p>A free agent audit shows whether you could prove — not just claim — that every agent acted within the authority it was granted.</p>
    <a class="btn-red big" href="/contact">Book an agent audit →</a>
    <div class="pills"><span>Delegated authority</span><span>AgDR Handoff</span><span>SPIFFE / Fulcio</span><span>FRE 902(13)–(14)</span></div>
  </section>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

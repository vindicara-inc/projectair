<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import SiteHeader from '$lib/components/SiteHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';

  onMount(() => {
    setupReveal();
    const s = document.createElement('script');
    s.src = '/three.min.js';
    s.onload = initGlobe;
    document.head.appendChild(s);

    function initGlobe(){
      const el = document.getElementById('globe');
      if (!el || !window.THREE) return;
      const W = el.clientWidth || 420, H = 420;
      const scene = new THREE.Scene();
      const cam = new THREE.PerspectiveCamera(38, W/H, 0.1, 100); cam.position.z = 4.0;
      const rnd = new THREE.WebGLRenderer({ alpha:true, antialias:true });
      rnd.setPixelRatio(Math.min(devicePixelRatio, 2)); rnd.setSize(W, H); el.appendChild(rnd.domElement);
      const root = new THREE.Group(); root.rotation.z = 0.36; scene.add(root);
      const loader = new THREE.TextureLoader(); loader.crossOrigin = 'anonymous';
      const night = loader.load('/earth-night.jpg');
      const earth = new THREE.Mesh(new THREE.SphereGeometry(1.15, 72, 72), new THREE.MeshBasicMaterial({ map:night }));
      root.add(earth);
      earth.add(new THREE.Mesh(new THREE.SphereGeometry(1.152, 72, 72), new THREE.MeshBasicMaterial({ map:night, transparent:true, opacity:0.8, blending:THREE.AdditiveBlending })));
      const topo = loader.load('/earth-topology.png');
      earth.add(new THREE.Mesh(new THREE.SphereGeometry(1.156, 72, 72), new THREE.MeshBasicMaterial({ map:topo, color:0xffffff, transparent:true, opacity:1, blending:THREE.AdditiveBlending })));
      (function loop(){ requestAnimationFrame(loop); earth.rotation.y += 0.0011; rnd.render(scene, cam); })();
      addEventListener('resize', () => { const w = el.clientWidth; cam.aspect = w/H; cam.updateProjectionMatrix(); rnd.setSize(w, H); });
    }
  });
</script>

<svelte:head>
  <title>Government &amp; public sector · Project AIR — sovereign agent accountability</title>
  <meta name="description" content="Air-gapped and sovereign deployments can't reach public Sigstore. Project AIR runs a private Rekor v2 / Tessera transparency log inside your enclave, signed with FIPS-validated cryptography, so agent accountability clears DoD IL5/IL6 with no path out." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind">
  <div class="dotfield"></div>
  <SiteHeader />

  <!-- hero -->
  <section class="hero">
    <div class="hl">
      <div class="eyebrow">Solutions / Government &amp; public sector</div>
      <h1>Sovereign means it never phones home.<br><em>The transparency log runs inside the enclave.</em></h1>
      <p class="sub">Air-gapped and sovereign deployments can't reach public Sigstore. <span class="air">AIR</span> runs a private Rekor v2 / Tessera transparency log inside your boundary, signed with <b>FIPS-validated</b> cryptography, so agent accountability clears <b>IL5 / IL6</b> with no network path out.</p>
      <div class="tagrow">
        <span>FedRAMP High</span><span>DoD IL5 / IL6</span><span>FIPS 140-3</span><span>air-gapped</span>
      </div>
      <div class="ctarow">
        <a class="btn-red" href="/contact">Request a sovereign briefing</a>
        <a class="bookd" href="#evidence">See the evidence ↓</a>
      </div>
      <div class="trustline">No phone-home · US-person operated · dedicated tenancy</div>
    </div>

    <div class="hfx">
      <div class="hglow"></div>
      <div class="glabel">· Sovereign enclave · private transparency log · <span class="lv">no egress</span> ·</div>
      <div id="globe" class="globe"></div>
    </div>
  </section>

  <!-- 01 the stakes -->
  <div class="breaker rv"><span class="bn">01</span><span class="bk">The stakes</span></div>
  <div class="scene rv">
    <div class="ts">06:20:11 · enclave: classified-workflow-7</div>
    <div class="big">An agent acted inside a classified workflow, on a network with no path to the public internet.</div>
    <div class="sub">IL6 forbids phone-home and public Sigstore is unreachable, yet you still must prove what the agent did and that the record holds. The proof has to be generated and anchored <b>inside the boundary</b>, or it doesn't exist.</div>
  </div>

  <!-- 02 the mandate -->
  <div class="breaker rv"><span class="bn">02</span><span class="bk">The mandate</span></div>
  <section class="wrap">
    <h2 class="rv">Two words, "air-gapped" and "sovereign," carry a lot of law.</h2>
    <p class="lead rv">What the impact-level ladder and the crypto floor require.</p>
    <div class="mcards">
      <div class="mc rv">
        <div class="mt">FedRAMP / DoD IL</div>
        <div class="ml">the impact-level ladder</div>
        <p><em>IL5</em> requires FedRAMP High plus a DISA Provisional Authorization, FIPS-validated cryptographic modules for all encryption, US-person administrative access, and physical separation from non-DoD tenants. <em>IL6</em>, for data classified up to Secret, can run only in an air-gapped government community cloud.</p>
        <div class="mf flag">Naming in flight: FedRAMP "Authorization" becomes "Certification," Impact Levels become Classes A–D, and the Low / Moderate / High labels are removed from January 2027.</div>
      </div>
      <div class="mc rv">
        <div class="mt">FIPS 140-3</div>
        <div class="ml">the crypto floor</div>
        <p>FIPS 140-3 replaces 140-2 by 2026. NIST stopped accepting new 140-2 submissions in April 2022, and existing 140-2 validations sunset in 2026.</p>
        <div class="mf"><span class="air">AIR</span>'s Ed25519 / BLAKE3 / ML-DSA-65 stack runs on FIPS-validated module images, so the signing path clears IL review instead of blocking it.</div>
      </div>
      <div class="mc rv">
        <div class="mt">Sovereign transparency</div>
        <div class="ml">the wedge</div>
        <p>An air-gapped deployment cannot anchor to public Sigstore. <span class="air">AIR</span> runs a private <em>Rekor v2 / Tessera</em> transparency log inside the enclave, so inclusion proofs exist without a packet leaving.</p>
        <div class="mf">A three-tier checkpoint-key-custody ladder is how sovereignty is priced and how the trust root stays in your hands.</div>
      </div>
    </div>
  </section>

  <!-- 03 how AIR answers -->
  <div class="breaker rv"><span class="bn">03</span><span class="bk">How <span class="air">AIR</span> answers</span></div>
  <section class="wrap">
    <h2 class="rv">Every sovereign requirement, mapped to a capability.</h2>
    <div class="maprows">
      <div class="mr rv"><div class="demand">No network path to public Sigstore?</div><div class="answer"><span class="layer">Air-gapped</span>A private Rekor v2 / Tessera transparency log runs inside the enclave.</div></div>
      <div class="mr rv"><div class="demand">FIPS-validated cryptography for all encryption?</div><div class="answer"><span class="layer">Prove</span>Signing runs on FIPS-validated module images (FIPS 140-3).</div></div>
      <div class="mr rv"><div class="demand">US-person administration and tenant separation?</div><div class="answer"><span class="layer">Deploy</span>Dedicated, single-tenant, operated by your own cleared people.</div></div>
      <div class="mr rv"><div class="demand">Prove an agent never exceeded its authority?</div><div class="answer"><span class="layer">Protect</span>Human-bound delegation plus deterministic Structural Verification.</div></div>
      <div class="mr rv"><div class="demand">Who holds the trust root?</div><div class="answer"><span class="layer">Key custody</span>A three-tier checkpoint-key-custody ladder keeps it inside your boundary.</div></div>
    </div>
  </section>

  <!-- 04 the evidence -->
  <div class="breaker rv" id="evidence"><span class="bn">04</span><span class="bk">The evidence</span></div>
  <section class="evsec">
    <div class="evtext rv">
      <h2>Verified without a single packet leaving your boundary.</h2>
      <p>The record is signed in-process with FIPS-validated cryptography and anchored to a transparency log that lives inside the enclave. Your own people verify inclusion, offline, with no call to Vindicara and no call to the public internet.</p>
      <a class="flink" href="/evidence">See the evidence model →</a>
    </div>
    <div class="record rv">
      <div class="rec-h">AgDR record · agdr/v2 · in-enclave</div>
      <div class="chainrow"><b>Delegation</b> · operator authorized classified-workflow-7</div>
      <div class="chainrow"><b>Action</b> · task executed — within declared scope</div>
      <div class="chainrow"><b>Anchor</b> · private Rekor v2 / Tessera — no egress</div>
      <div class="chainrow halt"><b>Halt</b> · out-of-scope call blocked — SV-SCOPE</div>
      <div class="rec-sign">sig: ed25519 / ML-DSA-65 · FIPS-validated · in-enclave log</div>
      <div class="verify">✓ inclusion proven offline · zero network path out</div>
    </div>
  </section>

  <!-- 05 what you get -->
  <div class="breaker rv"><span class="bn">05</span><span class="bk">What you get</span></div>
  <section class="wrap">
    <h2 class="rv">The sovereign tier, and the enterprise floor under it.</h2>
    <div class="tiers">
      <div class="tier feat rv">
        <div class="tn">Air-gapped</div><div class="tl">regulated · sovereign</div>
        <ul>
          <li>Air-gapped license — no phone-home</li>
          <li>Private Rekor v2 / Tessera transparency log</li>
          <li>FIPS-validated signing (140-3)</li>
          <li>Three-tier checkpoint-key custody</li>
          <li>Admissibility Pack — FRE 902 + expert support</li>
        </ul>
        <a class="pb" href="/contact">Request a sovereign briefing</a>
      </div>
      <div class="tier rv">
        <div class="tn">Enterprise</div><div class="tl">the floor under it</div>
        <ul>
          <li>Containment — halt agents before harm</li>
          <li>Causal graph, query &amp; replay</li>
          <li>SIEM: Splunk · Datadog · Sentinel · Sumo</li>
          <li>SSO / OIDC, SLA</li>
          <li>SOC 2 · ISO 42001 · EU AI Act · NIST</li>
        </ul>
        <a class="pb" href="/contact">Talk to us</a>
      </div>
    </div>
    <p class="payline">Sovereignty is the lever: you don't pay us to reach your network, you pay us to prove your agents inside it, with the trust root never leaving your hands.</p>
  </section>

  <!-- close -->
  <section class="close rv">
    <h2>Prove your agents without leaving the enclave.</h2>
    <p>A sovereign briefing for your security and accreditation teams. We walk the IL5 / IL6 path, the FIPS posture, and the in-enclave transparency log, on your terms.</p>
    <a class="btn-red big" href="/contact">Request a sovereign briefing →</a>
    <div class="pills">
      <span>FedRAMP High</span><span>DoD IL5 / IL6</span><span>FIPS 140-3</span><span>ML-DSA-65</span><span>air-gapped</span><span>FRE 902(13)–(14)</span>
    </div>
  </section>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

<style>
  /* page-specific: the sovereign globe */
  .globe{width:100%;height:420px}
  .glabel{position:absolute;top:0;left:0;right:0;text-align:center;font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--faint);z-index:2}
  .glabel .lv{color:var(--good)}
</style>

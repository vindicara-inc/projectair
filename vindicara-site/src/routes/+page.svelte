<script>
  // @ts-nocheck
  import { onMount } from 'svelte';

  let openMenu = $state(null);
  function toggleMenu(id){ openMenu = openMenu === id ? null : id; }

  onMount(() => {
    const onDocClick = () => { openMenu = null; };
    document.addEventListener('click', onDocClick);

    const s = document.createElement('script');
    s.src = '/three.min.js';
    s.onload = initGlobe;
    document.head.appendChild(s);

    function initGlobe(){
      const el=document.getElementById('globe'); if(!el||!window.THREE) return;
      const W=el.clientWidth||440, H=440;
      const scene=new THREE.Scene();
      const cam=new THREE.PerspectiveCamera(38,W/H,0.1,100); cam.position.z=4.0;
      const rnd=new THREE.WebGLRenderer({alpha:true,antialias:true}); rnd.setPixelRatio(Math.min(devicePixelRatio,2)); rnd.setSize(W,H); el.appendChild(rnd.domElement);
      const root=new THREE.Group(); root.rotation.z=0.36; scene.add(root);
      const loader=new THREE.TextureLoader(); loader.crossOrigin='anonymous';
      const night=loader.load('/earth-night.jpg');
      const earth=new THREE.Mesh(new THREE.SphereGeometry(1.15,72,72), new THREE.MeshBasicMaterial({map:night}));
      root.add(earth);
      earth.add(new THREE.Mesh(new THREE.SphereGeometry(1.152,72,72), new THREE.MeshBasicMaterial({map:night,transparent:true,opacity:0.8,blending:THREE.AdditiveBlending})));
      const topo=loader.load('/earth-topology.png');
      earth.add(new THREE.Mesh(new THREE.SphereGeometry(1.156,72,72), new THREE.MeshBasicMaterial({map:topo,color:0xffffff,transparent:true,opacity:1,blending:THREE.AdditiveBlending})));
      earth.add(new THREE.Mesh(new THREE.SphereGeometry(1.159,72,72), new THREE.MeshBasicMaterial({map:topo,color:0xffffff,transparent:true,opacity:0.9,blending:THREE.AdditiveBlending})));
      (function loop(){requestAnimationFrame(loop); earth.rotation.y+=0.0011; rnd.render(scene,cam);})();
      addEventListener('resize',()=>{const w=el.clientWidth;cam.aspect=w/H;cam.updateProjectionMatrix();rnd.setSize(w,H);});
    }
  });
</script>

<svelte:head>
  <title>Project AIR · The accountability layer for AI agents</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
</svelte:head>

<div class="air-home">
<div class="dotfield"></div>

<div class="annc">Commercial tiers now in private beta with design partners · <a href="/contact">Book an agent audit →</a></div>

<header>
  <div class="bar">
    <a class="logo" href="/"><img src="/logo.svg" alt="Project AIR" class="logo-img" /></a>
    <nav>
      <button class="nav-item" class:on={openMenu==='solutions'} onclick={(e)=>{ e.stopPropagation(); toggleMenu('solutions'); }}>Solutions <span class="car">▾</span></button>
      <button class="nav-item" class:on={openMenu==='products'} onclick={(e)=>{ e.stopPropagation(); toggleMenu('products'); }}>Products <span class="car">▾</span></button>
      <button class="nav-item" class:on={openMenu==='company'} onclick={(e)=>{ e.stopPropagation(); toggleMenu('company'); }}>Company <span class="car">▾</span></button>
      <a class="ghost" href="/about">Customers</a>
      <a class="ghost" href="/pricing">Pricing</a>
    </nav>
    <div class="right">
      <a class="ghost" href="/flightdeck">Sign in</a>
      <a class="cta" href="/contact">Book a demo</a>
    </div>
  </div>

  <div class="mega" class:open={openMenu==='solutions'} onclick={(e)=>e.stopPropagation()}>
    <div class="mega-in">
      <div class="col">
        <h4>By industry</h4>
        <a class="mi" href="/platform"><span class="ic"></span><span><span class="mt">Healthcare</span><span class="md">FHIR/HL7, HIPAA, BAA</span></span></a>
        <a class="mi" href="/platform"><span class="ic"></span><span><span class="mt">Finance &amp; insurance</span><span class="md">FINRA/SEC audit trails</span></span></a>
        <a class="mi" href="/platform"><span class="ic"></span><span><span class="mt">Government &amp; public sector</span><span class="md">Air-gapped, sovereign</span></span></a>
        <a class="mi" href="/platform"><span class="ic"></span><span><span class="mt">AI agent platforms</span><span class="md">Accountability for your users</span></span></a>
      </div>
      <div class="col">
        <h4>By use case</h4>
        <a class="mi" href="/platform"><span class="ic"></span><span><span class="mt">Audit readiness</span><span class="md">SOC 2 · HIPAA · ISO 42001 · EU AI Act</span></span></a>
        <a class="mi" href="/platform"><span class="ic"></span><span><span class="mt">Incident response</span><span class="md">Reconstruct &amp; prove in minutes</span></span></a>
        <a class="mi" href="/evidence"><span class="ic"></span><span><span class="mt">Compliance evidence</span><span class="md">Records assessors actually ask for</span></span></a>
        <a class="mi" href="/platform"><span class="ic"></span><span><span class="mt">Agent governance</span><span class="md">Who authorized what, proven</span></span></a>
      </div>
      <div class="col">
        <h4>By framework</h4>
        <a class="mi" href="/standards"><span class="ic"></span><span><span class="mt">SOC 2</span><span class="md">CC7.2 / CC7.3 agent evidence</span></span></a>
        <a class="mi" href="/standards"><span class="ic"></span><span><span class="mt">HIPAA</span><span class="md">45 CFR 164.312(b)</span></span></a>
        <a class="mi" href="/standards"><span class="ic"></span><span><span class="mt">ISO 42001</span><span class="md">AI management system</span></span></a>
        <a class="mi" href="/standards"><span class="ic"></span><span><span class="mt">EU AI Act</span><span class="md">Article 72 logging</span></span></a>
      </div>
      <div class="col hl">
        <h4>Highlights</h4>
        <a class="hcard feat" href="/contact"><div class="ht">Book an agent audit</div><div class="hd">See what your agents did. Free eval, nothing deployed.</div></a>
        <a class="hcard" href="/evidence"><div class="ht">Hardware-rooted evidence</div><div class="hd">Validated on real NVIDIA H100 confidential compute.</div></a>
      </div>
    </div>
  </div>

  <div class="mega" class:open={openMenu==='products'} onclick={(e)=>e.stopPropagation()}>
    <div class="mega-rich">
      <a class="feature" href="/platform">
        <div class="feat-dots"></div>
        <div class="feat-body">
          <div class="feat-kicker">Project <span class="air">AIR</span> Platform</div>
          <div class="feat-title">Your complete agent-accountability HQ</div>
          <div class="feat-link">Explore platform →</div>
        </div>
      </a>
      <div class="prod-grid">
        <a class="pcard" href="/audit"><div class="pc-h">Audit</div><div class="pc-d">The record you take into your audit.</div><div class="pc-l">Learn more →</div></a>
        <a class="pcard" href="/prove"><div class="pc-h">Prove</div><div class="pc-d">Signed, anchored, independently verifiable.</div><div class="pc-l">Learn more →</div></a>
        <a class="pcard" href="/protect"><div class="pc-h">Protect</div><div class="pc-d">Halt agents before harm, not after.</div><div class="pc-l">Learn more →</div></a>
        <a class="pcard" href="/monitor"><div class="pc-h">Monitor</div><div class="pc-d">16 detectors, every action, live.</div><div class="pc-l">Learn more →</div></a>
        <a class="pcard" href="/get-started"><div class="pc-h"><span class="air">AIR</span> SDK &amp; CLI</div><div class="pc-d">Open source, on PyPI. Start in an afternoon.</div><div class="pc-l">Learn more →</div></a>
        <a class="pcard" href="/flightdeck"><div class="pc-h">FlightDeck</div><div class="pc-d">The operator cockpit for your fleet.</div><div class="pc-l">Learn more →</div></a>
        <a class="pcard" href="/pricing"><div class="pc-h"><span class="air">AIR</span> Cloud</div><div class="pc-d">Hosted ingestion, retention, alerting.</div><div class="pc-l">Learn more →</div></a>
        <a class="pcard" href="/admissibility"><div class="pc-h">Admissibility</div><div class="pc-d">Self-authenticating, FRE 902(13)–(14).</div><div class="pc-l">Learn more →</div></a>
        <a class="pcard" href="/structural-verification"><div class="pc-h">Structural Verification</div><div class="pc-d">The deterministic floor agents can't talk past.</div><div class="pc-l">Learn more →</div></a>
      </div>
    </div>
  </div>

  <div class="mega" class:open={openMenu==='company'} onclick={(e)=>e.stopPropagation()}>
    <div class="mega-in">
      <div class="col">
        <h4>Company</h4>
        <a class="mi" href="/about"><span class="ic"></span><span><span class="mt">About</span><span class="md">Why we build the record</span></span></a>
        <a class="mi" href="/about"><span class="ic"></span><span><span class="mt">Customers</span><span class="md">Who runs on <span class="air">AIR</span></span></span></a>
        <a class="mi" href="/contact"><span class="ic"></span><span><span class="mt">Contact</span><span class="md">Talk to us</span></span></a>
      </div>
      <div class="col">
        <h4>Resources</h4>
        <a class="mi" href="/blog"><span class="ic"></span><span><span class="mt">Blog</span><span class="md">Writing on agent accountability</span></span></a>
        <a class="mi" href="/press"><span class="ic"></span><span><span class="mt">Press</span><span class="md">News &amp; coverage</span></span></a>
        <a class="mi" href="https://github.com/vindicara-inc/projectair" target="_blank" rel="noopener"><span class="ic"></span><span><span class="mt">Docs &amp; GitHub</span><span class="md">MIT, read every line</span></span></a>
      </div>
      <div class="col">
        <h4>Community</h4>
        <a class="mi" href="https://github.com/vindicara-inc/projectair" target="_blank" rel="noopener"><span class="ic"></span><span><span class="mt">Open source</span><span class="md">Our OSS projects</span></span></a>
        <a class="mi" href="/about"><span class="ic"></span><span><span class="mt">Customer stories</span><span class="md">Who runs on <span class="air">AIR</span></span></span></a>
        <a class="mi" href="/contact"><span class="ic"></span><span><span class="mt">Events</span><span class="md">Where to find us</span></span></a>
        <a class="mi" href="/design-partner"><span class="ic"></span><span><span class="mt">Partners</span><span class="md">Build with Vindicara</span></span></a>
      </div>
      <div class="col hl">
        <h4>Highlights</h4>
        <a class="hcard feat" href="https://www.nvidia.com/en-us/startups/" target="_blank" rel="noopener"><div class="ht">NVIDIA Inception member</div><div class="hd">In the Innovation Lab review.</div></a>
        <a class="hcard" href="/design-partner"><div class="ht">Become a design partner</div><div class="hd">Shape the roadmap, founder-led integration.</div></a>
      </div>
    </div>
  </div>
</header>

<section class="hero2">
  <div>
    <h1>When your agents act on their own, can you prove what they did?</h1>
    <p class="sub"><span class="air">AIR</span> signs every agent action, binds it to the human who authorized it, and anchors it to a public log. One loop, four moves.</p>
    <div class="looprow">AUDIT <span class="pipe">|</span> PROVE <span class="pipe">|</span> PROTECT <span class="pipe">|</span> MONITOR</div>
    <div class="cta-row">
      <a class="btn-red" href="/get-started">Start free</a>
      <a class="bookd" href="/contact">Book a demo →</a>
    </div>
    <div class="trustline">Open source · MIT · no credit card · verify it yourself</div>
    <div class="statchips">
      <div class="sc"><b>212</b> agents live</div>
      <div class="sc"><b>Ed25519</b> signed</div>
      <div class="sc"><b>BLAKE3</b> chained</div>
    </div>
  </div>
  <div class="globe-wrap">
    <div class="glow-bg"></div>
    <div class="glabel">· Global agent network · <span class="lv">live</span> ·</div>
    <div id="globe" class="globe"></div>
  </div>
</section>

<div class="scene">
  <div class="ts">02:14:07 · agent: records-export-07</div>
  <div class="big">An agent with database access just exported 9,000 patient records.</div>
  <div class="sub">Your team can tell you it happened. They can't prove what it was authorized to do, or that the log wasn't edited after. That's the question every regulator, auditor, and court is about to ask.</div>
</div>

<section class="sec">
  <div class="wrap">
    <h2>Audit it. Prove it. Protect it. Monitor it.</h2>
    <p class="lead">One loop, running the whole time, so the answer exists before you need it.</p>
    <div class="feat2">
      <div class="fcard">
        <h3>Catch what breaks scope, the instant it happens.</h3>
        <p>16 detectors read every action in real time. The deterministic floor halts an agent the moment it steps outside what a human authorized.</p>
        <a class="flink" href="/monitor">See detection →</a>
        <div class="shot">
          <div class="ui-title2">Signed Intent Capsule · chain</div>
          <div class="chainrow"><b>Delegation</b> · dr.okafor authorized claims-bot</div>
          <div class="chainrow"><b>Action</b> · ehr.read — in scope</div>
          <div class="chainrow halt"><b>Halt</b> · bulk export blocked — SV-EXFIL</div>
          <div class="verify">✓ chain intact · verify on search.sigstore.dev</div>
        </div>
      </div>
      <div class="fcard">
        <h3>Prove it to anyone, without their trust.</h3>
        <p>Every action is signed in-process, bound to the authorizing human, and anchored to a public log. Self-authenticating evidence an auditor, insurer, or court can verify.</p>
        <a class="flink" href="/evidence">See the evidence →</a>
        <div class="shot">
          <div class="ui-title2">Containment</div>
          <div class="ui-row crit"><span>Agent halted · awaiting approval</span><span class="tag">Held</span></div>
          <div class="ui-row"><span>Approve &amp; sign · Auth0 / passkey</span><span class="ok">FIDO2</span></div>
          <div class="ui-foot">No agent acts without a delegation. Forged tokens stay halted.</div>
        </div>
      </div>
    </div>
    <div class="quote">
      <div class="q">Turn <span class="air" style="font-style:italic">AIR</span> on.</div>
      <div class="qsub">And from this moment, every action is on the record.</div>
    </div>
  </div>
</section>

<div class="proof">
  <h2>This page proves it.</h2>
  <p>Every request you just made was signed and anchored to a public transparency log. Not a claim, a dare. Verify it yourself, with zero Vindicara infrastructure in the path.</p>
  <div class="v">› verify on search.sigstore.dev</div>
</div>

<div class="trust">
  <span>OWASP Agentic</span><span>EU AI Act Art. 72</span><span>NIST AI RMF</span><span>FRE 902(13)–(14)</span><span>NVIDIA Inception</span><span>MIT open source</span>
</div>
</div>

<style>
  .air-home{
    --navy:#070d1a; --navy1:#0c1426; --panel:#101c34; --raise:#16264a;
    --white:#F7FAFF; --soft:#F3D98A; --faint:#FFC83D;
    --line:rgba(255,255,255,.14); --line2:rgba(255,255,255,.08);
    --air:#E63946; --air2:#ff5763; --airbg:rgba(230,57,70,.16);
    position:relative; min-height:100vh; background:var(--navy); color:var(--white);
    font-family:'Inter',system-ui,-apple-system,sans-serif; -webkit-font-smoothing:antialiased;
  }
  .dotfield{position:fixed;inset:0;z-index:0;pointer-events:none;
    background-image:radial-gradient(circle, rgba(255,255,255,.55) 1.1px, transparent 1.9px);
    background-size:24px 24px;
    -webkit-mask-image:radial-gradient(circle,#000 0%,transparent 45%);
    mask-image:radial-gradient(circle,#000 0%,transparent 45%);
    -webkit-mask-size:42% 42%;mask-size:42% 42%;
    -webkit-mask-repeat:no-repeat;mask-repeat:no-repeat;
    animation:dotsweep 26s linear infinite}
  @keyframes dotsweep{
    0%{-webkit-mask-position:0% 38%;mask-position:0% 38%}
    25%{-webkit-mask-position:50% 38%;mask-position:50% 38%}
    50%{-webkit-mask-position:100% 38%;mask-position:100% 38%}
    75%{-webkit-mask-position:50% 38%;mask-position:50% 38%}
    100%{-webkit-mask-position:0% 38%;mask-position:0% 38%}}
  @media (prefers-reduced-motion: reduce){ .dotfield{animation:none;opacity:.5} }
  .annc{position:relative;z-index:1;background:var(--air);color:#fff;text-align:center;font-size:13px;padding:9px 16px;font-weight:500}
  .annc a{color:#fff;text-decoration:underline;text-underline-offset:2px;font-weight:600}
  header{position:sticky;top:0;z-index:40;background:rgba(12,20,38,.95);backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
  .bar{max-width:1240px;margin:0 auto;display:flex;align-items:center;justify-content:space-between;padding:14px 28px}
  .logo{display:flex;align-items:center;gap:9px;text-decoration:none}
  .logo-img{height:120px;width:auto;display:block;margin-left:-64px;margin-top:-38px}
  .air{color:var(--air2);font-weight:700}
  nav{display:flex;align-items:center;gap:4px}
  .nav-item{background:none;border:0;color:var(--white);font-family:inherit;font-size:14.5px;font-weight:500;padding:10px 14px;cursor:pointer;display:flex;align-items:center;gap:6px;border-radius:8px}
  .nav-item:hover,.nav-item.on{color:#fff;background:rgba(255,255,255,.07)}
  .nav-item .car{font-size:10px;color:var(--faint);transition:transform .15s}
  .nav-item.on .car{transform:rotate(180deg);color:var(--air2)}
  .right{display:flex;align-items:center;gap:8px}
  .ghost{color:var(--white);font-size:14px;text-decoration:none;padding:9px 12px;font-weight:500;border-radius:8px}
  .ghost:hover{color:#fff;background:rgba(255,255,255,.07)}
  .cta{background:var(--air);color:#fff;border:0;font-weight:600;font-size:14px;padding:10px 18px;border-radius:9px;cursor:pointer;text-decoration:none;display:inline-block}
  .cta:hover{background:var(--air2)}
  .mega{display:none;position:absolute;left:0;right:0;top:100%;background:var(--panel);border-bottom:1px solid var(--line);box-shadow:0 30px 60px -24px rgba(0,0,0,.85)}
  .mega.open{display:block}
  .mega-in{max-width:1240px;margin:0 auto;display:grid;grid-template-columns:1fr 1fr 1fr 1.1fr;padding:6px 28px 20px}
  .col{padding:18px 26px 8px;border-right:1px solid var(--line2)}
  .col:last-child{border-right:0}
  .col h4{font-size:11px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);margin-bottom:12px}
  .mi{display:flex;align-items:flex-start;gap:11px;padding:7px 0;text-decoration:none;color:var(--white)}
  .mi:hover .mt{color:var(--air2)}
  .mi .ic{flex:none;width:18px;height:18px;border-radius:5px;background:var(--airbg);border:1px solid rgba(230,57,70,.4);margin-top:1px}
  .mt{font-size:14px;font-weight:600;color:var(--white)}
  .md{font-size:12px;color:var(--soft);margin-top:1px;line-height:1.4}
  .hl h4{color:var(--air2)}
  .hcard{display:block;text-decoration:none;border:1px solid var(--line);border-radius:12px;padding:15px;margin-bottom:11px;background:var(--raise)}
  .hcard:hover{border-color:var(--air)}
  .hcard.feat{background:linear-gradient(180deg,var(--airbg),var(--raise));border-color:rgba(230,57,70,.5)}
  .hcard .ht{font-size:15px;font-weight:700;color:var(--white)}
  .hcard .hd{font-size:12px;color:var(--soft);margin-top:4px;line-height:1.45}
  .wrap{max-width:1100px;margin:0 auto;padding:0 28px;position:relative;z-index:1}
  .cta-row{display:flex;gap:12px;align-items:center;margin-top:30px;flex-wrap:wrap}
  .btn-red{background:var(--air);color:#fff;border:0;font:600 15px Inter,sans-serif;padding:13px 22px;border-radius:10px;cursor:pointer;text-decoration:none;display:inline-block}
  .btn-red:hover{background:var(--air2)}
  .pip{font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--faint);border:1px solid var(--line);border-radius:8px;padding:11px 14px;background:rgba(0,0,0,.3)}
  .scene{position:relative;z-index:1;margin:46px auto;max-width:760px;background:#0c1733;border:1px solid var(--line);border-left:3px solid var(--air);border-radius:14px;padding:26px 30px}
  .scene .ts{font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--air2)}
  .scene .big{font-size:21px;color:#eef3fb;line-height:1.5;margin-top:10px;font-weight:600}
  .scene .sub{font-size:15px;color:#cdd8ec;margin-top:12px;line-height:1.6}
  .sec{padding:46px 0;position:relative;z-index:1}
  .sec h2{font-size:32px;font-weight:800;letter-spacing:-.02em;text-align:center;color:#fff}
  .sec .lead{text-align:center;color:#cdd8ec;font-size:16px;max-width:60ch;margin:12px auto 0}
  .proof{position:relative;z-index:1;margin:46px auto;max-width:860px;text-align:center;background:linear-gradient(180deg,var(--airbg),transparent);border:1px solid rgba(230,57,70,.4);border-radius:16px;padding:34px}
  .proof h2{font-size:26px;color:#fff;font-weight:800}
  .proof p{color:#cdd8ec;font-size:15px;margin:10px auto 0;max-width:62ch;line-height:1.6}
  .proof .v{margin-top:16px;font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--air2)}
  .trust{display:flex;gap:10px;flex-wrap:wrap;justify-content:center;margin:28px 0 72px;position:relative;z-index:1}
  .trust span{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--faint);border:1px solid var(--line);padding:7px 12px;border-radius:999px}
  .mega-rich{max-width:1240px;margin:0 auto;display:grid;grid-template-columns:300px 1fr;gap:18px;padding:22px 28px 28px}
  .feature{position:relative;border-radius:16px;overflow:hidden;background:#0a1228;border:1px solid var(--line);display:flex;align-items:flex-end;min-height:280px;text-decoration:none}
  .feat-dots{position:absolute;inset:0;background-image:radial-gradient(circle, rgba(255,255,255,.5) 1px, transparent 1.7px);background-size:18px 18px;-webkit-mask-image:radial-gradient(circle at 72% 26%,#000,transparent 72%);mask-image:radial-gradient(circle at 72% 26%,#000,transparent 72%)}
  .feat-body{position:relative;padding:22px}
  .feat-kicker{color:var(--faint);font-size:12px;font-weight:600;letter-spacing:.12em;text-transform:uppercase}
  .feat-title{color:#fff;font-size:21px;font-weight:800;margin-top:8px;line-height:1.18}
  .feat-link{color:var(--air2);font-weight:600;font-size:14px;margin-top:14px}
  .prod-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
  .pcard{border:1px solid var(--line);border-radius:12px;padding:16px;text-decoration:none;background:var(--panel);display:flex;flex-direction:column}
  .pcard:hover{border-color:var(--air)}
  .pc-h{color:#fff;font-weight:700;font-size:15px}
  .pc-d{color:var(--soft);font-size:12.5px;margin-top:5px;line-height:1.42;flex:1}
  .pc-l{color:var(--air2);font-size:12px;font-weight:600;margin-top:12px}
  .hero2{position:relative;z-index:1;max-width:1180px;margin:0 auto;padding:64px 28px 18px;display:grid;grid-template-columns:1.05fr 1fr;gap:40px;align-items:center}
  .hero2 h1{font-size:46px;font-weight:800;letter-spacing:-.03em;line-height:1.09;color:#fff;margin:14px 0 0}
  .hero2 .sub{font-size:17px;color:#cdd8ec;line-height:1.6;margin-top:18px;max-width:52ch}
  .hero2 .cta-row{justify-content:flex-start}
  .bookd{color:#fff;text-decoration:none;font-weight:600;font-size:15px;padding:13px 6px}
  .bookd:hover{color:var(--air2)}
  .trustline{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--faint);margin-top:16px}
  .looprow{font-family:'JetBrains Mono',monospace;font-size:13px;letter-spacing:.14em;color:#fff;font-weight:600;margin-top:20px}
  .looprow .pipe{color:var(--air2);margin:0 9px;font-weight:700}
  .glow-bg{position:absolute;inset:-26px;z-index:-1;background:radial-gradient(60% 60% at 72% 26%, rgba(230,57,70,.24), transparent 70%);filter:blur(18px)}
  .ui-row{display:flex;justify-content:space-between;align-items:center;gap:10px;background:#101c34;border:1px solid var(--line2);border-radius:9px;padding:9px 12px;margin-bottom:7px;color:#dbe3f2;font-size:12.5px}
  .ui-row.crit{border-color:rgba(230,57,70,.45)}
  .ui-row .tag{font-size:10px;color:#ff9a9a;border:1px solid rgba(230,57,70,.45);padding:2px 8px;border-radius:999px;white-space:nowrap}
  .ui-row .ok{font-size:11px;color:#3fd99b;white-space:nowrap}
  .ui-foot{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--faint);margin-top:8px}
  .ui-title2{font-weight:700;color:#fff;font-size:13px;margin-bottom:10px}
  .chainrow{background:#101c34;border:1px solid var(--line2);border-left:2px solid var(--faint);border-radius:0 8px 8px 0;padding:8px 12px;margin-bottom:6px;color:#dbe3f2;font-size:12.5px}
  .chainrow b{color:#fff}
  .chainrow.halt{border-left-color:var(--air)}
  .verify{margin-top:8px;color:#3fd99b;font-family:'JetBrains Mono',monospace;font-size:11px}
  .feat2{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:30px}
  .fcard{background:#0c1733;border:1px solid var(--line);border-radius:18px;padding:26px 26px 0;overflow:hidden}
  .fcard h3{font-size:20px;font-weight:700;color:#fff;line-height:1.25}
  .fcard p{font-size:14px;color:#cdd8ec;line-height:1.55;margin-top:10px}
  .flink{display:inline-block;color:var(--air2);font-weight:600;font-size:13px;margin-top:12px;text-decoration:none}
  .shot{margin-top:20px;border-radius:14px 14px 0 0;border:1px solid var(--line);border-bottom:0;background:#0b1426;padding:14px}
  .quote{max-width:880px;margin:46px auto 0;text-align:center}
  .quote .q{font-size:32px;font-weight:700;color:#fff;line-height:1.2;letter-spacing:-.01em}
  .quote .qsub{font-size:17px;color:#cdd8ec;margin-top:14px;line-height:1.55}
  .globe-wrap{position:relative;display:flex;align-items:center;justify-content:center}
  .globe{width:100%;height:440px}
  .glabel{position:absolute;top:6px;left:0;right:0;text-align:center;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint)}
  .glabel .lv{color:#3fd99b}
  .statchips{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}
  .sc{font-family:'JetBrains Mono',monospace;font-size:12px;color:#cdd8ec;border:1px solid var(--line);border-radius:999px;padding:7px 13px}
  .sc b{color:#fff}
  @media(max-width:880px){ .hero2{grid-template-columns:1fr} .feat2{grid-template-columns:1fr} }
  @media(max-width:820px){ .hero2 h1{font-size:36px} }
</style>

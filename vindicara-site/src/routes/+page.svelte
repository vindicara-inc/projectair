<script>
  import { goto } from '$app/navigation';
</script>

<svelte:head>
  <title>Vindicara · Project AIR</title>
  <meta name="description" content="Project AIR by Vindicara is the forensic accountability layer for AI agents: every agent action is cryptographically signed, bound to the human who authorized it, and anchored to a public transparency log for independent verification. MIT SDK and CLI on PyPI: pip install projectair." />
  <meta property="og:title" content="Vindicara · Project AIR" />
  <meta property="og:description" content="The system of record for autonomous agents. Tamper-evident, independently verifiable evidence of what your AI agents did and who authorized it." />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://vindicara.io/" />
  <meta property="og:site_name" content="Vindicara" />
  {@html '<script type="application/ld+json">' + JSON.stringify({
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "Vindicara",
    "url": "https://vindicara.io/",
    "description": "Vindicara builds Project AIR, a forensic accountability layer for AI agents: signed, tamper-evident, independently verifiable records of agent actions, anchored to a public transparency log.",
    "sameAs": ["https://pypi.org/project/projectair/"]
  }) + '</' + 'script>'}
</svelte:head>

<div id="splash">
  <div class="glow"><i></i><i></i></div>
  <div class="grain"></div>
  <div class="splashdots"></div>
  <div class="inner">
    <div class="co">VINDICARA</div>
    <h1>The immutable record of<br>delegated authority.</h1>
    <p class="sub">The system of record for autonomous agents. Every action your agents take is bound to the human who authorized it and sealed as <b>tamper-evident, independently verifiable evidence.</b></p>
    <div class="pa"><span class="ln"></span>Project <span class="air">AIR</span><span class="tm">™</span><span class="ln"></span></div>
    <div class="cta">
      <button class="btn" onclick={() => goto('/overview')}>Enter Project AIR</button>
    </div>
  </div>
  <div class="inception">
    <a href="https://www.nvidia.com/en-us/startups/" target="_blank" rel="noopener" aria-label="NVIDIA Inception program">
      <img src="/nvidia-inception-program-badge.svg" alt="NVIDIA Inception program member badge" width="139" height="60" />
    </a>
    <span class="imember">Vindicara is a member of the NVIDIA Inception program</span>
  </div>
  <div class="status"><span class="dot"></span>This page runs on Project AIR · every request signed and anchored to Sigstore Rekor</div>
  <div class="nvlegal">&copy; 2026 NVIDIA, the NVIDIA logo, and NVIDIA Inception are trademarks and/or registered trademarks of NVIDIA Corporation in the U.S. and other countries.</div>
</div>

<style>
  #splash{position:fixed;inset:0;z-index:2;display:grid;place-items:center;text-align:center;padding:40px;
    background:radial-gradient(circle at 50% 32%,#0b1530,#04060d 72%);overflow:hidden}
  .splashdots{position:absolute;inset:0;z-index:1;pointer-events:none;
    background-image:radial-gradient(circle, rgba(255,255,255,.6) 1.1px, transparent 1.9px);
    background-size:24px 24px;
    -webkit-mask-image:radial-gradient(circle,#000 0%,transparent 45%);
    mask-image:radial-gradient(circle,#000 0%,transparent 45%);
    -webkit-mask-size:40% 40%;mask-size:40% 40%;
    -webkit-mask-repeat:no-repeat;mask-repeat:no-repeat;
    animation:dotsweep 26s linear infinite}
  .inner{position:relative;z-index:3;max-width:820px}
  .co{font-family:var(--mono);font-size:15px;letter-spacing:.42em;text-transform:uppercase;color:var(--white);font-weight:700}
  h1{font-size:60px;margin:22px 0 0;letter-spacing:-.03em}
  .sub{font-size:17px;color:var(--soft);margin:24px auto 0;max-width:54ch;line-height:1.6}
  .sub b{color:var(--white);font-weight:600}
  .pa{display:inline-flex;align-items:center;gap:10px;margin-top:30px;font-family:var(--display);font-size:20px;font-weight:600}
  .pa .ln{width:42px;height:1px;background:var(--line)}
  .pa .tm{font-size:9px;vertical-align:super;color:var(--faint)}
  .cta{display:flex;gap:14px;justify-content:center;margin-top:34px}
  .inception{position:relative;z-index:3;margin-top:34px;display:flex;flex-direction:column;align-items:center;gap:8px}
  .inception img{display:block;width:139px;height:auto}
  .imember{font-family:var(--mono);font-size:10px;letter-spacing:.08em;color:var(--faint)}
  .nvlegal{position:absolute;bottom:10px;left:0;right:0;text-align:center;font-size:8.5px;color:var(--faint);opacity:.55;z-index:3;padding:0 20px}
  .status{position:absolute;bottom:30px;left:0;right:0;text-align:center;font-family:var(--mono);font-size:10px;letter-spacing:.08em;color:var(--faint);z-index:3}
  .status .dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--good);margin-right:7px;box-shadow:0 0 8px var(--good)}
  @media (max-height:780px){ h1{font-size:48px} }
  @media (max-width:700px){ h1{font-size:38px} }
</style>

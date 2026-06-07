<script>
  import { goto } from '$app/navigation';
</script>

<svelte:head><title>Vindicara · Project AIR</title></svelte:head>

<div id="splash">
  <div class="glow"><i></i><i></i></div>
  <div class="grain"></div>
  <div class="splashdots"></div>
  <div class="inner">
    <div class="co">VINDICARA</div>
    <h1>The immutable record of<br>delegated authority.</h1>
    <p class="sub">Industry-leading security infrastructure for the agent economy. We make the record that proves <b>what your AI agents did, and who authorized them.</b></p>
    <div class="pa"><span class="ln"></span>Project <span class="air">AIR</span><span class="tm">™</span><span class="ln"></span></div>
    <div class="cta">
      <button class="btn" onclick={() => goto('/overview')}>Enter Project AIR</button>
    </div>
  </div>
  <div class="status"><span class="dot"></span>This page runs on Project AIR · every request signed and anchored to Sigstore Rekor</div>
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
  .status{position:absolute;bottom:30px;left:0;right:0;text-align:center;font-family:var(--mono);font-size:10px;letter-spacing:.08em;color:var(--faint);z-index:3}
  .status .dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--good);margin-right:7px;box-shadow:0 0 8px var(--good)}
  @media (max-height:780px){ h1{font-size:48px} }
  @media (max-width:700px){ h1{font-size:38px} }
</style>

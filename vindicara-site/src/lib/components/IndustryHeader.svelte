<script>
  // Shared sticky header. Solutions mega-menu + a hamburger menu (holds FlightDeck + nav).
  // Styling comes from $lib/styles/industry.css (imported by the page/shell).
  // @ts-nocheck
  import { onMount } from 'svelte';

  let open = $state(false);       // Solutions mega-menu
  let menuOpen = $state(false);   // hamburger menu

  function openFlightdeck() {
    menuOpen = false;
    const w = 1440, h = 900;
    const left = Math.max(0, Math.round((window.screen.width - w) / 2));
    const top = Math.max(0, Math.round((window.screen.height - h) / 2));
    window.open('/flightdeck', 'flightdeck', `popup,width=${w},height=${h},left=${left},top=${top}`);
  }

  onMount(() => {
    // Close menus when clicking outside the header (robust against Svelte 5 event delegation).
    const onDoc = (e) => { if (!e.target.closest('header')) { open = false; menuOpen = false; } };
    document.addEventListener('click', onDoc);
    return () => document.removeEventListener('click', onDoc);
  });
</script>

<header>
  <div class="bar">
    <a class="logo" href="/home"><img src="/plane.svg" alt="" class="logo-img" /><span class="wordmark"><span class="proj">project</span> <span class="air-wm">AIR</span><span class="tm">™</span></span></a>
    <nav>
      <button class="nav-item" class:on={open} onclick={() => { open = !open; menuOpen = false; }}>Solutions <span class="car">▾</span></button>
      <a href="/platform" class="nv">Products</a>
      <a href="/about" class="nv">Company</a>
      <a href="/pricing" class="nv">Pricing</a>
    </nav>
    <div class="right">
      <a class="cta" href="/contact">Book a demo</a>
      <button class="burger" class:on={menuOpen} aria-label="Menu" onclick={() => { menuOpen = !menuOpen; open = false; }}><span></span><span></span><span></span></button>
    </div>
  </div>

  <!-- Solutions mega-menu -->
  <div class="mega" class:open>
    <div class="mega-in">
      <div class="col">
        <h4>By industry</h4>
        <a class="mi" href="/solutions/healthcare"><span class="ic"></span><span><span class="mt">Healthcare</span><span class="md">FHIR/HL7, HIPAA, BAA</span></span></a>
        <a class="mi" href="/solutions/finance"><span class="ic"></span><span><span class="mt">Finance &amp; insurance</span><span class="md">FINRA/SEC audit trails</span></span></a>
        <a class="mi" href="/solutions/government"><span class="ic"></span><span><span class="mt">Government &amp; public sector</span><span class="md">Air-gapped, sovereign</span></span></a>
        <a class="mi" href="/solutions/platforms"><span class="ic"></span><span><span class="mt">AI agent platforms</span><span class="md">Accountability for your users</span></span></a>
      </div>
      <div class="col">
        <h4>By use case</h4>
        <a class="mi" href="/solutions/audit-readiness"><span class="ic"></span><span><span class="mt">Audit readiness</span><span class="md">SOC 2 · HIPAA · ISO 42001 · EU AI Act</span></span></a>
        <a class="mi" href="/solutions/incident-response"><span class="ic"></span><span><span class="mt">Incident response</span><span class="md">Reconstruct &amp; prove in minutes</span></span></a>
        <a class="mi" href="/solutions/compliance-evidence"><span class="ic"></span><span><span class="mt">Compliance evidence</span><span class="md">Records assessors actually ask for</span></span></a>
        <a class="mi" href="/solutions/agent-governance"><span class="ic"></span><span><span class="mt">Agent governance</span><span class="md">Who authorized what, proven</span></span></a>
      </div>
      <div class="col">
        <h4>By framework</h4>
        <a class="mi" href="/solutions/soc2"><span class="ic"></span><span><span class="mt">SOC 2</span><span class="md">CC7.2 / CC7.3 agent evidence</span></span></a>
        <a class="mi" href="/solutions/hipaa"><span class="ic"></span><span><span class="mt">HIPAA</span><span class="md">45 CFR 164.312(b)</span></span></a>
        <a class="mi" href="/solutions/iso-42001"><span class="ic"></span><span><span class="mt">ISO 42001</span><span class="md">AI management system</span></span></a>
        <a class="mi" href="/solutions/eu-ai-act"><span class="ic"></span><span><span class="mt">EU AI Act</span><span class="md">Article 12 logging</span></span></a>
      </div>
      <div class="col hl">
        <h4>Highlights</h4>
        <a class="hcard feat" href="/contact"><div class="ht">Book an agent audit</div><div class="hd">See what your agents did. Free eval, nothing deployed.</div></a>
        <a class="hcard" href="/evidence"><div class="ht">Hardware-rooted evidence</div><div class="hd">Validated on real NVIDIA H100 confidential compute.</div></a>
      </div>
    </div>
  </div>

  <!-- Hamburger menu -->
  <div class="hammenu" class:open={menuOpen}>
    <button class="hm-fd" onclick={openFlightdeck}>FlightDeck →</button>
    <a class="hm-l" href="/flightdeck">Sign in</a>
    <a class="hm-l" href="/explore">Explore everything</a>
  </div>
</header>

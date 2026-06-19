<script>
  // @ts-nocheck
  import { onMount } from 'svelte';
  import SiteHeader from '$lib/components/SiteHeader.svelte';
  import { setupReveal } from '$lib/reveal.js';
  import '$lib/styles/industry.css';
  onMount(setupReveal);

  const groups = [
    {
      label: 'Solutions · By industry', accent: '#ff5763',
      items: [
        ['Healthcare', 'Prove what your agents did to ePHI.', '/solutions/healthcare'],
        ['Finance & insurance', 'The SEC 17a-4 audit trail, for the agent layer.', '/solutions/finance'],
        ['Government & public sector', 'Sovereign accountability that never phones home.', '/solutions/government'],
        ['AI agent platforms', 'Hand your users provable accountability.', '/solutions/platforms']
      ]
    },
    {
      label: 'Solutions · By use case', accent: '#ffd84d',
      items: [
        ['Audit readiness', 'Walk into the assessment already covered.', '/solutions/audit-readiness'],
        ['Incident response', 'Reconstruct and prove an incident in minutes.', '/solutions/incident-response'],
        ['Compliance evidence', 'The record assessors actually ask for.', '/solutions/compliance-evidence'],
        ['Agent governance', 'Who authorized what, proven.', '/solutions/agent-governance']
      ]
    },
    {
      label: 'Solutions · By framework', accent: '#a78bfa',
      items: [
        ['SOC 2', 'CC7.2 / CC7.3 evidence for the agent layer.', '/solutions/soc2'],
        ['HIPAA', '45 CFR 164.312(b) audit controls for agents.', '/solutions/hipaa'],
        ['ISO 42001', 'Operational evidence for your AI management system.', '/solutions/iso-42001'],
        ['EU AI Act', 'Article 12 logging, Article 73 incident reporting.', '/solutions/eu-ai-act']
      ]
    },
    {
      label: 'Products', accent: '#ff5763',
      items: [
        ['The platform', 'Monitor, enforce, prove, account.', '/platform'],
        ['Audit', 'The record you take into your audit.', '/audit'],
        ['Prove', 'Signed, anchored, independently verifiable.', '/prove'],
        ['Protect', 'Halt agents before harm, not after.', '/protect'],
        ['Monitor', '16 detectors, every action, live.', '/monitor'],
        ['Evidence', 'The forensic evidence model.', '/evidence'],
        ['Structural Verification', "The deterministic floor agents can't talk past.", '/structural-verification'],
        ['Admissibility', 'Self-authenticating, FRE 902(13)–(14).', '/admissibility'],
        ['FlightDeck', 'The operator console for your fleet.', '/flightdeck'],
        ['AIR SDK & CLI', 'Open source, on PyPI. Start in an afternoon.', '/get-started'],
        ['Standards', 'How AIR maps to the frameworks.', '/standards'],
        ['Pricing', 'Free shows the shape; paid makes it provable.', '/pricing']
      ]
    },
    {
      label: 'Company & resources', accent: '#9fb0d0',
      items: [
        ['About', 'Why we build the record.', '/about'],
        ['Blog', 'Writing on agent accountability.', '/blog'],
        ['Press', 'News & coverage.', '/press'],
        ['Design partner', 'Shape the roadmap, founder-led.', '/design-partner'],
        ['Contact', 'Book an agent audit.', '/contact'],
        ['Security', 'Our security posture.', '/security'],
        ['Terms', 'Terms of service.', '/terms'],
        ['Privacy', 'Privacy policy.', '/privacy']
      ]
    }
  ];
</script>

<svelte:head>
  <title>Explore · Project AIR — everything in one place</title>
  <meta name="description" content="The full directory of Project AIR — every solution by industry, use case and framework, every product, and every company resource, one line each." />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
</svelte:head>

<div class="ind">
  <div class="dotfield"></div>
  <SiteHeader />

  <section class="dhero">
    <div class="eyebrow">Directory</div>
    <h1>Everything <span class="proj">project</span> <span class="air">AIR</span>, in one place.</h1>
    <p class="lead">Every solution, product, and resource — one line each.</p>
  </section>

  {#each groups as g}
    <section class="grp" style="--ga:{g.accent}">
      <div class="ghead"><span class="gdot"></span><h2>{g.label}</h2></div>
      <div class="cards">
        {#each g.items as [title, desc, href]}
          <a class="c rv" {href}>
            <div class="ct">{title}</div>
            <div class="cd">{desc}</div>
            <div class="ca">→</div>
          </a>
        {/each}
      </div>
    </section>
  {/each}

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <span class="fmail">support@vindicara.io · This page is itself on the record.</span>
  </footer>
</div>

<style>
  .dhero{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:54px 28px 8px}
  .dhero h1{font-size:clamp(30px,5vw,46px);font-weight:800;letter-spacing:-.02em;color:#fff;margin:12px 0 0;line-height:1.1}
  .dhero h1 .proj{font-family:'Spectral',Georgia,serif;font-style:italic;font-weight:500;color:#fff}
  .dhero .lead{color:var(--soft);font-size:16px;margin-top:12px}

  .grp{position:relative;z-index:1;max-width:1100px;margin:40px auto 0;padding:0 28px}
  .ghead{display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--line);padding-bottom:12px;margin-bottom:18px}
  .gdot{width:9px;height:9px;border-radius:50%;background:var(--ga);box-shadow:0 0 12px var(--ga)}
  .ghead h2{font-family:'JetBrains Mono',monospace;font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:var(--soft);font-weight:500}

  .cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
  .c{display:block;position:relative;background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:16px 18px;text-decoration:none;transition:.16s}
  .c:hover{border-color:var(--ga);box-shadow:0 0 0 1px var(--ga),0 14px 34px -20px rgba(0,0,0,.8);transform:translateY(-2px)}
  .ct{font-size:15px;font-weight:700;color:#fff}
  .cd{font-size:12.5px;color:var(--soft);margin-top:5px;line-height:1.5;max-width:34ch}
  .ca{position:absolute;top:15px;right:16px;color:var(--ga);font-size:14px;opacity:0;transition:.16s}
  .c:hover .ca{opacity:1}

  @media(max-width:860px){ .cards{grid-template-columns:1fr 1fr} }
  @media(max-width:560px){ .cards{grid-template-columns:1fr} }
</style>

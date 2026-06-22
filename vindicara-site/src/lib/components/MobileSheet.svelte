<script>
  // @ts-nocheck
  // Touch nav drawer for the marketing header, shown <=820px where the desktop
  // mega-nav is hidden. Rendered OUTSIDE <header> on purpose: the header's
  // backdrop-filter is a containing block for position:fixed, which would clip a
  // full-screen drawer nested inside it. Because it lives outside <header>, the
  // header's CSS custom properties do not cascade in; the palette is redefined on
  // .mnav below. Keep the link taxonomy in sync with the megas in SiteHeader.svelte.
  import { beginAuth0Login } from '$lib/console/stores/session';

  let { open = $bindable(false) } = $props();
  let expanded = $state(null);

  const sections = [
    { id: 'solutions', label: 'Solutions', groups: [
      { label: 'By industry', links: [
        { t: 'Healthcare', h: '/solutions/healthcare' },
        { t: 'Finance & insurance', h: '/solutions/finance' },
        { t: 'Government & public sector', h: '/solutions/government' },
        { t: 'AI agent platforms', h: '/solutions/platforms' }
      ] },
      { label: 'By use case', links: [
        { t: 'Audit readiness', h: '/solutions/audit-readiness' },
        { t: 'Incident response', h: '/solutions/incident-response' },
        { t: 'Compliance evidence', h: '/solutions/compliance-evidence' },
        { t: 'Agent governance', h: '/solutions/agent-governance' }
      ] },
      { label: 'By framework', links: [
        { t: 'SOC 2', h: '/solutions/soc2' },
        { t: 'HIPAA', h: '/solutions/hipaa' },
        { t: 'ISO 42001', h: '/solutions/iso-42001' },
        { t: 'EU AI Act', h: '/solutions/eu-ai-act' }
      ] }
    ] },
    { id: 'products', label: 'Products', groups: [
      { label: null, links: [
        { t: 'Platform', h: '/platform' },
        { t: 'Audit', h: '/audit' },
        { t: 'Prove', h: '/prove' },
        { t: 'Protect', h: '/protect' },
        { t: 'Monitor', h: '/monitor' },
        { t: 'AIR SDK & CLI', h: '/get-started' },
        { t: 'FlightDeck', h: '/flightdeck?demo=1' },
        { t: 'AIR Cloud', h: '/pricing' },
        { t: 'Admissibility', h: '/admissibility' },
        { t: 'Structural Verification', h: '/structural-verification' }
      ] }
    ] },
    { id: 'company', label: 'Company', groups: [
      { label: null, links: [
        { t: 'About', h: '/about' },
        { t: 'Contact', h: '/contact' },
        { t: 'Policy', h: '/policy' },
        { t: 'Blog', h: '/blog' },
        { t: 'Press', h: '/press' },
        { t: 'Docs & GitHub', h: 'https://github.com/vindicara-inc/projectair', ext: true },
        { t: 'Partners', h: '/design-partner' }
      ] }
    ] }
  ];
  const direct = [
    { t: 'Customers', h: '/get-started' },
    { t: 'Pricing', h: '/pricing' }
  ];

  function close() { open = false; expanded = null; }
  function toggleSection(id) { expanded = expanded === id ? null : id; }
  function onSignin() { close(); beginAuth0Login(); }
  function onKey(e) { if (e.key === 'Escape') close(); }

  // Lock the page behind the drawer while it is open.
  $effect(() => {
    if (typeof document === 'undefined') return;
    document.body.style.overflow = open ? 'hidden' : '';
    return () => { document.body.style.overflow = ''; };
  });

  // Force-close if the viewport grows past the mobile breakpoint, so an open
  // drawer never lingers (or keeps the body scroll-locked) on desktop.
  $effect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(min-width:901px)');
    const sync = () => { if (mq.matches) open = false; };
    sync();
    mq.addEventListener('change', sync);
    return () => mq.removeEventListener('change', sync);
  });
</script>

<svelte:window onkeydown={onKey} />

<div class="mnav">
  <div class="scrim" class:open onclick={close} aria-hidden="true"></div>

  <nav id="mobile-nav" class="sheet" class:open inert={!open} aria-label="Site">
    <div class="sheet-in">
      {#each sections as s}
        <button
          class="sect"
          class:on={expanded === s.id}
          aria-expanded={expanded === s.id}
          onclick={() => toggleSection(s.id)}
        >{s.label}<span class="chev">▾</span></button>
        {#if expanded === s.id}
          <div class="panel">
            {#each s.groups as g}
              {#if g.label}<div class="glabel">{g.label}</div>{/if}
              {#each g.links as l}
                <a class="lnk" href={l.h} target={l.ext ? '_blank' : null} rel={l.ext ? 'noopener' : null} onclick={close}>{l.t}</a>
              {/each}
            {/each}
          </div>
        {/if}
      {/each}

      {#each direct as l}
        <a class="sect solo" href={l.h} onclick={close}>{l.t}</a>
      {/each}

      <div class="acts">
        <button type="button" class="signin" onclick={onSignin}>Sign in</button>
        <a class="cta" href="/contact" onclick={close}>Book a demo</a>
      </div>
    </div>
  </nav>
</div>

<style>
  .mnav{
    --panel:#101c34; --raise:#16264a;
    --white:#F7FAFF; --soft:#F3D98A; --faint:#FFC83D;
    --line:rgba(255,255,255,.14); --line2:rgba(255,255,255,.08);
    --air:#E63946; --air2:#ff5763;
    font-family:'Inter',system-ui,-apple-system,sans-serif;
  }
  .scrim{position:fixed;inset:0;background:rgba(4,8,18,.62);backdrop-filter:blur(2px);
    opacity:0;pointer-events:none;transition:opacity .25s ease;z-index:45}
  .scrim.open{opacity:1;pointer-events:auto}
  .sheet{display:block;position:fixed;top:0;right:0;bottom:0;width:min(87vw,360px);background:var(--panel);
    border-left:1px solid var(--line);box-shadow:-34px 0 64px -22px rgba(0,0,0,.85);
    transform:translateX(100%);transition:transform .28s cubic-bezier(.4,0,.2,1);
    z-index:46;overflow-y:auto;-webkit-overflow-scrolling:touch}
  .sheet.open{transform:translateX(0)}
  .sheet-in{display:flex;flex-direction:column;padding:14px 18px calc(22px + env(safe-area-inset-bottom))}
  .sect{width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;
    background:none;border:0;border-bottom:1px solid var(--line2);color:var(--white);
    font-family:inherit;font-size:16px;font-weight:600;padding:15px 2px;cursor:pointer;text-align:left;
    text-decoration:none}
  .sect.solo{display:flex}
  .sect .chev{font-size:11px;color:var(--faint);transition:transform .18s ease}
  .sect.on{color:#fff}
  .sect.on .chev{transform:rotate(180deg);color:var(--air2)}
  .panel{display:flex;flex-direction:column;padding:2px 2px 12px}
  .glabel{font-size:10.5px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;
    color:var(--faint);margin:14px 0 3px}
  .lnk{color:var(--soft);text-decoration:none;font-size:14.5px;line-height:1.3;
    padding:10px 0 10px 13px;border-left:1px solid var(--line2)}
  .lnk:hover,.lnk:active{color:var(--air2);border-left-color:var(--air2)}
  .acts{display:flex;flex-direction:column;gap:10px;margin-top:20px}
  .signin{background:none;border:1px solid var(--line);color:var(--white);font-family:inherit;
    font-weight:600;font-size:15px;padding:13px;border-radius:10px;cursor:pointer}
  .signin:hover{border-color:rgba(255,255,255,.3)}
  .cta{background:var(--air);color:#fff;text-align:center;font-weight:700;font-size:15px;
    padding:14px;border-radius:10px;text-decoration:none}
  .cta:hover,.cta:active{background:var(--air2)}
  .sect:focus-visible,.lnk:focus-visible,.signin:focus-visible,.cta:focus-visible{
    outline:2px solid var(--air2);outline-offset:2px;border-radius:4px}
  @media(min-width:901px){ .mnav{display:none} }
  @media(prefers-reduced-motion:reduce){
    .sheet,.scrim,.sect .chev{transition:none}
  }
</style>

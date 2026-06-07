<script>
  import { goto } from '$app/navigation';

  let { active = '', title = '', scroll = false, children } = $props();
  let menuOpen = $state(false);

  const product = [
    { id: 'overview',     label: 'Overview',     to: '/overview',     num: '01' },
    { id: 'platform',     label: 'The platform', to: '/platform',     num: '02' },
    { id: 'evidence',     label: 'Evidence',     to: '/evidence',     num: '03' },
    { id: 'structural-verification', label: 'Structural verification', to: '/structural-verification', num: '04' },
    { id: 'standards',    label: 'Standards alignment', to: '/standards', num: '05' }
  ];
  const proof = [
    { id: 'admissibility', label: 'Admissibility', to: '/admissibility', num: '06' },
    { id: 'pricing',       label: 'Pricing',       to: '/pricing',       num: '07' }
  ];
  const company = [
    { id: 'about', label: 'About', to: '/about' },
    { id: 'blog',  label: 'Blog',  to: '/blog' },
    { id: 'press', label: 'Press', to: '/press' },
    { id: 'terms', label: 'Terms', to: '/terms' },
    { id: 'privacy', label: 'Privacy', to: '/privacy' },
    { id: 'security', label: 'Security', to: '/security' }
  ];
</script>

<div class="glow"><i></i><i></i></div>
<div class="grain"></div>

<div class="app">
  <aside class="rail">
    <a class="brand" href="/" data-sveltekit-preload-data>
      <div class="co">Project</div>
      <div class="pa">Project <span class="air">AIR</span><span class="tm">™</span></div>
    </a>
    <nav class="nav">
      <div class="lbl">Product</div>
      {#each product as n}
        <a class="nv {active===n.id?'on':''}" href={n.to}><span class="num">{n.num}</span>{n.label}</a>
      {/each}
      <div class="lbl">Proof &amp; trust</div>
      {#each proof as n}
        <a class="nv {active===n.id?'on':''}" href={n.to}><span class="num">{n.num}</span>{n.label}</a>
      {/each}
    </nav>
    <div class="railcta">
      <button class="fd" onclick={() => goto('/flightdeck')}>F L I G H T D E C K</button>
      <button class="dp" onclick={() => goto('/design-partner')}>Become a design partner</button>
    </div>
    <div class="status"><span class="dot"></span><b>Ops chain live</b><br>Rekor #1466351923 · anchored 41s ago</div>
  </aside>

  <div class="main">
    <div class="topbar">
      <button class="burger" onclick={() => (menuOpen = !menuOpen)} aria-label="Menu"><span></span><span></span><span></span></button>
      <a class="mbrand" href="/">Project <span class="air">AIR</span></a>
      <div class="crumb">vindicara.io / <b>{title}</b></div>
      <span class="sp"></span>
      <a class="ghostlink" href="https://github.com/vindicara-inc/projectair" target="_blank" rel="noopener">View source · MIT</a>
      <span class="chip"><span class="pmt">$</span> pip install projectair</span>
    </div>

    {#if menuOpen}
      <nav class="mmenu">
        <div class="mlbl">Product</div>
        {#each product as n}<a class="ml {active===n.id?'on':''}" href={n.to} onclick={() => (menuOpen = false)}>{n.label}</a>{/each}
        <div class="mlbl">Proof &amp; trust</div>
        {#each proof as n}<a class="ml {active===n.id?'on':''}" href={n.to} onclick={() => (menuOpen = false)}>{n.label}</a>{/each}
        <div class="mlbl">Company</div>
        {#each company as c}<a class="ml" href={c.to} onclick={() => (menuOpen = false)}>{c.label}</a>{/each}
        <a class="ml" href="/contact" onclick={() => (menuOpen = false)}>Contact</a>
        <button class="fd" onclick={() => { menuOpen = false; goto('/flightdeck'); }}>F L I G H T D E C K</button>
        <button class="dp" onclick={() => { menuOpen = false; goto('/design-partner'); }}>Become a design partner</button>
      </nav>
    {/if}

    <div class="stage {scroll ? 'scroll' : 'fixed'}">
      {@render children?.()}
    </div>

    <footer class="foot">
      <span class="fco">Vindicara · Project <span class="air">AIR</span> v1.0.1</span>
      <nav class="fnav">
        {#each company as c}<a href={c.to}>{c.label}</a>{/each}
        <a href="/contact">Contact</a>
      </nav>
      <span class="fmail">support@vindicara.io · press@vindicara.io</span>
    </footer>
  </div>
</div>

<style>
  .app{display:grid;grid-template-columns:256px 1fr;height:100vh;position:relative;z-index:2}
  .rail{border-right:1px solid var(--line);display:flex;flex-direction:column;background:linear-gradient(180deg,var(--navy1),var(--navy))}
  .brand{height:50px;display:flex;flex-direction:column;justify-content:center;padding:0 22px;border-bottom:1px solid var(--line);text-decoration:none;color:var(--white)}
  .brand .co{display:none}
  .brand .pa{font-family:var(--display);font-size:19px;font-weight:600;line-height:1}
  .brand .tm{font-size:9px;vertical-align:super;color:var(--faint)}
  .nav{padding:14px 12px;flex:1;display:flex;flex-direction:column;gap:2px;overflow:auto}
  .nav .lbl{font-family:var(--mono);font-size:9px;letter-spacing:.18em;text-transform:uppercase;color:var(--faint);padding:12px 12px 6px}
  .nv{display:flex;align-items:center;gap:12px;text-decoration:none;padding:10px 12px;color:var(--soft);font-size:13.5px;font-weight:500;border-left:2px solid transparent;transition:.14s}
  .nv .num{font-family:var(--mono);font-size:10px;color:var(--faint);width:18px}
  .nv:hover{background:rgba(255,255,255,.04);color:var(--white)}
  .nv.on{background:var(--panel);color:var(--white);border-left-color:var(--air);font-weight:600;box-shadow:var(--shadow)}
  .nv.on .num{color:var(--air2)}
  .railcta{padding:14px;border-top:1px solid var(--line)}
  .fd{display:block;width:100%;text-align:center;padding:11px;background:#fff;color:var(--air);border:0;cursor:pointer;font-family:var(--ui);font-weight:700;font-size:12.5px;letter-spacing:.04em;transition:.15s;margin-bottom:9px}
  .fd:hover{background:#f0e6ef}
  .dp{display:block;width:100%;text-align:center;padding:11px;background:var(--air);color:#fff;border:0;cursor:pointer;font-family:var(--ui);font-weight:600;font-size:12.5px;transition:.15s}
  .dp:hover{background:var(--air2)}
  .status{padding:11px 16px;border-top:1px solid var(--line);font-family:var(--mono);font-size:9.5px;color:var(--faint);line-height:1.7}
  .status .dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--good);margin-right:6px;vertical-align:middle;box-shadow:0 0 7px var(--good)}
  .status b{color:var(--soft);font-weight:500}

  .main{display:flex;flex-direction:column;min-width:0;height:100vh}
  .topbar{height:50px;flex:0 0 50px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:14px;padding:0 30px;background:var(--navy1)}
  .crumb{font-family:var(--mono);font-size:10.5px;color:var(--faint)} .crumb b{color:var(--soft);font-weight:500}
  .topbar .sp{flex:1}
  .ghostlink{font-family:var(--mono);font-size:11px;color:var(--air2);text-decoration:none;border-bottom:1px solid transparent}
  .ghostlink:hover{border-bottom-color:var(--air2)}

  .stage{flex:1;min-height:0;padding:34px 40px}
  .stage.fixed{overflow:hidden}
  .stage.scroll{overflow:auto}

  .foot{height:42px;flex:0 0 42px;border-top:1px solid var(--line);display:flex;align-items:center;gap:18px;padding:0 30px;background:var(--navy1);font-size:11.5px}
  .fco{font-family:var(--mono);font-size:10px;color:var(--soft)}
  .fnav{display:flex;gap:16px;margin-left:8px}
  .fnav a{color:var(--white);text-decoration:none} .fnav a:hover{color:var(--air2)}
  .fmail{margin-left:auto;font-family:var(--mono);font-size:10px;color:var(--soft)}

  .burger{display:none;width:36px;height:36px;border:1px solid var(--line);background:rgba(255,255,255,.04);flex-direction:column;align-items:center;justify-content:center;gap:4px;cursor:pointer;flex:0 0 36px;padding:0}
  .burger span{display:block;width:16px;height:1.6px;background:var(--soft)}
  .mbrand{display:none;font-family:var(--display);font-size:16px;font-weight:600;color:var(--white);text-decoration:none}
  .mmenu{display:flex;flex-direction:column;gap:0;padding:10px 18px 22px;border-bottom:1px solid var(--line);background:var(--navy1);position:relative;z-index:4}
  .mmenu .mlbl{font-family:var(--mono);font-size:9px;letter-spacing:.18em;text-transform:uppercase;color:var(--faint);padding:14px 2px 4px}
  .mmenu .ml{padding:12px 2px;color:var(--soft);text-decoration:none;font-size:15.5px;border-bottom:1px solid var(--line)}
  .mmenu .ml.on{color:var(--white);font-weight:600}
  .mmenu .fd{margin-top:16px}
  .mmenu .dp{margin-top:9px}

  @media (max-height:780px){ .stage.fixed{overflow:auto} }
  @media (max-width:1080px){
    .app{grid-template-columns:1fr} .rail{display:none}
    .main{height:auto;min-height:100vh} .stage.fixed{overflow:visible}
    .burger{display:flex} .mbrand{display:block}
    .crumb,.ghostlink,.chip{display:none}
    .topbar{padding:0 16px;gap:12px}
    .stage{padding:22px 18px}
    .foot{flex-wrap:wrap;height:auto;padding:12px 20px;gap:8px} .fmail{margin-left:0;width:100%}
  }
</style>

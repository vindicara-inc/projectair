<script lang="ts">
  import '$lib/console/console.css';
  import { onMount } from 'svelte';
  import { get } from 'svelte/store';
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import Rail from '$lib/console/components/Rail.svelte';
  import Drawer from '$lib/console/components/Drawer.svelte';
  import LockScreen from '$lib/console/components/LockScreen.svelte';
  import ModeToggle from '$lib/console/components/forensics/ModeToggle.svelte';
  import DemoBadge from '$lib/console/components/forensics/DemoBadge.svelte';
  import SignIn from '$lib/console/components/forensics/SignIn.svelte';
  import ClockOut from '$lib/console/components/forensics/ClockOut.svelte';
  import { beginAuth0Login, logout, sessionToken } from '$lib/console/stores/session';
  import { mode } from '$lib/console/stores/mode';
  import { operator, signedIn, openSignIn } from '$lib/console/stores/operator';

  let { children } = $props();
  let drawerOpen = $state(false);

  // Auth-gate: in LIVE mode with no token, send the operator to Auth0 first.
  // Demo mode never redirects (public showcase). Skip on /flightdeck/auth/*.
  onMount(() => {
    const onAuthRoute = get(page).url.pathname.startsWith('/flightdeck/auth/');
    if (!onAuthRoute && get(mode) === 'live' && !get(sessionToken)) {
      void beginAuth0Login();
    }
  });

  const titles: Record<string, { title: string; crumb: string; dept: boolean }> = {
    '/flightdeck': { title: 'FlightDeck', crumb: '/ department', dept: true },
    '/flightdeck/': { title: 'FlightDeck', crumb: '/ department', dept: true },
    '/flightdeck/incidents': { title: 'Incidents', crumb: '/ incidents', dept: false },
    '/flightdeck/incidents/': { title: 'Incidents', crumb: '/ incidents', dept: false },
    '/flightdeck/report': { title: 'Report', crumb: '/ report', dept: false },
    '/flightdeck/report/': { title: 'Report', crumb: '/ report', dept: false },
    '/flightdeck/readiness': { title: 'Deterministic floor', crumb: '', dept: false },
    '/flightdeck/readiness/': { title: 'Deterministic floor', crumb: '', dept: false },
    '/flightdeck/agents': { title: 'Agent fleet', crumb: '/ agent fleet', dept: false },
    '/flightdeck/agents/': { title: 'Agent fleet', crumb: '/ agent fleet', dept: false },
    '/flightdeck/stepup': { title: 'Step-up queue', crumb: '/ step-up queue', dept: false },
    '/flightdeck/stepup/': { title: 'Step-up queue', crumb: '/ step-up queue', dept: false },
    '/flightdeck/handoff': { title: 'Handoff lineage', crumb: '/ handoff lineage', dept: false },
    '/flightdeck/handoff/': { title: 'Handoff lineage', crumb: '/ handoff lineage', dept: false },
    '/flightdeck/evidence': { title: 'Evidence packs', crumb: '/ evidence packs', dept: false },
    '/flightdeck/evidence/': { title: 'Evidence packs', crumb: '/ evidence packs', dept: false },
    '/flightdeck/rules': { title: 'Rules', crumb: '/ rules', dept: false },
    '/flightdeck/rules/': { title: 'Rules', crumb: '/ rules', dept: false },
    '/flightdeck/plugins': { title: 'Plugins', crumb: '/ plugins', dept: false },
    '/flightdeck/plugins/': { title: 'Plugins', crumb: '/ plugins', dept: false },
    '/flightdeck/insurance': { title: 'Insurance API', crumb: '/ insurance API', dept: false },
    '/flightdeck/insurance/': { title: 'Insurance API', crumb: '/ insurance API', dept: false },
    '/flightdeck/settings': { title: 'Settings', crumb: '/ settings', dept: false },
    '/flightdeck/settings/': { title: 'Settings', crumb: '/ settings', dept: false }
  };
  let meta = $derived(titles[$page.url.pathname] ?? { title: 'FlightDeck', crumb: $page.url.pathname, dept: false });
</script>

<div class="aurora"><i></i><i></i><i></i></div>
<div class="grain"></div>

<div class="app">
  <Rail />
  <main class="work">
    <div class="wbar reveal">
      <button class="burger" onclick={() => (drawerOpen = true)} aria-label="menu"><span></span><span></span><span></span></button>
      {#if meta.title}<h1>{meta.title}</h1>{/if}{#if meta.crumb}<span class="crumb">{meta.crumb}</span>{/if}
      {#if meta.dept}<span class="deptTag">Department view</span>{/if}
      <button class="navlink" class:on={$page.url.pathname.startsWith('/flightdeck/incidents')} onclick={() => goto('/flightdeck/incidents')}>Incidents</button>
      <button class="navlink" class:on={$page.url.pathname.startsWith('/flightdeck/report')} onclick={() => goto('/flightdeck/report')}>Report</button>
      <span class="spacer"></span>
      <DemoBadge />
      <ModeToggle />
      {#if $mode === 'demo'}
        {#if $signedIn}
          <button class="me" onclick={openSignIn} title="Sign in / switch operator">
            <div><div class="men">{$operator.name}</div><div class="mer">{$operator.organization}</div></div>
            <span class="melock">{$operator.authMethod}</span>
          </button>
        {:else}
          <button class="authbtn" onclick={openSignIn}><span class="key"></span>Authorize</button>
        {/if}
      {:else if $sessionToken}
        <button class="exitbtn" onclick={() => logout()}>Exit</button>
      {:else}
        <button class="authbtn" onclick={() => beginAuth0Login()}><span class="key"></span>Authorize</button>
      {/if}
      <a class="backsite" href="/">vindicara.io</a>
    </div>

    {#key $mode}
      {@render children()}
    {/key}

    <footer class="tagfoot">
      <span class="w">Monitor</span>
      <span class="bar">|</span>
      <span class="w">Protect</span>
      <span class="bar">|</span>
      <span class="w">Prove</span>
    </footer>
  </main>
</div>

<Drawer open={drawerOpen} onclose={() => (drawerOpen = false)} />
<LockScreen />
<SignIn />
<ClockOut />

<style>
  .app { position: relative; z-index: 2; display: grid; grid-template-columns: 320px 1fr; gap: 18px; align-items: start; min-height: 100vh; padding: 22px; }
  .work { display: flex; flex-direction: column; gap: 24px; min-width: 0; min-height: calc(100vh - 44px); }
  .wbar { display: flex; align-items: center; gap: 14px; height: 44px; }
  .wbar h1 { font-family: var(--display); font-weight: 600; font-size: 25px; letter-spacing: -.02em; white-space: nowrap; flex: 0 0 auto; }
  .crumb { color: var(--muted); font-size: 13px; }
  .navlink { background: none; border: 0; border-bottom: 2px solid transparent; color: var(--muted); font-family: var(--ui); font-size: 13px; font-weight: 600; cursor: pointer; padding: 4px 2px; }
  .navlink:hover { color: var(--ink); }
  .navlink.on { color: var(--ink); border-bottom-color: var(--air); }
  .spacer { flex: 1; }
  .authbtn { display: flex; align-items: center; gap: 9px; padding: 9px 15px; border: 1px solid rgba(155,107,255,.4); background: linear-gradient(180deg, rgba(155,107,255,.22), rgba(155,107,255,.05)); color: #e0d3ff; font-weight: 600; font-size: 13px; cursor: pointer; }
  .authbtn .key { width: 14px; height: 14px; border-radius: 3px; background: radial-gradient(circle at 30% 30%, #fff, #b69bff); box-shadow: 0 0 12px rgba(155,107,255,.6); }
  .exitbtn { display: flex; align-items: center; padding: 9px 15px; border: 1px solid rgba(255,107,129,.4); background: linear-gradient(180deg, rgba(255,107,129,.18), rgba(255,107,129,.04)); color: #ffd0d4; font-weight: 600; font-size: 13px; cursor: pointer; font-family: inherit; }
  .exitbtn:hover { border-color: rgba(255,107,129,.7); color: #fff; }
  .me { display: flex; align-items: center; gap: 10px; padding: 5px 12px; border: 1px solid var(--hair); background: rgba(255,255,255,.03); font: inherit; color: inherit; cursor: pointer; text-align: left; }
  .me:hover { border-color: var(--stroke); background: rgba(255,255,255,.06); }
  .men { font-size: 12.5px; font-weight: 600; line-height: 1.1; }
  .mer { font-size: 10px; color: var(--faint); margin-top: 1px; }
  .melock { font-family: var(--mono); font-size: 8.5px; letter-spacing: .06em; color: #cdbcff; border: 1px solid rgba(155,107,255,.3); background: rgba(155,107,255,.1); padding: 2px 6px; }
  .backsite { color: var(--muted); font-size: 12px; text-decoration: none; font-family: var(--mono); }
  .backsite:hover { color: var(--ink); }
  .burger { width: 38px; height: 38px; border: 1px solid var(--hair); background: rgba(255,255,255,.04); display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 4px; cursor: pointer; flex: 0 0 38px; }
  .burger span { display: block; width: 16px; height: 1.5px; background: var(--ink); }
  .deptTag { font-family: var(--mono); font-size: 9px; letter-spacing: .1em; text-transform: uppercase; color: #cdbcff; border: 1px solid rgba(155,107,255,.3); background: rgba(155,107,255,.1); padding: 3px 8px; }
  .tagfoot { margin-top: auto; padding: 26px 0 6px; display: flex; align-items: center; justify-content: center; gap: 16px; border-top: 1px solid var(--hair); }
  .tagfoot .w { font-family: var(--mono); font-size: 11px; letter-spacing: .34em; text-transform: uppercase; color: var(--muted); }
  .tagfoot .bar { color: var(--air); font-weight: 700; opacity: .8; }
  @media (max-width: 980px) { .app { grid-template-columns: 1fr; } }
</style>

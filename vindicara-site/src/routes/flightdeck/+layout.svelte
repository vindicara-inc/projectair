<script lang="ts">
  import '$lib/console/console.css';
  import { onMount } from 'svelte';
  import { get } from 'svelte/store';
  import { page } from '$app/stores';
  import { env } from '$env/dynamic/public';
  import Rail from '$lib/console/components/Rail.svelte';
  import Drawer from '$lib/console/components/Drawer.svelte';
  import LockScreen from '$lib/console/components/LockScreen.svelte';
  import { beginAuth0Login, logout, sessionToken } from '$lib/console/stores/session';

  let { children } = $props();
  let drawerOpen = $state(false);

  // Auth-gate: in live mode, no token means send the operator to Auth0 first.
  // Skip the gate on /flightdeck/auth/* (callback + logout) so those pages can
  // finish their own flow instead of being bounced back into Auth0.
  onMount(() => {
    const onAuthRoute = get(page).url.pathname.startsWith('/flightdeck/auth/');
    if (!onAuthRoute && env.PUBLIC_AIR_API_MODE === 'live' && !get(sessionToken)) {
      void beginAuth0Login();
    }
  });

  const titles: Record<string, { title: string; crumb: string; dept: boolean }> = {
    '/flightdeck': { title: 'FlightDeck', crumb: '/ department', dept: true },
    '/flightdeck/': { title: 'FlightDeck', crumb: '/ department', dept: true },
    '/flightdeck/readiness': { title: 'Buyer readiness', crumb: '/ buyer readiness', dept: false },
    '/flightdeck/readiness/': { title: 'Buyer readiness', crumb: '/ buyer readiness', dept: false },
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
      <h1>{meta.title}</h1><span class="crumb">{meta.crumb}</span>
      {#if meta.dept}<span class="deptTag">Department view</span>{/if}
      <span class="spacer"></span>
      {#if $sessionToken}
        <button class="exitbtn" onclick={() => logout()}>Exit</button>
      {:else}
        <button class="authbtn" onclick={() => beginAuth0Login()}><span class="key"></span>Authorize</button>
      {/if}
      <a class="backsite" href="/">vindicara.io</a>
    </div>
    {@render children()}
  </main>
</div>

<Drawer open={drawerOpen} onclose={() => (drawerOpen = false)} />
<LockScreen />

<style>
  .app { position: relative; z-index: 2; display: grid; grid-template-columns: 320px 1fr; gap: 18px; align-items: start; min-height: 100vh; padding: 22px; }
  .work { display: flex; flex-direction: column; gap: 24px; min-width: 0; }
  .wbar { display: flex; align-items: center; gap: 14px; height: 44px; }
  .wbar h1 { font-family: var(--display); font-weight: 600; font-size: 25px; letter-spacing: -.02em; }
  .crumb { color: var(--muted); font-size: 13px; }
  .spacer { flex: 1; }
  .authbtn { display: flex; align-items: center; gap: 9px; padding: 9px 15px; border: 1px solid rgba(155,107,255,.4); background: linear-gradient(180deg, rgba(155,107,255,.22), rgba(155,107,255,.05)); color: #e0d3ff; font-weight: 600; font-size: 13px; cursor: pointer; }
  .authbtn .key { width: 14px; height: 14px; border-radius: 3px; background: radial-gradient(circle at 30% 30%, #fff, #b69bff); box-shadow: 0 0 12px rgba(155,107,255,.6); }
  .exitbtn { display: flex; align-items: center; padding: 9px 15px; border: 1px solid rgba(255,107,129,.4); background: linear-gradient(180deg, rgba(255,107,129,.18), rgba(255,107,129,.04)); color: #ffd0d4; font-weight: 600; font-size: 13px; cursor: pointer; font-family: inherit; }
  .exitbtn:hover { border-color: rgba(255,107,129,.7); color: #fff; }
  .backsite { color: var(--muted); font-size: 12px; text-decoration: none; font-family: var(--mono); }
  .backsite:hover { color: var(--ink); }
  .burger { width: 38px; height: 38px; border: 1px solid var(--hair); background: rgba(255,255,255,.04); display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 4px; cursor: pointer; flex: 0 0 38px; }
  .burger span { display: block; width: 16px; height: 1.5px; background: var(--ink); }
  .deptTag { font-family: var(--mono); font-size: 9px; letter-spacing: .1em; text-transform: uppercase; color: #cdbcff; border: 1px solid rgba(155,107,255,.3); background: rgba(155,107,255,.1); padding: 3px 8px; }
  @media (max-width: 980px) { .app { grid-template-columns: 1fr; } }
</style>

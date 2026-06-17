<script lang="ts">
  import '$lib/console/console.css';
  import { onMount } from 'svelte';
  import { get } from 'svelte/store';
  import { page } from '$app/stores';
  import Rail from '$lib/console/components/Rail.svelte';
  import Drawer from '$lib/console/components/Drawer.svelte';
  import FlightDeckNav from '$lib/console/components/FlightDeckNav.svelte';
  import LockScreen from '$lib/console/components/LockScreen.svelte';
  import SignIn from '$lib/console/components/forensics/SignIn.svelte';
  import ClockOut from '$lib/console/components/forensics/ClockOut.svelte';
  import { beginAuth0Login, sessionToken } from '$lib/console/stores/session';
  import { mode } from '$lib/console/stores/mode';

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

  // Full-bleed pages that bring their own nav (no Rail): the Overview landing
  // and the transient Auth0 callback/logout pages.
  const bareShellPaths = ['/flightdeck', '/flightdeck/'];
  let overviewShell = $derived(
    bareShellPaths.includes($page.url.pathname) || $page.url.pathname.startsWith('/flightdeck/auth/')
  );
</script>

{#if overviewShell}
  {#key $mode}
    {@render children()}
  {/key}
  <SignIn />
  <ClockOut />
  <LockScreen />
{:else}
<div class="aurora"><i></i><i></i><i></i></div>
<div class="grain"></div>

<div class="console-page">
  <FlightDeckNav onMenuClick={() => (drawerOpen = true)} />

  <div class="app">
    <Rail />

    <main class="work">
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
</div>

<Drawer open={drawerOpen} onclose={() => (drawerOpen = false)} />
<LockScreen />
<SignIn />
<ClockOut />
{/if}

<style>
  .console-page { position: relative; z-index: 2; min-height: 100vh; }
  .app { display: grid; grid-template-columns: 320px 1fr; gap: 18px; align-items: start; min-height: calc(100vh - 56px); padding: 18px 22px 22px; }
  .work { display: flex; flex-direction: column; gap: 24px; min-width: 0; min-height: calc(100vh - 96px); }
  .tagfoot { margin-top: auto; padding: 26px 0 6px; display: flex; align-items: center; justify-content: center; gap: 16px; border-top: 1px solid var(--hair); }
  .tagfoot .w { font-family: var(--mono); font-size: 11px; letter-spacing: .34em; text-transform: uppercase; color: var(--muted); }
  .tagfoot .bar { color: var(--air); font-weight: 700; opacity: .55; }
  @media (max-width: 980px) { .app { grid-template-columns: 1fr; } }
</style>

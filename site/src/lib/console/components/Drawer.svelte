<script lang="ts">
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { lockSession } from '$lib/console/stores/session';

  let { open = false, onclose } = $props();

  const groups = [
    { title: 'Department', items: [
      { label: 'Overview', to: '/dashboard/', tag: '' },
      { label: 'Active delegations', to: '/dashboard/', tag: 'dept' },
      { label: 'Agent fleet', to: '/dashboard/', tag: 'live' },
      { label: 'Step-up queue', to: '/dashboard/', tag: 'live' },
      { label: 'Handoff lineage', to: '/dashboard/', tag: 'L4' }
    ]},
    { title: 'Policy & proof', items: [
      { label: 'Rules', to: '/dashboard/rules/', tag: '.md' },
      { label: 'Buyer readiness', to: '/dashboard/readiness/', tag: '4/4' },
      { label: 'Evidence packs', to: '/dashboard/readiness/', tag: 'live' },
      { label: 'Compliance', to: '/dashboard/readiness/', tag: '' }
    ]},
    { title: 'Plugins', items: [
      { label: 'All plugins', to: '/dashboard/plugins/', tag: '9' },
      { label: 'SIEM export', to: '/dashboard/plugins/', tag: '5' },
      { label: 'Insurance API', to: '/dashboard/insurance/', tag: 'ENT' }
    ]},
    { title: 'Account', items: [
      { label: 'Settings', to: '/dashboard/settings/', tag: 'ENT' }
    ]}
  ];

  function nav(to: string) { goto(to); onclose?.(); }
</script>

<div class="scrim {open ? 'on' : ''}" onclick={() => onclose?.()} role="presentation"></div>
<nav class="drawer {open ? 'on' : ''}" aria-hidden={!open}>
  <div class="dhead"><span class="dot"></span><span class="logo">Project&nbsp;<span class="air">AIR</span></span><span class="dtag">flightdeck</span><button class="x" onclick={() => onclose?.()}>✕</button></div>

  {#each groups as g}
    <div class="dgrp">{g.title}</div>
    {#each g.items as it}
      <button class="ditem {$page.url.pathname === it.to ? 'on' : ''}" onclick={() => nav(it.to)}>
        <span class="di"></span>{it.label}{#if it.tag}<span class="tag">{it.tag}</span>{/if}
      </button>
    {/each}
  {/each}

  <div class="dgrp"> </div>
  <button class="ditem lk" onclick={() => { lockSession(); onclose?.(); }}><span class="di"></span>Lock session</button>
</nav>

<style>
  .scrim { position: fixed; inset: 0; background: rgba(0,0,0,.5); backdrop-filter: blur(2px); z-index: 40; opacity: 0; pointer-events: none; transition: .25s; }
  .scrim.on { opacity: 1; pointer-events: auto; }
  .drawer { position: fixed; top: 0; left: 0; bottom: 0; width: 300px; z-index: 41; transform: translateX(-110%); transition: transform .28s cubic-bezier(.2,.7,.2,1);
    border-right: 1px solid var(--stroke); background: linear-gradient(160deg, rgba(20,22,30,.97), rgba(8,9,14,.98)); backdrop-filter: blur(30px); display: flex; flex-direction: column; overflow: auto; }
  .drawer.on { transform: none; }
  .dhead { padding: 20px; display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--hair); }
  .dot { width: 11px; height: 11px; border-radius: 2px; background: var(--air); box-shadow: 0 0 14px var(--air); }
  .logo { font-family: var(--display); font-weight: 600; font-size: 18px; }
  .logo :global(.air) { color: var(--air); font-weight: 700; }
  .dtag { margin-left: auto; font-family: var(--mono); font-size: 9px; letter-spacing: .16em; text-transform: uppercase; color: var(--faint); }
  .x { color: var(--faint); cursor: pointer; font-size: 16px; background: none; border: 0; flex: 0 0 auto; }
  .dgrp { padding: 15px 16px 5px; font-family: var(--mono); font-size: 9px; letter-spacing: .16em; text-transform: uppercase; color: var(--faint); }
  .ditem { width: 100%; text-align: left; background: none; border: 0; display: flex; align-items: center; gap: 12px; padding: 11px 18px; cursor: pointer; color: var(--muted); font-size: 13.5px; border-left: 2px solid transparent; transition: .13s; font-family: var(--ui); }
  .ditem:hover { background: rgba(255,255,255,.04); color: var(--ink); }
  .ditem.on { color: var(--ink); border-left-color: var(--air); background: rgba(230,57,70,.08); }
  .di { width: 7px; height: 7px; border-radius: 50%; background: var(--faint); flex: 0 0 7px; }
  .ditem.on .di { background: var(--air); box-shadow: 0 0 8px var(--air); }
  .ditem.lk { color: #ffc4a3; }
  .ditem.lk .di { background: var(--orange); }
  .tag { margin-left: auto; font-family: var(--mono); font-size: 8.5px; color: var(--faint); border: 1px solid var(--hair); padding: 2px 6px; }
</style>

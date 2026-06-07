<script lang="ts">
  import { goto } from '$app/navigation';
  import Core3D from './Core3D.svelte';

  const pillars = [
    { tag: 'M', accent: '#6db5ff', label: 'Monitor', value: '16 + SV', sub: 'detectors + structural verification', to: '/flightdeck' },
    { tag: 'E', accent: '#ff5d68', label: 'Enforce', value: 'deterministic', sub: "floor that can't be jailbroken", to: '/flightdeck/readiness' },
  ];
  const pillarsLower = [
    { tag: 'P', accent: '#48e6a4', label: 'Prove', value: 'Rekor', sub: 'anchored 41s ago · ml-dsa-65', to: '/flightdeck/readiness' },
    { tag: 'A', accent: '#9b6bff', label: 'Account', value: '94%', sub: 'agents bound to a human', to: '/flightdeck' },
  ];
</script>

<aside class="rail glass hud k reveal">
  <div class="rhead"><span class="dot"></span><span class="logo">Project&nbsp;<span class="air">AIR</span></span><span class="rtag">core</span></div>

  {#each pillars as p}
    <button class="flat clk" style="--accent:{p.accent}" onclick={() => goto(p.to)}>
      <div class="tagL">{p.tag}</div>
      <div><div class="lab">{p.label}</div><div class="val">{p.value} {#if p.label === 'Enforce'}<span class="goarrow">&rarr;</span>{/if}</div><div class="sub">{p.sub}</div></div>
    </button>
  {/each}

  <Core3D />

  {#each pillarsLower as p, i}
    <button class="flat clk" style="--accent:{p.accent}{i === pillarsLower.length - 1 ? ';border-bottom:0' : ''}" onclick={() => goto(p.to)}>
      <div class="tagL">{p.tag}</div>
      <div><div class="lab">{p.label}</div><div class="val">{p.value}</div><div class="sub">{p.sub}</div></div>
    </button>
  {/each}

  <div class="rfoot">No agent is autonomous · only <b>delegated authority</b></div>
</aside>

<style>
  .rail { display: flex; flex-direction: column; overflow: hidden; height: calc(100vh - 44px); position: sticky; top: 22px; }
  .rhead { padding: 20px 22px; border-bottom: 1px solid var(--hair); display: flex; align-items: center; gap: 10px; }
  .dot { width: 11px; height: 11px; border-radius: 2px; background: var(--air); box-shadow: 0 0 16px var(--air); }
  .logo { font-family: var(--display); font-weight: 600; font-size: 19px; }
  .logo :global(.air), .air { color: var(--air); font-weight: 700; }
  .rtag { margin-left: auto; font-family: var(--mono); font-size: 9.5px; letter-spacing: .18em; text-transform: uppercase; color: var(--faint); }
  .flat { width: 100%; text-align: left; background: none; border: 0; border-bottom: 1px solid var(--hair); padding: 18px 22px; display: flex; align-items: center; gap: 14px; position: relative; color: var(--ink); }
  .flat::before { content: ''; position: absolute; left: 0; top: 14px; bottom: 14px; width: 3px; background: linear-gradient(180deg, color-mix(in srgb, var(--accent) 14%, transparent), var(--accent)); }
  .flat.clk { cursor: pointer; transition: background .15s; }
  .flat.clk:hover { background: rgba(255,255,255,.05); }
  .flat.clk:hover .goarrow { opacity: 1; transform: translateX(2px); }
  .tagL { font-family: var(--display); font-weight: 700; font-size: 16px; color: var(--accent); width: 18px; text-align: center; }
  .lab { font-family: var(--mono); font-size: 10px; letter-spacing: .16em; text-transform: uppercase; color: var(--faint); }
  .val { font-family: var(--display); font-size: 21px; font-weight: 600; line-height: 1.05; margin-top: 3px; }
  .goarrow { color: var(--accent); font-family: var(--ui); opacity: .45; transition: .18s; display: inline-block; margin-left: 2px; }
  .sub { font-size: 11px; color: var(--muted); margin-top: 3px; }
  .rfoot { padding: 14px 22px; font-family: var(--mono); font-size: 9.5px; letter-spacing: .1em; color: var(--faint); }
  .rfoot b { color: var(--ink); }
</style>

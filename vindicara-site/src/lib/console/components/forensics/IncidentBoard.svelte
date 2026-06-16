<script lang="ts">
  import type { FeedItem } from '$lib/console/forensics/feed';
  import SeverityPill from './SeverityPill.svelte';

  let {
    serious,
    alerts,
    onopen
  }: { serious: FeedItem[]; alerts: FeedItem[]; onopen: (scenarioId: string) => void } = $props();

  const actionLabel: Record<FeedItem['action'], string> = {
    halted: 'Halted',
    blocked: 'Blocked',
    contained: 'Blocked & paused',
    flagged: 'Flagged'
  };
</script>

<div class="board">
  <!-- TOP HALF — serious: AIR halted the agent -->
  <section class="zone hot">
    <header class="bandhead">
      <span class="pulse" aria-hidden="true"></span>
      <div class="bh-text">
        <h2>Serious derailment</h2>
        <span class="bh-sub">Project AIR stopped the agent before it could act</span>
      </div>
      <span class="count hot">{serious.length} halted</span>
    </header>

    <div class="grid">
      {#each serious as it}
        {#if it.scenarioId}
          <button class="card sev-{it.severity} clickable" onclick={() => onopen(it.scenarioId!)}>
            <div class="ctop">
              <span class="stat a-{it.action}">{actionLabel[it.action]}</span>
              <SeverityPill severity={it.severity} />
              <span class="time">{it.time}</span>
            </div>
            <div class="agent">{it.agent} <span class="domain">· {it.domain}</span></div>
            <div class="title">{it.title}</div>
            <div class="summary">{it.summary}</div>
            <div class="open">Open incident <span class="arr">→</span></div>
          </button>
        {:else}
          <div class="card sev-{it.severity}">
            <div class="ctop">
              <span class="stat a-{it.action}">{actionLabel[it.action]}</span>
              <SeverityPill severity={it.severity} />
              <span class="time">{it.time}</span>
            </div>
            <div class="agent">{it.agent} <span class="domain">· {it.domain}</span></div>
            <div class="title">{it.title}</div>
            <div class="summary">{it.summary}</div>
            <div class="sealed">✓ Evidence sealed · signed chain</div>
          </div>
        {/if}
      {/each}
    </div>
  </section>

  <!-- DIVIDER -->
  <div class="split"><span>Monitoring — no action needed</span></div>

  <!-- BOTTOM HALF — alerts: AIR flagged, no halt -->
  <section class="zone calm">
    <header class="bandhead">
      <span class="eye" aria-hidden="true"></span>
      <div class="bh-text">
        <h2>Flagged for awareness</h2>
        <span class="bh-sub">Within bounds — Project AIR logged it, did not halt</span>
      </div>
      <span class="count calm">{alerts.length} flagged</span>
    </header>

    <div class="grid calmgrid">
      {#each alerts as it}
        <button class="acard sev-{it.severity}" onclick={() => it.scenarioId && onopen(it.scenarioId)}>
          <div class="atop">
            <span class="flagpill">Flagged</span>
            <span class="time">{it.time}</span>
          </div>
          <div class="atitle">{it.title}</div>
          <div class="ameta">{it.agent} · {it.domain}</div>
          <div class="asummary">{it.summary}</div>
          <div class="aopen">Open <span class="arr">→</span></div>
        </button>
      {/each}
    </div>
  </section>
</div>

<style>
  .board { display: flex; flex-direction: column; gap: 4px; }

  /* zones */
  .zone { padding: 18px 20px 22px; border: 1px solid var(--hair); position: relative; overflow: hidden; }
  .hot { border-color: rgba(230,57,70,.28); background:
    radial-gradient(120% 100% at 0% 0%, rgba(230,57,70,.1), transparent 60%),
    linear-gradient(180deg, rgba(230,57,70,.05), rgba(255,255,255,.01)); }
  .calm { border-color: rgba(109,181,255,.2); background:
    linear-gradient(180deg, rgba(109,181,255,.04), rgba(255,255,255,.008)); }

  .bandhead { display: flex; align-items: center; gap: 13px; margin-bottom: 16px; }
  .bh-text { display: flex; flex-direction: column; }
  .bandhead h2 { font-family: var(--display); font-size: 19px; font-weight: 600; letter-spacing: -.01em; }
  .bh-sub { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .pulse { width: 11px; height: 11px; border-radius: 50%; background: var(--air); box-shadow: 0 0 14px var(--air); animation: blip 1.6s ease-in-out infinite; flex: 0 0 11px; }
  .eye { width: 11px; height: 11px; border-radius: 50%; border: 2px solid var(--blue); flex: 0 0 11px; }
  @keyframes blip { 0%,100% { opacity: 1; } 50% { opacity: .3; } }
  @media (prefers-reduced-motion: reduce) { .pulse { animation: none; } }
  .count { margin-left: auto; font-family: var(--mono); font-size: 10px; letter-spacing: .1em; text-transform: uppercase; padding: 5px 11px; border: 1px solid; white-space: nowrap; }
  .count.hot { color: #ffd0d4; border-color: rgba(230,57,70,.45); background: rgba(230,57,70,.12); }
  .count.calm { color: #bcd6ff; border-color: rgba(109,181,255,.4); background: rgba(109,181,255,.1); }

  /* serious cards */
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(290px, 1fr)); gap: 13px; }
  .card { text-align: left; font: inherit; color: var(--ink); border: 1px solid var(--hair); border-left: 3px solid var(--slate); background: rgba(10,12,17,.5); padding: 15px 17px; display: flex; flex-direction: column; gap: 0; }
  .card.sev-critical { border-left-color: var(--air); }
  .card.sev-high { border-left-color: var(--amber); }
  .card.sev-medium { border-left-color: var(--blue); }
  .card.clickable { cursor: pointer; transition: transform .14s, border-color .14s, background .14s; }
  .card.clickable:hover { transform: translateY(-2px); border-color: rgba(230,57,70,.45); background: rgba(230,57,70,.07); }
  .ctop { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
  .stat { font-family: var(--mono); font-size: 9px; letter-spacing: .07em; font-weight: 600; padding: 3px 8px; text-transform: uppercase; border: 1px solid; }
  .a-halted, .a-blocked { color: #ffd0d4; background: rgba(230,57,70,.14); border-color: rgba(230,57,70,.42); }
  .a-contained { color: #ffd9a6; background: rgba(255,180,84,.13); border-color: rgba(255,180,84,.36); }
  .time { margin-left: auto; font-family: var(--mono); font-size: 10px; color: var(--faint); }
  .agent { font-family: var(--mono); font-size: 11px; color: var(--muted); }
  .domain { color: var(--faint); }
  .title { font-size: 15px; font-weight: 600; line-height: 1.3; margin: 7px 0 5px; }
  .summary { font-size: 12.5px; color: var(--muted); line-height: 1.5; }
  .open { margin-top: 12px; font-size: 12.5px; font-weight: 600; color: #ffb9bf; }
  .card.clickable:hover .arr { display: inline-block; transform: translateX(3px); transition: transform .14s; }
  .sealed { margin-top: 12px; font-family: var(--mono); font-size: 10px; color: #bff5df; letter-spacing: .03em; }

  /* divider */
  .split { display: flex; align-items: center; gap: 14px; margin: 14px 2px; color: var(--faint); font-family: var(--mono); font-size: 9.5px; letter-spacing: .18em; text-transform: uppercase; }
  .split::before, .split::after { content: ''; height: 1px; flex: 1; background: linear-gradient(90deg, transparent, var(--hair), transparent); }

  /* alert cards — calmer, lighter */
  .calmgrid { grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); }
  .acard { display: flex; flex-direction: column; text-align: left; font: inherit; color: var(--ink); cursor: pointer; border: 1px solid var(--hair); border-left: 2px solid rgba(109,181,255,.4); background: rgba(255,255,255,.015); padding: 13px 15px; transition: transform .14s, border-color .14s, background .14s; }
  .acard:hover { transform: translateY(-2px); border-color: rgba(109,181,255,.5); background: rgba(109,181,255,.06); }
  .acard.sev-medium { border-left-color: rgba(109,181,255,.6); }
  .aopen { margin-top: 10px; font-size: 11.5px; font-weight: 600; color: #bcd6ff; }
  .acard:hover .arr { display: inline-block; transform: translateX(3px); transition: transform .14s; }
  .atop { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .flagpill { font-family: var(--mono); font-size: 8.5px; letter-spacing: .08em; font-weight: 600; text-transform: uppercase; color: #bcd6ff; border: 1px solid rgba(109,181,255,.34); background: rgba(109,181,255,.1); padding: 2px 7px; }
  .atitle { font-size: 13px; font-weight: 600; line-height: 1.3; }
  .ameta { font-family: var(--mono); font-size: 10px; color: var(--faint); margin: 5px 0 6px; }
  .asummary { font-size: 12px; color: var(--muted); line-height: 1.45; }
</style>

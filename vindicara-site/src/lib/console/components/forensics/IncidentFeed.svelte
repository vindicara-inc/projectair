<script lang="ts">
  import type { BuiltScenario } from '$lib/console/forensics/types';
  import StatusPill from './StatusPill.svelte';
  import SeverityPill from './SeverityPill.svelte';

  let { incidents, onopen }: { incidents: BuiltScenario[]; onopen: (id: string) => void } = $props();
</script>

<div class="feed">
  {#each incidents as inc}
    <button class="row glass hud" onclick={() => onopen(inc.id)}>
      <div class="lead">
        <div class="pills"><StatusPill status={inc.status} /><SeverityPill severity={inc.severity} /></div>
        <div class="title">{inc.title}</div>
        <div class="summary">{inc.plainHeadline}</div>
      </div>
      <div class="side">
        <div class="agent">{inc.agentLabel}</div>
        <div class="when">{new Date(inc.occurredAt).toLocaleString()}</div>
        <div class="go">Review <span class="arr">→</span></div>
      </div>
    </button>
  {/each}
</div>

<style>
  .feed { display: flex; flex-direction: column; gap: 14px; }
  .row {
    display: grid; grid-template-columns: 1fr auto; gap: 22px; text-align: left; cursor: pointer;
    padding: 18px 22px; color: var(--ink); align-items: center; transition: transform .14s, border-color .14s;
  }
  .row:hover { transform: translateY(-1px); border-color: rgba(230,57,70,.4); }
  .pills { display: flex; gap: 8px; margin-bottom: 9px; }
  .title { font-family: var(--display); font-size: 18px; font-weight: 600; letter-spacing: -.01em; line-height: 1.2; }
  .summary { font-size: 13px; color: var(--muted); margin-top: 6px; line-height: 1.5; max-width: 74ch; }
  .side { text-align: right; display: flex; flex-direction: column; gap: 5px; white-space: nowrap; }
  .agent { font-family: var(--mono); font-size: 11px; color: var(--muted); }
  .when { font-size: 11px; color: var(--faint); }
  .go { margin-top: 6px; font-size: 12.5px; font-weight: 600; color: #ffb9bf; }
  .row:hover .arr { display: inline-block; transform: translateX(3px); transition: transform .14s; }
  @media (max-width: 720px) {
    .row { grid-template-columns: 1fr; }
    .side { text-align: left; flex-direction: row; gap: 14px; align-items: center; }
  }
</style>

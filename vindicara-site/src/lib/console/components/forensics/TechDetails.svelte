<script lang="ts">
  // The two-layer device: plain English stays on the surface; everything technical —
  // codes, hashes, signatures, framework references — lives one click away in here.
  let { label = 'Technical details', children } = $props();
</script>

<details class="techd">
  <summary><span class="chev" aria-hidden="true">▸</span>{label}</summary>
  <div class="tbody">{@render children?.()}</div>
</details>

<style>
  .techd { border-top: 1px solid var(--hair); margin-top: 12px; }
  summary {
    list-style: none; cursor: pointer; display: flex; align-items: center; gap: 7px;
    padding: 9px 0 0; font-family: var(--mono); font-size: 10px; letter-spacing: .1em;
    text-transform: uppercase; color: var(--faint); user-select: none;
  }
  summary::-webkit-details-marker { display: none; }
  summary:hover { color: var(--muted); }
  .chev { transition: transform .15s; display: inline-block; }
  details[open] .chev { transform: rotate(90deg); }
  .tbody {
    padding: 11px 0 2px; font-family: var(--mono); font-size: 11px; line-height: 1.7;
    color: var(--muted); word-break: break-word;
  }
  :global(.techd .tbody .k) { color: var(--faint); }
  :global(.techd .tbody b) { color: var(--ink); font-weight: 600; }
  :global(.techd .tbody .hash) { color: #9fb4d8; }
</style>

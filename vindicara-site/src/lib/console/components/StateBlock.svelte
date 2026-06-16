<script lang="ts">
  import { mode } from '$lib/console/stores/mode';
  import { goto } from '$app/navigation';
  let { kind = 'loading', message = '' } = $props();
</script>

{#if kind === 'loading'}
  <div class="state"><div class="spinner"></div>Loading…</div>
{:else if kind === 'error'}
  {#if $mode === 'live'}
    <!-- Honest Live empty state: the API isn't reachable, so show nothing invented. -->
    <div class="state live">
      <div class="eh">Live data isn’t connected here</div>
      <p>
        This view reads real records from the live AIR API. It isn’t reachable in this
        environment, so nothing is shown rather than invented. Switch to
        <b>Demo&nbsp;Mode</b> to walk the console on local fixtures.
      </p>
      <button class="btn" onclick={() => mode.set('demo')}>Switch to Demo Mode</button>
      <details class="tech">
        <summary>Technical details</summary>
        <div class="tbody">live API · {message || 'request failed'}</div>
      </details>
    </div>
  {:else}
    <div class="state err">Couldn't load this. {message}</div>
  {/if}
{:else}
  <div class="state">{message || 'Nothing here yet.'}</div>
{/if}

<style>
  .live { text-align: center; padding: 34px 24px; }
  .live .eh { font-family: var(--display); font-size: 19px; font-weight: 600; color: var(--ink); }
  .live p { font-size: 13px; color: var(--muted); line-height: 1.6; max-width: 56ch; margin: 11px auto 16px; }
  .live b { color: var(--ink); }
  .live .btn { display: inline-block; padding: 9px 16px; font-size: 12px; }
  .tech { margin-top: 16px; }
  .tech summary { list-style: none; cursor: pointer; font-family: var(--mono); font-size: 9.5px; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); }
  .tech summary::-webkit-details-marker { display: none; }
  .tech .tbody { margin-top: 8px; font-family: var(--mono); font-size: 11px; color: var(--muted); }
</style>

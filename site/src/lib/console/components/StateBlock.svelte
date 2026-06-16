<script lang="ts">
  let { kind = 'loading', message = '' } = $props();
</script>

{#if kind === 'loading'}
  <div class="state"><div class="spinner"></div>Loading…</div>
{:else if kind === 'error'}
  <div class="state err">Couldn't load this. {message}</div>
{:else}
  <div class="state">{message || 'Nothing here yet.'}</div>
{/if}

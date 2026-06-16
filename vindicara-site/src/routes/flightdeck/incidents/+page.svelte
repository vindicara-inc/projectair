<script lang="ts">
  import { mode, selectedScenarioId } from '$lib/console/stores/mode';
  import { incidentsFor } from '$lib/console/forensics/data';
  import { seriousIncidents, alertIncidents } from '$lib/console/forensics/feed';
  import IncidentBoard from '$lib/console/components/forensics/IncidentBoard.svelte';
  import IncidentDetail from '$lib/console/components/forensics/IncidentDetail.svelte';
  import Panel from '$lib/console/components/Panel.svelte';

  let view = $state<'feed' | 'detail'>('feed');

  let incidents = $derived(incidentsFor($mode));
  let selected = $derived(incidents.find((i) => i.id === $selectedScenarioId) ?? incidents[0]);

  function open(id: string) {
    selectedScenarioId.set(id);
    view = 'detail';
  }
</script>

{#if $mode === 'live'}
  <Panel>
    <div class="empty">
      <div class="eh">No live incidents connected yet</div>
      <p>
        Live Mode reads real forensic chains from the AIR API. This console isn’t wired to a live
        source in this environment, so nothing is shown here — rather than invent data. Switch to
        <b>Demo Mode</b> to walk the fleet.
      </p>
    </div>
  </Panel>
{:else if view === 'detail' && selected}
  <IncidentDetail scenario={selected} onback={() => (view = 'feed')} />
{:else}
  <IncidentBoard serious={seriousIncidents} alerts={alertIncidents} onopen={open} />
{/if}

<style>
  .empty { padding: 30px 24px; text-align: center; }
  .eh { font-family: var(--display); font-size: 20px; font-weight: 600; }
  .empty p { font-size: 13.5px; color: var(--muted); line-height: 1.6; max-width: 60ch; margin: 12px auto 0; }
  .empty b { color: var(--ink); }
</style>

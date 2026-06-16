<script lang="ts">
  import type { IncidentStatus } from '$lib/console/forensics/types';
  // clean = nothing wrong; flagged = violations found; contained = AIR blocked it
  // and paused for a human (a good outcome).
  let { status }: { status: IncidentStatus } = $props();
  const plain: Record<IncidentStatus, string> = {
    clean: 'Clean',
    flagged: 'Flagged',
    contained: 'Blocked & paused'
  };
</script>

<span class="stt t-{status}"><span class="dot"></span>{plain[status]}</span>

<style>
  .stt {
    display: inline-flex; align-items: center; gap: 6px; font-family: var(--mono);
    font-size: 9.5px; letter-spacing: .06em; font-weight: 600; padding: 3px 9px;
    border: 1px solid; text-transform: uppercase; white-space: nowrap;
  }
  .dot { width: 6px; height: 6px; border-radius: 50%; }
  .t-clean { color: #bff5df; background: rgba(72,230,164,.12); border-color: rgba(72,230,164,.32); }
  .t-clean .dot { background: var(--teal); box-shadow: 0 0 7px var(--teal); }
  .t-flagged { color: #ffd0d4; background: rgba(230,57,70,.12); border-color: rgba(230,57,70,.4); }
  .t-flagged .dot { background: var(--air); box-shadow: 0 0 7px var(--air); }
  .t-contained { color: #bcd6ff; background: rgba(109,181,255,.12); border-color: rgba(109,181,255,.34); }
  .t-contained .dot { background: var(--blue); box-shadow: 0 0 7px var(--blue); }
</style>

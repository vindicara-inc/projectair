<script lang="ts">
  import type { Severity } from '$lib/console/forensics/types';
  // CRITICAL red, HIGH amber, verified/clean green — the brand severity scale.
  let { severity, label = severity }: { severity: Severity; label?: string } = $props();
</script>

<span class="sev s-{severity}">{label.toUpperCase()}</span>

<style>
  .sev {
    font-family: var(--mono); font-size: 9px; letter-spacing: .08em; font-weight: 600;
    padding: 3px 8px; white-space: nowrap; border: 1px solid;
  }
  .s-critical { color: #ffd0d4; background: rgba(230,57,70,.14); border-color: rgba(230,57,70,.42); }
  .s-high { color: #ffd49a; background: rgba(255,180,84,.13); border-color: rgba(255,180,84,.34); }
  .s-medium { color: #bcd6ff; background: rgba(109,181,255,.12); border-color: rgba(109,181,255,.32); }
  .s-low { color: #c2c8d2; background: rgba(138,146,160,.14); border-color: rgba(138,146,160,.3); }
</style>

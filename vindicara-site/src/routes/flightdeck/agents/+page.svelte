<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  // Screen retired in the redesign; the new nav maps it here.
  onMount(() => goto('/flightdeck/rules', { replaceState: true }));
</script>

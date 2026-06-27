<script lang="ts">
  import { page } from '$app/stores';
  import FlightdeckSignIn from '$lib/console/components/FlightdeckSignIn.svelte';
  import { authError } from '$lib/console/stores/session';

  $effect(() => {
    const error = $page.url.searchParams.get('error');
    if (error) authError.set(error);
  });
</script>

<svelte:head>
  <title>Sign in · Flightdeck · Project AIR</title>
  <meta name="robots" content="noindex" />
</svelte:head>

<FlightdeckSignIn />

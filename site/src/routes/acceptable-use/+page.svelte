<script lang="ts">
  import LegalDocument from '$lib/components/LegalDocument.svelte';
  import raw from '$lib/legal/acceptable-use-policy.md?raw';
</script>

<svelte:head>
  <title>Acceptable Use Policy | Vindicara AIR</title>
  <meta name="description" content="Vindicara, Inc. Acceptable Use Policy describing prohibited activities and the defensive-security mission of Project AIR. Version 1.0 under counsel review." />
  <link rel="canonical" href="https://vindicara.io/acceptable-use" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://vindicara.io/acceptable-use" />
  <meta property="og:title" content="Acceptable Use Policy | Vindicara AIR" />
  <meta property="og:description" content="Prohibited activities and acceptable uses of the Vindicara services." />
  <meta name="robots" content="index, follow" />
</svelte:head>

<LegalDocument {raw} />

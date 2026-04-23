<script lang="ts">
  import LegalDocument from '$lib/components/LegalDocument.svelte';
  import raw from '$lib/legal/terms-of-service.md?raw';
</script>

<svelte:head>
  <title>Terms of Service | Vindicara AIR</title>
  <meta name="description" content="Vindicara, Inc. Terms of Service governing use of vindicara.io, the projectair Python package, AIR Cloud, and AIR Enterprise. Version 1.0 under counsel review." />
  <link rel="canonical" href="https://vindicara.io/terms" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://vindicara.io/terms" />
  <meta property="og:title" content="Terms of Service | Vindicara AIR" />
  <meta property="og:description" content="Vindicara, Inc. Terms of Service." />
  <meta name="robots" content="index, follow" />
</svelte:head>

<LegalDocument {raw} />

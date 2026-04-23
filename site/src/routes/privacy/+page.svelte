<script lang="ts">
  import LegalDocument from '$lib/components/LegalDocument.svelte';
  import raw from '$lib/legal/privacy-policy.md?raw';
</script>

<svelte:head>
  <title>Privacy Policy | Vindicara AIR</title>
  <meta name="description" content="Vindicara, Inc. Privacy Policy explaining how personal information is collected, used, stored, and shared. CCPA, CPRA, GDPR, and UK GDPR covered. Version 1.0 under counsel review." />
  <link rel="canonical" href="https://vindicara.io/privacy" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://vindicara.io/privacy" />
  <meta property="og:title" content="Privacy Policy | Vindicara AIR" />
  <meta property="og:description" content="Vindicara, Inc. Privacy Policy. CCPA + GDPR coverage." />
  <meta name="robots" content="index, follow" />
</svelte:head>

<LegalDocument {raw} />

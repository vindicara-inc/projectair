<script lang="ts">
  import LegalDocument from '$lib/components/LegalDocument.svelte';
  import raw from '$lib/legal/security-disclosure-policy.md?raw';
</script>

<svelte:head>
  <title>Responsible Security Disclosure Policy | Vindicara AIR</title>
  <meta name="description" content="Safe harbor and coordinated 90-day disclosure policy for good-faith security research on Vindicara systems and the Project AIR codebase. Version 1.0 under counsel review." />
  <link rel="canonical" href="https://vindicara.io/security" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://vindicara.io/security" />
  <meta property="og:title" content="Security Disclosure Policy | Vindicara AIR" />
  <meta property="og:description" content="Coordinated disclosure, safe harbor, and responsible reporting for Project AIR." />
  <meta name="robots" content="index, follow" />
</svelte:head>

<LegalDocument {raw} />

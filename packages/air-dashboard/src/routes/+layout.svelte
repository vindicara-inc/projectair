<script lang="ts">
  import '../app.css';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';
  import { base } from '$app/paths';
  import { authStore } from '$lib/stores/auth.svelte';
  import { roleStore } from '$lib/stores/role.svelte';
  import { cloudSession } from '$lib/stores/cloud_session.svelte';
  import Sidebar from '$lib/panels/Sidebar.svelte';
  import TopBar from '$lib/panels/TopBar.svelte';
  import WelcomeGate from '$lib/panels/WelcomeGate.svelte';
  import AssistantOrb from '$lib/panels/AssistantOrb.svelte';
  import AssistantChat from '$lib/panels/AssistantChat.svelte';

  let { children } = $props();

  const adminRoutes = [`${base}/team`, `${base}/activity`, `${base}/compliance`, `${base}/analytics`];

  onMount(() => {
    authStore.init();
  });

  $effect(() => {
    if (!cloudSession.isConnected) return;
    const path = $page.url.pathname;
    if (adminRoutes.some((r) => path.startsWith(r)) && !roleStore.isAdmin) {
      goto(`${base}/`);
    }
  });
</script>

<svelte:head>
  <meta name="description" content="AIR Cloud: forensic evidence console for instrumented AI agents." />
</svelte:head>

{#if authStore.phase === 'loading'}
  <div class="flex items-center justify-center h-screen" style="background: var(--color-base); font-family: var(--font-ui);">
    <span class="text-value text-sm">Authenticating...</span>
  </div>
{:else if authStore.phase === 'gate'}
  <WelcomeGate />
{:else}
  <Sidebar />
  <TopBar />
  <main class="ml-14 pt-10">
    {@render children()}
  </main>
  <AssistantOrb />
  <AssistantChat />
{/if}

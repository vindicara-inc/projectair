<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { authStore } from '$lib/stores/auth.svelte';

  let { children } = $props();

  onMount(() => {
    authStore.init();
  });
</script>

<svelte:head>
  <meta name="description" content="AIR Cloud: forensic evidence console for instrumented AI agents." />
</svelte:head>

{#if authStore.phase === 'loading'}
  <div class="flex items-center justify-center h-screen bg-nebula-bg">
    <div class="flex items-center gap-3">
      <div class="w-3 h-3 bg-violet-500 rounded-full animate-pulse"></div>
      <span class="text-sm text-white/60 font-mono">Authenticating...</span>
    </div>
  </div>
{:else if authStore.phase === 'gate'}
  <div class="flex items-center justify-center h-screen bg-nebula-bg">
    <div class="glass-panel p-12 rounded-3xl text-center max-w-md">
      <div class="w-16 h-16 mx-auto mb-6 bg-gradient-to-br from-violet-500 to-indigo-500 rounded-2xl flex items-center justify-center text-2xl font-bold">
        A
      </div>
      <h1 class="text-2xl font-bold text-violet-300 mb-3">AIR Cloud</h1>
      <p class="text-white/60 text-sm mb-8">Forensic evidence console for instrumented AI agents.</p>
      <button
        onclick={() => authStore.login()}
        class="w-full py-4 bg-gradient-to-r from-indigo-600 to-violet-600 hover:brightness-110 rounded-2xl font-medium transition-all active:scale-[0.985]"
      >
        Sign in with Auth0
      </button>
    </div>
  </div>
{:else}
  {@render children()}
{/if}

<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { exchangeAuthCode, unlock, authError } from '$lib/console/stores/session';

  let error = $state<string | null>(null);

  function returnToSignIn(message: string) {
    authError.set(message);
    void goto(`/flightdeck/sign-in/?error=${encodeURIComponent(message)}`);
  }

  onMount(async () => {
    const params = new URLSearchParams(location.search);
    const code = params.get('code');
    const oauthErr = params.get('error_description') ?? params.get('error');
    if (oauthErr) { error = oauthErr; returnToSignIn(oauthErr); return; }
    if (!code) {
      const message = 'No authorization code returned from Auth0.';
      error = message;
      returnToSignIn(message);
      return;
    }
    try {
      const token = await exchangeAuthCode(code);
      unlock(token);
      goto('/flightdeck');
    } catch (e) {
      error = e instanceof Error ? e.message : 'Sign-in failed.';
      returnToSignIn(error);
    }
  });
</script>

<div class="cb">
  {#if error}<div class="err">{error}</div><a class="back" href="/flightdeck">Back to FlightDeck</a>
  {:else}Completing sign-in...{/if}
</div>
<style>
  .cb { display:grid; place-items:center; gap:14px; height:100vh; font-family:var(--mono,monospace); color:#9aa1ad; padding:24px; text-align:center; }
  .err { color:#ffd0d4; max-width:520px; line-height:1.5; }
  .back { color:#cdbcff; text-decoration:none; }
</style>

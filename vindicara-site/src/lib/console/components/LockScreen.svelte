<script lang="ts">
  import { goto } from '$app/navigation';
  import { locked, unlock } from '$lib/console/stores/session';
  import { env } from '$env/dynamic/public';

  let phase = $state<'idle' | 'halting' | 'off' | 'login'>('idle');
  let isLocked = $state(false);
  $effect(() => locked.subscribe((v) => {
    isLocked = v;
    if (v && phase === 'idle') run();
    if (!v) phase = 'idle';
  }));

  function run() {
    phase = 'halting';
    setTimeout(() => { phase = 'off'; }, 650);
    setTimeout(() => {
      phase = 'login';
      if (env.PUBLIC_AIR_API_MODE === 'live') void goto('/flightdeck/sign-in/');
    }, 1500);
  }

  function doUnlock() { unlock(); }
</script>

{#if isLocked}
  <div class="lockwrap">
    {#if phase === 'halting'}
      <div class="halt"><div class="ht">● agents halted · sealing chain · locking</div></div>
    {/if}
    {#if phase === 'login'}
      <div class="lock">
        <div class="lcard glass hud k">
          <div class="llogo"><span class="dot"></span><h2>Project&nbsp;<span class="air">AIR</span></h2></div>
          <div class="lsub">Session locked. Re-authenticate to resume agents.</div>
          <div class="lf"><label>Email</label><input type="email" value="kevin.minn@vindicara.io" /></div>
          <div class="lf"><label>Password</label><input type="password" value="••••••••••" /></div>
          <button class="lbtn" onclick={doUnlock}>Continue</button>
          <div class="lor">or</div>
          <button class="pkbtn" onclick={doUnlock}><span class="key"></span>Continue with passkey</button>
          <div class="lfoot">secured by Auth0 · FIDO2 / WebAuthn</div>
        </div>
      </div>
    {/if}
  </div>
{/if}

<style>
  .lockwrap { position: fixed; inset: 0; z-index: 60; }
  .halt { position: fixed; inset: 0; display: grid; place-items: center; background: #000; animation: flash .65s ease forwards; }
  .ht { font-family: var(--mono); font-size: 12.5px; letter-spacing: .22em; text-transform: uppercase; color: #ffd0d4; text-shadow: 0 0 18px rgba(230,57,70,.85); }
  @keyframes flash { 0% { opacity: 0; } 30% { opacity: 1; } 100% { opacity: 1; } }
  .lock { position: fixed; inset: 0; display: grid; place-items: center; background: radial-gradient(circle at 50% 28%, #0c0e15, #040508); animation: fadein .55s ease forwards; }
  @keyframes fadein { from { opacity: 0; } to { opacity: 1; } }
  .lcard { width: 362px; max-width: 90vw; padding: 34px 30px 22px; text-align: center; }
  .llogo { display: flex; align-items: center; justify-content: center; gap: 9px; margin-bottom: 4px; }
  .dot { width: 11px; height: 11px; border-radius: 2px; background: var(--air); box-shadow: 0 0 14px var(--air); }
  h2 { font-family: var(--display); font-weight: 600; font-size: 21px; }
  h2 :global(.air), .air { color: var(--air); font-weight: 700; }
  .lsub { font-size: 12.5px; color: var(--muted); margin: 7px 0 22px; }
  .lf { text-align: left; margin-bottom: 13px; }
  .lf label { display: block; font-family: var(--mono); font-size: 9px; letter-spacing: .12em; text-transform: uppercase; color: var(--faint); margin-bottom: 6px; }
  .lf input { width: 100%; padding: 11px 13px; background: rgba(0,0,0,.32); border: 1px solid var(--stroke); color: var(--ink); font-family: var(--ui); font-size: 13.5px; outline: none; }
  .lf input:focus { border-color: rgba(230,57,70,.5); }
  .lbtn { width: 100%; padding: 12px; border: 0; background: linear-gradient(180deg, #ff5d68, #E63946); color: #fff; font-weight: 700; font-size: 14px; cursor: pointer; margin-top: 4px; }
  .lbtn:hover { filter: brightness(1.1); }
  .lor { display: flex; align-items: center; gap: 10px; color: var(--faint); font-size: 11px; margin: 15px 0; }
  .lor::before, .lor::after { content: ''; height: 1px; flex: 1; background: var(--hair); }
  .pkbtn { width: 100%; padding: 11px; border: 1px solid rgba(155,107,255,.4); background: rgba(155,107,255,.1); color: #e0d3ff; font-weight: 600; font-size: 13px; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 9px; }
  .key { width: 13px; height: 13px; border-radius: 3px; background: radial-gradient(circle at 30% 30%, #fff, #b69bff); }
  .lfoot { margin-top: 20px; font-family: var(--mono); font-size: 9px; letter-spacing: .08em; color: var(--faint); }
</style>

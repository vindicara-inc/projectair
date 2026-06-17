<script lang="ts">
  // Demo sign-in: captures the operator's name + organization. On submit the operator
  // store is set, so the top-bar chip, the Console operator card, and the report's
  // "Authorized by" box all show this identity.
  import { signInOpen, signIn } from '$lib/console/stores/operator';
  import { resetSession } from '$lib/console/stores/sessionlog';

  let name = $state('Kevin Minn');
  let organization = $state('Vindicara');
  let role = $state('Founder · root authority');

  function submit(authMethod: 'passkey' | 'auth0') {
    signIn({ name, organization, role, authMethod });
    resetSession();
    signInOpen.set(false);
  }
</script>

{#if $signInOpen}
  <div class="wrap" role="presentation" onclick={() => signInOpen.set(false)}>
    <div class="card glass hud k" role="dialog" aria-modal="true" onclick={(e) => e.stopPropagation()}>
      <button class="x" aria-label="close" onclick={() => signInOpen.set(false)}>✕</button>
      <div class="logo"><span class="dot"></span><h2>Project&nbsp;<span class="air">AIR</span></h2></div>
      <div class="sub">Authorize this session. Your name and organization are bound to everything you approve.</div>

      <div class="f"><label>Name</label><input bind:value={name} placeholder="Your name" /></div>
      <div class="f"><label>Organization</label><input bind:value={organization} placeholder="Your hospital / company" /></div>
      <div class="f"><label>Role</label><input bind:value={role} placeholder="Your role" /></div>

      <button class="lbtn" onclick={() => submit('passkey')}><span class="key"></span>Continue with passkey</button>
      <button class="abtn" onclick={() => submit('auth0')}>Continue with Auth0</button>
      <div class="foot">secured by Auth0 · FIDO2 / WebAuthn · identity recorded on-chain</div>
    </div>
  </div>
{/if}

<style>
  .wrap { position: fixed; inset: 0; z-index: 70; display: grid; place-items: center; background: radial-gradient(circle at 50% 30%, rgba(8,9,14,.86), rgba(4,5,8,.94)); backdrop-filter: blur(4px); animation: fade .25s ease; }
  @keyframes fade { from { opacity: 0; } to { opacity: 1; } }
  .card { position: relative; width: 380px; max-width: 92vw; padding: 30px 30px 22px; text-align: center; }
  .x { position: absolute; top: 12px; right: 14px; background: none; border: 0; color: var(--faint); font-size: 15px; cursor: pointer; }
  .logo { display: flex; align-items: center; justify-content: center; gap: 9px; }
  .dot { width: 11px; height: 11px; border-radius: 2px; background: var(--air); box-shadow: 0 0 14px var(--air); }
  h2 { font-family: var(--display); font-weight: 600; font-size: 21px; }
  h2 :global(.air), .air { color: var(--air); font-weight: 700; }
  .sub { font-size: 12.5px; color: var(--muted); margin: 8px 0 20px; line-height: 1.5; }
  .f { text-align: left; margin-bottom: 12px; }
  .f label { display: block; font-family: var(--mono); font-size: 9px; letter-spacing: .12em; text-transform: uppercase; color: var(--faint); margin-bottom: 6px; }
  .f input { width: 100%; padding: 11px 13px; background: rgba(0,0,0,.32); border: 1px solid var(--stroke); color: var(--ink); font-family: var(--ui); font-size: 13.5px; outline: none; }
  .f input:focus { border-color: rgba(230,57,70,.5); }
  .lbtn { width: 100%; padding: 12px; border: 0; background: linear-gradient(180deg, #ff5d68, #E63946); color: #fff; font-weight: 700; font-size: 14px; cursor: pointer; margin-top: 6px; display: flex; align-items: center; justify-content: center; gap: 9px; }
  .lbtn:hover { filter: brightness(1.1); }
  .key { width: 13px; height: 13px; border-radius: 3px; background: radial-gradient(circle at 30% 30%, #fff, #ffd0d4); }
  .abtn { width: 100%; padding: 10px; margin-top: 10px; border: 1px solid var(--stroke); background: rgba(255,255,255,.04); color: var(--ink); font-weight: 600; font-size: 13px; cursor: pointer; }
  .abtn:hover { filter: brightness(1.2); }
  .foot { margin-top: 18px; font-family: var(--mono); font-size: 9px; letter-spacing: .06em; color: var(--faint); }
</style>

<script lang="ts">
  import { beginAuth0Login } from '$lib/console/stores/session';
</script>

<div class="lo">
  <div class="ok">You have successfully logged out.</div>
  <button class="login" onclick={() => beginAuth0Login()}>Log in again</button>
  <a class="home" href="/home">Back to vindicara.io</a>
</div>

<style>
  .lo { display:grid; place-items:center; gap:18px; height:100vh; font-family:var(--mono,monospace); color:#9aa1ad; padding:24px; text-align:center; }
  .ok { color:#cde8d4; max-width:520px; line-height:1.5; font-size:15px; }
  .login { padding:10px 18px; border:1px solid rgba(155,107,255,.4); background:linear-gradient(180deg, rgba(155,107,255,.22), rgba(155,107,255,.05)); color:#e0d3ff; font-weight:600; font-size:13px; cursor:pointer; font-family:inherit; }
  .home { color:#cdbcff; text-decoration:none; font-size:12px; }
  .home:hover { color:#fff; }
</style>

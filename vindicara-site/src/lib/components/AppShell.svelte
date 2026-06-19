<script>
  // @ts-nocheck
  // Shared interior shell. Top-nav header + content stage + unified footer,
  // matching the /solutions/* + homepage design system (industry.css).
  // Props kept for backwards-compat with existing pages; layout no longer uses the rail.
  import SiteHeader from '$lib/components/SiteHeader.svelte';
  import '$lib/styles/industry.css';
  let { active = '', title = '', scroll = false, dots = true, children } = $props();
</script>

<div class="ind">
  {#if dots}<div class="dotfield"></div>{/if}
  <SiteHeader />

  <main class="stage">
    {@render children?.()}
  </main>

  <footer class="foot">
    <nav class="fnav">
      <a href="/terms">Terms</a>
      <a href="/privacy">Privacy</a>
      <a href="/security">Security</a>
      <a href="/dpa">DPA</a>
    </nav>
    <span class="fmail">© Vindicara · support@vindicara.io</span>
  </footer>
</div>

<style>
  .stage{position:relative;z-index:1;width:100%;max-width:1140px;margin:0 auto;padding:34px 28px 54px}
  .fnav{display:flex;gap:6px 16px;flex-wrap:wrap;justify-content:center}
  .fnav a{color:var(--soft);text-decoration:none}
  .fnav a:hover{color:var(--air2)}
</style>

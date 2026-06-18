<script>
  // @ts-nocheck
  // Shared interior shell. Top-nav header + content stage + unified footer,
  // matching the /solutions/* + homepage design system (industry.css).
  // Props kept for backwards-compat with existing pages; layout no longer uses the rail.
  import IndustryHeader from '$lib/components/IndustryHeader.svelte';
  import '$lib/styles/industry.css';
  let { active = '', title = '', scroll = false, children } = $props();
</script>

<div class="ind">
  <div class="dotfield"></div>
  <IndustryHeader />

  <main class="stage">
    {@render children?.()}
  </main>

  <footer class="foot">
    <span class="fco">Vindicara · <span class="proj">project</span> <span class="air-wm">AIR</span> v1.0.1</span>
    <nav class="fnav">
      <a href="/explore">Explore</a>
      <a href="/about">About</a>
      <a href="/blog">Blog</a>
      <a href="/press">Press</a>
      <a href="/pricing">Pricing</a>
      <a href="/security">Security</a>
      <a href="/terms">Terms</a>
      <a href="/privacy">Privacy</a>
      <a href="/contact">Contact</a>
    </nav>
    <span class="fmail">support@vindicara.io</span>
  </footer>
</div>

<style>
  .stage{position:relative;z-index:1;width:100%;max-width:1140px;margin:0 auto;padding:34px 28px 54px}
  .fnav{display:flex;gap:6px 16px;flex-wrap:wrap;justify-content:center}
  .fnav a{color:var(--soft);text-decoration:none}
  .fnav a:hover{color:var(--air2)}
</style>

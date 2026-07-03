<script>
  import AppShell from '$components/AppShell.svelte';
  import { posts, displayDate } from '$lib/blog/posts.js';
</script>
<svelte:head>
  <title>Vindicara · Blog</title>
  <link rel="alternate" type="application/rss+xml" title="Vindicara Blog" href="https://vindicara.io/rss.xml" />
</svelte:head>

<AppShell active="blog" title="blog" scroll={true}>
  <div class="prose">
    <div class="eyebrow">Blog</div>
    <h1>Notes from the evidence layer.</h1>
    <p>Engineering, compliance, and strategy from the team building Project AIR.</p>

    <div class="posts">
      {#each posts as p}
        <a class="post" href={p.href}>
          <div class="ptag">{p.tag} · {displayDate(p.date)}</div>
          <div class="ptitle">{p.title}</div>
          <div class="pdesc">{p.description}</div>
          <div class="pmore">Read →</div>
        </a>
      {/each}
    </div>
  </div>
</AppShell>

<style>
  .prose h1{font-size:36px;margin:14px 0 0}
  .posts{display:flex;flex-direction:column;gap:14px;margin:24px 0 14px}
  .post{display:block;border:1px solid var(--line);background:var(--panel);box-shadow:var(--shadow);padding:20px;text-decoration:none;color:var(--white);transition:.15s}
  .post:hover{border-color:var(--air);transform:translateY(-2px)}
  .ptag{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--air2)}
  .ptitle{font-family:var(--display);font-size:20px;font-weight:600;margin:8px 0 6px}
  .pdesc{font-size:13px;color:var(--soft);line-height:1.5}
  .pmore{font-family:var(--mono);font-size:11px;color:var(--air2);margin-top:12px}
</style>

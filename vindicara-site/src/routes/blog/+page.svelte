<script>
  import AppShell from '$components/AppShell.svelte';
  // These three are live posts on vindicara.io/blog today. New entries drop in here.
  const posts = [
    { t: 'Structural Verification: a deterministic floor that cannot be prompt-injected', d: 'Why per-call guardrails miss trajectory-level attacks, and how the SV checks catch them.', tag: 'Engineering', href: 'https://vindicara.io/blog/structural-verification', date: '2026' },
    { t: 'EU AI Act Article 72: a practical readiness guide', d: 'What post-market monitoring evidence actually has to contain, and how to produce it.', tag: 'Compliance', href: 'https://vindicara.io/blog/eu-ai-act-article-72-guide', date: '2026' },
    { t: 'The forensic layer: a market map', d: 'Where evidence-grade infrastructure sits next to prevention, governance, and observability.', tag: 'Strategy', href: 'https://vindicara.io/blog/forensic-layer-market-map', date: '2026' }
  ];
</script>
<svelte:head><title>Vindicara · Blog</title></svelte:head>

<AppShell active="blog" title="blog" scroll={true}>
  <div class="prose">
    <div class="eyebrow">Blog</div>
    <h1>Notes from the evidence layer.</h1>
    <p>Engineering, compliance, and strategy from the team building Project AIR.</p>

    <div class="posts">
      {#each posts as p}
        <a class="post" href={p.href} target="_blank" rel="noopener">
          <div class="ptag">{p.tag} · {p.date}</div>
          <div class="ptitle">{p.t}</div>
          <div class="pdesc">{p.d}</div>
          <div class="pmore">Read →</div>
        </a>
      {/each}
    </div>
    <p class="muted">More posts are published on the live blog. New entries are added to this index.</p>
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

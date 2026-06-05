<script lang="ts">
  import vindicaraLogoDay from '$lib/assets/vindicara-logo-day.png';
  import vindicaraLogoNight from '$lib/assets/vindicara-logo-night.png';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';

  let mobileMenuOpen = $state(false);

  // Article 72 applies on 2 August 2026 for high-risk (Annex III) systems.
  // Target midnight CEST (UTC+2). Countdown computed client-side; never hardcoded.
  const TARGET = new Date('2026-08-02T00:00:00+02:00').getTime();

  let now = $state(Date.now());
  let live = $derived(now >= TARGET);
  let remaining = $derived(Math.max(0, TARGET - now));
  let days = $derived(Math.floor(remaining / 86400000));
  let hours = $derived(Math.floor((remaining % 86400000) / 3600000));
  let minutes = $derived(Math.floor((remaining % 3600000) / 60000));
  let seconds = $derived(Math.floor((remaining % 60000) / 1000));

  $effect(() => {
    const id = setInterval(() => { now = Date.now(); }, 1000);
    return () => clearInterval(id);
  });

  function pad(n: number): string {
    return n.toString().padStart(2, '0');
  }
</script>

<svelte:head>
  <title>EU AI Act Article 72 Compliance for AI Agents | Project AIR by Vindicara</title>
  <meta name="description" content="The EU AI Act becomes enforceable for high-risk AI systems on August 2, 2026. Article 72 requires continuous post-market monitoring. Project AIR generates the signed, exportable evidence in minutes. Open source, MIT." />
  <meta name="keywords" content="EU AI Act Article 72, EU AI Act Article 12, post-market monitoring AI, high-risk AI systems compliance, AI agent audit trail EU, August 2 2026 deadline, conformity assessment AI agents, Annex III high-risk AI" />

  <link rel="canonical" href="https://vindicara.io/eu-ai-act" />

  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://vindicara.io/eu-ai-act" />
  <meta property="og:title" content="EU AI Act Article 72 Compliance for AI Agents | Project AIR by Vindicara" />
  <meta property="og:description" content="Article 72 requires continuous post-market monitoring for high-risk AI systems from August 2, 2026. Project AIR generates signed, exportable evidence in minutes." />

  <meta name="twitter:title" content="EU AI Act Article 72 Compliance for AI Agents | Project AIR by Vindicara" />
  <meta name="twitter:description" content="Continuous, signed, tamper-evident records for high-risk AI agents. Article 72 ready before August 2, 2026." />

  {@html `<script type="application/ld+json">${JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: 'Home', item: 'https://vindicara.io/' },
      { '@type': 'ListItem', position: 2, name: 'EU AI Act', item: 'https://vindicara.io/eu-ai-act' },
    ],
  })}<\/script>`}
</svelte:head>

<!-- NAV -->
<nav class="fixed top-0 w-full z-50 backdrop-blur-2xl" style="background-color: color-mix(in srgb, var(--surface) 60%, transparent); border-bottom: 1px solid var(--border-subtle);">
  <div class="max-w-screen-2xl mx-auto px-6 flex items-center justify-between h-16">
    <a href="/" class="flex items-center gap-1">
      <img src={vindicaraLogoNight} alt="Vindicara" class="h-10 w-auto logo-night mix-blend-screen" /><img src={vindicaraLogoDay} alt="Vindicara" class="h-10 w-auto logo-day" />
      <span class="font-mono text-[10px] tracking-[0.18em] uppercase px-1.5 py-0.5" style="color: var(--text-primary); border: 1px solid var(--border); box-shadow: 0 0 10px var(--badge-shadow);">Project AIR&#8482;</span>
    </a>

    <div class="hidden md:flex items-center gap-8 text-sm">
      <a href="/#how-it-works" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">How It Works</a>
      <a href="/admissibility#certification" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">FRE 902(13)</a>
      <a href="/blog" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Blog</a>
      <a href="/pricing" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Pricing</a>
    </div>

    <div class="hidden md:flex items-center gap-3">
      <ThemeToggle />
      <a href="/contact" class="btn-secondary text-xs px-4 py-2">Talk to us</a>
      <a href="https://github.com/vindicara-inc/projectair" class="btn-primary text-xs px-4 py-2">
        <svg class="w-4 h-4 mr-1.5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        GitHub
      </a>
    </div>

    <div class="md:hidden flex items-center gap-2">
      <ThemeToggle />
      <button
        style="color: var(--text-muted);"
        onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'}
        onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
        onclick={() => mobileMenuOpen = !mobileMenuOpen}
      >
        <svg class="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          {#if mobileMenuOpen}
            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
          {:else}
            <path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
          {/if}
        </svg>
      </button>
    </div>
  </div>

  {#if mobileMenuOpen}
    <div class="md:hidden backdrop-blur-2xl px-6 py-4 space-y-3" style="border-top: 1px solid var(--border-subtle); background-color: color-mix(in srgb, var(--surface) 95%, transparent);">
      <a href="/#how-it-works" style="color: var(--text-muted);" class="block text-sm">How It Works</a>
      <a href="/admissibility#certification" style="color: var(--text-muted);" class="block text-sm">FRE 902(13)</a>
      <a href="/blog" style="color: var(--text-muted);" class="block text-sm">Blog</a>
      <a href="/pricing" style="color: var(--text-muted);" class="block text-sm">Pricing</a>
      <div class="flex gap-3 pt-2">
        <a href="/contact" class="btn-secondary text-xs px-4 py-2">Talk to us</a>
        <a href="https://github.com/vindicara-inc/projectair" class="btn-primary text-xs px-4 py-2">GitHub</a>
      </div>
    </div>
  {/if}
</nav>

<main class="pt-16">
  <!-- HERO + COUNTDOWN -->
  <section class="py-20 sm:py-28 relative overflow-hidden">
    <div class="absolute inset-0">
      <img src="/hero-mesh.png" alt="" class="w-full h-full object-cover opacity-25" />
      <div class="absolute inset-0" style="background: linear-gradient(to bottom, var(--surface), color-mix(in srgb, var(--surface) 88%, transparent), var(--surface));"></div>
    </div>
    <div class="relative max-w-screen-xl mx-auto px-6 text-center">
      <div class="inline-flex items-center gap-2 px-3 py-1.5 glass-panel text-xs mb-8 font-mono" style="color: var(--text-secondary);">
        <span class="w-2 h-2 rounded-full bg-brand-red animate-pulse"></span>
        EU AI ACT · ENFORCEMENT BEGINS AUGUST 2, 2026
      </div>

      <h1 class="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight leading-[1.08] max-w-4xl mx-auto" style="color: var(--text-primary);">
        Article 72 compliance for AI agents, <span class="text-gradient-brand">before the deadline.</span>
      </h1>

      <!-- Countdown -->
      <div class="mt-10 flex items-center justify-center gap-3 sm:gap-5">
        {#if live}
          <div class="px-6 py-4 border border-brand-red/40 bg-brand-red/5">
            <p class="text-xl sm:text-2xl font-black text-brand-red font-mono">Enforcement is live</p>
          </div>
        {:else}
          {#each [{ v: days, l: 'days' }, { v: hours, l: 'hrs' }, { v: minutes, l: 'min' }, { v: seconds, l: 'sec' }] as unit (unit.l)}
            <div class="flex flex-col items-center">
              <span class="text-3xl sm:text-5xl font-black font-mono tabular-nums" style="color: var(--text-primary);">{unit.l === 'days' ? unit.v : pad(unit.v)}</span>
              <span class="text-[10px] sm:text-xs font-mono uppercase tracking-wider mt-1" style="color: var(--text-faint);">{unit.l}</span>
            </div>
          {/each}
        {/if}
      </div>
      <p class="mt-3 text-xs font-mono uppercase tracking-wider" style="color: var(--text-faint);">to August 2, 2026 · 00:00 CET</p>

      <p class="mt-8 text-base sm:text-lg max-w-2xl mx-auto leading-relaxed" style="color: var(--text-muted);">
        On August 2, 2026, the EU AI Act's obligations for high-risk AI systems become fully enforceable. If your AI agents are high-risk under Annex III, Article 72 requires you to continuously monitor what those systems do in production and keep records you can hand a regulator. Project AIR generates that evidence, signed and exportable, in minutes.
      </p>

      <div class="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
        <a href="/contact" class="btn-primary text-base px-8 py-4">Book a readiness call</a>
        <a href="https://pypi.org/project/projectair/" class="btn-secondary text-base px-8 py-4 font-mono">pip install projectair</a>
      </div>

      <p class="mt-8 text-xs max-w-xl mx-auto" style="color: var(--text-faint);">
        Open source, MIT licensed. NVIDIA Inception member. Already running in production on our own Rekor-anchored infrastructure, which you can verify yourself.
      </p>
    </div>
  </section>

  <!-- WHAT ARTICLE 72 REQUIRES -->
  <section class="py-24 relative" style="border-top: 1px solid var(--border-subtle);">
    <div class="max-w-screen-xl mx-auto px-6">
      <div class="text-center mb-14">
        <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-3 font-mono">What the law requires</p>
        <h2 class="text-3xl sm:text-4xl font-bold tracking-tight max-w-3xl mx-auto">Article 72 and Article 12, in plain language.</h2>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl mx-auto">
        <div class="p-7" style="border: 1px solid var(--border); background-color: color-mix(in srgb, var(--surface-overlay) 40%, transparent);">
          <p class="font-mono text-[11px] tracking-wider uppercase text-brand-red mb-3">Article 72 · Post-market monitoring</p>
          <p class="text-sm leading-relaxed" style="color: var(--text-secondary);">
            Providers of high-risk AI systems must actively and systematically collect, document, and analyse data on system performance throughout its lifecycle, against a documented monitoring plan. For autonomous agents that means a continuous, tamper-evident record of what the agent did, not a sampled log.
          </p>
        </div>
        <div class="p-7" style="border: 1px solid var(--border); background-color: color-mix(in srgb, var(--surface-overlay) 40%, transparent);">
          <p class="font-mono text-[11px] tracking-wider uppercase text-brand-red mb-3">Article 12 · Record-keeping</p>
          <p class="text-sm leading-relaxed" style="color: var(--text-secondary);">
            High-risk systems must technically allow the automatic recording of events over the system's lifetime, with traceability appropriate to the intended purpose, capable of identifying situations that may present a risk or lead to a substantial modification.
          </p>
        </div>
      </div>

      <div class="max-w-4xl mx-auto mt-6 p-6 border border-brand-red/30 bg-brand-red/[0.03]">
        <p class="text-sm leading-relaxed" style="color: var(--text-secondary);">
          <span class="font-semibold" style="color: var(--text-primary);">Penalties.</span> Breaching provider obligations such as Article 72 carries fines up to 15 million euros or 3% of total worldwide annual turnover, whichever is higher (Article 99). The top tier, 35 million euros or 7%, applies to prohibited practices under Article 5. This is board-level risk, not a checkbox.
        </p>
      </div>

      <div class="max-w-4xl mx-auto mt-6 p-6" style="border: 1px solid var(--border);">
        <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
          <span class="font-semibold" style="color: var(--text-secondary);">Scope, honestly.</span> Only high-risk systems are in scope. The August 2, 2026 date applies to high-risk systems under Annex III. AI that is a regulated medical device falls under Article 6(1) and Annex I, whose obligations apply August 2, 2027. If you are not sure which applies to you, that is exactly the conversation to have now.
        </p>
      </div>
    </div>
  </section>

  <!-- THE GAP -->
  <section class="py-24 relative" style="border-top: 1px solid var(--border-subtle); background-color: color-mix(in srgb, var(--surface-raised) 30%, transparent);">
    <div class="max-w-screen-xl mx-auto px-6">
      <div class="text-center mb-14">
        <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-3 font-mono">The gap</p>
        <h2 class="text-3xl sm:text-4xl font-bold tracking-tight max-w-3xl mx-auto">Your application logs were not built to be evidence.</h2>
        <p class="mt-4 text-base max-w-2xl mx-auto leading-relaxed" style="color: var(--text-muted);">
          Logs can be edited, they have gaps, and they cannot prove they were not tampered with after an incident. Article 72 asks you to demonstrate continuous monitoring with records you can stand behind. Standard observability tooling does not clear that bar.
        </p>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-0 max-w-5xl mx-auto" style="border: 1px solid var(--border);">
        <div class="p-6" style="border-bottom: 1px solid var(--border); border-right: 1px solid var(--border);">
          <p class="font-mono text-[11px] tracking-wider uppercase mb-2" style="color: var(--text-muted);">What you probably have</p>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">Mutable app logs, sampled traces, dashboards that show performance but not intent.</p>
        </div>
        <div class="p-6" style="border-bottom: 1px solid var(--border); border-right: 1px solid var(--border);">
          <p class="font-mono text-[11px] tracking-wider uppercase mb-2" style="color: var(--text-muted);">What Article 72 expects</p>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">Continuous, complete, tamper-evident records tied to a monitoring plan.</p>
        </div>
        <div class="p-6 bg-brand-red/[0.04]" style="border-bottom: 1px solid var(--border);">
          <p class="font-mono text-[11px] tracking-wider uppercase text-brand-red mb-2">What Project AIR gives you</p>
          <p class="text-sm leading-relaxed" style="color: var(--text-secondary);">Every agent action signed in-process with BLAKE3 and Ed25519, forward-chained for integrity, anchored to public Sigstore Rekor, exportable as conformity artifacts.</p>
        </div>
      </div>
    </div>
  </section>

  <!-- HOW AIR GETS YOU THERE -->
  <section class="py-24 relative" style="border-top: 1px solid var(--border-subtle);">
    <div class="max-w-screen-xl mx-auto px-6">
      <div class="text-center mb-14">
        <p class="text-brand-cyan text-sm font-semibold uppercase tracking-wider mb-3 font-mono">How AIR gets you there</p>
        <h2 class="text-3xl sm:text-4xl font-bold tracking-tight max-w-3xl mx-auto">Three steps. Most of it automated.</h2>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="p-7" style="border: 1px solid var(--border); background-color: color-mix(in srgb, var(--surface-overlay) 40%, transparent);">
          <p class="font-mono text-[11px] tracking-wider uppercase mb-3 text-brand-red">01 · Instrument in five minutes</p>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">Drop-in SDK for LangChain, OpenAI, Anthropic, LlamaIndex, Gemini, and Google ADK. Every action becomes a signed AgDR record, a Signed Intent Capsule.</p>
        </div>
        <div class="p-7" style="border: 1px solid var(--border); background-color: color-mix(in srgb, var(--surface-overlay) 40%, transparent);">
          <p class="font-mono text-[11px] tracking-wider uppercase mb-3 text-brand-red">02 · Monitor continuously</p>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">The chain captures what the agent did, in order, with cryptographic integrity. AIR-04 flags gaps in the chain itself, so you can prove the record is complete.</p>
        </div>
        <div class="p-7" style="border: 1px solid var(--border); background-color: color-mix(in srgb, var(--surface-overlay) 40%, transparent);">
          <p class="font-mono text-[11px] tracking-wider uppercase mb-3 text-brand-red">03 · Export on demand</p>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">Generate Article 72 post-market monitoring evidence and Article 12 log artifacts in one command. Counsel and compliance complete the filing; AIR supplies the runtime proof.</p>
        </div>
      </div>

      <div class="max-w-3xl mx-auto mt-10 dark-embed p-5 font-mono text-xs sm:text-sm leading-relaxed">
        <div><span class="text-brand-purple">from</span> <span class="text-zinc-300">airsdk</span> <span class="text-brand-purple">import</span> <span class="text-brand-cyan">AIRCallbackHandler</span></div>
        <div class="mt-1"><span class="text-zinc-300">handler = </span><span class="text-brand-cyan">AIRCallbackHandler</span><span class="text-zinc-300">(key=</span><span class="text-green-400">"..."</span><span class="text-zinc-300">)</span></div>
        <div class="mt-1"><span class="text-zinc-300">agent = </span><span class="text-brand-cyan">AgentExecutor</span><span class="text-zinc-300">(callbacks=[handler])</span></div>
      </div>
    </div>
  </section>

  <!-- HONEST SCOPE -->
  <section class="py-24 relative" style="border-top: 1px solid var(--border-subtle); background-color: color-mix(in srgb, var(--surface-raised) 30%, transparent);">
    <div class="max-w-3xl mx-auto px-6 text-center">
      <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-3 font-mono">Honest scope</p>
      <h2 class="text-2xl sm:text-3xl font-bold tracking-tight">What AIR does, and what it does not.</h2>
      <p class="mt-5 text-base leading-relaxed" style="color: var(--text-muted);">
        Project AIR produces the technical evidence layer Article 72 and Article 12 require: continuous, signed, tamper-evident records and exportable artifacts. It does not file your conformity assessment for you, and it is not legal advice. It gives your compliance team and counsel evidence they can rely on instead of logs they cannot.
      </p>
      <div class="mt-8">
        <a href="/admissibility" class="btn-secondary text-sm px-6 py-3">Read the admissibility architecture</a>
      </div>
    </div>
  </section>

  <!-- CTA -->
  <section class="py-24 relative overflow-hidden">
    <div class="absolute inset-0">
      <img src="/hero-mesh.png" alt="" class="w-full h-full object-cover opacity-20" />
      <div class="absolute inset-0" style="background: linear-gradient(to top, var(--surface), color-mix(in srgb, var(--surface) 92%, transparent), var(--surface));"></div>
    </div>
    <div class="relative max-w-xl mx-auto px-6 text-center">
      <h2 class="text-3xl sm:text-4xl font-bold tracking-tight">
        {#if live}
          The deadline has passed. Get your evidence layer right now.
        {:else}
          {days} days is enough time to get the evidence layer right.
        {/if}
      </h2>
      <p class="mt-5 text-base leading-relaxed" style="color: var(--text-muted);">
        Talk to us about an Article 72 readiness path for your agents. Design partners get hands-on help wiring AIR into production.
      </p>
      <div class="mt-8 flex flex-col sm:flex-row items-center justify-center gap-4">
        <a href="/contact" class="btn-primary text-base px-8 py-4">Book a readiness call</a>
        <a href="/blog/eu-ai-act-article-72-guide" class="btn-secondary text-base px-8 py-4">Read the developer's guide</a>
      </div>
    </div>
  </section>
</main>

<!-- FOOTER -->
<footer class="w-full relative z-20" style="border-top: 1px solid var(--border-subtle); background-color: var(--surface);">
  <div class="max-w-screen-xl mx-auto px-6 py-14">
    <div class="grid grid-cols-2 md:grid-cols-4 gap-8">
      <div class="col-span-2 md:col-span-1">
        <div class="flex items-center gap-1 mb-4">
          <img src={vindicaraLogoNight} alt="Vindicara" class="h-10 w-auto logo-night mix-blend-screen" /><img src={vindicaraLogoDay} alt="Vindicara" class="h-10 w-auto logo-day" />
          <span class="font-mono text-[10px] tracking-[0.18em] uppercase px-1.5 py-0.5" style="color: var(--text-primary); border: 1px solid var(--border); box-shadow: 0 0 10px var(--badge-shadow);">Project AIR&#8482;</span>
        </div>
        <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
          Project AIR by Vindicara. Evidence-grade infrastructure for AI agents: forensic reconstruction, signed evidence, and containment for autonomous agents.
        </p>
      </div>

      <div>
        <h3 class="text-sm font-semibold mb-4">Product</h3>
        <ul class="space-y-2 text-sm" style="color: var(--text-muted);">
          <li><a href="/#how-it-works" style="color: inherit;" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">How It Works</a></li>
          <li><a href="/#standards" style="color: inherit;" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Standards</a></li>
          <li><a href="/pricing" style="color: inherit;" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Pricing</a></li>
          <li><a href="https://github.com/vindicara-inc/projectair#readme" style="color: inherit;" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Docs</a></li>
        </ul>
      </div>

      <div>
        <h3 class="text-sm font-semibold mb-4">Company</h3>
        <ul class="space-y-2 text-sm" style="color: var(--text-muted);">
          <li><a href="mailto:Kevin.Minn@vindicara.io" style="color: inherit;" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Kevin.Minn@vindicara.io</a></li>
          <li><a href="/blog" style="color: inherit;" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Blog</a></li>
          <li><a href="https://github.com/vindicara-inc/projectair" style="color: inherit;" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">GitHub</a></li>
        </ul>
      </div>

      <div>
        <h3 class="text-sm font-semibold mb-4">Legal</h3>
        <ul class="space-y-2 text-sm" style="color: var(--text-muted);">
          <li><a href="/terms" style="color: inherit;" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Terms of Service</a></li>
          <li><a href="/privacy" style="color: inherit;" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Privacy Policy</a></li>
          <li><a href="/acceptable-use" style="color: inherit;" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Acceptable Use</a></li>
          <li><a href="/security" style="color: inherit;" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Security Disclosure</a></li>
        </ul>
      </div>
    </div>

    <div class="mt-12 pt-8 flex items-center gap-4" style="border-top: 1px solid var(--border-subtle);">
      <img src="/nvidia-inception-program-badge.svg" alt="NVIDIA Inception program member" class="h-8 w-auto" />
      <p class="text-xs" style="color: var(--text-muted);">Vindicara is a member of the NVIDIA Inception program.</p>
    </div>

    <div class="mt-8 flex flex-col md:flex-row items-center justify-between gap-4">
      <p class="text-xs" style="color: var(--text-faint);">&copy; 2026 Vindicara, Inc. · Project AIR.</p>
      <div class="flex items-center gap-4">
        <a href="https://github.com/vindicara-inc/projectair" style="color: var(--text-faint);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-faint)'} class="transition-colors">
          <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        </a>
      </div>
    </div>
  </div>
</footer>

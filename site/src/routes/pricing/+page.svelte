<script lang="ts">
  import vindicaraLogoDay from '$lib/assets/vindicara-logo-day.png';
  import vindicaraLogoNight from '$lib/assets/vindicara-logo-night.png';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';


  let mobileMenuOpen = $state(false);
</script>

<svelte:head>
  <title>Pricing | Vindicara AIR</title>
  <meta name="description" content="Vindicara AIR pricing. Open source on PyPI under MIT. Commercial tiers available in private beta. Contact us." />
  <link rel="canonical" href="https://vindicara.io/pricing" />

  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://vindicara.io/pricing" />
  <meta property="og:title" content="Pricing | Vindicara AIR" />
  <meta property="og:description" content="Open source on PyPI under MIT. Commercial deployments in private beta. Contact us." />
  <meta property="og:image:alt" content="Vindicara AIR pricing: open source and commercial tiers." />

  <meta name="twitter:title" content="Pricing | Vindicara AIR" />
  <meta name="twitter:description" content="Open source on PyPI under MIT. Commercial deployments in private beta. Contact us." />

  {@html `<script type="application/ld+json">${JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'Product',
    '@id': 'https://vindicara.io/pricing#product',
    name: 'Vindicara AIR',
    description: 'Forensic reconstruction and incident response for AI agents. Signed forensic evidence from agent traces.',
    brand: { '@type': 'Brand', name: 'Vindicara' },
    url: 'https://vindicara.io/pricing',
    offers: [
      {
        '@type': 'Offer',
        name: 'Open Source',
        price: '0',
        priceCurrency: 'USD',
        availability: 'https://schema.org/InStock',
        description: 'MIT-licensed air CLI, airsdk Python SDK with LangChain, OpenAI, Anthropic, and LlamaIndex instrumentation. 16 detectors. JSON, PDF, CEF, and Article 72 template export. Community support.',
        url: 'https://github.com/vindicara-inc/projectair',
      },
    ],
  })}<\/script>`}

  {@html `<script type="application/ld+json">${JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: 'Home', item: 'https://vindicara.io/' },
      { '@type': 'ListItem', position: 2, name: 'Pricing', item: 'https://vindicara.io/pricing' },
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
      <a href="/#standards" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Standards</a>
      <a href="/admissibility#certification" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">FRE 902(13)</a>
      <a href="/blog" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Blog</a>
      <a href="/pricing" style="color: var(--text-primary);" class="transition-colors">Pricing</a>
    </div>

    <div class="hidden md:flex items-center gap-3">
      <ThemeToggle />
      <a href="https://github.com/vindicara-inc/projectair#readme" class="btn-secondary text-xs px-4 py-2">Docs</a>
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
      <a href="/#how-it-works" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="block text-sm">How It Works</a>
      <a href="/#standards" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="block text-sm">Standards</a>
      <a href="/admissibility#certification" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="block text-sm">FRE 902(13)</a>
      <a href="/blog" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="block text-sm">Blog</a>
      <a href="/pricing" style="color: var(--text-primary);" class="block text-sm">Pricing</a>
      <div class="flex gap-3 pt-2">
        <a href="https://github.com/vindicara-inc/projectair#readme" class="btn-secondary text-xs px-4 py-2">Docs</a>
        <a href="https://github.com/vindicara-inc/projectair" class="btn-primary text-xs px-4 py-2">GitHub</a>
      </div>
    </div>
  {/if}
</nav>

<main class="pt-16">
  <!-- HEADER -->
  <section class="py-20 relative">
    <div class="absolute inset-0">
      <img src="/hero-mesh.png" alt="" class="w-full h-full object-cover opacity-20" />
      <div class="absolute inset-0" style="background: linear-gradient(to bottom, var(--surface), color-mix(in srgb, var(--surface) 90%, transparent), var(--surface));"></div>
    </div>
    <div class="relative max-w-screen-xl mx-auto px-6 text-center">
      <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-4 font-mono">Pricing</p>
      <h1 class="text-5xl sm:text-6xl font-black tracking-tight max-w-3xl mx-auto">Open source.</h1>
      <p class="mt-5 text-lg max-w-2xl mx-auto leading-relaxed" style="color: var(--text-muted);">
        The <code class="font-mono" style="color: var(--text-secondary);">air</code> CLI and <code class="font-mono" style="color: var(--text-secondary);">airsdk</code> Python SDK are available<br />on PyPI under the MIT license.
      </p>
    </div>
  </section>

  <!-- FREE TIER -->
  <section class="pb-24">
    <div class="max-w-screen-xl mx-auto px-6">
      <div class="max-w-2xl mx-auto p-8" style="border: 1px solid var(--border);">
        <div class="flex items-center justify-between mb-2">
          <h2 class="text-sm font-mono uppercase tracking-wider" style="color: var(--text-muted);">Open Source</h2>
          <span class="font-mono text-[10px] text-green-400 border border-green-400/30 bg-green-400/5 px-2 py-0.5 uppercase tracking-wider">Available</span>
        </div>
        <p class="text-3xl font-black mt-4">Free</p>
        <p class="text-sm mt-1" style="color: var(--text-muted);">Forever. MIT license. On PyPI.</p>
        <ul class="mt-7 space-y-3 text-sm" style="color: var(--text-muted);">
          <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span><span class="font-mono" style="color: var(--text-secondary);">air</span> CLI: trace, demo, report</span></li>
          <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span><span class="font-mono" style="color: var(--text-secondary);">airsdk</span>: LangChain, OpenAI, Anthropic, LlamaIndex, Gemini, ADK, NeMo</span></li>
          <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>16 detectors (10 OWASP Agentic + 3 LLM + 3 AIR-native)</span></li>
          <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Signed Intent Capsule chain, local-only</span></li>
          <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>JSON, PDF, CEF, Article 72 template export</span></li>
          <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Zero-Trust agent registry enforcement</span></li>
          <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Community support</span></li>
        </ul>
        <div class="mt-8">
          <div class="dark-embed px-4 py-2 font-mono text-sm text-zinc-300 text-center">
            <span class="text-zinc-500">$</span> pip install projectair
          </div>
        </div>
        <a href="https://github.com/vindicara-inc/projectair" class="btn-secondary w-full mt-4 text-sm">View on GitHub</a>
      </div>
    </div>
  </section>

  <!-- COMMERCIAL -->
  <section class="py-24" style="border-top: 1px solid var(--border-subtle);">
    <div class="max-w-screen-xl mx-auto px-6 text-center">
      <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-4 font-mono">Commercial</p>
      <h2 class="text-4xl sm:text-5xl font-black tracking-tight">Commercial tiers in private beta.</h2>
      <p class="mt-5 text-lg max-w-2xl mx-auto leading-relaxed" style="color: var(--text-muted);">
        Team, Enterprise, and Air-Gapped deployments are available to design partners. Everything in Open Source, plus:
      </p>
      <div class="max-w-3xl mx-auto mt-10 p-8 text-left" style="border: 1px solid var(--border); background-color: var(--glass);">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-x-10 gap-y-8">
          <div>
            <h3 class="text-xs font-mono uppercase tracking-wider mb-4" style="color: var(--text-muted);">Verification + Detection</h3>
            <ul class="space-y-3 text-sm" style="color: var(--text-muted);">
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Structural Verification (SV-SECRET, SV-NET, SV-SCOPE, SV-EXFIL, SV-ENTITY)</span></li>
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Premium ASI04 supply chain detectors (dependency install, manifest drift, untrusted fetch)</span></li>
            </ul>
          </div>

          <div>
            <h3 class="text-xs font-mono uppercase tracking-wider mb-4" style="color: var(--text-muted);">AIR Cloud</h3>
            <ul class="space-y-3 text-sm" style="color: var(--text-muted);">
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Push chains to hosted workspace, S3, or webhooks</span></li>
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Incident alerting (Slack, PagerDuty, webhook)</span></li>
            </ul>
          </div>

          <div>
            <h3 class="text-xs font-mono uppercase tracking-wider mb-4" style="color: var(--text-muted);">Data Governance</h3>
            <ul class="space-y-3 text-sm" style="color: var(--text-muted);">
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Data-asset lineage + data-subject tracking</span></li>
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>DSAR automation (data subject access requests)</span></li>
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>OpenLineage export</span></li>
            </ul>
          </div>

          <div>
            <h3 class="text-xs font-mono uppercase tracking-wider mb-4" style="color: var(--text-muted);">SIEM + Integrations</h3>
            <ul class="space-y-3 text-sm" style="color: var(--text-muted);">
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Splunk HEC, Datadog, Microsoft Sentinel, Sumo Logic</span></li>
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>HL7v2 + FHIR R4 clinical interop</span></li>
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Clinical evidence sidecar (SIEM gateway)</span></li>
            </ul>
          </div>

          <div>
            <h3 class="text-xs font-mono uppercase tracking-wider mb-4" style="color: var(--text-muted);">Compliance + Reports</h3>
            <ul class="space-y-3 text-sm" style="color: var(--text-muted);">
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>NIST AI RMF report</span></li>
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>SOC 2 AI report</span></li>
            </ul>
          </div>

          <div>
            <h3 class="text-xs font-mono uppercase tracking-wider mb-4" style="color: var(--text-muted);">Enterprise</h3>
            <ul class="space-y-3 text-sm" style="color: var(--text-muted);">
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Air-gapped license (no phone-home)</span></li>
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>Auth0 OIDC / JWT verification (Layer 3 containment)</span></li>
              <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">&#x203A;</span><span>SLA, BAA available for design partners</span></li>
            </ul>
          </div>
        </div>
        <a href="/contact" class="btn-primary w-full mt-10 text-sm">Contact us</a>
      </div>
    </div>
  </section>

  <!-- FAQ -->
  <section class="py-20" style="border-top: 1px solid var(--border-subtle);">
    <div class="max-w-screen-xl mx-auto px-6">
      <div class="text-center mb-14">
        <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-3 font-mono">Questions</p>
        <h2 class="text-3xl sm:text-4xl font-bold tracking-tight">Before you ask</h2>
      </div>

      <div class="max-w-3xl mx-auto space-y-8">
        <div>
          <h3 class="text-lg font-semibold mb-2" style="color: var(--text-primary);">What stays free forever?</h3>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
            The <code class="font-mono" style="color: var(--text-secondary);">air</code> CLI, the <code class="font-mono" style="color: var(--text-secondary);">airsdk</code> Python SDK, the signed Intent Capsule chain, and all 16 detectors: 10 OWASP Top 10 for Agentic Applications (ASI01 through ASI10), 3 OWASP Top 10 for LLM Applications categories (LLM01, LLM04, LLM06), and 3 AIR-native detectors. JSON, PDF, and CEF export formats included. EU AI Act Article 72 evidence template generator included. Zero-Trust agent registry enforcement included. All MIT-licensed, all self-hosted, no seat limits, no trace limits.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold mb-2" style="color: var(--text-primary);">What do the commercial tiers add?</h3>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
            Structural Verification, premium supply chain detectors, AIR Cloud (chain push to hosted workspace, S3, or webhooks), SIEM integrations (Splunk, Datadog, Sentinel, Sumo Logic), data governance (lineage, DSAR, OpenLineage), compliance reports (NIST AI RMF, SOC 2 AI), HL7v2 + FHIR R4 clinical interop, incident alerting (Slack, PagerDuty, webhook), and air-gapped licensing. Commercial tiers are currently in private beta. <a href="/contact" style="color: var(--text-secondary); text-decoration: underline; text-underline-offset: 4px;">Contact us</a> for access.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold mb-2" style="color: var(--text-primary);">Can I evaluate before committing?</h3>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
            Yes. The OSS tier covers the full forensic record path end-to-end and works with any inference backend. You can prove the detector quality and the chain-of-custody story before any commercial conversation. Once you talk to us, design-partner engagements are hands-on: we work with you to wire AIR into your stack before any contract is signed.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold mb-2" style="color: var(--text-primary);">Does the forensic record work offline?</h3>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
            Yes. OSS is local-only by default. Capsules are signed and chained on the machine running the agent, with no cloud dependency. AIR Cloud is opt-in. The chain itself is portable: export it to JSON, PDF, or CEF and hand it to any downstream system or auditor.
          </p>
        </div>
      </div>
    </div>
  </section>

  <!-- CTA -->
  <section class="py-20 relative overflow-hidden" style="border-top: 1px solid var(--border-subtle);">
    <div class="absolute inset-0">
      <img src="/hero-mesh.png" alt="" class="w-full h-full object-cover opacity-25" />
      <div class="absolute inset-0" style="background: linear-gradient(to top, var(--surface), color-mix(in srgb, var(--surface) 95%, transparent), var(--surface));"></div>
    </div>
    <div class="relative max-w-screen-xl mx-auto px-6 text-center">
      <h2 class="text-3xl sm:text-4xl font-bold tracking-tight max-w-3xl mx-auto">
        Start the forensic record today.<br />
        <span class="text-gradient-brand">Commercial tiers available in private beta.</span>
      </h2>
      <div class="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
        <a href="https://github.com/vindicara-inc/projectair" class="btn-primary text-base px-8 py-4">
          <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
          View on GitHub
        </a>
        <a href="/contact" class="btn-secondary text-base px-8 py-4">Contact us</a>
      </div>
      <div class="mt-8">
        <div class="inline-block dark-embed px-4 py-2 font-mono text-sm text-zinc-300">
          <span class="text-zinc-500">$</span> pip install projectair
        </div>
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
          AI Incident Response. Forensic reconstruction, signed evidence, and containment for autonomous agents.
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
      <p class="text-xs" style="color: var(--text-faint);">&copy; 2026 Vindicara, Inc. · AI Incident Response.</p>
      <div class="flex items-center gap-4">
        <a href="https://github.com/vindicara-inc/projectair" style="color: var(--text-faint);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-faint)'} class="transition-colors">
          <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        </a>
      </div>
    </div>
  </div>
</footer>

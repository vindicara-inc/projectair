<script lang="ts">
  import vindicaraLogoDay from '$lib/assets/vindicara-logo-day.png';
  import vindicaraLogoNight from '$lib/assets/vindicara-logo-night.png';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';


  let mobileMenuOpen = $state(false);
</script>

<svelte:head>
  <title>Pricing | Vindicara AIR</title>
  <meta name="description" content="Vindicara AIR pricing. Free OSS forever under MIT license. Pro at $99/mo for Structural Verification, premium detectors, AIR Cloud, and compliance reports. Team at $599/mo for hosted Cloud workspaces, SIEM, and incident workflows. Enterprise priced on request for SSO, on-prem, and SLA." />
  <link rel="canonical" href="https://vindicara.io/pricing" />

  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://vindicara.io/pricing" />
  <meta property="og:title" content="Pricing | Vindicara AIR" />
  <meta property="og:description" content="Free OSS forever. Pro at $99/mo. Team at $599/mo. Enterprise priced on request." />
  <meta property="og:image:alt" content="Vindicara AIR pricing: open source, individual, team, enterprise." />

  <meta name="twitter:title" content="Pricing | Vindicara AIR" />
  <meta name="twitter:description" content="Free OSS forever. Pro at $99/mo. Team at $599/mo. Enterprise priced on request." />

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
        description: 'MIT-licensed air CLI, airsdk Python SDK with LangChain, OpenAI, Anthropic, and LlamaIndex instrumentation. 16 detectors (10 OWASP Agentic + 3 OWASP LLM + 3 AIR-native). JSON, PDF, CEF, and Article 72 template export. Community support.',
        url: 'https://github.com/vindicara-inc/projectair',
      },
      {
        '@type': 'Offer',
        name: 'Pro',
        price: '99',
        priceCurrency: 'USD',
        availability: 'https://schema.org/InStock',
        description: 'Personal AIR Cloud workspace with multi-agent dashboard, Structural Verification (SV-SECRET, SV-NET, SV-SCOPE, SV-EXFIL, SV-ENTITY), Premium ASI04 supply-chain detectors, NIST AI RMF and SOC2-AI reports, 14-day money-back guarantee, license-gated via projectair-pro.',
        priceSpecification: {
          '@type': 'UnitPriceSpecification',
          price: '99',
          priceCurrency: 'USD',
          billingIncrement: 1,
          unitText: 'MONTH',
        },
      },
      {
        '@type': 'Offer',
        name: 'Team',
        price: '599',
        priceCurrency: 'USD',
        availability: 'https://schema.org/InStock',
        description: 'Shared team workspace with multi-agent dashboards, activity feeds, role-based access, SIEM integrations (Datadog, Splunk, Sumo Logic, Microsoft Sentinel), incident workflows with alerting and assignment.',
        priceSpecification: {
          '@type': 'UnitPriceSpecification',
          price: '599',
          priceCurrency: 'USD',
          billingIncrement: 1,
          unitText: 'MONTH',
        },
      },
      {
        '@type': 'Offer',
        name: 'Enterprise',
        availability: 'https://schema.org/InStock',
        description: 'SSO, SAML, RBAC, on-premises / VPC / air-gapped deployment, HIPAA BAA, branded compliance evidence packaging (Article 72, NIST AI RMF, SOC2-AI, SB 53), insurance carrier integrations for AI liability policies, dedicated IR contact, 24/7 support, SLA. Pricing on request.',
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
      <h1 class="text-4xl sm:text-5xl font-bold tracking-tight max-w-3xl mx-auto">Free for individuals to evaluate. Paid when the evidence becomes the workflow.</h1>
      <p class="mt-5 text-lg max-w-2xl mx-auto leading-relaxed" style="color: var(--text-muted);">
        The <code class="font-mono" style="color: var(--text-secondary);">air</code> CLI and <code class="font-mono" style="color: var(--text-secondary);">airsdk</code> Python SDK are MIT-licensed and free forever, with all 16 detectors and core export formats. Pro adds the personal AIR Cloud workspace, Structural Verification, premium detectors, and licensed enterprise features. Team adds the shared team workspace, SIEM, and incident workflows. Enterprise adds SSO, on-prem, BAA, and SLA.
      </p>
      <div class="mt-6 flex items-center justify-center">
        <a href="https://www.producthunt.com/posts/project-air-by-vindicara" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-2.5 px-4 py-2.5 transition-colors group" style="border: 1px solid var(--border); background-color: var(--glass);" onmouseenter={(e) => e.currentTarget.style.backgroundColor = 'var(--glass-border)'} onmouseleave={(e) => e.currentTarget.style.backgroundColor = 'var(--glass)'}>
          <svg class="w-5 h-5 text-[#FF6154]" viewBox="0 0 40 40" fill="currentColor"><path d="M20 0C8.954 0 0 8.954 0 20s8.954 20 20 20 20-8.954 20-20S31.046 0 20 0zm0 36.8C10.728 36.8 3.2 29.272 3.2 20S10.728 3.2 20 3.2 36.8 10.728 36.8 20 29.272 36.8 20 36.8zm2.8-22.4h-7.2v11.2h4.4v-3.2h2.8c2.648 0 4.8-2.152 4.8-4.8V19.2c0-2.648-2.152-4.8-4.8-4.8zm1.6 4.8c0 .884-.716 1.6-1.6 1.6h-2.8v-3.2h2.8c.884 0 1.6.716 1.6 1.6z"/></svg>
          <span class="text-xs font-mono uppercase tracking-wider transition-colors" style="color: var(--text-muted);">Find us on Product Hunt</span>
        </a>
      </div>
    </div>
  </section>

  <!-- TIER CARDS -->
  <section class="pb-20">
    <div class="max-w-screen-xl mx-auto px-6">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-0 max-w-7xl mx-auto" style="border: 1px solid var(--border);">
        <!-- Open Source -->
        <div class="p-7" style="border-bottom: 1px solid var(--border);">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-sm font-mono uppercase tracking-wider" style="color: var(--text-muted);">Open Source</h2>
            <span class="font-mono text-[10px] text-green-400 border border-green-400/30 bg-green-400/5 px-2 py-0.5 uppercase tracking-wider">Available</span>
          </div>
          <p class="text-3xl font-black mt-4">Free</p>
          <p class="text-sm mt-1" style="color: var(--text-muted);">Forever. MIT license.</p>
          <p class="text-xs mt-1" style="color: var(--text-faint);">Self-hosted. No seat limits. No phone-home.</p>
          <ul class="mt-7 space-y-3 text-sm" style="color: var(--text-muted);">
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span><span class="font-mono" style="color: var(--text-secondary);">air</span> CLI: trace, demo, report</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span><span class="font-mono" style="color: var(--text-secondary);">airsdk</span>: LangChain, OpenAI, Anthropic, LlamaIndex, Gemini, Google ADK</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>All 16 detectors (10 OWASP Agentic ASI01&#8211;ASI10 + 3 OWASP LLM + 3 AIR-native)</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Signed Intent Capsule chain, local-only</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>JSON, PDF, CEF, EU AI Act Article 72 template export</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Zero-Trust agent registry enforcement</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Community support (GitHub Issues)</span></li>
          </ul>
          <a href="https://github.com/vindicara-inc/projectair" class="btn-secondary w-full mt-7 text-sm">View on GitHub</a>
        </div>

        <!-- Pro — MOST POPULAR -->
        <div class="p-7" style="border-bottom: 1px solid var(--border); background-color: var(--glass);">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-sm font-mono uppercase tracking-wider" style="color: var(--text-muted);">Pro</h2>
            <span class="font-mono text-[10px] text-brand-red border border-brand-red/30 bg-brand-red/5 px-2 py-0.5 uppercase tracking-wider">Most popular</span>
          </div>
          <p class="text-3xl font-black mt-4">$99<span class="text-base font-normal" style="color: var(--text-muted);">/mo</span></p>
          <p class="text-sm mt-1" style="color: var(--text-muted);">Or $890/year. Cancel anytime.</p>
          <p class="text-xs mt-1" style="color: var(--text-faint);">Your personal AIR control plane. Run your agents, see them in one dashboard, prove intent.</p>
          <ul class="mt-7 space-y-3 text-sm" style="color: var(--text-muted);">
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Everything in Open Source</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span><strong style="color: var(--text-primary);">Personal AIR Cloud workspace</strong> with <strong style="color: var(--text-primary);">multi-agent dashboard</strong></span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span><strong style="color: var(--text-primary);">Structural Verification</strong> (SV-SECRET, SV-NET, SV-SCOPE, SV-EXFIL, SV-ENTITY): deterministic intent enforcement, no LLM in the verification path</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span><strong style="color: var(--text-primary);">Premium ASI04</strong> supply-chain detectors (dependency install, manifest drift, untrusted fetch)</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span><strong style="color: var(--text-primary);">Premium compliance reports</strong>: NIST AI RMF, SOC2-AI</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>License works air-gapped (local Ed25519 verification, no phone-home)</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>14-day money-back guarantee</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Email support</span></li>
          </ul>
          <a
            href="https://buy.stripe.com/fZu6oG1V01k82JibTx1RC04"
            class="btn-primary w-full mt-7 text-sm"
            rel="noopener"
          >Buy monthly · $99</a>
          <p class="text-center text-[10px] mt-1.5" style="color: var(--text-faint);">14-day refund. No questions.</p>
          <a
            href="https://buy.stripe.com/cNi9AS0QWfaYbfOe1F1RC01"
            class="block text-center text-xs mt-2 underline underline-offset-4"
            style="color: var(--text-muted);"
            onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-secondary)'}
            onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
            rel="noopener"
          >Or pay annually for $890, save $298</a>
        </div>

        <!-- Team -->
        <div class="p-7" style="border-bottom: 1px solid var(--border);">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-sm font-mono uppercase tracking-wider" style="color: var(--text-muted);">Team</h2>
            <span class="font-mono text-[10px] px-2 py-0.5 uppercase tracking-wider" style="color: var(--text-secondary); border: 1px solid var(--border); background-color: var(--glass);">Team workspace</span>
          </div>
          <p class="text-3xl font-black mt-4">$599<span class="text-base font-normal" style="color: var(--text-muted);">/mo</span></p>
          <p class="text-sm mt-1" style="color: var(--text-muted);">Or $5,400/year. Hosted AIR Cloud for your team.</p>
          <p class="text-xs mt-1" style="color: var(--text-faint);">Plus your security team. Shared workspace, SIEM, incident workflows.</p>
          <ul class="mt-7 space-y-3 text-sm" style="color: var(--text-muted);">
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Everything in Pro, organization-wide</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span><strong style="color: var(--text-primary);">Shared team workspace</strong> with multi-agent dashboards, activity feeds, and role-based access</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span><strong style="color: var(--text-primary);">SIEM integrations</strong>: Datadog, Splunk, Sumo Logic, Microsoft Sentinel</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span><strong style="color: var(--text-primary);">Incident workflows</strong> with alerting and assignment</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Shared keys, workspace roles, audit log</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Email + Slack support</span></li>
          </ul>
          <a
            href="https://buy.stripe.com/4gMdR8dDI9QEgA88Hl1RC02"
            class="btn-primary w-full mt-7 text-sm"
            rel="noopener"
          >Buy monthly · $599</a>
          <a
            href="https://buy.stripe.com/eVq9ASdDI3sg2Ji4r51RC03"
            class="block text-center text-xs mt-3 underline underline-offset-4"
            style="color: var(--text-muted);"
            onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-secondary)'}
            onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
            rel="noopener"
          >Or pay annually for $5,400, save $1,788</a>
        </div>

        <!-- Enterprise -->
        <div class="p-7">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-sm font-mono uppercase tracking-wider" style="color: var(--text-muted);">Enterprise</h2>
            <span class="font-mono text-[10px] px-2 py-0.5 uppercase tracking-wider" style="color: var(--text-secondary); border: 1px solid var(--border); background-color: var(--glass);">Custom</span>
          </div>
          <p class="text-3xl font-black mt-4">Talk to us</p>
          <p class="text-sm mt-1" style="color: var(--text-muted);">Regulated industries, on-prem, SLA, BAA.</p>
          <ul class="mt-7 space-y-3 text-sm" style="color: var(--text-muted);">
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Everything in Team</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>SSO, SAML, RBAC</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>On-prem / VPC / air-gapped deployment</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>HIPAA BAA</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Branded compliance evidence packaging (Article 72, NIST AI RMF, SOC2-AI, SB 53)</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Insurance carrier integrations for AI liability policies</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Dedicated IR contact, 24/7 support, SLA</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Volume-tiered pricing aligned to agents instrumented</span></li>
          </ul>
          <a href="/contact?tier=enterprise" class="btn-secondary w-full mt-7 text-sm">Talk to us</a>
        </div>
      </div>
      <!-- Responsive: on large screens, cards are side-by-side with right borders instead of bottom -->
      <style>
        @media (min-width: 1024px) {
          .grid.lg\:grid-cols-4 > :nth-child(1),
          .grid.lg\:grid-cols-4 > :nth-child(2),
          .grid.lg\:grid-cols-4 > :nth-child(3) {
            border-bottom: none !important;
            border-right: 1px solid var(--border) !important;
          }
          .grid.lg\:grid-cols-4 > :nth-child(4) {
            border-bottom: none !important;
          }
        }
      </style>
    </div>
  </section>

  <!-- FEATURE COMPARISON -->
  <section class="py-20" style="border-top: 1px solid var(--border-subtle);">
    <div class="max-w-screen-xl mx-auto px-6">
      <div class="text-center mb-14">
        <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-3 font-mono">Compare</p>
        <h2 class="text-3xl sm:text-4xl font-bold tracking-tight">What you get at each tier</h2>
      </div>

      <div class="max-w-6xl mx-auto overflow-x-auto">
        <table class="w-full text-sm" style="border: 1px solid var(--border);">
          <thead>
            <tr style="background-color: var(--glass); color: var(--text-muted);">
              <th class="text-left p-4 font-mono text-xs uppercase tracking-wider font-semibold" style="border-bottom: 1px solid var(--border);">Capability</th>
              <th class="text-center p-4 font-mono text-xs uppercase tracking-wider font-semibold" style="border-bottom: 1px solid var(--border);">Free (OSS)</th>
              <th class="text-center p-4 font-mono text-xs uppercase tracking-wider font-semibold" style="border-bottom: 1px solid var(--border); background-color: var(--glass);">Pro $99/mo</th>
              <th class="text-center p-4 font-mono text-xs uppercase tracking-wider font-semibold" style="border-bottom: 1px solid var(--border);">Team $599/mo</th>
              <th class="text-center p-4 font-mono text-xs uppercase tracking-wider font-semibold" style="border-bottom: 1px solid var(--border);">Enterprise</th>
            </tr>
          </thead>
          <tbody style="color: var(--text-secondary);">
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">All 16 detectors (10 OWASP Agentic + 3 LLM + 3 AIR-native)</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400" style="background-color: var(--glass);">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Signed Intent Capsule chain (local)</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400" style="background-color: var(--glass);">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">EU AI Act Article 72 template export</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400" style="background-color: var(--glass);">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">JSON / PDF / CEF export</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400" style="background-color: var(--glass);">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Zero-Trust agent registry enforcement</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400" style="background-color: var(--glass);">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Structural Verification (SV-SECRET, SV-NET, SV-SCOPE, SV-EXFIL, SV-ENTITY)</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400" style="background-color: var(--glass);">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Premium ASI04 supply-chain detectors</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400" style="background-color: var(--glass);">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">NIST AI RMF + SOC2-AI reports</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400" style="background-color: var(--glass);">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Personal AIR Cloud workspace</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400" style="background-color: var(--glass);">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4"><strong>Multi-agent dashboard</strong></td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center" style="background-color: var(--glass); color: var(--text-secondary);">&#10003; (single user)</td>
              <td class="p-4 text-center" style="color: var(--text-secondary);">&#10003; (team)</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Air-gapped license verification</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400" style="background-color: var(--glass);">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">14-day money-back guarantee</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400" style="background-color: var(--glass);">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center" style="color: var(--text-secondary);">Custom terms</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Shared team workspace + activity feeds</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint); background-color: var(--glass);">&mdash;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Role-based workspace access</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint); background-color: var(--glass);">&mdash;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">SIEM integrations (Datadog / Splunk / Sumo / Sentinel)</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint); background-color: var(--glass);">&mdash;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Incident workflows + alerting</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint); background-color: var(--glass);">&mdash;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">SSO, SAML, RBAC</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint); background-color: var(--glass);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">On-prem / VPC / air-gapped deployment</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint); background-color: var(--glass);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">HIPAA BAA</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint); background-color: var(--glass);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Branded compliance packaging</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint); background-color: var(--glass);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Insurance carrier integrations</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint); background-color: var(--glass);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr style="border-bottom: 1px solid var(--border-subtle);">
              <td class="p-4">Dedicated IR contact + SLA</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint); background-color: var(--glass);">&mdash;</td>
              <td class="p-4 text-center" style="color: var(--text-faint);">&mdash;</td>
              <td class="p-4 text-center text-green-400">&#10003;</td>
            </tr>
            <tr>
              <td class="p-4">Support</td>
              <td class="p-4 text-center" style="color: var(--text-muted);">Community</td>
              <td class="p-4 text-center" style="color: var(--text-secondary); background-color: var(--glass);">Email</td>
              <td class="p-4 text-center" style="color: var(--text-secondary);">Email + Slack</td>
              <td class="p-4 text-center" style="color: var(--text-secondary);">24/7 with SLA</td>
            </tr>
          </tbody>
        </table>
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
            The <code class="font-mono" style="color: var(--text-secondary);">air</code> CLI, the <code class="font-mono" style="color: var(--text-secondary);">airsdk</code> Python SDK, the signed Intent Capsule chain, and all 16 detectors: 10 OWASP Top 10 for Agentic Applications (ASI01 through ASI10), 3 OWASP Top 10 for LLM Applications categories (LLM01, LLM04, LLM06), and 3 AIR-native detectors (chain integrity, NemoGuard safety classification, NemoGuard corroboration). JSON, PDF, and CEF export formats included. EU AI Act Article 72 evidence template generator included. Zero-Trust agent registry enforcement included. All MIT-licensed, all self-hosted, no seat limits, no trace limits.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold mb-2" style="color: var(--text-primary);">What does the $99 Pro tier add?</h3>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
            Pro turns AIR from a forensic library into your personal control plane. The headline feature is the <strong style="color: var(--text-secondary);">personal AIR Cloud workspace with a multi-agent dashboard</strong>: every agent you instrument writes signed evidence into one place you can actually look at on Tuesday morning.
          </p>
          <p class="text-sm leading-relaxed mt-3" style="color: var(--text-muted);">
            On top of that, Pro adds <strong style="color: var(--text-secondary);">Structural Verification</strong> (SV-SECRET, SV-NET, SV-SCOPE, SV-EXFIL, SV-ENTITY): five deterministic checks over the causal graph that verify whether an agent session honored its declared intent. No LLM in the verification path. Pro also adds <strong style="color: var(--text-secondary);">Premium ASI04 supply-chain detectors</strong> (dependency install, manifest drift, untrusted fetch) on top of the OSS MCP-naming detector, and <strong style="color: var(--text-secondary);">premium compliance reports</strong> for NIST AI RMF and SOC2-AI.
          </p>
          <p class="text-sm leading-relaxed mt-3" style="color: var(--text-muted);">
            The licensed Pro features ship in a separate <code class="font-mono" style="color: var(--text-secondary);">projectair-pro</code> package. License verification is a local Ed25519 signature check against the vendor public key: no phone-home, no usage tracking, works air-gapped. Pro is covered by a 14-day money-back guarantee.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold mb-2" style="color: var(--text-primary);">When should I move from Pro to Team?</h3>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
            When you have more than one human looking at the evidence. Pro is built for a single operator running one or many agents: you get the multi-agent dashboard and Structural Verification, but the workspace is yours. Team is the same evidence pipeline shared with your security or compliance peers, with role-based access, SIEM export to your existing stack (Datadog, Splunk, Sumo, Sentinel), incident workflows, and Slack support. If your auditor or your SOC needs to see the chain too, that is the Team line.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold mb-2" style="color: var(--text-primary);">Why is Team flat-priced but Enterprise is not?</h3>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
            Team is a shared AIR Cloud workspace with the same shape for every customer: shared workspace with role-based access, multi-agent dashboards, SIEM export, incident workflows, alerting. That has a flat price ($599/mo). Enterprise pricing depends on agent volume, the compliance frameworks in scope, deployment model (hosted, VPC, on-prem), and whether you need insurance integrations, SSO, BAA, or an SLA. Quoting a single number on a marketing page misrepresents the work either way. Send us your shape and we will send you a quote and a deployment plan within one business day.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold mb-2" style="color: var(--text-primary);">Can I evaluate Team or Enterprise before committing?</h3>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
            Yes. The OSS tier covers the full forensic record path end-to-end and works with any inference backend. You can prove the detector quality and the chain-of-custody story before any Cloud conversation. Once you talk to us, design-partner engagements are hands-on: we work with you to wire AIR into your stack, including SIEM and SSO if needed, before any contract is signed.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold mb-2" style="color: var(--text-primary);">Does the forensic record work offline?</h3>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
            Yes. OSS is local-only by default. Capsules are signed and chained on the machine running the agent, with no cloud dependency. AIR Cloud is opt-in. The chain itself is portable: export it to JSON, PDF, or CEF and hand it to any downstream system or auditor.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold mb-2" style="color: var(--text-primary);">How is the license verified?</h3>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">
            The license is an Ed25519-signed JSON token. Verification is local against the vendor public key embedded in the <code class="font-mono" style="color: var(--text-secondary);">projectair-pro</code> package. No phone-home, no usage tracking, no network dependency. After purchase, run <code class="font-mono" style="color: var(--text-secondary);">air login --license &lt;token&gt;</code> and <code class="font-mono" style="color: var(--text-secondary);">air status</code> to confirm.
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
        <span class="text-gradient-brand">Upgrade when the evidence becomes the workflow.</span>
      </h2>
      <div class="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
        <a href="https://github.com/vindicara-inc/projectair" class="btn-primary text-base px-8 py-4">
          <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
          View on GitHub
        </a>
        <a href="https://buy.stripe.com/aFa14m438d2QgA88Hl1RC00" class="btn-primary text-base px-8 py-4" rel="noopener">Start with Pro</a>
        <a href="/contact?tier=team" class="btn-secondary text-base px-8 py-4">Talk to us</a>
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

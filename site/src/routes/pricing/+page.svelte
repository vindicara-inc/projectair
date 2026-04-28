<script lang="ts">
  import vindicaraLogo from '$lib/assets/vindicara-logo.png';

  let mobileMenuOpen = $state(false);
</script>

<svelte:head>
  <title>Pricing | Vindicara AIR</title>
  <meta name="description" content="Vindicara AIR pricing. Free OSS forever under MIT license. Individual at $29/mo for AIR Cloud client and premium reports. Team and Enterprise priced on request for hosted Cloud workspaces, SSO, on-prem, and SLA." />
  <link rel="canonical" href="https://vindicara.io/pricing" />

  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://vindicara.io/pricing" />
  <meta property="og:title" content="Pricing | Vindicara AIR" />
  <meta property="og:description" content="Free OSS forever. Individual at $29/mo. Team and Enterprise priced on request." />
  <meta property="og:image:alt" content="Vindicara AIR pricing: open source, individual, team, enterprise." />

  <meta name="twitter:title" content="Pricing | Vindicara AIR" />
  <meta name="twitter:description" content="Free OSS forever. Individual at $29/mo. Team and Enterprise priced on request." />

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
        description: 'MIT-licensed air CLI, airsdk Python SDK with LangChain, OpenAI, Anthropic, and LlamaIndex instrumentation. 14 detectors. JSON, PDF, CEF, and Article 72 template export. Community support.',
        url: 'https://github.com/vindicara-inc/projectair',
      },
      {
        '@type': 'Offer',
        name: 'Individual',
        price: '29',
        priceCurrency: 'USD',
        availability: 'https://schema.org/InStock',
        description: 'AIR Cloud client SDK, premium compliance reports (NIST AI RMF, SOC2-AI), premium detectors, license-gated via projectair-pro.',
        priceSpecification: {
          '@type': 'UnitPriceSpecification',
          price: '29',
          priceCurrency: 'USD',
          billingIncrement: 1,
          unitText: 'MONTH',
        },
      },
      {
        '@type': 'Offer',
        name: 'Team',
        availability: 'https://schema.org/InStock',
        description: 'Hosted AIR Cloud workspace, multi-agent dashboards, SIEM export, incident workflows, and alerting. Pricing on request.',
      },
      {
        '@type': 'Offer',
        name: 'Enterprise',
        availability: 'https://schema.org/InStock',
        description: 'SSO, SAML, RBAC, on-premises deployment, EU AI Act Article 72 evidence packaging, SLA, BAA, dedicated IR contact, insurance carrier integrations. Pricing on request.',
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
<nav class="fixed top-0 w-full z-50 bg-obsidian/60 backdrop-blur-2xl border-b border-white/5">
  <div class="max-w-screen-2xl mx-auto px-6 flex items-center justify-between h-16">
    <a href="/" class="flex items-center gap-1">
      <img src={vindicaraLogo} alt="Vindicara" class="h-10 w-auto mix-blend-screen" />
      <span class="font-mono text-[10px] tracking-[0.18em] uppercase text-white border border-white/30 px-1.5 py-0.5 shadow-[0_0_10px_rgba(255,255,255,0.25)]">Project AIR™</span>
    </a>

    <div class="hidden md:flex items-center gap-8 text-sm text-zinc-400">
      <a href="/#how-it-works" class="hover:text-white transition-colors">How It Works</a>
      <a href="/#standards" class="hover:text-white transition-colors">Standards</a>
      <a href="/blog" class="hover:text-white transition-colors">Blog</a>
      <a href="/pricing" class="text-white">Pricing</a>
    </div>

    <div class="hidden md:flex items-center gap-3">
      <a href="https://github.com/vindicara-inc/projectair#readme" class="btn-secondary text-xs px-4 py-2">Docs</a>
      <a href="https://github.com/vindicara-inc/projectair" class="btn-primary text-xs px-4 py-2">
        <svg class="w-4 h-4 mr-1.5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        GitHub
      </a>
    </div>

    <button
      class="md:hidden text-zinc-400 hover:text-white"
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

  {#if mobileMenuOpen}
    <div class="md:hidden border-t border-white/5 bg-obsidian/95 backdrop-blur-2xl px-6 py-4 space-y-3">
      <a href="/#how-it-works" class="block text-sm text-zinc-400 hover:text-white">How It Works</a>
      <a href="/#standards" class="block text-sm text-zinc-400 hover:text-white">Standards</a>
      <a href="/blog" class="block text-sm text-zinc-400 hover:text-white">Blog</a>
      <a href="/pricing" class="block text-sm text-white">Pricing</a>
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
      <div class="absolute inset-0 bg-gradient-to-b from-obsidian via-obsidian/90 to-obsidian"></div>
    </div>
    <div class="relative max-w-screen-xl mx-auto px-6 text-center">
      <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-4 font-mono">Pricing</p>
      <h1 class="text-4xl sm:text-5xl font-bold tracking-tight max-w-3xl mx-auto">Free for individuals to evaluate. Paid when it pays you back.</h1>
      <p class="mt-5 text-lg text-zinc-400 max-w-2xl mx-auto leading-relaxed">
        The <code class="font-mono text-zinc-200">air</code> CLI and <code class="font-mono text-zinc-200">airsdk</code> Python SDK are MIT-licensed and free forever, with all 14 detectors and core export formats. Pro adds the AIR Cloud client, premium compliance reports, and licensed enterprise features.
      </p>
    </div>
  </section>

  <!-- TIER CARDS -->
  <section class="pb-20">
    <div class="max-w-screen-xl mx-auto px-6">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-0 border border-white/10 max-w-7xl mx-auto">
        <!-- Open Source -->
        <div class="p-7 border-b lg:border-b-0 lg:border-r border-white/10">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-sm font-mono uppercase tracking-wider text-zinc-400">Open Source</h2>
            <span class="font-mono text-[10px] text-green-400 border border-green-400/30 bg-green-400/5 px-2 py-0.5 uppercase tracking-wider">Available</span>
          </div>
          <p class="text-3xl font-black mt-4">Free</p>
          <p class="text-sm text-zinc-500 mt-1">Forever. MIT license.</p>
          <ul class="mt-7 space-y-3 text-sm text-zinc-400">
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span><span class="font-mono text-zinc-200">air</span> CLI: trace, demo, report</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span><span class="font-mono text-zinc-200">airsdk</span>: LangChain, OpenAI, Anthropic, LlamaIndex</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>14 detectors (10 OWASP Agentic + 3 LLM + 1 AIR-native)</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Signed Intent Capsule chain, local-only</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>JSON, PDF, CEF, Article 72 template export</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Zero-Trust agent registry enforcement</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Community support</span></li>
          </ul>
          <a href="https://github.com/vindicara-inc/projectair" class="btn-secondary w-full mt-7 text-sm">View on GitHub</a>
        </div>

        <!-- Individual -->
        <div class="p-7 border-b lg:border-b-0 lg:border-r border-white/10 bg-white/[0.015]">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-sm font-mono uppercase tracking-wider text-zinc-400">Individual</h2>
            <span class="font-mono text-[10px] text-brand-red border border-brand-red/30 bg-brand-red/5 px-2 py-0.5 uppercase tracking-wider">New</span>
          </div>
          <p class="text-3xl font-black mt-4">$29<span class="text-base font-normal text-zinc-500">/mo</span></p>
          <p class="text-sm text-zinc-500 mt-1">Or $290/year. Cancel anytime.</p>
          <ul class="mt-7 space-y-3 text-sm text-zinc-400">
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Everything in Open Source</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>AIR Cloud client SDK (push capsules to a hosted workspace)</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Premium reports: NIST AI RMF, SOC2-AI</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Premium detectors as they ship</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>License works air-gapped (no phone-home)</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Email support</span></li>
          </ul>
          <a href="/contact?tier=individual" class="btn-primary w-full mt-7 text-sm">Buy a license</a>
        </div>

        <!-- Team -->
        <div class="p-7 border-b lg:border-b-0 lg:border-r border-white/10">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-sm font-mono uppercase tracking-wider text-zinc-400">Team</h2>
            <span class="font-mono text-[10px] text-zinc-300 border border-white/30 bg-white/5 px-2 py-0.5 uppercase tracking-wider">Custom</span>
          </div>
          <p class="text-3xl font-black mt-4">Talk to us</p>
          <p class="text-sm text-zinc-500 mt-1">Hosted AIR Cloud for your team.</p>
          <ul class="mt-7 space-y-3 text-sm text-zinc-400">
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Everything in Individual, organization-wide</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Hosted AIR Cloud workspace, multi-agent dashboards</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>SIEM integrations: Datadog, Splunk, Sumo, Sentinel</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Incident workflows + alerting</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Shared keys + workspace roles</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Email + Slack support</span></li>
          </ul>
          <a href="/contact?tier=team" class="btn-secondary w-full mt-7 text-sm">Talk to us</a>
        </div>

        <!-- Enterprise -->
        <div class="p-7">
          <div class="flex items-center justify-between mb-2">
            <h2 class="text-sm font-mono uppercase tracking-wider text-zinc-400">Enterprise</h2>
            <span class="font-mono text-[10px] text-zinc-300 border border-white/30 bg-white/5 px-2 py-0.5 uppercase tracking-wider">Custom</span>
          </div>
          <p class="text-3xl font-black mt-4">Talk to us</p>
          <p class="text-sm text-zinc-500 mt-1">Regulated industries, on-prem, SLA.</p>
          <ul class="mt-7 space-y-3 text-sm text-zinc-400">
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Everything in Team</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>SSO, SAML, RBAC</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>On-prem / VPC / air-gapped deployment</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Branded compliance evidence packaging</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>Insurance carrier integrations</span></li>
            <li class="flex items-start gap-2"><span class="text-brand-red mt-0.5 font-mono">›</span><span>SLA, dedicated IR contact, BAA</span></li>
          </ul>
          <a href="/contact?tier=enterprise" class="btn-secondary w-full mt-7 text-sm">Talk to us</a>
        </div>
      </div>
    </div>
  </section>

  <!-- FEATURE COMPARISON -->
  <section class="py-20 border-t border-white/5">
    <div class="max-w-screen-xl mx-auto px-6">
      <div class="text-center mb-14">
        <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-3 font-mono">Compare</p>
        <h2 class="text-3xl sm:text-4xl font-bold tracking-tight">What you get at each tier</h2>
      </div>

      <div class="max-w-6xl mx-auto overflow-x-auto">
        <table class="w-full text-sm border border-white/10">
          <thead>
            <tr class="bg-white/[0.02] text-zinc-400">
              <th class="text-left p-4 font-mono text-xs uppercase tracking-wider font-semibold border-b border-white/10">Capability</th>
              <th class="text-center p-4 font-mono text-xs uppercase tracking-wider font-semibold border-b border-white/10">Open Source</th>
              <th class="text-center p-4 font-mono text-xs uppercase tracking-wider font-semibold border-b border-white/10 bg-white/[0.015]">Individual</th>
              <th class="text-center p-4 font-mono text-xs uppercase tracking-wider font-semibold border-b border-white/10">Team</th>
              <th class="text-center p-4 font-mono text-xs uppercase tracking-wider font-semibold border-b border-white/10">Enterprise</th>
            </tr>
          </thead>
          <tbody class="text-zinc-300">
            <tr class="border-b border-white/5">
              <td class="p-4"><span class="font-mono text-zinc-200">air</span> CLI and <span class="font-mono text-zinc-200">airsdk</span></td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400 bg-white/[0.015]">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">Signed Intent Capsule chain (BLAKE3 + Ed25519)</td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400 bg-white/[0.015]">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">14 detectors (10 OWASP Agentic + 3 LLM + 1 AIR-native)</td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400 bg-white/[0.015]">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">JSON, PDF, CEF exports + Article 72 template</td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400 bg-white/[0.015]">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">AIR Cloud client SDK</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-green-400 bg-white/[0.015]">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">Premium reports (NIST AI RMF, SOC2-AI)</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-green-400 bg-white/[0.015]">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">Hosted AIR Cloud workspace</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-zinc-600 bg-white/[0.015]">–</td>
              <td class="p-4 text-center text-green-400">Multi-agent</td>
              <td class="p-4 text-center text-green-400">Unlimited</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">SIEM integrations (Datadog, Splunk, Sumo, Sentinel)</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-zinc-600 bg-white/[0.015]">–</td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">Incident workflows and alerting</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-zinc-600 bg-white/[0.015]">–</td>
              <td class="p-4 text-center text-green-400">✓</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">SSO, SAML, RBAC</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-zinc-600 bg-white/[0.015]">–</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">On-prem / VPC / air-gapped deployment</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-zinc-600 bg-white/[0.015]">–</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">Branded compliance evidence packaging</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-zinc-600 bg-white/[0.015]">–</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">Insurance carrier integrations</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-zinc-600 bg-white/[0.015]">–</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr class="border-b border-white/5">
              <td class="p-4">SLA, dedicated IR contact, BAA</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-zinc-600 bg-white/[0.015]">–</td>
              <td class="p-4 text-center text-zinc-600">–</td>
              <td class="p-4 text-center text-green-400">✓</td>
            </tr>
            <tr>
              <td class="p-4">Support</td>
              <td class="p-4 text-center text-zinc-400">Community</td>
              <td class="p-4 text-center text-zinc-300 bg-white/[0.015]">Email</td>
              <td class="p-4 text-center text-zinc-300">Email + Slack</td>
              <td class="p-4 text-center text-zinc-300">24/7 with SLA</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- FAQ -->
  <section class="py-20 border-t border-white/5">
    <div class="max-w-screen-xl mx-auto px-6">
      <div class="text-center mb-14">
        <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-3 font-mono">Questions</p>
        <h2 class="text-3xl sm:text-4xl font-bold tracking-tight">Before you ask</h2>
      </div>

      <div class="max-w-3xl mx-auto space-y-8">
        <div>
          <h3 class="text-lg font-semibold text-white mb-2">What stays free forever?</h3>
          <p class="text-sm text-zinc-400 leading-relaxed">
            The <code class="font-mono text-zinc-200">air</code> CLI, the <code class="font-mono text-zinc-200">airsdk</code> Python SDK, the signed Intent Capsule chain, and all 14 detectors: 10 OWASP Top 10 for Agentic Applications (ASI01 through ASI10), 3 OWASP Top 10 for LLM Applications categories (LLM01, LLM04, LLM06), and 1 AIR-native forensic-chain-integrity check. JSON, PDF, and CEF export formats included. EU AI Act Article 72 evidence template generator included. Zero-Trust agent registry enforcement included. All MIT-licensed, all self-hosted, no seat limits, no trace limits.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold text-white mb-2">What does the $29 Individual tier add?</h3>
          <p class="text-sm text-zinc-400 leading-relaxed">
            The Individual tier unlocks the AIR Cloud client SDK (push your capsules to a hosted workspace instead of managing JSONL files yourself), premium compliance reports for NIST AI RMF and SOC2-AI on top of the OSS Article 72 template, and premium detector additions as they ship. The licensed Pro features ship in a separate <code class="font-mono text-zinc-200">projectair-pro</code> package; verification is a local Ed25519 signature check on the license token, with no phone-home, so it works air-gapped.
        </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold text-white mb-2">Why no public price for Team and Enterprise?</h3>
          <p class="text-sm text-zinc-400 leading-relaxed">
            Team and Enterprise pricing depends on agent volume, the compliance frameworks in scope, deployment model (hosted, VPC, on-prem), and whether you need insurance integrations, SSO, BAA, or an SLA. Quoting a single number on a marketing page misrepresents the work either way. Send us your shape and we will send you a quote and a deployment plan within one business day.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold text-white mb-2">Can I evaluate Team or Enterprise before committing?</h3>
          <p class="text-sm text-zinc-400 leading-relaxed">
            Yes. The OSS tier covers the full forensic record path end-to-end and works with any inference backend. You can prove the detector quality and the chain-of-custody story before any Cloud conversation. Once you talk to us, design-partner engagements are hands-on: we work with you to wire AIR into your stack, including SIEM and SSO if needed, before any contract is signed.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold text-white mb-2">Does the forensic record work offline?</h3>
          <p class="text-sm text-zinc-400 leading-relaxed">
            Yes. OSS is local-only by default. Capsules are signed and chained on the machine running the agent, with no cloud dependency. AIR Cloud is opt-in. The chain itself is portable: export it to JSON, PDF, or CEF and hand it to any downstream system or auditor.
          </p>
        </div>

        <div>
          <h3 class="text-lg font-semibold text-white mb-2">How is the license verified?</h3>
          <p class="text-sm text-zinc-400 leading-relaxed">
            The license is an Ed25519-signed JSON token. Verification is local against the vendor public key embedded in the <code class="font-mono text-zinc-200">projectair-pro</code> package. No phone-home, no usage tracking, no network dependency. After purchase, run <code class="font-mono text-zinc-200">air login --license &lt;token&gt;</code> and <code class="font-mono text-zinc-200">air status</code> to confirm.
          </p>
        </div>
      </div>
    </div>
  </section>

  <!-- CTA -->
  <section class="py-20 relative overflow-hidden border-t border-white/5">
    <div class="absolute inset-0">
      <img src="/hero-mesh.png" alt="" class="w-full h-full object-cover opacity-25" />
      <div class="absolute inset-0 bg-gradient-to-t from-obsidian via-obsidian/95 to-obsidian"></div>
    </div>
    <div class="relative max-w-screen-xl mx-auto px-6 text-center">
      <h2 class="text-3xl sm:text-4xl font-bold tracking-tight max-w-3xl mx-auto">
        Start the forensic record today.<br />
        <span class="text-gradient-brand">Upgrade when the evidence becomes the product.</span>
      </h2>
      <div class="mt-10 flex flex-col sm:flex-row items-center justify-center gap-4">
        <a href="https://github.com/vindicara-inc/projectair" class="btn-primary text-base px-8 py-4">
          <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
          View on GitHub
        </a>
        <a href="/contact?tier=team" class="btn-secondary text-base px-8 py-4">Talk to us</a>
      </div>
      <div class="mt-8">
        <div class="inline-block bg-obsidian-lighter border border-white/10 px-4 py-2 font-mono text-sm text-zinc-300">
          <span class="text-zinc-500">$</span> pip install projectair
        </div>
      </div>
    </div>
  </section>
</main>

<!-- FOOTER -->
<footer class="w-full border-t border-white/5 bg-obsidian relative z-20">
  <div class="max-w-screen-xl mx-auto px-6 py-14">
    <div class="grid grid-cols-2 md:grid-cols-4 gap-8">
      <div class="col-span-2 md:col-span-1">
        <div class="flex items-center gap-1 mb-4">
          <img src={vindicaraLogo} alt="Vindicara" class="h-8 w-auto mix-blend-screen" />
          <span class="font-mono text-[10px] tracking-[0.18em] uppercase text-white border border-white/30 px-1.5 py-0.5 shadow-[0_0_10px_rgba(255,255,255,0.25)]">Project AIR™</span>
        </div>
        <p class="text-sm text-zinc-500 leading-relaxed">
          AI Incident Response. Forensic reconstruction, signed evidence, and containment for autonomous agents.
        </p>
      </div>

      <div>
        <h3 class="text-sm font-semibold mb-4">Product</h3>
        <ul class="space-y-2 text-sm text-zinc-500">
          <li><a href="/#how-it-works" class="hover:text-white transition-colors">How It Works</a></li>
          <li><a href="/#standards" class="hover:text-white transition-colors">Standards</a></li>
          <li><a href="/pricing" class="hover:text-white transition-colors">Pricing</a></li>
          <li><a href="https://github.com/vindicara-inc/projectair#readme" class="hover:text-white transition-colors">Docs</a></li>
        </ul>
      </div>

      <div>
        <h3 class="text-sm font-semibold mb-4">Company</h3>
        <ul class="space-y-2 text-sm text-zinc-500">
          <li><a href="mailto:Kevin.Minn@vindicara.io" class="hover:text-white transition-colors">Kevin.Minn@vindicara.io</a></li>
          <li><a href="/blog" class="hover:text-white transition-colors">Blog</a></li>
          <li><a href="https://github.com/vindicara-inc/projectair" class="hover:text-white transition-colors">GitHub</a></li>
        </ul>
      </div>

      <div>
        <h3 class="text-sm font-semibold mb-4">Legal</h3>
        <ul class="space-y-2 text-sm text-zinc-500">
          <li><a href="/terms" class="hover:text-white transition-colors">Terms of Service</a></li>
          <li><a href="/privacy" class="hover:text-white transition-colors">Privacy Policy</a></li>
          <li><a href="/acceptable-use" class="hover:text-white transition-colors">Acceptable Use</a></li>
          <li><a href="/security" class="hover:text-white transition-colors">Security Disclosure</a></li>
        </ul>
      </div>
    </div>

    <div class="mt-12 pt-8 border-t border-white/5 flex flex-col md:flex-row items-center justify-between gap-4">
      <p class="text-xs text-zinc-600">&copy; 2026 Vindicara, Inc. · AI Incident Response.</p>
      <div class="flex items-center gap-4">
        <a href="https://github.com/vindicara-inc/projectair" class="text-zinc-600 hover:text-white transition-colors">
          <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        </a>
      </div>
    </div>
  </div>
</footer>

<script lang="ts">
  import vindicaraLogoDay from '$lib/assets/vindicara-logo-day.png';
  import vindicaraLogoNight from '$lib/assets/vindicara-logo-night.png';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';


  const industries = [
    {
      name: 'Healthcare',
      href: '/solutions/healthcare',
      tagline: 'HIPAA-grade audit trails for clinical AI agents',
      description: 'Every PHI access signed, timestamped, and tamper-evident. Prove 45 CFR 164.312(b) compliance with cryptographic evidence, not checkbox assertions.',
    },
    {
      name: 'Financial Services',
      href: '/solutions/finance',
      tagline: 'Forensic accountability for autonomous trading and advisory agents',
      description: 'Signed intent capsules prove what your AI recommended, why, and whether a human approved it. Built for SEC, FINRA, and MiFID II audit requirements.',
    },
    {
      name: 'Government',
      href: '/solutions/government',
      tagline: 'Zero-trust evidence chains for public sector AI deployments',
      description: 'NIST AI RMF aligned. Post-quantum signatures (ML-DSA-65) ready. Air-gapped deployment options for classified environments.',
    },
  ];
</script>

<svelte:head>
  <title>Solutions | Vindicara</title>
  <meta name="description" content="Industry-specific forensic evidence for AI agents. Healthcare, financial services, government." />
</svelte:head>

<nav class="fixed top-0 w-full z-50 backdrop-blur-2xl" style="background-color: color-mix(in srgb, var(--surface) 60%, transparent); border-bottom: 1px solid var(--border-subtle);">
  <div class="max-w-screen-2xl mx-auto px-6 flex items-center justify-between h-16">
    <a href="/" class="flex items-center gap-1">
      <img src={vindicaraLogoNight} alt="Vindicara" class="h-10 w-auto logo-night mix-blend-screen" /><img src={vindicaraLogoDay} alt="Vindicara" class="h-10 w-auto logo-day" />
    </a>
    <div class="hidden md:flex items-center gap-8 text-sm">
      <a href="/solutions" style="color: var(--text-primary);" class="transition-colors">Solutions</a>
      <a href="/pricing" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Pricing</a>
      <a href="/blog" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Blog</a>
      <a href="/get-started" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Get Started</a>
      <a href="/dashboard" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Dashboard</a>
    </div>
    <div class="hidden md:flex items-center gap-3">
      <ThemeToggle />
      <a href="/get-started" class="btn-primary text-xs px-4 py-2">Get Started</a>
    </div>
  </div>
</nav>

<section class="min-h-screen pt-32 pb-20 px-6">
  <div class="max-w-screen-lg mx-auto">
    <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-4 font-mono">Solutions</p>
    <h1 class="text-5xl md:text-6xl font-bold tracking-tight leading-[1.1] mb-6">
      Forensic evidence<br />for every industry
    </h1>
    <p class="text-xl max-w-2xl mb-20" style="color: var(--text-muted);">
      AI agents operate in regulated environments. Project AIR provides the cryptographically signed audit trail that proves compliance, detects threats, and survives legal scrutiny.
    </p>

    <div class="grid gap-8">
      {#each industries as industry}
        <a
          href={industry.href}
          class="group block glass-panel p-8 hover:border-brand-red/30 transition-all"
        >
          <p class="text-brand-red text-xs font-mono uppercase tracking-wider mb-2">{industry.tagline}</p>
          <h2 class="text-2xl font-bold mb-3 group-hover:text-brand-red transition-colors">{industry.name}</h2>
          <p class="leading-relaxed" style="color: var(--text-muted);">{industry.description}</p>
        </a>
      {/each}
    </div>

    <div class="mt-20 text-center">
      <p class="text-sm mb-6" style="color: var(--text-muted);">Works with any AI framework. Install in under 60 seconds.</p>
      <div class="flex items-center justify-center gap-4">
        <a href="/get-started" class="btn-primary text-sm px-8 py-3">Get Started</a>
        <a href="/pricing" class="btn-secondary text-sm px-8 py-3">View Pricing</a>
      </div>
    </div>
  </div>
</section>

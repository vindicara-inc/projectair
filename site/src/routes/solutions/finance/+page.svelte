<script lang="ts">
  import vindicaraLogoDay from '$lib/assets/vindicara-logo-day.png';
  import vindicaraLogoNight from '$lib/assets/vindicara-logo-night.png';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';


  const capabilities = [
    { title: 'Trade Decision Audit Trail', description: 'Every recommendation, execution, and risk assessment by an AI trading agent is captured as a signed intent capsule. Regulators can verify the complete decision chain.' },
    { title: 'SEC and FINRA Compliance', description: 'Signed forensic chains provide the books-and-records evidence required under SEC Rule 17a-4 and FINRA 3110. Tamper-evident by design, not by policy.' },
    { title: 'Fiduciary Proof', description: 'When an AI advisory agent recommends a portfolio allocation, the signed chain proves what data it considered, what alternatives it evaluated, and why it chose the recommendation it did.' },
    { title: 'Insider Threat Detection', description: 'OWASP-mapped detectors flag unauthorized data access, privilege escalation, and exfiltration attempts. ASI03 Zero-Trust enforcement ensures agents only access authorized resources.' },
    { title: 'Human Approval Gates', description: 'Containment Layer 3 requires JWT-verified human approval for high-value trades, large transfers, or account modifications. Bad tokens leave actions permanently halted.' },
    { title: 'Cross-Agent Chain of Custody', description: 'When a research agent hands off to a trading agent, Layer 4 handoff protocol maintains cryptographic chain of custody with Sigstore Rekor counter-attestation.' },
  ];
</script>

<svelte:head>
  <title>Financial Services Solutions | Vindicara</title>
  <meta name="description" content="Forensic evidence for AI trading and advisory agents. SEC, FINRA, MiFID II compliant audit trails." />
</svelte:head>

<nav class="fixed top-0 w-full z-50 backdrop-blur-2xl" style="background-color: color-mix(in srgb, var(--surface) 60%, transparent); border-bottom: 1px solid var(--border-subtle);">
  <div class="max-w-screen-2xl mx-auto px-6 flex items-center justify-between h-16">
    <a href="/" class="flex items-center gap-1">
      <img src={vindicaraLogoNight} alt="Vindicara" class="h-10 w-auto logo-night mix-blend-screen" /><img src={vindicaraLogoDay} alt="Vindicara" class="h-10 w-auto logo-day" />
    </a>
    <div class="hidden md:flex items-center gap-8 text-sm">
      <a href="/solutions" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Solutions</a>
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

<section class="pt-32 pb-12 px-6">
  <div class="max-w-screen-lg mx-auto">
    <div class="flex items-center gap-2 text-sm mb-8 font-mono" style="color: var(--text-muted);">
      <a href="/solutions" class="transition-colors" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}>Solutions</a>
      <span>/</span>
      <span style="color: var(--text-secondary);">Financial Services</span>
    </div>

    <div class="max-w-3xl mx-auto text-center mb-20">
      <h1 class="text-5xl md:text-6xl font-bold tracking-tight leading-[1.1] mb-6">
        Prove every<br />AI-driven trade
      </h1>
      <p class="text-xl mb-8" style="color: var(--text-muted);">
        Autonomous trading agents, robo-advisors, and risk models make decisions that move markets. Project AIR provides the signed forensic evidence that proves what happened, why, and who approved it.
      </p>
      <div class="flex items-center justify-center gap-4">
        <a href="/get-started" class="btn-primary text-sm px-8 py-3">Get Started</a>
        <a href="mailto:Kevin.Minn@vindicara.io" class="btn-secondary text-sm px-8 py-3">Contact Sales</a>
      </div>
    </div>
  </div>
</section>

<section class="pb-20 px-6">
  <div class="max-w-screen-lg mx-auto">
    <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-8 font-mono">Capabilities</p>
    <div class="grid md:grid-cols-2 gap-6">
      {#each capabilities as cap}
        <div class="glass-panel p-6">
          <h3 class="text-lg font-bold mb-2">{cap.title}</h3>
          <p class="text-sm leading-relaxed" style="color: var(--text-muted);">{cap.description}</p>
        </div>
      {/each}
    </div>
  </div>
</section>

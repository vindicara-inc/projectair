<script lang="ts">
  import vindicaraLogo from '$lib/assets/vindicara-logo.png';

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

<nav class="fixed top-0 w-full z-50 bg-obsidian/60 backdrop-blur-2xl border-b border-white/5">
  <div class="max-w-screen-2xl mx-auto px-6 flex items-center justify-between h-16">
    <a href="/" class="flex items-center gap-1">
      <img src={vindicaraLogo} alt="Vindicara" class="h-10 w-auto mix-blend-screen" />
    </a>
    <div class="hidden md:flex items-center gap-8 text-sm text-zinc-400">
      <a href="/solutions" class="hover:text-white transition-colors">Solutions</a>
      <a href="/pricing" class="hover:text-white transition-colors">Pricing</a>
      <a href="/blog" class="hover:text-white transition-colors">Blog</a>
      <a href="/get-started" class="hover:text-white transition-colors">Get Started</a>
      <a href="/dashboard" class="hover:text-white transition-colors">Dashboard</a>
    </div>
    <div class="hidden md:flex items-center gap-3">
      <a href="/get-started" class="btn-primary text-xs px-4 py-2">Get Started</a>
    </div>
  </div>
</nav>

<section class="pt-32 pb-12 px-6">
  <div class="max-w-screen-lg mx-auto">
    <div class="flex items-center gap-2 text-sm text-zinc-500 mb-8 font-mono">
      <a href="/solutions" class="hover:text-white transition-colors">Solutions</a>
      <span>/</span>
      <span class="text-zinc-300">Financial Services</span>
    </div>

    <div class="max-w-3xl mx-auto text-center mb-20">
      <h1 class="text-5xl md:text-6xl font-bold tracking-tight leading-[1.1] mb-6">
        Prove every<br />AI-driven trade
      </h1>
      <p class="text-xl text-zinc-400 mb-8">
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
          <p class="text-zinc-400 text-sm leading-relaxed">{cap.description}</p>
        </div>
      {/each}
    </div>
  </div>
</section>

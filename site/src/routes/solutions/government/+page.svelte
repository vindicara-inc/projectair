<script lang="ts">
  import vindicaraLogoDay from '$lib/assets/vindicara-logo-day.png';
  import vindicaraLogoNight from '$lib/assets/vindicara-logo-night.png';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';


  const capabilities = [
    { title: 'NIST AI RMF Aligned', description: 'Forensic evidence mapped to the four RMF functions: GOVERN, MAP, MEASURE, MANAGE. Generate compliance reports directly from your signed chain.' },
    { title: 'Post-Quantum Ready', description: 'ML-DSA-65 (FIPS 204) post-quantum signatures available as opt-in. Ed25519 default with a clear upgrade path when CNSA 2.0 mandates take effect.' },
    { title: 'Zero Data Exfiltration', description: 'All 16 OWASP-mapped detectors run locally. No telemetry, no cloud calls, no data leaves your network. Classification-safe by architecture.' },
    { title: 'Air-Gapped Deployment', description: 'NIM-packaged deployment option for disconnected environments. The entire detection and verification stack runs without internet access.' },
    { title: 'Public Verification', description: 'RFC 3161 timestamps and Sigstore Rekor inclusion proofs. Any third party can verify chain integrity using public infrastructure. Zero vendor lock-in.' },
    { title: 'FedRAMP Path', description: 'Built on AWS GovCloud-compatible primitives (DynamoDB, Lambda, API Gateway). Separation of data plane and control plane supports authorization boundary requirements.' },
  ];
</script>

<svelte:head>
  <title>Government Solutions | Vindicara</title>
  <meta name="description" content="Zero-trust forensic evidence for government AI deployments. NIST AI RMF aligned, post-quantum ready, air-gapped capable." />
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
      <span style="color: var(--text-secondary);">Government</span>
    </div>

    <div class="max-w-3xl mx-auto text-center mb-20">
      <h1 class="text-5xl md:text-6xl font-bold tracking-tight leading-[1.1] mb-6">
        Trust but verify.<br />Cryptographically.
      </h1>
      <p class="text-xl mb-8" style="color: var(--text-muted);">
        Government AI systems operate under strict oversight requirements. Project AIR delivers NIST-aligned, tamper-evident forensic evidence that satisfies compliance mandates without compromising operational security.
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

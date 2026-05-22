<script lang="ts">
  import vindicaraLogoDay from '$lib/assets/vindicara-logo-day.png';
  import vindicaraLogoNight from '$lib/assets/vindicara-logo-night.png';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';


  const capabilities = [
    { title: 'PHI Access Audit Trail', description: 'Every patient record access by an AI agent is captured as a signed intent capsule with BLAKE3 chain hashing and Ed25519 signatures. No PHI touches go unrecorded.' },
    { title: '45 CFR 164.312(b) Compliance', description: 'Audit controls required by the HIPAA Security Rule are satisfied through tamper-evident forensic chains. Each record is cryptographically linked to the previous one.' },
    { title: 'Integrity Controls', description: '45 CFR 164.312(c) integrity requirements are met by the signed chain architecture. Any modification to any record is detectable at the byte level.' },
    { title: 'Breach Detection', description: '16 OWASP-mapped detectors run locally with zero data exfiltration. Prompt injection, data leakage, privilege escalation, and tool misuse are flagged in real time.' },
    { title: 'Human-in-the-Loop', description: 'Auth0-verified containment (Layer 3) ensures sensitive clinical actions require human approval via JWT-verified step-up authentication. Deny rules override step-up rules.' },
    { title: 'Compliance Reporting', description: 'Generate HIPAA evidence reports, EU AI Act Article 72 reports, and NIST AI RMF assessments directly from your signed forensic chain.' },
  ];
</script>

<svelte:head>
  <title>Healthcare Solutions | Vindicara</title>
  <meta name="description" content="HIPAA-grade forensic evidence for clinical AI agents. Signed audit trails, PHI access logging, breach detection." />
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
      <span style="color: var(--text-secondary);">Healthcare</span>
    </div>

    <div class="max-w-3xl mx-auto text-center mb-20">
      <h1 class="text-5xl md:text-6xl font-bold tracking-tight leading-[1.1] mb-6">
        Prove every<br />clinical AI decision
      </h1>
      <p class="text-xl mb-8" style="color: var(--text-muted);">
        AI agents in healthcare access PHI, recommend treatments, and make clinical decisions. Project AIR provides the cryptographic proof that every access was authorized, every decision was logged, and every action can be audited.
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

<section class="pb-20 px-6">
  <div class="max-w-screen-lg mx-auto">
    <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-4 font-mono">Quick Start</p>
    <h2 class="text-3xl font-bold mb-8">Instrument a clinical agent in 4 lines</h2>
    <div class="dark-embed rounded-lg p-6 font-mono text-sm leading-relaxed">
      <pre class="text-zinc-300 overflow-x-auto"><span class="text-brand-cyan">from</span> airsdk <span class="text-brand-cyan">import</span> AIRRecorder

recorder = AIRRecorder(<span class="text-green-400">"clinical-chain.jsonl"</span>)

recorder.tool_start(tool_name=<span class="text-green-400">"ehr_read"</span>, tool_args=&#123;<span class="text-green-400">"patient_id"</span>: <span class="text-green-400">"P-4821"</span>&#125;)
recorder.tool_end(tool_output=<span class="text-green-400">"HbA1c: 7.2, BP: 138/88"</span>)

recorder.llm_start(prompt=<span class="text-green-400">"Review labs and recommend next steps"</span>)
recorder.llm_end(response=<span class="text-green-400">"Recommend titrating metformin..."</span>)

recorder.agent_finish(final_output=<span class="text-green-400">"Clinical review complete"</span>)</pre>
    </div>
    <p class="text-sm mt-4" style="color: var(--text-muted);">Every call generates a signed, tamper-evident record. Run <code class="font-mono text-brand-cyan">air demo --healthcare</code> to see it in action.</p>
  </div>
</section>

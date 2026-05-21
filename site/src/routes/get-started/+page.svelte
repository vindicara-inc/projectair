<script lang="ts">
  import vindicaraLogo from '$lib/assets/vindicara-logo.png';

  let copiedPip = $state(false);
  let copiedPipx = $state(false);
  let platform = $state<'mac' | 'windows' | 'linux'>('mac');

  function copy(text: string, which: 'pip' | 'pipx') {
    navigator.clipboard?.writeText(text);
    if (which === 'pip') { copiedPip = true; setTimeout(() => copiedPip = false, 2000); }
    else { copiedPipx = true; setTimeout(() => copiedPipx = false, 2000); }
  }

  const frameworks = [
    { name: 'OpenAI', code: 'from airsdk.integrations import instrument_openai\ninstrument_openai(client, recorder)' },
    { name: 'Anthropic', code: 'from airsdk.integrations import instrument_anthropic\ninstrument_anthropic(client, recorder)' },
    { name: 'LangChain', code: 'from airsdk import AIRCallbackHandler\nagent.run("task", callbacks=[AIRCallbackHandler(recorder)])' },
    { name: 'Google Gemini', code: 'from airsdk.integrations import instrument_gemini\ninstrument_gemini(client, recorder)' },
    { name: 'Google ADK', code: 'from airsdk.integrations import instrument_adk\ninstrument_adk(agent, recorder)' },
    { name: 'LlamaIndex', code: 'from airsdk.integrations import instrument_llamaindex\ninstrument_llamaindex(llm, recorder)' },
  ];

  const cliCommands = [
    { cmd: 'air demo', desc: 'Run the full demo (30 seconds, zero setup)' },
    { cmd: 'air demo --healthcare', desc: 'HIPAA-aligned clinical AI demo' },
    { cmd: 'air trace chain.jsonl', desc: 'Verify signatures, run detectors, export report' },
    { cmd: 'air verify-public chain.jsonl', desc: 'Verify using only public infrastructure' },
    { cmd: 'air explain --finding ASI02', desc: 'Causal explanation for a finding' },
    { cmd: 'air verify-intent chain.jsonl', desc: 'Did the agent honor its declared intent?' },
    { cmd: 'air report article72', desc: 'Generate EU AI Act Article 72 report' },
  ];
</script>

<svelte:head>
  <title>Get Started | Vindicara Project AIR</title>
  <meta name="description" content="Install Project AIR and instrument your first AI agent in under 5 minutes. Step-by-step guide for macOS, Windows, and Linux." />
  <link rel="canonical" href="https://vindicara.io/get-started" />
</svelte:head>

<nav class="fixed top-0 w-full z-50 bg-obsidian/60 backdrop-blur-2xl border-b border-white/5">
  <div class="max-w-screen-2xl mx-auto px-6 flex items-center justify-between h-16">
    <a href="/" class="flex items-center gap-1">
      <img src={vindicaraLogo} alt="Vindicara" class="h-10 w-auto mix-blend-screen" />
      <span class="font-mono text-[10px] tracking-[0.18em] uppercase text-white border border-white/30 px-1.5 py-0.5 shadow-[0_0_10px_rgba(255,255,255,0.25)]">Project AIR&#8482;</span>
    </a>
    <div class="hidden md:flex items-center gap-8 text-sm text-zinc-400">
      <a href="/solutions" class="hover:text-white transition-colors">Solutions</a>
      <a href="/pricing" class="hover:text-white transition-colors">Pricing</a>
      <a href="/admissibility#certification" class="hover:text-white transition-colors">FRE 902(13)</a>
      <a href="/blog" class="hover:text-white transition-colors">Blog</a>
      <a href="/get-started" class="text-white transition-colors">Get Started</a>
      <a href="/dashboard" class="hover:text-white transition-colors">Dashboard</a>
    </div>
    <div class="hidden md:flex items-center gap-3">
      <a href="https://github.com/vindicara-inc/projectair" class="btn-primary text-xs px-4 py-2">
        <svg class="w-4 h-4 mr-1.5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        GitHub
      </a>
    </div>
  </div>
</nav>

<!-- HEADER -->
<section class="pt-32 pb-12 px-6">
  <div class="max-w-screen-md mx-auto">
    <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-4 font-mono">Get Started</p>
    <h1 class="text-4xl sm:text-5xl font-bold tracking-tight leading-[1.1] mb-4">
      First forensic report<br />in under 5 minutes
    </h1>
    <p class="text-xl text-zinc-400 mb-4">From install to signed evidence chain. Works on macOS, Windows, and Linux.</p>
  </div>
</section>

<!-- PLATFORM PICKER -->
<section class="pb-8 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex gap-2">
      <button
        class="px-4 py-2 text-sm font-mono uppercase tracking-wider transition-all cursor-pointer border {platform === 'mac' ? 'bg-brand-red text-white border-brand-red' : 'border-white/15 text-zinc-400 hover:text-white'}"
        onclick={() => platform = 'mac'}
      >macOS</button>
      <button
        class="px-4 py-2 text-sm font-mono uppercase tracking-wider transition-all cursor-pointer border {platform === 'windows' ? 'bg-brand-red text-white border-brand-red' : 'border-white/15 text-zinc-400 hover:text-white'}"
        onclick={() => platform = 'windows'}
      >Windows</button>
      <button
        class="px-4 py-2 text-sm font-mono uppercase tracking-wider transition-all cursor-pointer border {platform === 'linux' ? 'bg-brand-red text-white border-brand-red' : 'border-white/15 text-zinc-400 hover:text-white'}"
        onclick={() => platform = 'linux'}
      >Linux</button>
    </div>
  </div>
</section>

<!-- PREREQUISITES -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex items-center gap-3 mb-6">
      <span class="w-8 h-8 flex items-center justify-center text-sm font-bold font-mono bg-zinc-800 text-zinc-300 border border-white/10">0</span>
      <h2 class="text-2xl font-bold">Prerequisites</h2>
    </div>

    <div class="border border-white/10 p-6 space-y-4">
      <div class="flex items-start gap-3">
        <span class="text-brand-red font-mono mt-0.5 shrink-0">&#8250;</span>
        <div>
          <p class="text-sm text-white font-semibold">Python 3.10 or newer</p>
          {#if platform === 'mac'}
            <p class="text-sm text-zinc-400 mt-1">macOS ships with Python 3 on recent versions. Check with <code class="font-mono text-brand-cyan">python3 --version</code>. If not installed, the fastest path:</p>
            <div class="bg-obsidian-lighter border border-white/10 p-3 mt-2 font-mono text-xs text-zinc-300">
              <div><span class="text-zinc-500"># Option A: Homebrew (recommended)</span></div>
              <div>brew install python@3.13</div>
              <div class="mt-2"><span class="text-zinc-500"># Option B: Official installer</span></div>
              <div>https://www.python.org/downloads/macos/</div>
            </div>
          {:else if platform === 'windows'}
            <p class="text-sm text-zinc-400 mt-1">Open PowerShell or Command Prompt and run <code class="font-mono text-brand-cyan">python --version</code>. If Python is not installed:</p>
            <div class="bg-obsidian-lighter border border-white/10 p-3 mt-2 font-mono text-xs text-zinc-300">
              <div><span class="text-zinc-500"># Option A: Microsoft Store (easiest)</span></div>
              <div>winget install Python.Python.3.13</div>
              <div class="mt-2"><span class="text-zinc-500"># Option B: Official installer</span></div>
              <div>https://www.python.org/downloads/windows/</div>
              <div class="mt-1 text-zinc-500">IMPORTANT: Check "Add Python to PATH" during install</div>
            </div>
          {:else}
            <p class="text-sm text-zinc-400 mt-1">Most distributions ship Python 3. Check with <code class="font-mono text-brand-cyan">python3 --version</code>. If missing:</p>
            <div class="bg-obsidian-lighter border border-white/10 p-3 mt-2 font-mono text-xs text-zinc-300">
              <div><span class="text-zinc-500"># Ubuntu / Debian</span></div>
              <div>sudo apt update && sudo apt install python3 python3-pip python3-venv</div>
              <div class="mt-2"><span class="text-zinc-500"># Fedora / RHEL</span></div>
              <div>sudo dnf install python3 python3-pip</div>
              <div class="mt-2"><span class="text-zinc-500"># Arch</span></div>
              <div>sudo pacman -S python python-pip</div>
            </div>
          {/if}
        </div>
      </div>

      <div class="flex items-start gap-3">
        <span class="text-brand-red font-mono mt-0.5 shrink-0">&#8250;</span>
        <div>
          <p class="text-sm text-white font-semibold">pip or pipx</p>
          <p class="text-sm text-zinc-400 mt-1"><code class="font-mono text-brand-cyan">pip</code> works in any virtual environment. <code class="font-mono text-brand-cyan">pipx</code> installs the <code class="font-mono text-zinc-200">air</code> CLI globally without polluting your system Python.</p>
          {#if platform === 'mac'}
            <div class="bg-obsidian-lighter border border-white/10 p-3 mt-2 font-mono text-xs text-zinc-300">
              brew install pipx && pipx ensurepath
            </div>
          {:else if platform === 'windows'}
            <div class="bg-obsidian-lighter border border-white/10 p-3 mt-2 font-mono text-xs text-zinc-300">
              <div>python -m pip install --user pipx</div>
              <div>python -m pipx ensurepath</div>
              <div class="text-zinc-500 mt-1"># Restart your terminal after ensurepath</div>
            </div>
          {:else}
            <div class="bg-obsidian-lighter border border-white/10 p-3 mt-2 font-mono text-xs text-zinc-300">
              <div>python3 -m pip install --user pipx</div>
              <div>python3 -m pipx ensurepath</div>
            </div>
          {/if}
        </div>
      </div>
    </div>
  </div>
</section>

<!-- STEP 1: INSTALL -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex items-center gap-3 mb-6">
      <span class="w-8 h-8 flex items-center justify-center text-sm font-bold font-mono bg-brand-red text-white">1</span>
      <h2 class="text-2xl font-bold">Install Project AIR</h2>
    </div>

    <p class="text-sm text-zinc-400 mb-4">Choose one method. Both give you the <code class="font-mono text-zinc-200">air</code> CLI and <code class="font-mono text-zinc-200">airsdk</code> library.</p>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
      <div class="border border-white/10 p-5">
        <div class="flex items-center justify-between mb-3">
          <p class="text-sm font-bold font-mono text-white">pipx (recommended)</p>
          <span class="text-[10px] font-mono uppercase tracking-wider text-green-400 border border-green-400/30 bg-green-400/5 px-2 py-0.5">Global CLI</span>
        </div>
        <button
          onclick={() => copy('pipx install projectair', 'pipx')}
          class="w-full bg-obsidian-lighter border border-white/10 p-3 font-mono text-sm text-left flex items-center justify-between cursor-pointer hover:border-brand-red/30 transition-all"
        >
          {#if platform === 'windows'}
            <span><span class="text-zinc-500">PS&gt;</span> pipx install projectair</span>
          {:else}
            <span><span class="text-brand-red">$</span> pipx install projectair</span>
          {/if}
          <span class="text-xs text-zinc-500">{copiedPipx ? 'Copied' : 'Copy'}</span>
        </button>
        <p class="text-xs text-zinc-500 mt-2">Isolated install. Does not touch your project venv.</p>
      </div>

      <div class="border border-white/10 p-5">
        <div class="flex items-center justify-between mb-3">
          <p class="text-sm font-bold font-mono text-white">pip</p>
          <span class="text-[10px] font-mono uppercase tracking-wider text-zinc-400 border border-white/10 px-2 py-0.5">In venv</span>
        </div>
        <button
          onclick={() => copy('pip install projectair', 'pip')}
          class="w-full bg-obsidian-lighter border border-white/10 p-3 font-mono text-sm text-left flex items-center justify-between cursor-pointer hover:border-brand-red/30 transition-all"
        >
          {#if platform === 'windows'}
            <span><span class="text-zinc-500">PS&gt;</span> pip install projectair</span>
          {:else}
            <span><span class="text-brand-red">$</span> pip install projectair</span>
          {/if}
          <span class="text-xs text-zinc-500">{copiedPip ? 'Copied' : 'Copy'}</span>
        </button>
        <p class="text-xs text-zinc-500 mt-2">Inside a virtual environment or project.</p>
      </div>
    </div>

    {#if platform === 'windows'}
      <div class="border border-yellow-500/20 bg-yellow-500/5 p-4 mt-4">
        <p class="text-sm text-yellow-300 font-semibold mb-1">Windows note</p>
        <p class="text-xs text-zinc-400 leading-relaxed">If you get <code class="font-mono text-zinc-300">'air' is not recognized</code>, make sure Python's Scripts directory is on your PATH. Run <code class="font-mono text-zinc-300">python -m projectair.cli</code> as a fallback, or restart your terminal after <code class="font-mono text-zinc-300">pipx ensurepath</code>.</p>
      </div>
    {/if}
  </div>
</section>

<!-- STEP 2: VERIFY -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex items-center gap-3 mb-6">
      <span class="w-8 h-8 flex items-center justify-center text-sm font-bold font-mono bg-brand-red text-white">2</span>
      <h2 class="text-2xl font-bold">Verify the install</h2>
    </div>

    <div class="bg-obsidian-lighter border border-white/10 font-mono text-sm overflow-hidden">
      <div class="flex items-center gap-2 px-4 py-2.5 border-b border-white/5 text-zinc-500 text-xs">
        <span class="w-3 h-3 rounded-full bg-red-500/60"></span>
        <span class="w-3 h-3 rounded-full bg-yellow-500/60"></span>
        <span class="w-3 h-3 rounded-full bg-green-500/60"></span>
        <span class="ml-3 tracking-wider uppercase">{platform === 'windows' ? 'powershell' : 'terminal'}</span>
      </div>
      <div class="p-4 leading-relaxed">
        {#if platform === 'windows'}
          <div class="text-zinc-300"><span class="text-zinc-500">PS&gt;</span> air --version</div>
        {:else}
          <div class="text-zinc-300"><span class="text-brand-red">$</span> air --version</div>
        {/if}
        <div class="text-zinc-500">projectair 1.0.x</div>
        <div class="mt-3 text-zinc-300">
          {#if platform === 'windows'}
            <span class="text-zinc-500">PS&gt;</span> air demo
          {:else}
            <span class="text-brand-red">$</span> air demo
          {/if}
        </div>
        <div class="text-zinc-500">[AIR] Generating signed forensic chain...</div>
        <div class="text-zinc-500">[AIR] 14 detectors evaluated, 6 findings</div>
        <div class="text-emerald-400">[AIR] Chain verified. Report saved to forensic-report.json</div>
      </div>
    </div>
    <p class="text-sm text-zinc-400 mt-3"><code class="font-mono text-brand-cyan">air demo</code> generates a real signed chain, runs all 14 detectors, and exports a forensic report. No API key, no cloud, no config. Under 30 seconds.</p>
  </div>
</section>

<!-- STEP 3: INSTRUMENT -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex items-center gap-3 mb-6">
      <span class="w-8 h-8 flex items-center justify-center text-sm font-bold font-mono bg-brand-red text-white">3</span>
      <h2 class="text-2xl font-bold">Instrument your agent</h2>
    </div>

    <p class="text-zinc-400 text-sm mb-4">The recorder writes signed, tamper-evident records to a local JSONL chain. Every call is an Intent Capsule: BLAKE3-hashed, Ed25519-signed, forward-chained.</p>

    <div class="bg-obsidian-lighter border border-white/10 p-5 font-mono text-sm leading-relaxed overflow-x-auto">
      <pre class="text-zinc-300"><span class="text-brand-cyan">from</span> airsdk <span class="text-brand-cyan">import</span> AIRRecorder

recorder = AIRRecorder(<span class="text-green-400">"chain.jsonl"</span>)

recorder.llm_start(prompt=<span class="text-green-400">"Analyze this data..."</span>)
recorder.llm_end(response=<span class="text-green-400">"Here is the analysis..."</span>)

recorder.tool_start(tool_name=<span class="text-green-400">"db_query"</span>, tool_args=&#123;<span class="text-green-400">"sql"</span>: <span class="text-green-400">"SELECT ..."</span>&#125;)
recorder.tool_end(tool_output=<span class="text-green-400">"42 rows returned"</span>)

recorder.agent_finish(final_output=<span class="text-green-400">"Task complete"</span>)</pre>
    </div>
  </div>
</section>

<!-- STEP 4: FRAMEWORK INTEGRATIONS -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex items-center gap-3 mb-6">
      <span class="w-8 h-8 flex items-center justify-center text-sm font-bold font-mono bg-brand-red text-white">4</span>
      <h2 class="text-2xl font-bold">Framework integrations</h2>
    </div>
    <p class="text-zinc-400 text-sm mb-6">Already using a framework? One-line instrumentation. Same signed chain, zero boilerplate.</p>
    <div class="grid gap-3">
      {#each frameworks as fw}
        <div class="border border-white/10 px-5 py-4">
          <p class="text-sm font-bold mb-2">{fw.name}</p>
          <pre class="font-mono text-xs text-zinc-400 overflow-x-auto">{fw.code}</pre>
        </div>
      {/each}
    </div>
    <p class="text-xs text-zinc-500 mt-4 font-mono">Any OpenAI-compatible endpoint (NVIDIA NIM, vLLM, Together AI, Groq, Fireworks) also works via instrument_openai.</p>
  </div>
</section>

<!-- STEP 5: ANALYZE -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex items-center gap-3 mb-6">
      <span class="w-8 h-8 flex items-center justify-center text-sm font-bold font-mono bg-brand-red text-white">5</span>
      <h2 class="text-2xl font-bold">Analyze and export</h2>
    </div>

    <div class="bg-obsidian-lighter border border-white/10 font-mono text-sm overflow-hidden">
      <div class="flex items-center gap-2 px-4 py-2.5 border-b border-white/5 text-zinc-500 text-xs">
        <span class="w-3 h-3 rounded-full bg-red-500/60"></span>
        <span class="w-3 h-3 rounded-full bg-yellow-500/60"></span>
        <span class="w-3 h-3 rounded-full bg-green-500/60"></span>
        <span class="ml-3 tracking-wider uppercase">{platform === 'windows' ? 'powershell' : 'terminal'}</span>
      </div>
      <div class="p-4 leading-relaxed text-zinc-300">
        <div class="text-zinc-500"># Verify signatures + run all 14 detectors</div>
        <div>{platform === 'windows' ? '<span class="text-zinc-500">PS&gt;</span>' : '<span class="text-brand-red">$</span>'} air trace chain.jsonl</div>
        <div class="mt-3 text-zinc-500"># Verify using only public infrastructure (no Vindicara dependency)</div>
        <div>{platform === 'windows' ? '<span class="text-zinc-500">PS&gt;</span>' : '<span class="text-brand-red">$</span>'} air verify-public chain.jsonl</div>
        <div class="mt-3 text-zinc-500"># Generate EU AI Act Article 72 compliance report</div>
        <div>{platform === 'windows' ? '<span class="text-zinc-500">PS&gt;</span>' : '<span class="text-brand-red">$</span>'} air report article72</div>
        <div class="mt-3 text-zinc-500"># Causal explanation for a specific finding</div>
        <div>{platform === 'windows' ? '<span class="text-zinc-500">PS&gt;</span>' : '<span class="text-brand-red">$</span>'} air explain --finding ASI02</div>
      </div>
    </div>
  </div>
</section>

<!-- CLI REFERENCE -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-6 font-mono">CLI Reference</p>
    <div class="border border-white/10 overflow-hidden">
      {#each cliCommands as { cmd, desc }, i}
        <div class="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4 px-5 py-3 text-sm {i < cliCommands.length - 1 ? 'border-b border-white/5' : ''}">
          <code class="font-mono text-brand-cyan shrink-0 sm:w-64">{cmd}</code>
          <span class="text-zinc-400 text-xs sm:text-sm">{desc}</span>
        </div>
      {/each}
    </div>
  </div>
</section>

<!-- TROUBLESHOOTING -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-6 font-mono">Troubleshooting</p>
    <div class="space-y-6">
      <div>
        <h3 class="text-sm font-semibold text-white mb-2"><code class="font-mono text-brand-cyan">air</code> command not found</h3>
        {#if platform === 'windows'}
          <p class="text-sm text-zinc-400 leading-relaxed">Restart your terminal after installing. If still missing, check that Python's <code class="font-mono text-zinc-300">Scripts</code> folder is on your PATH: <code class="font-mono text-zinc-300">$env:PATH -split ";"</code>. As a fallback: <code class="font-mono text-zinc-300">python -m projectair.cli demo</code>.</p>
        {:else if platform === 'mac'}
          <p class="text-sm text-zinc-400 leading-relaxed">If you used pipx, run <code class="font-mono text-zinc-300">pipx ensurepath</code> and restart your shell. If you installed with pip inside a venv, make sure the venv is activated. As a fallback: <code class="font-mono text-zinc-300">python3 -m projectair.cli demo</code>.</p>
        {:else}
          <p class="text-sm text-zinc-400 leading-relaxed">Run <code class="font-mono text-zinc-300">pipx ensurepath</code> and restart your shell, or add <code class="font-mono text-zinc-300">~/.local/bin</code> to your PATH manually. As a fallback: <code class="font-mono text-zinc-300">python3 -m projectair.cli demo</code>.</p>
        {/if}
      </div>

      <div>
        <h3 class="text-sm font-semibold text-white mb-2">Python version too old</h3>
        <p class="text-sm text-zinc-400 leading-relaxed">Project AIR requires Python 3.10+. Check with <code class="font-mono text-zinc-300">{platform === 'windows' ? 'python' : 'python3'} --version</code>. If you have multiple versions, use <code class="font-mono text-zinc-300">python3.13 -m pip install projectair</code> to target the right one.</p>
      </div>

      <div>
        <h3 class="text-sm font-semibold text-white mb-2">Permission errors on install</h3>
        {#if platform === 'windows'}
          <p class="text-sm text-zinc-400 leading-relaxed">Run PowerShell as Administrator, or use <code class="font-mono text-zinc-300">pip install --user projectair</code>. Better yet, use pipx, which handles isolation for you.</p>
        {:else}
          <p class="text-sm text-zinc-400 leading-relaxed">Never use <code class="font-mono text-zinc-300">sudo pip install</code>. Use pipx (installs to <code class="font-mono text-zinc-300">~/.local/</code>) or create a virtual environment: <code class="font-mono text-zinc-300">python3 -m venv .venv && source .venv/bin/activate && pip install projectair</code>.</p>
        {/if}
      </div>

      <div>
        <h3 class="text-sm font-semibold text-white mb-2">Still stuck?</h3>
        <p class="text-sm text-zinc-400 leading-relaxed">Open an issue on <a href="https://github.com/vindicara-inc/projectair/issues" class="text-brand-cyan hover:underline">GitHub</a> or email <a href="mailto:support@vindicara.io" class="text-brand-cyan hover:underline">support@vindicara.io</a>.</p>
      </div>
    </div>
  </div>
</section>

<!-- CTA -->
<section class="py-16 px-6 border-t border-white/5">
  <div class="max-w-screen-md mx-auto text-center">
    <h2 class="text-2xl font-bold tracking-tight mb-4">Ready for more?</h2>
    <p class="text-zinc-400 text-sm mb-8 max-w-lg mx-auto">Full documentation, architecture deep-dives, and the complete API reference live on GitHub.</p>
    <div class="flex flex-col sm:flex-row items-center justify-center gap-4">
      <a href="https://github.com/vindicara-inc/projectair#readme" class="btn-primary text-sm px-6 py-3">
        <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        Read the docs
      </a>
      <a href="/pricing" class="btn-secondary text-sm px-6 py-3">See pricing</a>
    </div>
  </div>
</section>

<!-- FOOTER -->
<footer class="w-full border-t border-white/5 bg-obsidian relative z-20">
  <div class="max-w-screen-xl mx-auto px-6 py-14">
    <div class="grid grid-cols-2 md:grid-cols-4 gap-8">
      <div class="col-span-2 md:col-span-1">
        <div class="flex items-center gap-1 mb-4">
          <img src={vindicaraLogo} alt="Vindicara" class="h-10 w-auto mix-blend-screen" />
        </div>
        <p class="text-sm text-zinc-500 leading-relaxed">
          AI Incident Response. Forensic reconstruction, signed evidence, and containment for autonomous agents.
        </p>
      </div>
      <div>
        <h3 class="text-sm font-semibold mb-4">Product</h3>
        <ul class="space-y-2 text-sm text-zinc-500">
          <li><a href="/#how-it-works" class="hover:text-white transition-colors">How It Works</a></li>
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
          <li><a href="/security" class="hover:text-white transition-colors">Security Disclosure</a></li>
        </ul>
      </div>
    </div>
    <div class="mt-8 flex flex-col md:flex-row items-center justify-between gap-4">
      <p class="text-xs text-zinc-600">&copy; 2026 Vindicara, Inc.</p>
    </div>
  </div>
</footer>

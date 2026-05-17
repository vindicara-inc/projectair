<script lang="ts">
  import vindicaraLogo from '$lib/assets/vindicara-logo.png';
  let copied = $state(false);

  function copyInstall() {
    navigator.clipboard?.writeText('pip install projectair');
    copied = true;
    setTimeout(() => copied = false, 2000);
  }

  const frameworks = [
    { name: 'OpenAI', code: 'from airsdk.integrations import instrument_openai\ninstrument_openai(client, recorder)' },
    { name: 'Anthropic', code: 'from airsdk.integrations import instrument_anthropic\ninstrument_anthropic(client, recorder)' },
    { name: 'LangChain', code: 'from airsdk import AIRCallbackHandler\nagent.run("task", callbacks=[AIRCallbackHandler(recorder)])' },
    { name: 'Google Gemini', code: 'from airsdk.integrations import instrument_gemini\ninstrument_gemini(client, recorder)' },
    { name: 'Google ADK', code: 'from airsdk.integrations import instrument_adk\ninstrument_adk(agent, recorder)' },
    { name: 'LlamaIndex', code: 'from airsdk.integrations import instrument_llamaindex\ninstrument_llamaindex(llm, recorder)' },
    { name: 'NeMo Guardrails', code: 'from airsdk.integrations import instrument_nemo_guardrails\ninstrument_nemo_guardrails(rails, recorder)' },
  ];

  const cliCommands = [
    { cmd: 'air demo', desc: 'Run the full demo (30 seconds, zero setup)' },
    { cmd: 'air demo --healthcare', desc: 'HIPAA-aligned clinical AI demo' },
    { cmd: 'air trace chain.jsonl', desc: 'Verify signatures, run detectors, export report' },
    { cmd: 'air push chain.jsonl -k KEY', desc: 'Push chain to AIR Cloud' },
    { cmd: 'air verify-public chain.jsonl', desc: 'Verify using only public infrastructure' },
    { cmd: 'air explain --finding ASI02', desc: 'Causal explanation for a finding' },
    { cmd: 'air verify-intent chain.jsonl', desc: 'Did the agent honor its declared intent?' },
    { cmd: 'air report article72', desc: 'Generate EU AI Act Article 72 report' },
  ];
</script>

<svelte:head>
  <title>Get Started | Vindicara</title>
  <meta name="description" content="Install Project AIR and instrument your first AI agent in under 5 minutes. Step-by-step guide." />
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
      <a href="/get-started" class="text-white transition-colors">Get Started</a>
      <a href="/dashboard" class="hover:text-white transition-colors">Dashboard</a>
    </div>
    <div class="hidden md:flex items-center gap-3">
      <a href="/dashboard" class="btn-primary text-xs px-4 py-2">Launch Dashboard</a>
    </div>
  </div>
</nav>

<section class="pt-32 pb-12 px-6">
  <div class="max-w-screen-md mx-auto">
    <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-4 font-mono">Get Started</p>
    <h1 class="text-5xl font-bold tracking-tight leading-[1.1] mb-4">
      First forensic report<br />in under 5 minutes
    </h1>
    <p class="text-xl text-zinc-400 mb-12">From install to signed evidence chain.</p>
  </div>
</section>

<!-- Step 1 -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex items-center gap-3 mb-6">
      <span class="w-8 h-8 flex items-center justify-center text-sm font-bold font-mono bg-brand-red text-white">1</span>
      <h2 class="text-2xl font-bold">Install the SDK</h2>
    </div>
    <button
      onclick={copyInstall}
      class="w-full glass-panel p-5 font-mono text-left flex items-center justify-between cursor-pointer hover:border-brand-red/30 transition-all"
    >
      <span><span class="text-brand-red">$</span> pip install projectair</span>
      <span class="text-xs text-zinc-500">{copied ? 'Copied' : 'Click to copy'}</span>
    </button>
    <p class="text-zinc-500 text-sm mt-3">Then verify: <code class="font-mono text-brand-cyan">air demo</code></p>
  </div>
</section>

<!-- Step 2 -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex items-center gap-3 mb-6">
      <span class="w-8 h-8 flex items-center justify-center text-sm font-bold font-mono bg-brand-red text-white">2</span>
      <h2 class="text-2xl font-bold">Instrument your agent</h2>
    </div>
    <div class="glass-panel p-6 font-mono text-sm leading-relaxed overflow-x-auto">
      <pre class="text-zinc-300"><span class="text-brand-cyan">from</span> airsdk <span class="text-brand-cyan">import</span> AIRRecorder

recorder = AIRRecorder(<span class="text-green-400">"chain.jsonl"</span>)

recorder.llm_start(prompt=<span class="text-green-400">"Analyze this data..."</span>)
recorder.llm_end(response=<span class="text-green-400">"Here is the analysis..."</span>)

recorder.tool_start(tool_name=<span class="text-green-400">"db_query"</span>, tool_args=&#123;<span class="text-green-400">"sql"</span>: <span class="text-green-400">"SELECT ..."</span>&#125;)
recorder.tool_end(tool_output=<span class="text-green-400">"42 rows returned"</span>)

recorder.agent_finish(final_output=<span class="text-green-400">"Task complete"</span>)</pre>
    </div>
    <p class="text-zinc-500 text-sm mt-3">Every call writes a signed, tamper-evident record to the chain.</p>
  </div>
</section>

<!-- Step 3 -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex items-center gap-3 mb-6">
      <span class="w-8 h-8 flex items-center justify-center text-sm font-bold font-mono bg-brand-red text-white">3</span>
      <h2 class="text-2xl font-bold">Framework integrations</h2>
    </div>
    <p class="text-zinc-400 mb-6">Already using a framework? One-line integration:</p>
    <div class="grid gap-3">
      {#each frameworks as fw}
        <div class="glass-panel px-5 py-4">
          <p class="text-sm font-bold mb-2">{fw.name}</p>
          <pre class="font-mono text-xs text-zinc-400 overflow-x-auto">{fw.code}</pre>
        </div>
      {/each}
    </div>
  </div>
</section>

<!-- Step 4 -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex items-center gap-3 mb-6">
      <span class="w-8 h-8 flex items-center justify-center text-sm font-bold font-mono bg-brand-red text-white">4</span>
      <h2 class="text-2xl font-bold">Push to AIR Cloud</h2>
    </div>
    <p class="text-zinc-400 mb-4">Subscribe at <a href="/pricing" class="text-brand-cyan hover:underline">vindicara.io/pricing</a>, then push your chain:</p>
    <div class="glass-panel p-6 font-mono text-sm leading-relaxed overflow-x-auto">
      <pre class="text-zinc-300"><span class="text-zinc-500"># Via CLI</span>
air push chain.jsonl --api-key YOUR_KEY

<span class="text-zinc-500"># Or from Python</span>
<span class="text-brand-cyan">import</span> httpx, json

records = [json.loads(l) <span class="text-brand-cyan">for</span> l <span class="text-brand-cyan">in</span> open(<span class="text-green-400">"chain.jsonl"</span>) <span class="text-brand-cyan">if</span> l.strip()]
client = httpx.Client(
    base_url=<span class="text-green-400">"https://cloud.vindicara.io"</span>,
    headers=&#123;<span class="text-green-400">"X-API-Key"</span>: <span class="text-green-400">"YOUR_KEY"</span>&#125;
)
<span class="text-brand-cyan">for</span> r <span class="text-brand-cyan">in</span> records:
    client.post(<span class="text-green-400">"/v1/capsules"</span>, json=r)</pre>
    </div>
  </div>
</section>

<!-- Step 5 -->
<section class="pb-16 px-6">
  <div class="max-w-screen-md mx-auto">
    <div class="flex items-center gap-3 mb-6">
      <span class="w-8 h-8 flex items-center justify-center text-sm font-bold font-mono bg-brand-red text-white">5</span>
      <h2 class="text-2xl font-bold">View in Dashboard</h2>
    </div>
    <p class="text-zinc-400 mb-4">Sign in at <a href="/dashboard" class="text-brand-cyan hover:underline">vindicara.io/dashboard</a> to see your live chain, compliance scores, team activity, and analytics.</p>
    <a href="/dashboard" class="btn-primary text-sm px-8 py-3 inline-block">Launch Dashboard</a>
  </div>
</section>

<!-- CLI Reference -->
<section class="pb-20 px-6">
  <div class="max-w-screen-md mx-auto">
    <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-6 font-mono">CLI Reference</p>
    <div class="glass-panel overflow-hidden">
      {#each cliCommands as { cmd, desc }, i}
        <div class="flex items-center gap-4 px-5 py-3 text-sm {i < cliCommands.length - 1 ? 'border-b border-white/5' : ''}">
          <code class="font-mono text-brand-cyan shrink-0 w-64">{cmd}</code>
          <span class="text-zinc-400">{desc}</span>
        </div>
      {/each}
    </div>
  </div>
</section>

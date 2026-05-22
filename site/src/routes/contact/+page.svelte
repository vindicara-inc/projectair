<script lang="ts">
  import vindicaraLogoDay from '$lib/assets/vindicara-logo-day.png';
  import vindicaraLogoNight from '$lib/assets/vindicara-logo-night.png';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
  import { page } from '$app/state';


  let mobileMenuOpen = $state(false);

  // Pre-select the tier from ?tier=team etc. Read once at mount; subsequent
  // dropdown selection becomes the source of truth.
  let tier = $state(page.url.searchParams.get('tier') ?? 'team');
  let name = $state('');
  let email = $state('');
  let company = $state('');
  let role = $state('');
  let agentScale = $state('');
  let useCase = $state('');
  let timeline = $state('');
  let submitting = $state(false);
  let submitted = $state(false);
  let submitError = $state<string | null>(null);

  // Web3Forms access key. Submissions route to the email verified in the
  // Web3Forms account (Kevin.Minn@vindicara.io). Mailto fallback below stays
  // wired in case Web3Forms is ever down.
  const WEB3FORMS_ACCESS_KEY = '637532b6-0aa1-40a7-a418-81e1625669b8';
  const FALLBACK_MAILTO = 'Kevin.Minn@vindicara.io';

  async function handleSubmit(event: SubmitEvent) {
    event.preventDefault();
    submitError = null;

    if (!WEB3FORMS_ACCESS_KEY) {
      // Fallback: open mailto with prefilled body so the inquiry still reaches Kevin.
      const subject = encodeURIComponent(`AIR ${tier} inquiry: ${company || name}`);
      const body = encodeURIComponent(
        `Tier interest: ${tier}\n\nName: ${name}\nEmail: ${email}\nCompany: ${company}\nRole: ${role}\n\nAgent scale: ${agentScale}\nTimeline: ${timeline}\n\nUse case:\n${useCase}\n\n— Sent from vindicara.io/contact (Web3Forms not yet configured)`
      );
      window.location.href = `mailto:${FALLBACK_MAILTO}?subject=${subject}&body=${body}`;
      submitted = true;
      return;
    }

    submitting = true;
    try {
      const response = await fetch('https://api.web3forms.com/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          access_key: WEB3FORMS_ACCESS_KEY,
          subject: `AIR ${tier} inquiry from ${company || name}`,
          from_name: name,
          email,
          tier,
          company,
          role,
          agent_scale: agentScale,
          timeline,
          use_case: useCase,
          // Hidden honeypot field; bots fill anything, humans skip it.
          botcheck: '',
        }),
      });
      const data = await response.json();
      if (data.success) {
        submitted = true;
      } else {
        submitError = data.message || 'Submission failed. Please email Kevin.Minn@vindicara.io directly.';
      }
    } catch (err) {
      submitError = 'Network error. Please email Kevin.Minn@vindicara.io directly.';
    } finally {
      submitting = false;
    }
  }
</script>

<svelte:head>
  <title>Talk to us | Vindicara AIR</title>
  <meta name="description" content="Inquire about Vindicara AIR Team or Enterprise. We respond within one business day with a quote and a deployment plan tailored to your stack." />
  <link rel="canonical" href="https://vindicara.io/contact" />
  <meta property="og:type" content="website" />
  <meta property="og:url" content="https://vindicara.io/contact" />
  <meta property="og:title" content="Talk to us | Vindicara AIR" />
  <meta property="og:description" content="Get a quote and deployment plan for AIR Team or Enterprise within one business day." />
</svelte:head>

<!-- NAV (mirrors pricing page) -->
<nav class="fixed top-0 w-full z-50 backdrop-blur-2xl" style="background-color: color-mix(in srgb, var(--surface) 60%, transparent); border-bottom: 1px solid var(--border-subtle);">
  <div class="max-w-screen-2xl mx-auto px-6 flex items-center justify-between h-16">
    <a href="/" class="flex items-center gap-1">
      <img src={vindicaraLogoNight} alt="Vindicara" class="h-10 w-auto logo-night mix-blend-screen" /><img src={vindicaraLogoDay} alt="Vindicara" class="h-10 w-auto logo-day" />
      <span class="font-mono text-[10px] tracking-[0.18em] uppercase px-1.5 py-0.5" style="color: var(--text-primary); border: 1px solid var(--border); box-shadow: 0 0 10px var(--badge-shadow);">Project AIR&#8482;</span>
    </a>
    <div class="hidden md:flex items-center gap-8 text-sm">
      <a href="/#how-it-works" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">How It Works</a>
      <a href="/#standards" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Standards</a>
      <a href="/blog" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Blog</a>
      <a href="/pricing" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="transition-colors">Pricing</a>
    </div>
    <div class="hidden md:flex items-center gap-3">
      <ThemeToggle />
      <a href="https://github.com/vindicara-inc/projectair#readme" class="btn-secondary text-xs px-4 py-2">Docs</a>
      <a href="https://github.com/vindicara-inc/projectair" class="btn-primary text-xs px-4 py-2">GitHub</a>
    </div>
    <div class="md:hidden flex items-center gap-2">
      <ThemeToggle />
      <button
        style="color: var(--text-muted);"
        onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'}
        onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
        onclick={() => (mobileMenuOpen = !mobileMenuOpen)}
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
      <a href="/blog" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="block text-sm">Blog</a>
      <a href="/pricing" style="color: var(--text-muted);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'} class="block text-sm">Pricing</a>
      <div class="flex gap-3 pt-2">
        <a href="https://github.com/vindicara-inc/projectair#readme" class="btn-secondary text-xs px-4 py-2">Docs</a>
        <a href="https://github.com/vindicara-inc/projectair" class="btn-primary text-xs px-4 py-2">GitHub</a>
      </div>
    </div>
  {/if}
</nav>

<main class="pt-24 pb-20 max-w-3xl mx-auto px-6">
  <p class="text-brand-red text-sm font-semibold uppercase tracking-wider mb-4 font-mono">Contact</p>
  <h1 class="text-4xl sm:text-5xl font-bold tracking-tight">Talk to us.</h1>
  <p class="mt-4 text-lg leading-relaxed" style="color: var(--text-muted);">
    We respond to every inquiry within one business day with a quote, a deployment plan, and a 30-minute call to walk through your stack. Tell us what you are running and what evidence you need to produce.
  </p>

  {#if submitted}
    <div class="mt-12 border border-green-400/30 bg-green-400/5 p-8">
      <h2 class="text-xl font-semibold text-green-300">Thanks. Your inquiry is in.</h2>
      <p class="mt-3 text-sm leading-relaxed" style="color: var(--text-secondary);">
        Kevin will respond within one business day from <code class="font-mono" style="color: var(--text-primary);">Kevin.Minn@vindicara.io</code> with a tailored quote, the artifacts you should expect, and a 30-minute deployment-planning call slot.
      </p>
      <p class="mt-3 text-sm" style="color: var(--text-muted);">
        While you wait, you can <a href="https://github.com/vindicara-inc/projectair" class="text-brand-red hover:text-brand-red/80 underline">explore the OSS package</a> and run <code class="font-mono" style="color: var(--text-secondary);">pip install projectair && air demo</code> in 30 seconds to see the forensic chain in action.
      </p>
    </div>
  {:else}
    <form onsubmit={handleSubmit} class="mt-12 space-y-6">
      <div>
        <label for="tier" class="block text-sm font-mono uppercase tracking-wider mb-2" style="color: var(--text-muted);">Tier of interest</label>
        <select
          id="tier"
          bind:value={tier}
          required
          class="w-full border border-[var(--border)] px-4 py-3 focus:border-brand-red focus:outline-none"
          style="background-color: var(--surface-overlay); color: var(--text-primary);"
        >
          <option value="team">Team: $599/mo, hosted AIR Cloud workspace</option>
          <option value="enterprise">Enterprise: SSO/SAML, on-prem, SLA, BAA</option>
          <option value="individual">Individual: $39/mo (just buy it on the pricing page)</option>
          <option value="other">Other / not sure</option>
        </select>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label for="name" class="block text-sm font-mono uppercase tracking-wider mb-2" style="color: var(--text-muted);">Your name</label>
          <input
            id="name"
            type="text"
            bind:value={name}
            required
            class="w-full border border-[var(--border)] px-4 py-3 focus:border-brand-red focus:outline-none"
            style="background-color: var(--surface-overlay); color: var(--text-primary);"
          />
        </div>
        <div>
          <label for="email" class="block text-sm font-mono uppercase tracking-wider mb-2" style="color: var(--text-muted);">Work email</label>
          <input
            id="email"
            type="email"
            bind:value={email}
            required
            class="w-full border border-[var(--border)] px-4 py-3 focus:border-brand-red focus:outline-none"
            style="background-color: var(--surface-overlay); color: var(--text-primary);"
          />
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label for="company" class="block text-sm font-mono uppercase tracking-wider mb-2" style="color: var(--text-muted);">Company</label>
          <input
            id="company"
            type="text"
            bind:value={company}
            required
            class="w-full border border-[var(--border)] px-4 py-3 focus:border-brand-red focus:outline-none"
            style="background-color: var(--surface-overlay); color: var(--text-primary);"
          />
        </div>
        <div>
          <label for="role" class="block text-sm font-mono uppercase tracking-wider mb-2" style="color: var(--text-muted);">Your role</label>
          <input
            id="role"
            type="text"
            bind:value={role}
            placeholder="e.g. Head of Security, Platform Engineer, Compliance Lead"
            class="w-full border border-[var(--border)] px-4 py-3 focus:border-brand-red focus:outline-none"
            style="background-color: var(--surface-overlay); color: var(--text-primary);"
          />
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label for="agent_scale" class="block text-sm font-mono uppercase tracking-wider mb-2" style="color: var(--text-muted);">Agent scale</label>
          <select
            id="agent_scale"
            bind:value={agentScale}
            class="w-full border border-[var(--border)] px-4 py-3 focus:border-brand-red focus:outline-none"
            style="background-color: var(--surface-overlay); color: var(--text-primary);"
          >
            <option value="">Pick one</option>
            <option value="1-10">1-10 agents in production</option>
            <option value="10-50">10-50 agents</option>
            <option value="50-500">50-500 agents</option>
            <option value="500+">500+ agents</option>
            <option value="evaluating">Evaluating, not in production yet</option>
          </select>
        </div>
        <div>
          <label for="timeline" class="block text-sm font-mono uppercase tracking-wider mb-2" style="color: var(--text-muted);">Timeline</label>
          <select
            id="timeline"
            bind:value={timeline}
            class="w-full border border-[var(--border)] px-4 py-3 focus:border-brand-red focus:outline-none"
            style="background-color: var(--surface-overlay); color: var(--text-primary);"
          >
            <option value="">Pick one</option>
            <option value="immediate">Immediate (this quarter)</option>
            <option value="next-quarter">Next quarter</option>
            <option value="this-year">This year</option>
            <option value="exploring">Exploring, no deadline</option>
          </select>
        </div>
      </div>

      <div>
        <label for="use_case" class="block text-sm font-mono uppercase tracking-wider mb-2" style="color: var(--text-muted);">Use case</label>
        <textarea
          id="use_case"
          bind:value={useCase}
          rows="5"
          required
          placeholder="What are your agents doing? What evidence do you need to produce, and for whom (auditor, regulator, insurance carrier, internal IR)? Any specific compliance frameworks in scope?"
          class="w-full border border-[var(--border)] px-4 py-3 focus:border-brand-red focus:outline-none resize-y"
          style="background-color: var(--surface-overlay); color: var(--text-primary);"
        ></textarea>
      </div>

      {#if submitError}
        <div class="border border-brand-red/30 bg-brand-red/5 p-4 text-sm" style="color: var(--text-secondary);">
          {submitError}
        </div>
      {/if}

      <div class="flex flex-col sm:flex-row items-center gap-4">
        <button
          type="submit"
          disabled={submitting}
          class="btn-primary text-sm px-6 py-3 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting ? 'Sending...' : 'Send inquiry'}
        </button>
        <p class="text-xs" style="color: var(--text-muted);">
          Or email <a href="mailto:Kevin.Minn@vindicara.io" style="color: var(--text-secondary);" onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'} onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-secondary)'} class="underline">Kevin.Minn@vindicara.io</a> directly.
        </p>
      </div>
    </form>
  {/if}
</main>

<footer class="w-full relative z-20 mt-20" style="border-top: 1px solid var(--border-subtle); background-color: var(--surface);">
  <div class="max-w-screen-xl mx-auto px-6 py-10 text-center">
    <p class="text-xs" style="color: var(--text-faint);">&copy; 2026 Vindicara, Inc. · AI Incident Response.</p>
  </div>
</footer>

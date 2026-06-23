# Site Day Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a peachy-lilac light theme ("day mode") to the Vindicara marketing site with a toggle in the nav bar, OS preference detection, and localStorage persistence.

**Architecture:** CSS custom properties on `:root` define dark defaults; `data-theme="light"` on `<html>` overrides them. A Svelte 5 runes-based store manages the theme. An inline script in the layout prevents flash. Terminal/code blocks stay dark in both modes.

**Tech Stack:** SvelteKit 2, Svelte 5 (runes), Tailwind CSS 4 (`@theme` block), CSS custom properties.

**Spec:** `docs/superpowers/specs/2026-05-21-site-day-mode-design.md`

---

### Task 1: CSS Foundation + Theme Store

**Files:**
- Modify: `site/src/app.css`
- Create: `site/src/lib/theme.svelte.ts`

- [ ] **Step 1: Add semantic CSS custom properties to app.css**

Replace the existing `@theme` block and add `:root` / `:root[data-theme="light"]` variable definitions. Keep the `@theme` block for Tailwind integration but point it at the CSS vars.

```css
@import "tailwindcss";

@theme {
  --color-surface: var(--surface);
  --color-surface-raised: var(--surface-raised);
  --color-surface-overlay: var(--surface-overlay);
  --color-text-primary: var(--text-primary);
  --color-text-secondary: var(--text-secondary);
  --color-text-muted: var(--text-muted);
  --color-text-faint: var(--text-faint);
  --color-border: var(--border);
  --color-border-subtle: var(--border-subtle);
  --color-glass: var(--glass);
  --color-glass-border: var(--glass-border);

  --color-brand-red: #dc2626;
  --color-brand-red-dark: #991b1b;
  --color-brand-cyan: #06b6d4;
  --color-brand-purple: #8b5cf6;
  --color-brand-pink: #ec4899;

  --font-sans: 'Inter', system-ui, -apple-system, sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace, 'Fira Code', monospace;
}

:root {
  --surface: #0a0a0f;
  --surface-raised: #12121a;
  --surface-overlay: #1a1a2e;
  --text-primary: #ffffff;
  --text-secondary: #a1a1aa;
  --text-muted: #71717a;
  --text-faint: #52525b;
  --border: rgba(255, 255, 255, 0.1);
  --border-subtle: rgba(255, 255, 255, 0.05);
  --glass: rgba(255, 255, 255, 0.05);
  --glass-border: rgba(255, 255, 255, 0.1);
  --glow-surface: rgba(220, 38, 38, 0.15);
  --glow-surface-far: rgba(220, 38, 38, 0.05);
  --glow-cyan-surface: rgba(6, 182, 212, 0.15);
  --glow-cyan-far: rgba(6, 182, 212, 0.05);
  --badge-shadow: rgba(255, 255, 255, 0.25);
  --gradient-subtle-from: #ffffff;
  --gradient-subtle-to: #a1a1aa;
}

:root[data-theme="light"] {
  --surface: #f0e6ef;
  --surface-raised: #e8dce7;
  --surface-overlay: #dfd1de;
  --text-primary: #1a1a2e;
  --text-secondary: #4a3f52;
  --text-muted: #7a6d82;
  --text-faint: #9e8fa6;
  --border: rgba(26, 26, 46, 0.12);
  --border-subtle: rgba(26, 26, 46, 0.06);
  --glass: rgba(26, 26, 46, 0.04);
  --glass-border: rgba(26, 26, 46, 0.08);
  --glow-surface: rgba(220, 38, 38, 0.1);
  --glow-surface-far: rgba(220, 38, 38, 0.03);
  --glow-cyan-surface: rgba(6, 182, 212, 0.1);
  --glow-cyan-far: rgba(6, 182, 212, 0.03);
  --badge-shadow: rgba(26, 26, 46, 0.2);
  --gradient-subtle-from: #1a1a2e;
  --gradient-subtle-to: #4a3f52;
}
```

- [ ] **Step 2: Update component classes in app.css to use semantic tokens**

Update the `@layer base` and `@layer components` blocks:

```css
@layer base {
  ::selection {
    background-color: var(--color-brand-red);
    color: white;
  }

  html {
    scroll-behavior: smooth;
  }

  body {
    background-color: var(--surface);
    color: var(--text-primary);
    font-family: var(--font-sans);
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
  }
}

@layer components {
  .glass-panel {
    background: var(--glass);
    border: 1px solid var(--glass-border);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
  }

  .glow-red {
    box-shadow: 0 0 40px var(--glow-surface), 0 0 80px var(--glow-surface-far);
  }

  .glow-cyan {
    box-shadow: 0 0 40px var(--glow-cyan-surface), 0 0 80px var(--glow-cyan-far);
  }

  .text-gradient-brand {
    background: linear-gradient(135deg, #dc2626, #ec4899, #8b5cf6, #06b6d4);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .text-gradient-subtle {
    background: linear-gradient(135deg, var(--gradient-subtle-from), var(--gradient-subtle-to));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  .btn-primary {
    @apply inline-flex items-center justify-center px-6 py-3 rounded-lg font-semibold text-sm
           bg-brand-red hover:bg-brand-red-dark text-white transition-all duration-200
           shadow-lg shadow-brand-red/20 hover:shadow-brand-red/40;
  }

  .btn-secondary {
    @apply inline-flex items-center justify-center px-6 py-3 rounded-lg font-semibold text-sm
           transition-all duration-200;
    border: 1px solid var(--border);
    color: var(--text-primary);
  }

  .btn-secondary:hover {
    background: var(--glass);
  }

  .code-block {
    @apply font-mono text-sm rounded-lg p-4 overflow-x-auto;
    background: #1a1a2e;
    border: 1px solid rgba(255, 255, 255, 0.1);
    color: #e4e4e7;
  }

  .dark-embed {
    background: #1a1a2e;
    border: 1px solid rgba(255, 255, 255, 0.1);
    color: #e4e4e7;
  }
}
```

Note: `.btn-secondary` previously used `@apply border border-white/20 text-white hover:bg-white/5` which are theme-dependent. Now uses CSS vars directly. `.code-block` and a new `.dark-embed` class use hardcoded dark colors so they stay dark in both modes. `.btn-primary` text stays `text-white` (always white on red, not theme-dependent).

- [ ] **Step 3: Create the theme store**

Create `site/src/lib/theme.svelte.ts`:

```typescript
import { browser } from '$app/environment';

const STORAGE_KEY = 'vindicara-theme';

type Theme = 'dark' | 'light';

function getInitialTheme(): Theme {
  if (!browser) return 'dark';
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === 'dark' || stored === 'light') return stored;
  if (window.matchMedia('(prefers-color-scheme: light)').matches) return 'light';
  return 'dark';
}

function applyTheme(t: Theme) {
  if (!browser) return;
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem(STORAGE_KEY, t);
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', t === 'dark' ? '#0a0a0f' : '#f0e6ef');
}

let current: Theme = $state(getInitialTheme());

if (browser) {
  applyTheme(current);
  window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
    if (!localStorage.getItem(STORAGE_KEY)) {
      current = e.matches ? 'light' : 'dark';
      applyTheme(current);
    }
  });
}

export function toggleTheme() {
  current = current === 'dark' ? 'light' : 'dark';
  applyTheme(current);
}

export function getTheme(): Theme {
  return current;
}
```

- [ ] **Step 4: Verify the dev server starts**

Run:
```bash
cd site && npm run dev
```
Expected: Dev server starts without errors. The site should look identical to before (dark mode defaults still apply).

- [ ] **Step 5: Commit**

```bash
git add site/src/app.css site/src/lib/theme.svelte.ts
git commit -m "feat(site): add CSS custom properties and theme store for day mode"
```

---

### Task 2: Layout + Flash Prevention + Logo Assets

**Files:**
- Modify: `site/src/routes/+layout.svelte`
- Copy: `docs/vindicara-logo-transparent.png` -> `site/src/lib/assets/vindicara-logo-day.png`
- Copy: `docs/vindicara-logo-dark-bg.png` -> `site/src/lib/assets/vindicara-logo-night.png`

- [ ] **Step 1: Copy logo assets**

```bash
cp docs/vindicara-logo-transparent.png site/src/lib/assets/vindicara-logo-day.png
cp docs/vindicara-logo-dark-bg.png site/src/lib/assets/vindicara-logo-night.png
```

- [ ] **Step 2: Add flash-prevention inline script to +layout.svelte**

Update `site/src/routes/+layout.svelte` to add an inline script that sets `data-theme` before paint. Also update the `<meta name="theme-color">` to be dynamic:

```svelte
<script lang="ts">
  import '../app.css';
  import favicon from '$lib/assets/favicon.svg';

  let { children } = $props();
</script>

<svelte:head>
  <link rel="icon" href={favicon} />
  <link rel="alternate" type="application/rss+xml" title="Vindicara AIR Blog" href="https://vindicara.io/rss.xml" />

  <meta property="og:site_name" content="Vindicara" />
  <meta property="og:image" content="https://vindicara.io/og-image.png" />
  <meta property="og:image:width" content="1200" />
  <meta property="og:image:height" content="630" />

  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:site" content="@AIRbyVindicara" />
  <meta name="twitter:image" content="https://vindicara.io/og-image.png" />

  <meta name="theme-color" content="#0a0a0f" />

  {@html `<script>
    (function(){
      var t=localStorage.getItem('vindicara-theme');
      if(!t){t=window.matchMedia('(prefers-color-scheme:light)').matches?'light':'dark'}
      document.documentElement.setAttribute('data-theme',t);
      var m=document.querySelector('meta[name="theme-color"]');
      if(m)m.setAttribute('content',t==='dark'?'#0a0a0f':'#f0e6ef');
    })();
  <\/script>`}

  {@html `<script type="application/ld+json">${JSON.stringify({
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'Organization',
        '@id': 'https://vindicara.io/#organization',
        name: 'Vindicara',
        url: 'https://vindicara.io',
        logo: 'https://vindicara.io/og-image.png',
        sameAs: ['https://github.com/vindicara-inc/projectair', 'https://x.com/AIRbyVindicara', 'https://linkedin.com/company/vindicara-ai'],
      },
      {
        '@type': 'WebSite',
        '@id': 'https://vindicara.io/#website',
        url: 'https://vindicara.io',
        name: 'Vindicara',
        publisher: { '@id': 'https://vindicara.io/#organization' },
      },
    ],
  })}<\/script>`}
</svelte:head>

{@render children()}
```

- [ ] **Step 3: Run svelte-check**

```bash
cd site && npm run check
```
Expected: No errors.

- [ ] **Step 4: Commit**

```bash
git add site/src/routes/+layout.svelte site/src/lib/assets/vindicara-logo-day.png site/src/lib/assets/vindicara-logo-night.png
git commit -m "feat(site): add flash prevention script and logo assets for day mode"
```

---

### Task 3: Theme Toggle Component

**Files:**
- Create: `site/src/lib/components/ThemeToggle.svelte`

- [ ] **Step 1: Create the ThemeToggle component**

```svelte
<script lang="ts">
  import { toggleTheme, getTheme } from '$lib/theme.svelte';

  let theme = $derived(getTheme());
</script>

<button
  onclick={toggleTheme}
  class="transition-colors cursor-pointer"
  style="color: var(--text-muted);"
  onmouseenter={(e) => e.currentTarget.style.color = 'var(--text-primary)'}
  onmouseleave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
  aria-label="Toggle theme"
  title={theme === 'dark' ? 'Switch to day mode' : 'Switch to night mode'}
>
  {#if theme === 'dark'}
    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386l-1.591 1.591M21 12h-2.25m-.386 6.364l-1.591-1.591M12 18.75V21m-4.773-4.227l-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0z" />
    </svg>
  {:else}
    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z" />
    </svg>
  {/if}
</button>
```

Note: Uses `$derived(getTheme())` to reactively track the theme. Sun icon shown in dark mode (click to switch to light), moon icon shown in light mode (click to switch to dark).

- [ ] **Step 2: Verify it compiles**

```bash
cd site && npm run check
```
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add site/src/lib/components/ThemeToggle.svelte
git commit -m "feat(site): add ThemeToggle component with sun/moon icons"
```

---

### Task 4: Homepage Migration

**Files:**
- Modify: `site/src/routes/+page.svelte`

This is the largest file (~1176 lines). The migration replaces all hardcoded theme-sensitive color classes with semantic equivalents using CSS vars. Terminal blocks and code embeds stay dark.

- [ ] **Step 1: Update script imports**

Replace the logo import and add the theme imports at the top of the `<script>` block:

```typescript
import vindicaraLogoDay from '$lib/assets/vindicara-logo-day.png';
import vindicaraLogoNight from '$lib/assets/vindicara-logo-night.png';
import ThemeToggle from '$lib/components/ThemeToggle.svelte';
import { getTheme } from '$lib/theme.svelte';
import AsciinemaEmbed from '$lib/components/AsciinemaEmbed.svelte';

let mobileMenuOpen = $state(false);
let logo = $derived(getTheme() === 'dark' ? vindicaraLogoNight : vindicaraLogoDay);
```

Remove the old `import vindicaraLogo from '$lib/assets/vindicara-logo.png';` line.

- [ ] **Step 2: Update the NAV section**

Replace the nav with semantic colors and add the toggle. Key changes:
- `bg-obsidian/60` -> `style="background-color: color-mix(in srgb, var(--surface) 60%, transparent)"`
- `border-white/5` -> `style="border-color: var(--border-subtle)"`
- Logo: use `{logo}` instead of `{vindicaraLogo}`, remove `mix-blend-screen` class
- Add `<ThemeToggle />` before the CTA buttons in the desktop nav
- `text-white` for active links -> `style="color: var(--text-primary)"`
- `text-zinc-400` -> `style="color: var(--text-muted)"`
- `hover:text-white` -> use `onmouseenter`/`onmouseleave` with `var(--text-primary)` or keep as-is if using Tailwind semantic class

For practical migration, use Tailwind arbitrary values to keep the markup concise. The `@theme` block maps `--color-surface` etc. to Tailwind utilities, so use:
- `bg-surface` (maps to `var(--surface)`)
- `text-text-primary` (maps to `var(--text-primary)`)
- `border-border` (maps to `var(--border)`)

Or use inline `style` attributes for opacity-mixed values that Tailwind can't express.

The nav becomes:

```svelte
<nav class="fixed top-0 w-full z-50 backdrop-blur-2xl" style="background-color: color-mix(in srgb, var(--surface) 60%, transparent); border-bottom: 1px solid var(--border-subtle);">
  <div class="max-w-screen-2xl mx-auto px-6 flex items-center justify-between h-16">
    <a href="/" class="flex items-center gap-1">
      <img src={logo} alt="Vindicara" class="h-10 w-auto" />
      <span class="font-mono text-[10px] tracking-[0.18em] uppercase px-1.5 py-0.5" style="color: var(--text-primary); border: 1px solid var(--border); box-shadow: 0 0 10px var(--badge-shadow);">Project AIR&#8482;</span>
    </a>

    <div class="hidden md:flex items-center gap-8 text-sm" style="color: var(--text-muted);">
      <!-- nav links with hover behavior -->
    </div>

    <div class="hidden md:flex items-center gap-3">
      <ThemeToggle />
      <a href="/get-started" class="btn-secondary text-xs px-4 py-2">Get Started</a>
      <a href="/dashboard" class="btn-primary text-xs px-4 py-2">Launch Dashboard</a>
    </div>

    <!-- mobile hamburger button uses var(--text-muted) and var(--text-primary) -->
  </div>

  {#if mobileMenuOpen}
    <div class="md:hidden backdrop-blur-2xl px-6 py-4 space-y-3" style="border-top: 1px solid var(--border-subtle); background-color: color-mix(in srgb, var(--surface) 95%, transparent);">
      <!-- mobile links, add ThemeToggle in mobile menu too -->
    </div>
  {/if}
</nav>
```

- [ ] **Step 3: Update the HERO section**

Key replacements:
- `bg-gradient-to-t from-obsidian via-obsidian/90 to-obsidian/60` on the overlay div: use inline style with CSS gradient referencing `var(--surface)`.
- `text-white` on the h1 span -> `style="color: var(--text-primary)"`
- `text-zinc-400` -> `style="color: var(--text-secondary)"`
- `text-zinc-300` -> `style="color: var(--text-secondary)"`
- The animated terminal block (`bg-obsidian-lighter border border-white/10`) stays hardcoded dark: wrap in a container or keep the literal dark values since this is a "dark embed" exception.

Example for the hero overlay:
```svelte
<div class="absolute inset-0" style="background: linear-gradient(to top, var(--surface), color-mix(in srgb, var(--surface) 90%, transparent), color-mix(in srgb, var(--surface) 60%, transparent));"></div>
```

- [ ] **Step 4: Update remaining sections**

For each section in the homepage, apply the same replacement pattern:

**General rules applied throughout:**
- `bg-obsidian` -> no class needed (body handles it) or `style="background-color: var(--surface);"`
- `bg-obsidian-light/30` -> `style="background-color: color-mix(in srgb, var(--surface-raised) 30%, transparent);"`
- `bg-obsidian-lighter` / `bg-obsidian-lighter/40` -> `style="background-color: var(--surface-overlay);"` or with opacity
- `border-white/5` -> `style="border-color: var(--border-subtle);"`
- `border-white/10` -> `style="border-color: var(--border);"`
- `text-white` (headings, strong text) -> `style="color: var(--text-primary);"`
- `text-zinc-200`, `text-zinc-300` -> `style="color: var(--text-secondary);"`
- `text-zinc-400` -> `style="color: var(--text-secondary);"`
- `text-zinc-500` -> `style="color: var(--text-muted);"`
- `text-zinc-600` -> `style="color: var(--text-faint);"`
- `bg-white/[0.015]` (alternating rows) -> `style="background-color: var(--glass);"`
- `bg-white/[0.03]`, `bg-white/5` -> `style="background-color: var(--glass);"`
- `hover:text-white` -> hover to `var(--text-primary)`
- `hover:bg-white/5` -> hover to `var(--glass)`
- `bg-brand-red/5`, `border-brand-red/30` -> keep as-is (brand accent, not theme-dependent)

**Sections that stay hardcoded dark (terminal/code embeds):**
- The animated `air trace` terminal block in the hero
- The `air verify-intent` terminal in the Structural Verification section
- Code snippets inside the "How It Works" cards (the `pip install` / `from airsdk` blocks)
- The live demo API result panels and input textareas

For these, add the `dark-embed` class defined in `app.css` or keep explicit dark values. Do not replace their `bg-obsidian-lighter`, `border-white/10`, or `text-zinc-*` colors with semantic tokens.

- [ ] **Step 5: Update the footer**

Same pattern as the nav:
- `bg-obsidian` -> `style="background-color: var(--surface);"`
- Logo swap to `{logo}`, remove `mix-blend-screen`
- `border-white/5` -> `style="border-color: var(--border-subtle);"`
- Footer text colors to semantic vars
- Footer headings `text-white` -> `style="color: var(--text-primary);"`
- Footer links `text-zinc-500` -> `style="color: var(--text-muted);"`
- `hover:text-white` -> hover to `var(--text-primary)`
- NVIDIA badge: keep as-is (SVG, works on both backgrounds)

- [ ] **Step 6: Verify the homepage in both modes**

```bash
cd site && npm run dev
```

Open in browser. Toggle between dark and light mode. Check:
- Nav background, text, and toggle work
- Hero section: gradient overlay, text colors, terminal stays dark
- All body sections: correct backgrounds, text, borders
- Footer: logo swap, text colors, borders
- No flash on page reload

- [ ] **Step 7: Run svelte-check**

```bash
cd site && npm run check
```
Expected: No errors.

- [ ] **Step 8: Commit**

```bash
git add site/src/routes/+page.svelte
git commit -m "feat(site): migrate homepage to semantic theme tokens"
```

---

### Task 5: Shared Components Migration

**Files:**
- Modify: `site/src/lib/components/LegalDocument.svelte`
- Modify: `site/src/lib/components/ShareButtons.svelte`
- Modify: `site/src/lib/components/AsciinemaEmbed.svelte`
- Modify: `site/src/lib/components/admissibility/CertificationGenerator.svelte`
- Modify: `site/src/lib/components/admissibility/ChainExplorer.svelte`
- Modify: `site/src/lib/components/admissibility/FrameworkTabs.svelte`

- [ ] **Step 1: Update LegalDocument.svelte**

This component has its own nav, footer, AND a `<style>` block with hardcoded colors for `.legal-content`. Update:

1. Import the theme toggle and logos:
```typescript
import vindicaraLogoDay from '$lib/assets/vindicara-logo-day.png';
import vindicaraLogoNight from '$lib/assets/vindicara-logo-night.png';
import ThemeToggle from '$lib/components/ThemeToggle.svelte';
import { getTheme } from '$lib/theme.svelte';

let logo = $derived(getTheme() === 'dark' ? vindicaraLogoNight : vindicaraLogoDay);
```

2. Update nav and footer with same pattern as homepage (replace `bg-obsidian/60`, `border-white/5`, `text-zinc-*`, `text-white`, `mix-blend-screen`, add `ThemeToggle`).

3. Update the `<style>` block: replace all hardcoded `color: white` and `color: rgb(212, 212, 216)` etc. with CSS var references:
```css
.legal-content :global(h1) {
  color: var(--text-primary);
}
.legal-content :global(h2) {
  color: var(--text-primary);
  border-bottom: 1px solid var(--border);
}
.legal-content :global(h3) {
  color: var(--text-secondary);
}
.legal-content :global(h4) {
  color: var(--text-secondary);
}
.legal-content :global(p) {
  color: var(--text-secondary);
}
.legal-content :global(strong) {
  color: var(--text-primary);
}
.legal-content :global(li) {
  color: var(--text-secondary);
}
.legal-content :global(blockquote) {
  background: var(--glass);
  color: var(--text-secondary);
}
.legal-content :global(code) {
  background: var(--glass);
  color: var(--text-primary);
  border: 1px solid var(--glass-border);
}
.legal-content :global(pre) {
  /* stays dark - code block */
  background: #12121a;
  color: #e4e4e7;
  border: 1px solid rgba(255, 255, 255, 0.08);
}
.legal-content :global(hr) {
  border-top: 1px solid var(--border);
}
.legal-content :global(th) {
  background: var(--glass);
  color: var(--text-primary);
}
.legal-content :global(td) {
  color: var(--text-secondary);
}
.legal-content :global(th),
.legal-content :global(td) {
  border: 1px solid var(--border);
}
```

- [ ] **Step 2: Update ShareButtons.svelte**

Replace hardcoded theme colors with semantic vars. This is a small component (~72 lines).

- [ ] **Step 3: Update AsciinemaEmbed.svelte**

The asciinema player itself stays dark (it's a terminal recording). Keep the existing styling. Only update any wrapper/container colors if they reference theme-dependent obsidian values.

- [ ] **Step 4: Update admissibility components**

Update `CertificationGenerator.svelte`, `ChainExplorer.svelte`, and `FrameworkTabs.svelte` with the same pattern. These use `bg-obsidian-lighter`, `text-white`, `text-zinc-*`, `border-white/*` extensively. Apply semantic var replacements. Any code/JSON display areas stay dark.

- [ ] **Step 5: Run svelte-check**

```bash
cd site && npm run check
```
Expected: No errors.

- [ ] **Step 6: Commit**

```bash
git add site/src/lib/components/
git commit -m "feat(site): migrate shared components to semantic theme tokens"
```

---

### Task 6: Blog Layout + Blog Index Migration

**Files:**
- Modify: `site/src/routes/blog/+layout.svelte`
- Modify: `site/src/routes/blog/+page.svelte`

The blog layout wraps all blog post pages with its own nav and footer. Updating it covers the chrome for all 8 blog posts.

- [ ] **Step 1: Update blog/+layout.svelte**

Same nav/footer pattern as homepage:
1. Replace logo import, add theme toggle imports
2. `let logo = $derived(getTheme() === 'dark' ? vindicaraLogoNight : vindicaraLogoDay);`
3. Update nav: `bg-obsidian/60` -> `color-mix` with `var(--surface)`, remove `mix-blend-screen`, add `ThemeToggle`
4. Update footer: same semantic var replacements
5. All `text-zinc-*`, `text-white`, `border-white/*` -> semantic vars

- [ ] **Step 2: Update blog/+page.svelte (blog index)**

Replace theme-sensitive colors in the blog index listing page.

- [ ] **Step 3: Spot-check blog post pages**

Blog posts are wrapped by the blog layout, so their nav/footer are covered. However, blog posts themselves may have hardcoded `text-white`, `text-zinc-*`, `border-white/*` in their content areas. Scan all 8 blog post files and replace theme-sensitive classes with semantic vars.

The 8 blog posts are:
- `eu-ai-act-article-72-guide/+page.svelte`
- `forensic-layer-market-map/+page.svelte`
- `hipaa-ai-audit-problem/+page.svelte`
- `mcp-security-2026/+page.svelte`
- `nemoclaw-forensic-evidence/+page.svelte`
- `secure-ai-agents-5-minutes/+page.svelte`
- `structural-verification/+page.svelte`
- `trustworthy-agents-forensic-evidence/+page.svelte`

Apply the same replacements: `text-white` -> `var(--text-primary)`, `text-zinc-*` -> appropriate semantic var, `border-white/*` -> `var(--border)` or `var(--border-subtle)`, `bg-obsidian*` -> `var(--surface*)`.

Code blocks and terminal examples within blog posts stay dark.

- [ ] **Step 4: Run svelte-check**

```bash
cd site && npm run check
```
Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add site/src/routes/blog/
git commit -m "feat(site): migrate blog layout, index, and posts to semantic theme tokens"
```

---

### Task 7: Pricing + Get-Started + Contact Pages

**Files:**
- Modify: `site/src/routes/pricing/+page.svelte`
- Modify: `site/src/routes/get-started/+page.svelte`
- Modify: `site/src/routes/contact/+page.svelte`

These three pages each have their own nav and footer (copy-pasted).

- [ ] **Step 1: Update pricing/+page.svelte**

1. Replace logo import, add theme toggle imports, add `let logo = $derived(...)`.
2. Update nav and footer with semantic vars (same pattern as homepage).
3. Update page content: tier cards, comparison table, FAQ section.
   - Tier card borders (`border-white/10`) -> `var(--border)`
   - Alternating row backgrounds (`bg-white/[0.015]`) -> `var(--glass)`
   - Table header background (`bg-white/[0.02]`) -> `var(--glass)`
   - Table cells (`text-zinc-300`, `text-zinc-400`) -> semantic vars
   - `text-white` headings -> `var(--text-primary)`
   - Hero mesh overlay gradients -> `var(--surface)` based
   - Product Hunt badge -> `border-white/10` -> `var(--border)`, `bg-white/[0.03]` -> `var(--glass)`
4. Keep the Stripe buy links unchanged (external links, not theme-sensitive).

- [ ] **Step 2: Update get-started/+page.svelte**

Same nav/footer update. Replace theme-sensitive content colors.

- [ ] **Step 3: Update contact/+page.svelte**

Same nav/footer update. Replace theme-sensitive content colors.

- [ ] **Step 4: Run svelte-check**

```bash
cd site && npm run check
```
Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add site/src/routes/pricing/ site/src/routes/get-started/ site/src/routes/contact/
git commit -m "feat(site): migrate pricing, get-started, contact to semantic theme tokens"
```

---

### Task 8: Remaining Pages

**Files:**
- Modify: `site/src/routes/admissibility/+page.svelte`
- Modify: `site/src/routes/ops-chain/+page.svelte`
- Modify: `site/src/routes/github/+page.svelte`
- Modify: `site/src/routes/solutions/+page.svelte`
- Modify: `site/src/routes/solutions/government/+page.svelte`
- Modify: `site/src/routes/solutions/healthcare/+page.svelte`
- Modify: `site/src/routes/solutions/finance/+page.svelte`
- Modify: `site/src/routes/privacy/+page.svelte`
- Modify: `site/src/routes/terms/+page.svelte`
- Modify: `site/src/routes/security/+page.svelte`
- Modify: `site/src/routes/acceptable-use/+page.svelte`

- [ ] **Step 1: Update admissibility/+page.svelte**

This is 678 lines with its own nav. Update with the same pattern. The certification generator, chain explorer, and framework tabs are handled in Task 5.

- [ ] **Step 2: Update ops-chain/+page.svelte**

144 lines. Update nav (if it has one) and content colors.

- [ ] **Step 3: Update github/+page.svelte**

32 lines. Likely a redirect or minimal page. Update any theme colors.

- [ ] **Step 4: Update solutions pages**

`solutions/+page.svelte` (80 lines) and the three verticals (government, healthcare, finance, ~72 lines each). These are likely wrapped by a layout or standalone. Update theme colors.

- [ ] **Step 5: Update legal pages**

The four legal pages (`privacy/`, `terms/`, `security/`, `acceptable-use/`) use the `LegalDocument` component (updated in Task 5). Check if they have any additional hardcoded colors of their own. They likely just pass `raw` markdown content to `LegalDocument`, so they may need no changes. Verify by reading each file.

- [ ] **Step 6: Run svelte-check**

```bash
cd site && npm run check
```
Expected: No errors.

- [ ] **Step 7: Commit**

```bash
git add site/src/routes/admissibility/ site/src/routes/ops-chain/ site/src/routes/github/ site/src/routes/solutions/ site/src/routes/privacy/ site/src/routes/terms/ site/src/routes/security/ site/src/routes/acceptable-use/
git commit -m "feat(site): migrate remaining pages to semantic theme tokens"
```

---

### Task 9: Visual Verification + Final Check

**Files:** None new. Verification only.

- [ ] **Step 1: Start dev server and test dark mode**

```bash
cd site && npm run dev
```

Open browser. With dark mode active (default or via toggle), verify every page looks identical to before the migration:
- Homepage (all sections)
- Pricing
- Blog index + one blog post
- One legal page (terms or privacy)
- Admissibility
- Contact

- [ ] **Step 2: Test day mode**

Toggle to day mode. Verify:
- Background is peachy lilac (#f0e6ef), not white
- Text is deep navy, not black
- Nav and footer backgrounds are lilac-tinted with blur
- Logo swaps to the black-text transparent variant
- Terminal blocks and code embeds remain dark
- Brand red, cyan, purple accents are visible and readable
- Glass panels have the correct tinted appearance
- The comparison table on pricing is readable
- Blog post content is readable
- Legal content is readable

- [ ] **Step 3: Test OS preference detection**

1. Clear localStorage (`localStorage.removeItem('vindicara-theme')`)
2. Set macOS to light appearance
3. Hard-reload the page
4. Verify: day mode loads without flash
5. Set macOS to dark appearance
6. Hard-reload
7. Verify: dark mode loads without flash

- [ ] **Step 4: Test localStorage persistence**

1. Toggle to day mode
2. Navigate to a different page
3. Verify: day mode persists
4. Hard-reload
5. Verify: day mode persists (no flash)

- [ ] **Step 5: Test mobile nav**

Open in responsive mode (375px width). Verify:
- Hamburger menu works
- Theme toggle appears in mobile menu
- Colors are correct in both modes

- [ ] **Step 6: Run full check and build**

```bash
cd site && npm run check && npm run build
```
Expected: Both pass with no errors.

- [ ] **Step 7: Commit any fixes**

If any visual issues were found and fixed during verification:
```bash
git add -A site/src/
git commit -m "fix(site): polish day mode visual issues found during verification"
```

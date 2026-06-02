# Site Day Mode (Light Theme) Design

**Date:** 2026-05-21
**Surface:** `site/` (marketing site only)
**Status:** Approved

## Summary

Add a day mode (light theme) to the Vindicara marketing site. The light palette is peachy lilac, not white. The tactical aesthetic stays: sharp corners, monospace data labels, glass panels, same brand accents. Terminal and code blocks remain dark in both modes. Theme respects OS `prefers-color-scheme` on first visit, persists user choice in `localStorage`, and toggles via a sun/moon icon in the nav bar.

## Color System

All theme-sensitive colors are expressed as CSS custom properties. Dark mode is the default. Day mode overrides are applied via `data-theme="light"` on `<html>`.

### Semantic Tokens

| Token | Dark | Day |
|---|---|---|
| `--color-surface` | `#0a0a0f` | `#f0e6ef` |
| `--color-surface-raised` | `#12121a` | `#e8dce7` |
| `--color-surface-overlay` | `#1a1a2e` | `#dfd1de` |
| `--color-text-primary` | `#ffffff` | `#1a1a2e` |
| `--color-text-secondary` | `#a1a1aa` | `#4a3f52` |
| `--color-text-muted` | `#71717a` | `#7a6d82` |
| `--color-text-faint` | `#52525b` | `#9e8fa6` |
| `--color-border` | `rgba(255,255,255,0.1)` | `rgba(26,26,46,0.12)` |
| `--color-border-subtle` | `rgba(255,255,255,0.05)` | `rgba(26,26,46,0.06)` |
| `--color-glass` | `rgba(255,255,255,0.05)` | `rgba(26,26,46,0.04)` |
| `--color-glass-border` | `rgba(255,255,255,0.1)` | `rgba(26,26,46,0.08)` |

### Unchanged Tokens

Brand accents stay the same in both modes:

- `--color-brand-red: #dc2626`
- `--color-brand-red-dark: #991b1b`
- `--color-brand-cyan: #06b6d4`
- `--color-brand-purple: #8b5cf6`
- `--color-brand-pink: #ec4899`

### Gradient Tokens

Day mode gradients use the day surface color in place of obsidian. Gradient overlays on `hero-mesh.png` and section backgrounds use `var(--color-surface)` with opacity stops.

### Selection Color

Dark mode: red background, white text (unchanged).
Day mode: red background, white text (unchanged; brand red works on both grounds).

## Theme Infrastructure

### CSS (`app.css`)

The `@theme` block keeps the static brand tokens. Semantic tokens are defined in `:root` (dark defaults) and overridden in `:root[data-theme="light"]`. Tailwind 4 `@theme` values that reference the semantic vars work in both modes.

```
:root {
  --color-surface: #0a0a0f;
  --color-surface-raised: #12121a;
  /* ... all dark defaults */
}

:root[data-theme="light"] {
  --color-surface: #f0e6ef;
  --color-surface-raised: #e8dce7;
  /* ... all day overrides */
}
```

Component classes (`.glass-panel`, `.btn-primary`, `.btn-secondary`, `.code-block`, `.glow-red`, `.glow-cyan`) are updated to reference semantic tokens where they currently use hardcoded obsidian/white values.

The `.text-gradient-subtle` class needs a day variant: dark mode stays white-to-zinc, day mode uses navy-to-plum gradient.

### Theme Store (`site/src/lib/theme.ts`)

Svelte 5 runes-based store:
- On init: check `localStorage` for saved preference, fall back to `prefers-color-scheme` media query, fall back to `"dark"`.
- Exports reactive `theme` value (`"dark"` | `"light"`) and `toggleTheme()` function.
- On change: sets `data-theme` attribute on `document.documentElement`, saves to `localStorage`, updates `<meta name="theme-color">`.
- Listens for `prefers-color-scheme` changes (if no localStorage override exists, follows OS).

### Flash Prevention (`+layout.svelte`)

Inline `<script>` in `<svelte:head>` (not `<script lang="ts">`) that runs before paint:
1. Read `localStorage` theme preference.
2. If none, read `prefers-color-scheme`.
3. Set `data-theme` on `<html>` immediately.

This prevents a flash of the wrong theme on page load. The Svelte store hydrates from the same source and stays in sync.

### Meta Theme Color

`<meta name="theme-color">` updates reactively:
- Dark: `#0a0a0f`
- Day: `#f0e6ef`

## Toggle Component

Sun/moon icon button in the nav bar, positioned right-side before the CTA buttons ("Get Started" / "Launch Dashboard"). Same icon appears in the mobile hamburger menu.

Design:
- No border, no background. Icon only.
- `text-muted` color, `hover:text-primary` transition.
- Smooth icon crossfade or morph on click.
- `aria-label="Toggle theme"` for accessibility.
- `title` attribute shows current state ("Switch to day mode" / "Switch to night mode").

## Logo Swap

Two logo files in `site/src/lib/assets/`:
- `vindicara-logo-transparent.png` (black text, transparent bg) for day mode.
- `vindicara-logo-dark-bg.png` (white text, dark bg) for night mode.

Source originals: `docs/vindicara-logo-transparent.png` and `docs/vindicara-logo-dark-bg.png`.

In the nav and footer, the logo `<img>` swaps `src` based on the theme store. The current `mix-blend-screen` class is removed.

## Page Migration

### Class Replacement Map

All `.svelte` files under `site/src/routes/` and `site/src/lib/components/` are updated:

| Hardcoded class | Semantic replacement |
|---|---|
| `bg-obsidian` | `bg-[var(--color-surface)]` |
| `bg-obsidian/60`, `bg-obsidian/90`, `bg-obsidian/95` | `bg-[var(--color-surface)]/60` etc. |
| `bg-obsidian-light` | `bg-[var(--color-surface-raised)]` |
| `bg-obsidian-lighter`, `bg-obsidian-lighter/40`, `bg-obsidian-lighter/50` | `bg-[var(--color-surface-overlay)]` with opacity |
| `text-white` (body text) | `text-[var(--color-text-primary)]` |
| `text-zinc-200`, `text-zinc-300` | `text-[var(--color-text-secondary)]` |
| `text-zinc-400` | `text-[var(--color-text-secondary)]` |
| `text-zinc-500` | `text-[var(--color-text-muted)]` |
| `text-zinc-600` | `text-[var(--color-text-faint)]` |
| `text-zinc-700` | `text-[var(--color-text-faint)]` |
| `border-white/5`, `border-white/10`, `border-white/20` | `border-[var(--color-border-subtle)]` / `border-[var(--color-border)]` |
| `bg-white/5`, `bg-white/[0.015]`, `bg-white/[0.03]` | `bg-[var(--color-glass)]` |
| `hover:bg-white/5`, `hover:bg-white/[0.06]` | `hover:bg-[var(--color-glass)]` |
| `from-obsidian`, `via-obsidian/*`, `to-obsidian/*` | Gradient using `var(--color-surface)` |

The semantic tokens are registered as named Tailwind colors in the `@theme` block so classes are clean (`bg-surface` not `bg-[var(--color-surface)]`). Tailwind 4's `@theme` block supports referencing CSS custom properties defined elsewhere in the stylesheet. The `@theme` entries point at the `:root` vars, which swap on `data-theme="light"`.

### Pages to Migrate

1. `+layout.svelte` (nav, meta)
2. `+page.svelte` (homepage, largest surface)
3. `pricing/+page.svelte`
4. `blog/+page.svelte` and `blog/+layout.svelte`
5. 8 individual blog post pages
6. `solutions/+page.svelte` and 3 vertical pages (government, healthcare, finance)
7. `admissibility/+page.svelte`
8. `contact/+page.svelte`
9. `get-started/+page.svelte`
10. `ops-chain/+page.svelte`
11. `github/+page.svelte`
12. Legal pages: `privacy/`, `terms/`, `security/`, `acceptable-use/`
13. Shared components: `LegalDocument.svelte`, `ShareButtons.svelte`, `AsciinemaEmbed.svelte`, admissibility components

### Exceptions (Stay Dark in Both Modes)

These elements keep their hardcoded dark styling regardless of theme:

- Hero terminal animation block (the animated `air trace` output)
- Asciinema embed and its container
- Code snippet blocks inside "How It Works" cards (the `pip install` / `from airsdk` blocks)
- Structural Verification terminal block
- The live API demo result panels (guard + MCP scanner output areas)
- Any `code-block` class element

These are wrapped in a container that forces dark styling, preventing the theme vars from applying.

## Scope Boundaries

**In scope:** All files under `site/src/`. Logo assets. CSS custom properties. Theme store. Toggle component. Page-by-page class migration.

**Out of scope:**
- `packages/air-dashboard/` (already has its own light scheme)
- `src/vindicara/dashboard/` (legacy SSR dashboard)
- `packages/projectair/` (CLI/SDK, no UI)
- OG images and social cards (stay dark-branded)
- `hero-mesh.png` (single asset, opacity-adjusted per theme; no second image needed)

## Testing

- Manual browser test in both modes on homepage, pricing, blog index, one blog post, one solutions page, one legal page.
- Verify no flash of wrong theme on hard reload.
- Verify `prefers-color-scheme` detection works on first visit.
- Verify localStorage persistence survives page navigation and browser restart.
- Verify terminal/code blocks stay dark in day mode.
- Verify logo swap is correct in both modes.
- Run `npm run check` (svelte-check) to catch type errors.
- Visual spot-check on mobile viewport (nav toggle, mobile menu).

<script lang="ts">
  import { goto } from '$app/navigation';

  // The four APPM function pages, as a dictionary-style thumb index.
  let { active }: { active: 'audit' | 'prove' | 'protect' | 'monitor' } = $props();

  const tabs = [
    { key: 'audit', letter: 'A', label: 'Audit', href: '/audit', accent: 'var(--amber)' },
    { key: 'prove', letter: 'P', label: 'Prove', href: '/prove', accent: 'var(--violet)' },
    { key: 'protect', letter: 'P', label: 'Protect', href: '/protect', accent: 'var(--air)' },
    { key: 'monitor', letter: 'M', label: 'Monitor', href: '/monitor', accent: 'var(--emerald)' }
  ] as const;
</script>

<nav class="book-rail" aria-label="Functions">
  {#each tabs as t}
    <button
      class="book-tab"
      class:on={t.key === active}
      style="--tab-accent:{t.accent}"
      type="button"
      aria-current={t.key === active ? 'page' : undefined}
      aria-label={t.label}
      title={t.label}
      onclick={() => goto(t.href)}
    >
      {t.letter}
    </button>
  {/each}
</nav>

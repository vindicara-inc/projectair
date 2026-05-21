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

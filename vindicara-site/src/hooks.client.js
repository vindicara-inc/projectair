// Stale-chunk recovery.
//
// After a deploy, a visitor (or a CDN edge) may still hold a cached index.html that
// references a hashed JS chunk the new deploy has removed. The dynamic import then
// fails with "Failed to fetch dynamically imported module" and the app renders as
// unstyled, non-hydrated HTML. This reloads once to pull the fresh HTML.
//
// A short-lived sessionStorage guard prevents a reload loop if the chunk is genuinely
// gone (which should not happen once CloudFront keeps prior asset hashes for a deploy).

const GUARD_KEY = 'air:chunk-reload-at';
const GUARD_WINDOW_MS = 15000;

function reloadOnce() {
  try {
    const last = Number(sessionStorage.getItem(GUARD_KEY) || 0);
    if (Date.now() - last < GUARD_WINDOW_MS) return;
    sessionStorage.setItem(GUARD_KEY, String(Date.now()));
  } catch {
    // sessionStorage unavailable: fall through and reload anyway.
  }
  location.reload();
}

if (typeof window !== 'undefined') {
  // Vite fires this when a dynamic-import preload fails (the common stale-chunk case).
  window.addEventListener('vite:preloadError', (event) => {
    event.preventDefault();
    reloadOnce();
  });
}

/** @param {{ error: unknown }} input */
export function handleError({ error }) {
  const message = error instanceof Error ? error.message : String(error);
  if (/failed to fetch dynamically imported module|error loading dynamically imported module/i.test(message)) {
    reloadOnce();
  }
}

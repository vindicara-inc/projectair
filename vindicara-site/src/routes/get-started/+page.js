// Public page: prerendered so the install counter is baked at build time and the
// SSR server never hits pypistats per request. The rest of the site is SSR.
export const prerender = true;

// Bake the live PyPI install count into the page at build time (refreshes each
// deploy). pypistats has no browser CORS, so we fetch it during prerender.
// If pypistats is unreachable at build, fall back to the last-known 30-day count
// so the counter never silently disappears.
const FALLBACK_INSTALLS_MONTH = 380;

export async function load({ fetch }) {
  try {
    const res = await fetch('https://pypistats.org/api/packages/projectair/recent');
    if (res.ok) {
      const j = await res.json();
      const n = j?.data?.last_month;
      if (typeof n === 'number' && n > 0) return { installsMonth: n };
    }
  } catch (_) {
    /* fall through to the last-known value */
  }
  return { installsMonth: FALLBACK_INSTALLS_MONTH };
}

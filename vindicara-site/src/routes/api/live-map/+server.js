// Live map data, keyless. Real visitor locations come from the in-memory
// visitor store (server-side offline IP lookup, no Google, no API key), plus the
// real PyPI install count. Fails soft: empty map + count if anything is missing.
import { json } from '@sveltejs/kit';
import { snapshot } from '$lib/server/visitors.js';
import { INSTALLERS, INSTALLER_MAX } from '$lib/server/installs.js';

export const prerender = false;

/** @param {typeof globalThis.fetch} fetch */
async function installsMonth(fetch) {
  try {
    const res = await fetch('https://pypistats.org/api/packages/projectair/recent');
    if (res.ok) {
      const j = await res.json();
      const n = j?.data?.last_month;
      if (typeof n === 'number' && n > 0) return n;
    }
  } catch (_) { /* fall through */ }
  return null;
}

export async function GET({ fetch, setHeaders }) {
  setHeaders({ 'cache-control': 'public, max-age=30' });
  /** @type {{ active: any[], footprint: any[], mode: string }} */
  let map = { active: [], footprint: [], mode: 'visitors' };
  try { map = snapshot(); } catch (e) { map = { active: [], footprint: [], mode: 'error' }; }
  const installs = await installsMonth(fetch);
  return json({ ...map, installers: INSTALLERS, installerMax: INSTALLER_MAX, installsMonth: installs });
}

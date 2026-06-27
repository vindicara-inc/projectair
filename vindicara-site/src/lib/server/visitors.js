// Keyless live-map data source. The server tags each real visitor with an
// approximate location using an OFFLINE IP database (geoip-lite: bundled data,
// no API, no key, no Google). We keep a short rolling list in memory and serve
// aggregated points to the map. In-memory, so it resets on restart and is
// per-process; add a store later if cross-restart history is wanted.

const MAX = 8000;                 // cap entries to bound memory
const DAY = 86400000;
const ACTIVE_MS = 30 * 60 * 1000; // "active now" = last 30 minutes
const FOOTPRINT_MS = 30 * DAY;    // footprint = last 30 days

/** @type {{lat:number,lon:number,city:string,country:string,t:number}[]} */
const hits = [];

// Real recent visitor cities transcribed from GA4 (last 28 days) so the footprint
// reflects true geography from day one. Seeded an hour back so they read as
// footprint (white), not active (red). Live server tally adds real hits on top;
// these age out of the 30-day window as genuine traffic accumulates.
const SEED = [
  ['Singapore', 103.82, 1.35], ['Los Angeles', -118.24, 34.05], ['Dublin', -6.26, 53.35],
  ['Haikou', 110.33, 20.03], ['Nanning', 108.32, 22.82], ['Pune', 73.86, 18.52],
  ['San Jose', -121.89, 37.34]
];
for (const [city, lon, lat] of SEED) hits.push({ lat, lon, city, country: '', t: Date.now() - 3600000 });

let geoip = null;
let loaded = false;
async function getGeo() {
  if (!loaded) {
    loaded = true;
    try { geoip = (await import('geoip-lite')).default; }
    catch (_) { geoip = null; } // lib not installed -> map stays empty, page fine
  }
  return geoip;
}

function clientIp(event) {
  const xff = event.request.headers.get('x-forwarded-for');
  if (xff) return xff.split(',')[0].trim();
  try { return event.getClientAddress(); } catch (_) { return null; }
}

function isPrivate(ip) {
  return !ip || ip === '::1' || ip.startsWith('127.') || ip.startsWith('10.') ||
    ip.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

/** Record a real page visit. Fire-and-forget; never throws into the request. */
export async function recordVisit(event) {
  try {
    const url = event.url;
    const path = url.pathname;
    if (path.startsWith('/api') || path.startsWith('/_app') || path.includes('.')) return;
    const accept = event.request.headers.get('accept') || '';
    if (!accept.includes('text/html')) return;
    const ip = clientIp(event);
    if (isPrivate(ip)) return;
    const g = await getGeo();
    if (!g) return;
    const r = g.lookup(ip);
    if (!r || !r.ll) return;
    hits.push({ lat: r.ll[0], lon: r.ll[1], city: r.city || '', country: r.country || '', t: Date.now() });
    if (hits.length > MAX) hits.splice(0, hits.length - MAX);
  } catch (_) { /* never break a page render over analytics */ }
}

function aggregate(sinceMs) {
  const cut = Date.now() - sinceMs;
  const buckets = new Map();
  for (const h of hits) {
    if (h.t < cut) continue;
    const key = `${h.lat.toFixed(1)},${h.lon.toFixed(1)}`;
    const b = buckets.get(key);
    if (b) b.users++;
    else buckets.set(key, { lon: h.lon, lat: h.lat, city: h.city, users: 1 });
  }
  return [...buckets.values()];
}

/** Points for the map. */
export function snapshot() {
  // prune anything older than the footprint window
  const cut = Date.now() - FOOTPRINT_MS;
  while (hits.length && hits[0].t < cut) hits.shift();
  return { active: aggregate(ACTIVE_MS), footprint: aggregate(FOOTPRINT_MS), mode: 'visitors' };
}

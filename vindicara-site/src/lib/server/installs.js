// Real PyPI installs by country (last 30 days), from the public PyPI BigQuery
// dataset. Refresh by re-running the query in BigQuery and updating this list.
// Each entry: [country_code, lon, lat (centroid), installs]. Snapshot: 2026-06-27.
/** @type {[string, number, number, number][]} */
const ROWS = [
  ['US', -98.5, 39.8, 914], ['JP', 138.3, 36.2, 107], ['DE', 10.5, 51.2, 103],
  ['CN', 104.2, 35.9, 96], ['SG', 103.82, 1.35, 79], ['FR', 2.2, 46.6, 69],
  ['HK', 114.17, 22.32, 58], ['GB', -1.5, 52.4, 54], ['KR', 127.8, 35.9, 22],
  ['IL', 34.9, 31.0, 14], ['SE', 18.6, 60.1, 14], ['FI', 25.7, 61.9, 14],
  ['NL', 5.3, 52.1, 13], ['RU', 37.6, 55.7, 12], ['CA', -106.3, 56.1, 11],
  ['DK', 9.5, 56.3, 8], ['NO', 9.0, 61.0, 6], ['IE', -8.2, 53.4, 5],
  ['MD', 28.5, 47.4, 4], ['ES', -3.7, 40.5, 4], ['IN', 78.9, 22.6, 3],
  ['CL', -71.5, -35.7, 2], ['AU', 134.0, -25.3, 2], ['NP', 84.1, 28.4, 2],
  ['IT', 12.6, 41.9, 1], ['TW', 121.0, 23.7, 1], ['AD', 1.6, 42.5, 1],
  ['VG', -64.6, 18.4, 1], ['VN', 106.0, 16.0, 1], ['TH', 100.99, 15.9, 1]
];

export const INSTALLERS = ROWS.map(([code, lon, lat, installs]) => ({ code, lon, lat, installs }));
export const INSTALLER_TOTAL = ROWS.reduce((s, r) => s + r[3], 0);
export const INSTALLER_MAX = Math.max(...ROWS.map((r) => r[3]));

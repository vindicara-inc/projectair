// Server-only lookup: GA4 returns city + country names, not coordinates.
// Map the common ones to [lon, lat]; fall back to a country centroid; else null.
// Expand CITIES as real traffic surfaces new places (the endpoint logs misses).

/** @type {Record<string, number[]>} */
const CITIES = {
  // North America
  'new york': [-74.0, 40.71], 'san francisco': [-122.42, 37.77], 'los angeles': [-118.24, 34.05],
  'chicago': [-87.63, 41.88], 'seattle': [-122.33, 47.61], 'austin': [-97.74, 30.27],
  'boston': [-71.06, 42.36], 'miami': [-80.19, 25.76], 'toronto': [-79.38, 43.65],
  'vancouver': [-123.12, 49.28], 'montreal': [-73.57, 45.5], 'washington': [-77.04, 38.9],
  'atlanta': [-84.39, 33.75], 'denver': [-104.99, 39.74], 'dallas': [-96.8, 32.78],
  'houston': [-95.37, 29.76], 'san jose': [-121.89, 37.34], 'portland': [-122.68, 45.52],
  'phoenix': [-112.07, 33.45], 'mexico city': [-99.13, 19.43], 'guadalajara': [-103.35, 20.66],
  // South America
  'sao paulo': [-46.63, -23.55], 'rio de janeiro': [-43.2, -22.91], 'buenos aires': [-58.38, -34.6],
  'bogota': [-74.07, 4.71], 'lima': [-77.04, -12.05], 'santiago': [-70.65, -33.46],
  // Europe
  'london': [-0.13, 51.51], 'paris': [2.35, 48.85], 'amsterdam': [4.9, 52.37],
  'berlin': [13.4, 52.52], 'munich': [11.58, 48.14], 'frankfurt': [8.68, 50.11],
  'stockholm': [18.07, 59.33], 'madrid': [-3.7, 40.42], 'barcelona': [2.17, 41.39],
  'milan': [9.19, 45.46], 'rome': [12.5, 41.9], 'dublin': [-6.26, 53.35],
  'zurich': [8.54, 47.37], 'warsaw': [21.01, 52.23], 'lisbon': [-9.14, 38.72],
  'copenhagen': [12.57, 55.68], 'oslo': [10.75, 59.91], 'helsinki': [24.94, 60.17],
  'vienna': [16.37, 48.21], 'prague': [14.42, 50.08], 'brussels': [4.35, 50.85],
  'manchester': [-2.24, 53.48], 'edinburgh': [-3.19, 55.95], 'kyiv': [30.52, 50.45],
  'bucharest': [26.1, 44.43], 'athens': [23.73, 37.98], 'istanbul': [28.98, 41.01],
  // Middle East / Africa
  'dubai': [55.27, 25.2], 'tel aviv': [34.78, 32.08], 'riyadh': [46.68, 24.71],
  'cairo': [31.24, 30.04], 'lagos': [3.38, 6.52], 'nairobi': [36.82, -1.29],
  'johannesburg': [28.05, -26.2], 'cape town': [18.42, -33.92], 'casablanca': [-7.59, 33.57],
  // Asia / Oceania
  'mumbai': [72.88, 19.08], 'bangalore': [77.59, 12.97], 'bengaluru': [77.59, 12.97],
  'delhi': [77.21, 28.61], 'new delhi': [77.21, 28.61], 'hyderabad': [78.49, 17.39],
  'chennai': [80.27, 13.08], 'pune': [73.86, 18.52], 'singapore': [103.82, 1.35],
  'hong kong': [114.17, 22.32], 'shanghai': [121.47, 31.23], 'beijing': [116.41, 39.9],
  'shenzhen': [114.06, 22.54], 'seoul': [126.98, 37.57], 'tokyo': [139.69, 35.68],
  'osaka': [135.5, 34.69], 'bangkok': [100.5, 13.76], 'jakarta': [106.85, -6.21],
  'manila': [120.98, 14.6], 'kuala lumpur': [101.69, 3.14], 'ho chi minh city': [106.66, 10.82],
  'taipei': [121.56, 25.03], 'sydney': [151.21, -33.87], 'melbourne': [144.96, -37.81],
  'brisbane': [153.03, -27.47], 'auckland': [174.76, -36.85]
};

/** @type {Record<string, number[]>} */
const COUNTRIES = {
  'united states': [-98.5, 39.8], 'canada': [-106.3, 56.1], 'mexico': [-102.5, 23.6],
  'brazil': [-51.9, -14.2], 'argentina': [-63.6, -38.4], 'chile': [-71.5, -35.7],
  'colombia': [-74.3, 4.6], 'peru': [-75.0, -9.2], 'united kingdom': [-1.5, 52.4],
  'ireland': [-8.2, 53.4], 'france': [2.2, 46.6], 'germany': [10.5, 51.2],
  'netherlands': [5.3, 52.1], 'spain': [-3.7, 40.5], 'portugal': [-8.2, 39.6],
  'italy': [12.6, 41.9], 'switzerland': [8.2, 46.8], 'austria': [14.6, 47.7],
  'belgium': [4.5, 50.6], 'sweden': [18.6, 60.1], 'norway': [8.5, 60.5],
  'denmark': [9.5, 56.3], 'finland': [25.7, 61.9], 'poland': [19.1, 51.9],
  'czechia': [15.5, 49.8], 'romania': [24.9, 45.9], 'greece': [21.8, 39.1],
  'ukraine': [31.2, 48.4], 'turkey': [35.2, 39.0], 'russia': [105.3, 61.5],
  'india': [78.9, 20.6], 'china': [104.2, 35.9], 'japan': [138.3, 36.2],
  'south korea': [127.8, 35.9], 'singapore': [103.82, 1.35], 'indonesia': [113.9, -0.8],
  'thailand': [100.99, 15.9], 'vietnam': [108.3, 14.1], 'philippines': [121.8, 12.9],
  'malaysia': [101.98, 4.2], 'taiwan': [121.0, 23.7], 'australia': [133.8, -25.3],
  'new zealand': [174.9, -40.9], 'united arab emirates': [53.8, 23.4], 'israel': [34.9, 31.0],
  'saudi arabia': [45.1, 23.9], 'egypt': [30.8, 26.8], 'nigeria': [8.7, 9.1],
  'kenya': [37.9, -0.0], 'south africa': [22.9, -30.6], 'morocco': [-7.1, 31.8]
};

/**
 * Resolve a GA4 city/country to [lon, lat], or null if unknown.
 * @param {string|null|undefined} city
 * @param {string|null|undefined} country
 */
export function resolveCoords(city, country) {
  const c = (city || '').trim().toLowerCase();
  if (c && CITIES[c]) return CITIES[c];
  const k = (country || '').trim().toLowerCase();
  if (k && COUNTRIES[k]) return COUNTRIES[k];
  return null;
}

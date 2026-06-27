// Security headers carried by the app itself, not a CloudFront edge — so the
// same container is secure behind our ALB AND when a customer self-hosts it in
// their own / air-gapped network (where there is no CloudFront). Mirrors the
// previous CloudFront ResponseHeaders policy (site_stack.py).
//
// connect-src must list every host the console fetches at runtime (the API
// gateway + Auth0), or the CSP silently blocks it. AIR_API_ORIGIN is injected
// by the Fargate task; it falls back to the current production API.

import { recordVisit } from '$lib/server/visitors.js';

const API_ORIGIN = process.env.AIR_API_ORIGIN || 'https://qk0ymrk5be.execute-api.us-west-2.amazonaws.com';
const AUTH0_ORIGIN = 'https://dev-kilt2vkudvbu75ny.us.auth0.com';

// Google Analytics 4 via gtag.js (loaded in app.html). gtag.js is served from
// googletagmanager.com; GA4 then beacons measurement hits to google-analytics.com
// (regional subdomains like region1.google-analytics.com + analytics.google.com)
// over fetch (connect-src) with an img pixel fallback (img-src). All three
// directives must allow these hosts or the CSP silently drops analytics.
const GTM_ORIGIN = 'https://www.googletagmanager.com';
const GA_ORIGINS = 'https://www.google-analytics.com https://*.google-analytics.com https://*.analytics.google.com';

const CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  `img-src 'self' data: blob: ${GTM_ORIGIN} ${GA_ORIGINS}`,
  "font-src 'self' https://fonts.gstatic.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  `script-src 'self' 'unsafe-inline' ${GTM_ORIGIN}`,
  `connect-src 'self' ${API_ORIGIN} ${AUTH0_ORIGIN} ${GTM_ORIGIN} ${GA_ORIGINS}`,
  "form-action 'self'",
  'upgrade-insecure-requests'
].join('; ');

/** @type {import('@sveltejs/kit').Handle} */
export async function handle({ event, resolve }) {
  recordVisit(event); // keyless live-map: tag real visitors (fire-and-forget, never blocks)
  const response = await resolve(event);
  response.headers.set('Content-Security-Policy', CSP);
  response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  return response;
}

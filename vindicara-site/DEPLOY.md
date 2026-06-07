# Deploy hygiene for vindicara-site (S3 + CloudFront)

The two issues from the pressure test that must be fixed at deploy time, not in app code. The
SvelteKit `hooks.client.js` already added in this repo is the in-app half of fix 1; the rest is
infrastructure.

Replace `YOUR_BUCKET` and `YOUR_DISTRIBUTION_ID` below.

---

## 1. Stop the stale-chunk hydration crash

Root cause: a cached `index.html` (browser or CloudFront edge) points at a hashed JS chunk that a
newer deploy purged. The dynamic import fails and the page renders unstyled and un-hydrated.

Three rules:

**a. Cache HTML short, cache hashed assets forever.** Files under `_app/immutable/` carry content
hashes in their names, so they are safe to cache permanently. HTML must never be cached hard.

```bash
# 1) Immutable, content-hashed assets: long cache. No --delete, so old hashes survive a deploy.
aws s3 sync build/_app/ s3://YOUR_BUCKET/_app/ \
  --cache-control "public,max-age=31536000,immutable"

# 2) Everything else (HTML, favicon, etc.): no-cache so a new deploy is picked up immediately.
aws s3 sync build/ s3://YOUR_BUCKET/ --exclude "_app/*" \
  --cache-control "no-cache" --delete
```

**b. Keep previous asset hashes for at least one deploy.** Note the `_app/` sync above omits
`--delete` on purpose, so a visitor mid-session on the old HTML can still fetch the old chunk.
Prune stale assets on a slower cadence (for example weekly), never in the same step as a deploy.

**c. Invalidate the HTML on every deploy.**

```bash
aws cloudfront create-invalidation \
  --distribution-id YOUR_DISTRIBUTION_ID \
  --paths "/" "/*.html"
```

`hooks.client.js` is the safety net: if a stale chunk still slips through, the page reloads once to
pull fresh HTML instead of sitting there broken.

---

## 2. Security headers (CloudFront response-headers policy)

A security vendor with an F on securityheaders.io is a free screenshot for a skeptical reviewer.
Create a response-headers policy and attach it to the distribution behavior.

```bash
aws cloudfront create-response-headers-policy --response-headers-policy-config '{
  "Name": "vindicara-site-security",
  "SecurityHeadersConfig": {
    "StrictTransportSecurity": { "Override": true, "IncludeSubdomains": true, "Preload": true, "AccessControlMaxAgeSec": 63072000 },
    "ContentTypeOptions": { "Override": true },
    "FrameOptions": { "Override": true, "FrameOption": "DENY" },
    "ReferrerPolicy": { "Override": true, "ReferrerPolicy": "strict-origin-when-cross-origin" }
  },
  "CustomHeadersConfig": {
    "Items": [
      { "Header": "Permissions-Policy", "Value": "camera=(), microphone=(), geolocation=(), interest-cohort=()", "Override": true }
    ]
  }
}'
```

Then bind the returned policy id to the distribution's default cache behavior
(`ResponseHeadersPolicyId`) and deploy the distribution.

### Content-Security-Policy: set it in SvelteKit, not CloudFront

SvelteKit injects a small inline bootstrap script, so a hand-written CSP with `script-src 'self'`
will block hydration. Let SvelteKit hash its own inline code by configuring CSP in
`svelte.config.js` (it emits the policy as a `<meta>` tag on the prerendered pages):

```js
kit: {
  adapter: adapter({ fallback: 'index.html', strict: false }),
  alias: { $components: 'src/lib/components' },
  csp: {
    mode: 'auto',
    directives: {
      'default-src': ['self'],
      'script-src': ['self'],
      'style-src': ['self', 'unsafe-inline', 'https://fonts.googleapis.com'],
      'font-src': ['self', 'https://fonts.gstatic.com'],
      'img-src': ['self', 'data:'],
      'connect-src': ['self'],
      'base-uri': ['self'],
      'form-action': ['self'],
      'frame-ancestors': ['none']
    }
  }
}
```

The only external origins this site uses are Google Fonts (`fonts.googleapis.com` for the CSS,
`fonts.gstatic.com` for the files), which the directives above allow. There are no external API
calls in the redesign. Add `reportOnly` directives first and watch the console for one deploy
before enforcing, so you confirm nothing is blocked.

---

## Verify after deploy

1. Load the site in a fresh incognito window. It should render fully styled with no console errors.
2. `curl -sI https://vindicara.io/ | grep -i "strict-transport\|content-type-options\|frame-options"` returns the headers.
3. Run securityheaders.io and aim for A or better.
4. Hard-refresh and confirm `_app/immutable/*` come back `200` with a year-long `cache-control`, and the HTML comes back `no-cache`.

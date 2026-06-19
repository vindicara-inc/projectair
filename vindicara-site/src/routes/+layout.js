// Server-rendered app (adapter-node on ECS Fargate). Public routes render full
// HTML per request via SSR, so they stay indexable and always live. Keep ssr
// true: ssr=false once shipped empty JS shells and broke SEO. Per-route
// overrides: get-started prerenders (build-time install counter); the Flightdeck
// console is dynamic + client-rendered (see flightdeck/+layout.ts).
export const ssr = true;

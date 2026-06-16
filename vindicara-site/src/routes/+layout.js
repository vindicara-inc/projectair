// Prerendered static site: full HTML at build time for every marketing route.
// (ssr=false here previously caused every page to ship as an empty JS shell,
// which broke Google for Startups website verification and all SEO.)
export const prerender = true;

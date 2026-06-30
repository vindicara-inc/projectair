<script>
  import '$lib/styles/app.css';
  import { afterNavigate } from '$app/navigation';
  let { children } = $props();

  // GA4 key-event tracking. Fires `generate_lead` when a visitor reaches a
  // lead page, so conversions show up in GA4 (mark `generate_lead` as a Key
  // event in GA4 Admin). Page views are still auto-collected by gtag.
  /** @type {Record<string, string>} */
  const LEAD_PAGES = {
    '/contact': 'contact',
    '/design-partner': 'design_partner',
    '/get-started': 'get_started'
  };
  afterNavigate(({ to }) => {
    /** @type {any} */
    const w = typeof window !== 'undefined' ? window : null;
    if (!w || typeof w.gtag !== 'function') return;
    const path = to && to.url ? to.url.pathname : '';
    const label = LEAD_PAGES[path];
    if (label) {
      w.gtag('event', 'generate_lead', { lead_source: label, page_path: path });
    }
  });
</script>
{@render children()}

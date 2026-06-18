// Scroll-reveal helper for /solutions/* industry pages.
// Adds the `in` class to every `.rv` element as it scrolls into view,
// which drives both the fade-up and the section-numeral illumination.
// Call from a page's onMount. No-op (everything stays visible) when the
// user prefers reduced motion — industry.css shows `.rv` fully in that case.
export function setupReveal() {
  if (typeof window === 'undefined') return;
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
    }
  }, { threshold: 0.16 });
  document.querySelectorAll('.rv').forEach((el) => io.observe(el));
}

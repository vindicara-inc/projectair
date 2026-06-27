<script>
  // @ts-nocheck
  // Flat dotted world map with REAL live-visitor markers.
  // Base continents: precomputed land dot lattice (no runtime geoContains, which used
  // to freeze the page). White = recent visitor footprint (last 30 days, real GA4);
  // red = active right now (real GA4 realtime). Data from /api/live-map, polled live.
  import { onMount } from 'svelte';
  import { geoEquirectangular } from 'd3-geo';
  import { LAND_DOTS } from './landDots.js';

  let canvas;
  let footprint = []; // [{lon,lat,users}] visitors, last 30 days
  let active = [];    // [{lon,lat,users}] visitors, right now
  let installers = []; // [{lon,lat,installs}] real PyPI installs by country
  let imax = 1;
  let timer, raf;

  async function pull() {
    try {
      const r = await fetch('/api/live-map');
      if (!r.ok) return;
      const d = await r.json();
      footprint = Array.isArray(d.footprint) ? d.footprint : [];
      active = Array.isArray(d.active) ? d.active : [];
      installers = Array.isArray(d.installers) ? d.installers : [];
      imax = d.installerMax || 1;
    } catch (_) { /* keep last good data */ }
  }

  onMount(() => {
    const ctx = canvas.getContext('2d');
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const proj = geoEquirectangular();
    let W = 0, H = 0, dpr = 1, dots = [], rt;

    function build() {
      W = canvas.clientWidth || 800;
      H = canvas.clientHeight || 400;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = W * dpr; canvas.height = H * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const fitBox = { type: 'Polygon', coordinates: [[[-180, -56], [180, -56], [180, 80], [-180, 80], [-180, -56]]] };
      proj.fitSize([W, H], fitBox);
      // project the precomputed land lattice once (cheap; no geoContains)
      dots = [];
      for (const ll of LAND_DOTS) { const p = proj(ll); if (p) dots.push(p); }
    }
    build();
    let rz;
    const onResize = () => { clearTimeout(rz); rz = setTimeout(build, 150); };
    addEventListener('resize', onResize);

    function glow(x, y, rgb, pulse, scale) {
      const r = (8 + pulse * 6) * scale;
      const g = ctx.createRadialGradient(x, y, 0, x, y, r);
      g.addColorStop(0, `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${0.65 + pulse * 0.3})`);
      g.addColorStop(0.5, `rgba(${rgb[0]},${rgb[1]},${rgb[2]},${0.18 + pulse * 0.16})`);
      g.addColorStop(1, `rgba(${rgb[0]},${rgb[1]},${rgb[2]},0)`);
      ctx.fillStyle = g;
      ctx.beginPath(); ctx.arc(x, y, r, 0, 6.283); ctx.fill();
      ctx.fillStyle = `rgba(${rgb[0]},${rgb[1]},${rgb[2]},0.98)`;
      ctx.beginPath(); ctx.arc(x, y, 2.2 * scale, 0, 6.283); ctx.fill();
    }

    let t = 0;
    function render() {
      t += 0.016;
      ctx.clearRect(0, 0, W, H);
      ctx.globalCompositeOperation = 'lighter';
      const breathe = 0.72 + 0.12 * Math.sin(t * 1.2);
      ctx.fillStyle = `rgba(110,162,255,${breathe})`;
      for (let i = 0; i < dots.length; i++) { ctx.beginPath(); ctx.arc(dots[i][0], dots[i][1], 1.5, 0, 6.283); ctx.fill(); }

      // real PyPI installs by country (gold), sized by install volume
      for (const m of installers) {
        const p = proj([m.lon, m.lat]); if (!p) continue;
        const s = 0.75 + 1.5 * (Math.log(m.installs + 1) / Math.log(imax + 1));
        const pulse = reduce ? 0.5 : 0.42 + 0.18 * Math.sin(t * 1.1 + m.lon);
        glow(p[0], p[1], [255, 196, 92], pulse, s);
      }

      // recent visitor footprint (white), steady-ish
      for (const m of footprint) {
        const p = proj([m.lon, m.lat]); if (!p) continue;
        const pulse = reduce ? 0.6 : 0.4 + 0.2 * Math.sin(t * 1.4 + m.lon);
        glow(p[0], p[1], [205, 228, 255], pulse, 1);
      }
      // active right now (red), brighter pulse
      for (const m of active) {
        const p = proj([m.lon, m.lat]); if (!p) continue;
        const pulse = reduce ? 0.8 : 0.5 + 0.5 * Math.sin(t * 2.4 + m.lat);
        glow(p[0], p[1], [255, 92, 106], pulse, 1.25);
      }
      ctx.globalCompositeOperation = 'source-over';
      raf = requestAnimationFrame(render);
    }
    raf = requestAnimationFrame(render);

    pull();
    timer = setInterval(pull, 60000); // refresh real data every minute

    return () => {
      cancelAnimationFrame(raf);
      clearInterval(timer);
      removeEventListener('resize', onResize);
    };
  });
</script>

<div class="dotmap">
  <canvas bind:this={canvas}></canvas>
</div>

<style>
  .dotmap { position: relative; width: 100%; aspect-ratio: 2.65 / 1; background: transparent; overflow: visible; }
  .dotmap canvas { width: 100%; height: 100%; display: block; }
</style>

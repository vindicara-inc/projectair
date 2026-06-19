<script>
  // @ts-nocheck
  // Flat dotted world map with glowing live-visitor markers.
  // Base continents = blue dot lattice; Active users = white light, New users = red.
  // Reuses the d3-geo + world-atlas technique from the /intro globe, flat projection.
  import { onMount } from 'svelte';
  import { geoEquirectangular, geoContains } from 'd3-geo';
  import { feature } from 'topojson-client';
  import world from 'world-atlas/countries-110m.json';

  // Sample markers until GA realtime is wired in. type: 'active' | 'new'.
  const markers = [
    { lat: 40.71, lon: -74.0, type: 'active' },    // New York
    { lat: 37.77, lon: -122.42, type: 'new' },     // San Francisco
    { lat: 41.88, lon: -87.63, type: 'active' },   // Chicago
    { lat: 43.65, lon: -79.38, type: 'active' },   // Toronto
    { lat: 34.05, lon: -118.24, type: 'active' },  // Los Angeles
    { lat: 47.61, lon: -122.33, type: 'new' },     // Seattle
    { lat: 30.27, lon: -97.74, type: 'active' },   // Austin
    { lat: 42.36, lon: -71.06, type: 'active' },   // Boston
    { lat: 25.76, lon: -80.19, type: 'new' },      // Miami
    { lat: 19.43, lon: -99.13, type: 'active' },   // Mexico City
    { lat: -23.55, lon: -46.63, type: 'new' },     // Sao Paulo
    { lat: -34.60, lon: -58.38, type: 'active' },  // Buenos Aires
    { lat: 4.71, lon: -74.07, type: 'active' },    // Bogota
    { lat: 51.51, lon: -0.13, type: 'active' },    // London
    { lat: 48.85, lon: 2.35, type: 'active' },     // Paris
    { lat: 52.37, lon: 4.90, type: 'new' },        // Amsterdam
    { lat: 52.52, lon: 13.40, type: 'active' },    // Berlin
    { lat: 59.33, lon: 18.07, type: 'new' },       // Stockholm
    { lat: 40.42, lon: -3.70, type: 'active' },    // Madrid
    { lat: 45.46, lon: 9.19, type: 'active' },     // Milan
    { lat: 53.35, lon: -6.26, type: 'new' },       // Dublin
    { lat: 47.37, lon: 8.54, type: 'active' },     // Zurich
    { lat: 52.23, lon: 21.01, type: 'active' },    // Warsaw
    { lat: 25.20, lon: 55.27, type: 'active' },    // Dubai
    { lat: 32.08, lon: 34.78, type: 'active' },    // Tel Aviv
    { lat: 24.71, lon: 46.68, type: 'new' },       // Riyadh
    { lat: 30.04, lon: 31.24, type: 'active' },    // Cairo
    { lat: 6.52, lon: 3.38, type: 'new' },         // Lagos
    { lat: -1.29, lon: 36.82, type: 'active' },    // Nairobi
    { lat: -26.20, lon: 28.05, type: 'active' },   // Johannesburg
    { lat: 19.08, lon: 72.88, type: 'active' },    // Mumbai
    { lat: 12.97, lon: 77.59, type: 'new' },       // Bangalore
    { lat: 28.61, lon: 77.21, type: 'active' },    // Delhi
    { lat: 1.35, lon: 103.82, type: 'active' },    // Singapore
    { lat: 22.32, lon: 114.17, type: 'active' },   // Hong Kong
    { lat: 31.23, lon: 121.47, type: 'new' },      // Shanghai
    { lat: 37.57, lon: 126.98, type: 'active' },   // Seoul
    { lat: 35.68, lon: 139.69, type: 'active' },   // Tokyo
    { lat: 13.76, lon: 100.50, type: 'new' },      // Bangkok
    { lat: -6.21, lon: 106.85, type: 'active' },   // Jakarta
    { lat: -33.87, lon: 151.21, type: 'active' },  // Sydney
    { lat: -37.81, lon: 144.96, type: 'new' },     // Melbourne
    { lat: -36.85, lon: 174.76, type: 'active' }   // Auckland
  ];

  let canvas;

  onMount(() => {
    const ctx = canvas.getContext('2d');
    const land = feature(world, world.objects.countries);
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const proj = geoEquirectangular();

    let W = 0, H = 0, dpr = 1;
    let dots = [];

    function build() {
      W = canvas.clientWidth || 800;
      H = canvas.clientHeight || 400;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = W * dpr;
      canvas.height = H * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      // fit to the populated continent band (skip the empty Antarctica/polar gap)
      const fitBox = { type: 'Polygon', coordinates: [[[-180, -56], [180, -56], [180, 80], [-180, 80], [-180, -56]]] };
      proj.fitSize([W, H], fitBox);
      // land dot lattice
      dots = [];
      for (let lat = -56; lat <= 80; lat += 2.1) {
        for (let lon = -179; lon <= 179; lon += 2.1) {
          if (geoContains(land, [lon, lat])) {
            const p = proj([lon, lat]);
            if (p) dots.push(p);
          }
        }
      }
    }
    build();
    addEventListener('resize', build);

    let t = 0;
    function render() {
      t += 0.016;
      ctx.clearRect(0, 0, W, H);
      ctx.globalCompositeOperation = 'lighter';

      // base continents — all dots lit up (bright blue, gentle whole-map breathe)
      const breathe = 0.6 + 0.14 * Math.sin(t * 1.2);
      ctx.fillStyle = `rgba(96,150,255,${breathe})`;
      for (let i = 0; i < dots.length; i++) {
        ctx.beginPath();
        ctx.arc(dots[i][0], dots[i][1], 1.35, 0, 6.283);
        ctx.fill();
      }

      // live markers — bright glowing
      for (const m of markers) {
        const p = proj([m.lon, m.lat]);
        if (!p) continue;
        const [x, y] = p;
        const pulse = reduce ? 0.7 : 0.5 + 0.5 * Math.sin(t * 2 + (m.lon + m.lat));
        const c = m.type === 'new' ? [255, 92, 106] : [205, 228, 255];
        const r = 12 + pulse * 7;
        const g = ctx.createRadialGradient(x, y, 0, x, y, r);
        g.addColorStop(0, `rgba(${c[0]},${c[1]},${c[2]},${0.7 + pulse * 0.3})`);
        g.addColorStop(0.5, `rgba(${c[0]},${c[1]},${c[2]},${0.22 + pulse * 0.18})`);
        g.addColorStop(1, `rgba(${c[0]},${c[1]},${c[2]},0)`);
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(x, y, r, 0, 6.283); ctx.fill();
        ctx.fillStyle = m.type === 'new' ? 'rgba(255,205,210,0.98)' : 'rgba(255,255,255,1)';
        ctx.beginPath(); ctx.arc(x, y, 2.5, 0, 6.283); ctx.fill();
      }

      ctx.globalCompositeOperation = 'source-over';
      raf = requestAnimationFrame(render);
    }
    let raf = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(raf);
      removeEventListener('resize', build);
    };
  });
</script>

<div class="dotmap">
  <canvas bind:this={canvas}></canvas>
</div>

<style>
  .dotmap {
    position: relative;
    width: 100%;
    aspect-ratio: 2.65 / 1;
    background: transparent;
    overflow: visible;
  }
  .dotmap canvas { width: 100%; height: 100%; display: block; }
</style>

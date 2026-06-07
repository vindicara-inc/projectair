<script>
  import { onMount } from 'svelte';

  // Subtle Cowork-style starburst: slow constant spin, gentle lean toward the pointer.
  // Pure SVG + rAF, no deps. Rendered faint so it never competes with the headline.
  let group = $state(/** @type {SVGGElement | null} */ (null));
  let rays = $state(/** @type {Array<{ a: number, len: number, w: number, red: boolean }>} */ ([]));

  // build rays once (deterministic, so SSR and client match)
  const N = 60;
  for (let i = 0; i < N; i++) {
    const a = (i / N) * 360;
    const long = i % 5 === 0;
    const red = i % 15 === 0;
    rays.push({ a, len: long ? 230 : 150 + (i % 7) * 9, w: long ? 1.4 : 0.8, red });
  }

  onMount(() => {
    let raf = 0, spin = 0, tx = 0, ty = 0, cx = 0, cy = 0;
    /** @param {PointerEvent} e */
    const onMove = (e) => {
      const w = window.innerWidth, h = window.innerHeight;
      tx = ((e.clientX / w) - 0.5) * 14;   // max lean in degrees-ish
      ty = ((e.clientY / h) - 0.5) * -14;
    };
    window.addEventListener('pointermove', onMove);
    const loop = () => {
      spin += 0.04;                 // very slow constant rotation
      cx += (tx - cx) * 0.05;       // ease toward pointer lean
      cy += (ty - cy) * 0.05;
      if (group) group.setAttribute('transform', `rotate(${spin}) skewX(${cx*0.15}) skewY(${cy*0.15})`);
      raf = requestAnimationFrame(loop);
    };
    loop();
    return () => { cancelAnimationFrame(raf); window.removeEventListener('pointermove', onMove); };
  });
</script>

<svg class="mark" viewBox="-260 -260 520 520" aria-hidden="true">
  <g bind:this={group}>
    {#each rays as r}
      <line x1="0" y1="0" x2={r.len} y2="0" transform={`rotate(${r.a})`}
            stroke={r.red ? 'var(--air)' : 'rgba(255,255,255,.5)'} stroke-width={r.w} />
    {/each}
  </g>
</svg>

<style>
  .mark{position:absolute;width:760px;height:760px;left:50%;top:46%;transform:translate(-50%,-50%);
        opacity:.1;pointer-events:none;z-index:0;mix-blend-mode:screen}
  @media (max-width:700px){ .mark{width:520px;height:520px} }
</style>

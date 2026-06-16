<script lang="ts">
  import { onMount } from 'svelte';
  import { locked } from '$lib/console/stores/session';

  let host: HTMLDivElement;
  let canvas: HTMLCanvasElement;
  let isLocked = $state(false);
  $effect(() => { const u = locked.subscribe((v) => (isLocked = v)); return u; });

  onMount(() => {
    let raf = 0;
    let cleanup = () => {};
    (async () => {
      const THREE = await import('three');
      const W = host.clientWidth, H = host.clientHeight;
      const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      renderer.setSize(W, H, false);
      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(45, W / H, 0.1, 100);
      camera.position.set(0, 0, 5.7);
      const group = new THREE.Group();
      scene.add(group);

      // faint -> bright red shell, gradient by height
      const shellGeo = new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(1.0, 1));
      const sp = shellGeo.attributes.position, sN = sp.count;
      const sCol = new Float32Array(sN * 3);
      const faint = new THREE.Color(0x4a1217), bright = new THREE.Color(0xff6b74);
      let ymin = Infinity, ymax = -Infinity;
      for (let j = 0; j < sN; j++) { const y = sp.getY(j); if (y < ymin) ymin = y; if (y > ymax) ymax = y; }
      for (let j = 0; j < sN; j++) { const f = (sp.getY(j) - ymin) / ((ymax - ymin) || 1); const c = faint.clone().lerp(bright, f); sCol[j*3]=c.r; sCol[j*3+1]=c.g; sCol[j*3+2]=c.b; }
      shellGeo.setAttribute('color', new THREE.BufferAttribute(sCol, 3));
      const shell = new THREE.LineSegments(shellGeo, new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.85 }));
      group.add(shell);

      const core = new THREE.Mesh(new THREE.IcosahedronGeometry(0.44, 0), new THREE.MeshBasicMaterial({ color: 0xff5d68, transparent: true, opacity: 0.2 }));
      group.add(core);
      const coreWire = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(0.44, 0)), new THREE.LineBasicMaterial({ color: 0xffd0d4, transparent: true, opacity: 0.55 }));
      group.add(coreWire);

      const N = 420, pos = new Float32Array(N*3), col = new Float32Array(N*3);
      const cA = new THREE.Color(0x5a1820), cB = new THREE.Color(0xff6b74);
      for (let i = 0; i < N; i++) {
        const a = Math.random()*Math.PI*2, r = 1.4+Math.random()*0.5, y = (Math.random()-0.5)*0.4;
        pos[i*3]=Math.cos(a)*r; pos[i*3+1]=y; pos[i*3+2]=Math.sin(a)*r;
        const c = cA.clone().lerp(cB, Math.random()); col[i*3]=c.r; col[i*3+1]=c.g; col[i*3+2]=c.b;
      }
      const pg = new THREE.BufferGeometry();
      pg.setAttribute('position', new THREE.BufferAttribute(pos, 3));
      pg.setAttribute('color', new THREE.BufferAttribute(col, 3));
      const particles = new THREE.Points(pg, new THREE.PointsMaterial({ size: 0.04, vertexColors: true, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending, depthWrite: false }));
      scene.add(particles);

      let t = 0;
      const loop = () => {
        if (!isLocked) {
          t += 0.01;
          group.rotation.x = t*0.35; group.rotation.y = t*0.55;
          const s = 1 + Math.sin(t*1.6)*0.06; core.scale.setScalar(s); coreWire.scale.setScalar(s);
          particles.rotation.y = -t*0.25; particles.rotation.x = 0.35;
        }
        renderer.render(scene, camera);
        raf = requestAnimationFrame(loop);
      };
      loop();

      const onResize = () => {
        const w = host.clientWidth, h = host.clientHeight;
        camera.aspect = w / h; camera.updateProjectionMatrix(); renderer.setSize(w, h, false);
      };
      window.addEventListener('resize', onResize);
      cleanup = () => { cancelAnimationFrame(raf); window.removeEventListener('resize', onResize); renderer.dispose(); };
    })();
    return () => cleanup();
  });
</script>

<div class="core" bind:this={host}>
  <canvas bind:this={canvas}></canvas>
  <div class="corecap">signed · anchored · <b>AIR</b></div>
</div>

<style>
  .core { flex: 1; position: relative; min-height: 150px; border-bottom: 1px solid var(--hair); }
  canvas { position: absolute; inset: 0; }
  .corecap { position: absolute; left: 0; right: 0; bottom: 10px; text-align: center; font-family: var(--mono); font-size: 9.5px; letter-spacing: .2em; text-transform: uppercase; color: var(--faint); z-index: 4; }
  .corecap b { color: var(--air2); }
</style>

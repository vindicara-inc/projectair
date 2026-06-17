<script lang="ts">
  import { onMount } from 'svelte';

  let host: HTMLDivElement;

  onMount(() => {
    let raf = 0;
    let cleanup = () => {};

    (async () => {
      const THREE = await import('three');
      const { EffectComposer } = await import('three/examples/jsm/postprocessing/EffectComposer.js');
      const { RenderPass } = await import('three/examples/jsm/postprocessing/RenderPass.js');
      const { UnrealBloomPass } = await import('three/examples/jsm/postprocessing/UnrealBloomPass.js');
      const { OutputPass } = await import('three/examples/jsm/postprocessing/OutputPass.js');

      const readSize = () => ({
        W: host?.clientWidth ?? 0,
        H: host?.clientHeight ?? 0
      });
      let { W, H } = readSize();
      for (let i = 0; i < 30 && (W < 40 || H < 40); i++) {
        await new Promise((r) => requestAnimationFrame(r));
        ({ W, H } = readSize());
      }
      if (W < 40) W = 640;
      if (H < 40) H = 400;

      const scene = new THREE.Scene();
      const camera = new THREE.PerspectiveCamera(40, W / H, 0.1, 100);
      camera.position.set(0, 0, 3.35);
      camera.lookAt(0, 0, 0);

      const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
      renderer.setClearColor(0x000000, 0);
      renderer.setSize(W, H);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      renderer.toneMapping = THREE.ACESFilmicToneMapping;
      renderer.toneMappingExposure = 1.1;
      if (!host) return;
      host.appendChild(renderer.domElement);

      const composer = new EffectComposer(renderer);
      composer.addPass(new RenderPass(scene, camera));
      // Higher threshold + lower strength stops continent dots popping in/out of bloom.
      const bloom = new UnrealBloomPass(new THREE.Vector2(W, H), 0.28, 0.45, 0.28);
      composer.addPass(bloom);
      composer.addPass(new OutputPass());

      const spin = new THREE.Group();
      spin.scale.setScalar(0.82);
      scene.add(spin);

      const cv = document.createElement('canvas');
      cv.width = cv.height = 32;
      const g = cv.getContext('2d')!;
      const rg = g.createRadialGradient(16, 16, 0, 16, 16, 16);
      rg.addColorStop(0, 'rgba(255,255,255,1)');
      rg.addColorStop(1, 'rgba(255,255,255,0)');
      g.fillStyle = rg;
      g.fillRect(0, 0, 32, 32);
      const sprite = new THREE.CanvasTexture(cv);

      const palette = {
        coral: 0xff6b6b,
        amber: 0xffb84d,
        mint: 0x4ade80,
        sky: 0x38bdf8,
        violet: 0xa78bfa,
        rose: 0xf472b6,
        gold: 0xfbbf24,
        teal: 0x2dd4bf,
        halt: 0xff4d6d
      } as const;

      const nodeColors = [
        palette.amber,
        palette.mint,
        palette.halt,
        palette.violet,
        palette.sky,
        palette.rose,
        palette.gold,
        palette.teal,
        palette.coral
      ];

      interface ArcLink {
        curve: { getPoint: (t: number) => { copy: (v: { x: number; y: number; z: number }) => void; x: number; y: number; z: number } };
        pulse: { position: { copy: (v: unknown) => void } };
        line: { material: { opacity: number } };
        phase: number;
        speed: number;
      }

      const activeNodes: { position: { copy: (v: unknown) => void; x: number; y: number; z: number }; scale: { setScalar: (s: number) => void }; userData: Record<string, unknown> }[] = [];
      const arcLinks: ArcLink[] = [];

      function nodePos(u: number, v: number, r = 1.03) {
        const lon = u * 2 * Math.PI - Math.PI;
        const lat = (0.5 - v) * Math.PI;
        const yy = Math.sin(lat);
        const rr = Math.cos(lat);
        return new THREE.Vector3(Math.cos(lon) * rr * r, yy * r, Math.sin(lon) * rr * r);
      }

      function addArc(from: { x: number; y: number; z: number }, to: { x: number; y: number; z: number }, color: number, phase: number) {
        const mid = new THREE.Vector3().addVectors(from, to).multiplyScalar(0.5);
        mid.normalize().multiplyScalar(1.35);
        const curve = new THREE.QuadraticBezierCurve3(
          new THREE.Vector3(from.x, from.y, from.z),
          mid,
          new THREE.Vector3(to.x, to.y, to.z)
        );
        const pts = curve.getPoints(48);
        const lineGeo = new THREE.BufferGeometry().setFromPoints(pts);
        const line = new THREE.Line(
          lineGeo,
          new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.2, blending: THREE.AdditiveBlending })
        );
        spin.add(line);

        const pulse = new THREE.Mesh(
          new THREE.SphereGeometry(0.018, 8, 8),
          new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.95, blending: THREE.AdditiveBlending })
        );
        spin.add(pulse);

        arcLinks.push({ curve, pulse, line, phase, speed: 0.18 + Math.random() * 0.12 });
      }

      function wireActiveLinks() {
        // Cross-links only — never a closed polygon around the globe.
        const pairs: [number, number, number, number][] = [
          [0, 2, palette.violet, 0.55],
          [1, 3, palette.mint, 0.78],
          [0, 4, palette.sky, 0.32],
          [0, 3, palette.amber, 0.18],
          [1, 4, palette.teal, 0.44],
          [2, 4, palette.halt, 0.62],
          [2, 3, palette.coral, 0.27],
          [1, 2, palette.gold, 0.71],
          [3, 4, palette.rose, 0.36],
          [0, 6, palette.sky, 0.49],
          [1, 5, palette.mint, 0.83],
          [2, 7, palette.violet, 0.14],
          [4, 8, palette.amber, 0.58],
          [5, 7, palette.teal, 0.66],
          [6, 8, palette.gold, 0.41],
          [3, 8, palette.rose, 0.22],
          [0, 8, palette.coral, 0.74],
          [5, 8, palette.violet, 0.53]
        ];
        for (const [a, b, color, phase] of pairs) {
          const from = activeNodes[a];
          const to = activeNodes[b];
          if (from && to) addArc(from.position, to.position, color, phase);
        }
      }

      function addDots(isLand: (u: number, v: number) => boolean) {
        const land: number[] = [];
        const landColors: number[] = [];
        const equator = new THREE.Color(palette.amber);
        const temperate = new THREE.Color(palette.teal);
        const polar = new THREE.Color(palette.violet);
        const tint = new THREE.Color();
        const N = 16000;
        for (let i = 0; i < N; i++) {
          const y = 1 - (i / (N - 1)) * 2;
          const r = Math.sqrt(1 - y * y);
          const th = Math.PI * (3 - Math.sqrt(5)) * i;
          const x = Math.cos(th) * r;
          const z = Math.sin(th) * r;
          const u = (Math.atan2(z, x) + Math.PI) / (2 * Math.PI);
          const v = 1 - (Math.asin(y) + Math.PI / 2) / Math.PI;
          if (isLand(u, v)) {
            land.push(x * 1.01, y * 1.01, z * 1.01);
            const latBand = Math.abs(y);
            if (latBand < 0.38) tint.lerpColors(equator, temperate, latBand / 0.38);
            else tint.lerpColors(temperate, polar, (latBand - 0.38) / 0.62);
            landColors.push(tint.r, tint.g, tint.b);
          }
        }
        const lg = new THREE.BufferGeometry();
        lg.setAttribute('position', new THREE.Float32BufferAttribute(land, 3));
        lg.setAttribute('color', new THREE.Float32BufferAttribute(landColors, 3));
        spin.add(
          new THREE.Points(
            lg,
            new THREE.PointsMaterial({
              vertexColors: true,
              size: 0.026,
              sizeAttenuation: true,
              map: sprite,
              transparent: true,
              opacity: 0.92,
              depthWrite: false,
              blending: THREE.AdditiveBlending
            })
          )
        );
        [
          [0.18, 0.55],
          [0.52, 0.42],
          [0.78, 0.6],
          [0.33, 0.7],
          [0.62, 0.3],
          [0.11, 0.38],
          [0.44, 0.68],
          [0.86, 0.47],
          [0.27, 0.52]
        ].forEach((c, k) => {
          const pos = nodePos(c[0], c[1]);
          const halted = k === 2;
          const m = new THREE.Mesh(
            new THREE.SphereGeometry(halted ? 0.038 : 0.03, 12, 12),
            new THREE.MeshBasicMaterial({
              color: nodeColors[k] ?? palette.sky,
              transparent: true,
              opacity: 0.95,
              blending: THREE.AdditiveBlending
            })
          );
          m.position.copy(pos);
          m.userData.halted = halted;
          m.userData.phase = k * 1.3;
          spin.add(m);
          activeNodes.push(m);
        });

        wireActiveLinks();
      }

      const img = new Image();
      img.crossOrigin = 'anonymous';
      img.onload = () => {
        const c2 = document.createElement('canvas');
        c2.width = img.width;
        c2.height = img.height;
        const x2 = c2.getContext('2d')!;
        x2.drawImage(img, 0, 0);
        const d = x2.getImageData(0, 0, c2.width, c2.height).data;
        addDots((u, v) => {
          const px = Math.min(c2.width - 1, (u * c2.width) | 0);
          const py = Math.min(c2.height - 1, (v * c2.height) | 0);
          return d[(py * c2.width + px) * 4] > 18;
        });
      };
      img.onerror = () => addDots(() => Math.random() < 0.22);
      img.src = 'https://cdn.jsdelivr.net/npm/three-globe/example/img/earth-topology.png';

      const sp: number[] = [];
      for (let i = 0; i < 360; i++) {
        const u = Math.random();
        const v = Math.random();
        const lon = 2 * Math.PI * u;
        const lat = Math.acos(2 * v - 1);
        const radius = 4.5 + Math.random() * 3.5;
        sp.push(
          radius * Math.sin(lat) * Math.cos(lon),
          radius * Math.cos(lat),
          radius * Math.sin(lat) * Math.sin(lon)
        );
      }
      const sg = new THREE.BufferGeometry();
      sg.setAttribute('position', new THREE.Float32BufferAttribute(sp, 3));
      scene.add(
        new THREE.Points(
          sg,
          new THREE.PointsMaterial({
            color: 0xd8b4fe,
            size: 0.018,
            sizeAttenuation: true,
            transparent: true,
            opacity: 0.42,
            map: sprite,
            depthWrite: false,
            blending: THREE.AdditiveBlending
          })
        )
      );

      // Even fill — no single-sided point lights (Phong + rim light was leaving half the globe dark).
      scene.add(new THREE.AmbientLight(0xfff7ed, 0.95));
      scene.add(new THREE.HemisphereLight(0xffd6a5, 0x1e1033, 0.72));

      let t = 0;
      const loop = () => {
        t += 0.016;
        spin.rotation.y += 0.0011;

        // Only the halted node breathes slightly; arc lines stay steady (opacity was flickering).
        for (const n of activeNodes) {
          const halted = n.userData.halted as boolean;
          if (halted) {
            const phase = (n.userData.phase as number) ?? 0;
            n.scale.setScalar(1 + Math.sin(t * 2.5 + phase) * 0.12);
          } else {
            n.scale.setScalar(1);
          }
        }

        for (const link of arcLinks) {
          const u = (t * link.speed + link.phase) % 1;
          link.pulse.position.copy(link.curve.getPoint(u));
        }

        composer.render();
        raf = requestAnimationFrame(loop);
      };
      loop();

      const onResize = () => {
        const w = host.clientWidth || W;
        const h = host.clientHeight || H;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h);
        composer.setSize(w, h);
        bloom.resolution.set(w, h);
      };
      window.addEventListener('resize', onResize);
      cleanup = () => {
        cancelAnimationFrame(raf);
        window.removeEventListener('resize', onResize);
        composer.dispose();
        renderer.dispose();
        if (renderer.domElement.parentElement === host) host.removeChild(renderer.domElement);
      };
    })();

    return () => cleanup();
  });
</script>

<div class="globe-host" bind:this={host}></div>

<style>
  .globe-host {
    width: 100%;
    max-width: 400px;
    height: 400px;
    min-height: 400px;
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto;
    background: transparent;
    overflow: visible;
    -webkit-mask-image: radial-gradient(ellipse 78% 78% at 50% 48%, #000 42%, transparent 76%);
    mask-image: radial-gradient(ellipse 78% 78% at 50% 48%, #000 42%, transparent 76%);
  }

  .globe-host :global(canvas) {
    display: block;
    margin: 0 auto;
    background: transparent;
  }
</style>
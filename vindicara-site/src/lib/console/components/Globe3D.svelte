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
      const bloom = new UnrealBloomPass(new THREE.Vector2(W, H), 0.5, 0.55, 0.42);
      composer.addPass(bloom);
      composer.addPass(new OutputPass());

      const spin = new THREE.Group();
      spin.scale.setScalar(0.98);
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
        cyan: 0x00f0ff,
        magenta: 0xff2bd6,
        lime: 0x6dff3a,
        violet: 0xb24bff,
        blue: 0x2b8bff,
        pink: 0xff3d7f,
        yellow: 0xffe11a,
        teal: 0x1affd5,
        halt: 0xff2d5e
      } as const;

      const nodeColors = [
        palette.cyan,
        palette.magenta,
        palette.halt,
        palette.violet,
        palette.blue,
        palette.pink,
        palette.yellow,
        palette.teal,
        palette.lime
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
        const fromV = new THREE.Vector3(from.x, from.y, from.z);
        const toV = new THREE.Vector3(to.x, to.y, to.z);
        // Lift the control point proportional to the node gap: short links stay
        // low and gentle (no sharp hooks), long links arc smoothly higher.
        const d = fromV.distanceTo(toV);
        const ctrl = new THREE.Vector3().addVectors(fromV, toV).normalize().multiplyScalar(1.03 + d * 0.42);
        const curve = new THREE.QuadraticBezierCurve3(fromV, ctrl, toV);
        const line = new THREE.Mesh(
          new THREE.TubeGeometry(curve, 44, 0.012, 8, false),
          new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.85, blending: THREE.AdditiveBlending, depthWrite: false })
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
        // Evenly distributed web: a single skip-2 cycle touches every node once,
        // so the strings spread uniformly around the planet with no clustering.
        const N = activeNodes.length;
        const neon = [palette.cyan, palette.magenta, palette.lime, palette.violet, palette.blue, palette.pink, palette.yellow, palette.teal, palette.halt];
        for (let k = 0; k < N; k++) {
          const from = activeNodes[k];
          const to = activeNodes[(k + 2) % N];
          if (from && to) addArc(from.position, to.position, neon[k % neon.length], k / N);
        }
        // three longer cross-links, spread every third node, to fill open areas
        for (const k of [0, 3, 6]) {
          const from = activeNodes[k];
          const to = activeNodes[(k + 4) % N];
          if (from && to) addArc(from.position, to.position, neon[(k + 4) % neon.length], (k + 0.5) / N);
        }
        // two extra links across the lower region
        for (const [a, b] of [[4, 7], [5, 8]]) {
          const from = activeNodes[a];
          const to = activeNodes[b];
          if (from && to) addArc(from.position, to.position, neon[(a + 1) % neon.length], (a + 0.25) / N);
        }
      }

      function placeNodes() {
        const N = 9;
        const golden = Math.PI * (3 - Math.sqrt(5));
        for (let k = 0; k < N; k++) {
          const y = 1 - (k / (N - 1)) * 2;
          const rr = Math.sqrt(Math.max(0, 1 - y * y));
          const theta = golden * k;
          const pos = new THREE.Vector3(Math.cos(theta) * rr, y, Math.sin(theta) * rr).multiplyScalar(1.03);
          const halted = k === 2;
          const m = new THREE.Mesh(
            new THREE.SphereGeometry(halted ? 0.038 : 0.03, 12, 12),
            new THREE.MeshBasicMaterial({
              color: nodeColors[k] ?? palette.cyan,
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
        }

        wireActiveLinks();
      }

      // Jupiter texture, self-hosted at /jupiter.jpg (same-origin, CSP-safe).
      // Gas giant: smooth colour bands, so no bump map (no craters/relief).
      const loader = new THREE.TextureLoader();
      const planetTex = loader.load('/jupiter.jpg');
      planetTex.colorSpace = THREE.SRGBColorSpace;
      planetTex.anisotropy = 4;
      const planet = new THREE.Mesh(
        new THREE.SphereGeometry(1, 96, 96),
        new THREE.MeshStandardMaterial({ map: planetTex, roughness: 1, metalness: 0 })
      );
      spin.add(planet);

      // White dots circulating around the planet (a tilted orbital band).
      const orbitGroup = new THREE.Group();
      orbitGroup.rotation.set(0.52, 0, 0.16);
      scene.add(orbitGroup);
      const orbitPts: number[] = [];
      const ORB = 280;
      for (let i = 0; i < ORB; i++) {
        const a = Math.random() * Math.PI * 2;
        const rr = 1.32 + Math.random() * 0.72;
        const yy = (Math.random() - 0.5) * 0.3;
        orbitPts.push(Math.cos(a) * rr, yy, Math.sin(a) * rr);
      }
      const orbitGeo = new THREE.BufferGeometry();
      orbitGeo.setAttribute('position', new THREE.Float32BufferAttribute(orbitPts, 3));
      const orbit = new THREE.Points(
        orbitGeo,
        new THREE.PointsMaterial({ color: 0xffffff, size: 0.042, sizeAttenuation: true, map: sprite, transparent: true, opacity: 0.92, depthWrite: false, blending: THREE.AdditiveBlending })
      );
      orbitGroup.add(orbit);

      const sp: number[] = [];
      for (let i = 0; i < 800; i++) {
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
            color: 0xffffff,
            size: 0.02,
            sizeAttenuation: true,
            transparent: true,
            opacity: 0.8,
            map: sprite,
            depthWrite: false,
            blending: THREE.AdditiveBlending
          })
        )
      );

      // Moon lighting: soft cool fill + one warm directional key for crater
      // relief and a gentle terminator. Only the Moon (MeshStandard) responds.
      // Moody, mysterious lighting: low cool ambient so one side falls into
      // shadow, a strong warm side key, and a faint cool rim for atmosphere.
      // Low ambient so the far side falls into shadow (one dark side), a strong
      // warm key on the lit side, and a faint cool rim to define the silhouette.
      scene.add(new THREE.AmbientLight(0x2b3556, 0.12));
      const key = new THREE.DirectionalLight(0xffe6c8, 1.95);
      key.position.set(-1.8, 0.5, 0.9);
      scene.add(key);
      const rim = new THREE.DirectionalLight(0x8fb4ff, 0.4);
      rim.position.set(2, -0.4, -1.1);
      scene.add(rim);

      let t = 0;
      const loop = () => {
        t += 0.016;
        spin.rotation.y += 0.0011;
        orbit.rotation.y += 0.0012;

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
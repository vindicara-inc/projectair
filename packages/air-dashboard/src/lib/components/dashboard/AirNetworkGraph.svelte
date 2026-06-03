<script lang="ts">
  import { onMount } from 'svelte';
  import * as THREE from 'three';
  import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
  import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
  import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
  import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
  import { OutputPass } from 'three/examples/jsm/postprocessing/OutputPass.js';

  interface AgentNode {
    id: string;
    status: string;
    ops: number;
    tools: string[];
  }

  interface AgentEdge {
    from: string;
    to: string;
    kind: string;
  }

  let {
    agents = [],
    edges = [],
    onSelectAgent,
  }: {
    agents?: AgentNode[];
    edges?: AgentEdge[];
    onSelectAgent?: (id: string) => void;
  } = $props();

  let container: HTMLDivElement;

  onMount(() => {
    if (!container) return;

    const w = container.clientWidth;
    const h = container.clientHeight;
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, w / h, 0.1, 500);
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setClearColor(0x060610, 1);
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 0.6;
    container.appendChild(renderer.domElement);

    const composer = new EffectComposer(renderer);
    composer.addPass(new RenderPass(scene, camera));
    composer.addPass(new UnrealBloomPass(new THREE.Vector2(w, h), 0.15, 0.2, 0.85));
    composer.addPass(new OutputPass());

    camera.position.set(0, 12, 40);
    camera.lookAt(0, 0, 0);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.04;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.12;
    controls.maxDistance = 80;
    controls.minDistance = 10;

    scene.add(new THREE.AmbientLight(0x111122, 0.5));
    const hotCore = new THREE.PointLight(0x22d3ee, 0.3, 25);
    scene.add(hotCore);
    const backLight = new THREE.PointLight(0xa855f7, 0.2, 40);
    backLight.position.set(-15, 10, -15);
    scene.add(backLight);

    const nodeCount = agents.length || 1;
    const positions = new Map<string, THREE.Vector3>();
    const meshes = new Map<string, THREE.Mesh>();

    const maxOps = Math.max(1, ...agents.map(a => a.ops));

    agents.forEach((agent, i) => {
      const angle = (i / nodeCount) * Math.PI * 2;
      const radius = 12 + (agent.ops / maxOps) * 6;
      const ySpread = (i % 2 === 0 ? 1 : -1) * (2 + Math.random() * 3);
      const pos = new THREE.Vector3(
        Math.cos(angle) * radius,
        ySpread,
        Math.sin(angle) * radius,
      );
      positions.set(agent.id, pos);

      const isHalted = agent.status === 'halted' || agent.status === 'critical';
      const isFlagged = agent.status === 'flagged';
      const color = isHalted ? 0xff5468 : isFlagged ? 0xffb547 : 0x22d3ee;

      const nodeSize = 0.25 + (agent.ops / maxOps) * 0.35;
      const geo = new THREE.SphereGeometry(nodeSize, 12, 12);
      const mat = new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.3, transparent: true, opacity: 0.9, roughness: 0.4, metalness: 0.6 });
      const mesh = new THREE.Mesh(geo, mat);
      mesh.position.copy(pos);
      mesh.userData = { agentId: agent.id };
      scene.add(mesh);
      meshes.set(agent.id, mesh);

      // No glow sphere - bloom handles the subtle halo

      const labelCanvas = document.createElement('canvas');
      labelCanvas.width = 256;
      labelCanvas.height = 64;
      const ctx = labelCanvas.getContext('2d')!;
      ctx.font = 'bold 22px JetBrains Mono, monospace';
      ctx.fillStyle = isHalted ? '#ff5468' : isFlagged ? '#ffb547' : '#22d3ee';
      ctx.textAlign = 'center';
      ctx.fillText(agent.id, 128, 24);
      ctx.font = '16px JetBrains Mono, monospace';
      ctx.fillStyle = 'rgba(255,255,255,0.4)';
      ctx.fillText(`${agent.ops} ops`, 128, 48);

      const labelTex = new THREE.CanvasTexture(labelCanvas);
      const labelMat = new THREE.SpriteMaterial({ map: labelTex, transparent: true, opacity: 0.85 });
      const label = new THREE.Sprite(labelMat);
      label.position.copy(pos);
      label.position.y += nodeSize + 1.2;
      label.scale.set(5, 1.25, 1);
      scene.add(label);
    });

    for (const edge of edges) {
      const from = positions.get(edge.from);
      const to = positions.get(edge.to);
      if (!from || !to) continue;

      const isHandoff = edge.kind === 'handoff' || edge.kind === 'agent_message';
      const color = isHandoff ? 0xa855f7 : 0x22d3ee;

      const mid = new THREE.Vector3().lerpVectors(from, to, 0.5);
      mid.y += 2;
      const curve = new THREE.QuadraticBezierCurve3(from, mid, to);
      const points = curve.getPoints(32);
      const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
      const lineMat = new THREE.LineBasicMaterial({
        color,
        transparent: true,
        opacity: 0.25,
        blending: THREE.AdditiveBlending,
      });
      scene.add(new THREE.Line(lineGeo, lineMat));
    }

    if (edges.length === 0 && agents.length > 1) {
      for (let i = 0; i < agents.length; i++) {
        const from = positions.get(agents[i]!.id);
        const to = positions.get(agents[(i + 1) % agents.length]!.id);
        if (!from || !to) continue;
        const mid = new THREE.Vector3().lerpVectors(from, to, 0.5);
        mid.y += 1.5;
        const curve = new THREE.QuadraticBezierCurve3(from, mid, to);
        const lineGeo = new THREE.BufferGeometry().setFromPoints(curve.getPoints(24));
        const lineMat = new THREE.LineBasicMaterial({ color: 0x6366f1, transparent: true, opacity: 0.12, blending: THREE.AdditiveBlending });
        scene.add(new THREE.Line(lineGeo, lineMat));

        const toCenter = new THREE.Vector3(0, 0, 0);
        const cGeo = new THREE.BufferGeometry().setFromPoints([from!, toCenter]);
        const cMat = new THREE.LineBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.06 });
        scene.add(new THREE.Line(cGeo, cMat));
      }
    }

    const ringGeo = new THREE.RingGeometry(18, 18.1, 64);
    const ringMat = new THREE.MeshBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.04, side: THREE.DoubleSide });
    const ring = new THREE.Mesh(ringGeo, ringMat);
    ring.rotation.x = Math.PI / 2;
    scene.add(ring);

    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();

    function onClick(event: MouseEvent): void {
      const rect = container.getBoundingClientRect();
      mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
      raycaster.setFromCamera(mouse, camera);
      const allMeshes = [...meshes.values()];
      const hits = raycaster.intersectObjects(allMeshes);
      if (hits.length > 0) {
        const agentId = hits[0]!.object.userData.agentId as string;
        if (agentId) onSelectAgent?.(agentId);
      }
    }
    renderer.domElement.addEventListener('click', onClick);

    let frameId: number;
    let t = 0;

    function animate(): void {
      frameId = requestAnimationFrame(animate);
      t += 0.003;

      meshes.forEach((mesh, _id) => {
        mesh.position.y += Math.sin(t * 2 + mesh.position.x) * 0.003;
      });

      controls.update();
      composer.render();
    }
    animate();

    const resizeObs = new ResizeObserver(() => {
      if (!container) return;
      const rw = container.clientWidth;
      const rh = container.clientHeight;
      camera.aspect = rw / rh;
      camera.updateProjectionMatrix();
      renderer.setSize(rw, rh);
      composer.setSize(rw, rh);
    });
    resizeObs.observe(container);

    return () => {
      cancelAnimationFrame(frameId);
      renderer.domElement.removeEventListener('click', onClick);
      resizeObs.disconnect();
      controls.dispose();
      renderer.dispose();
    };
  });
</script>

<div bind:this={container} class="w-full h-full cursor-crosshair"></div>

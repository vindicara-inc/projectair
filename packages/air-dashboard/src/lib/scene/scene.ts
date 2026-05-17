/**
 * Three.js scene controller for the AIR HUD chain orbit.
 *
 * Lifecycle: mount(canvas) → start() → ... → dispose(). Designed to be called
 * once from a Svelte component; the controller owns its renderer, scene, and
 * raf handle. Callers push capsules in via ChainOrbit's add() method (exposed
 * on the returned controller).
 *
 * Design notes:
 * - No postprocessing in v1 (it is the perf cliff and screams generic-cyber).
 * - pixelRatio capped at 2 — sufficient on Retina M1, half the work of devicePixelRatio.
 * - Background is transparent so the CSS grid in app.css shows through. The
 *   scene contributes only the chain orbit, signal source, and detector swarm.
 */

import {
	AmbientLight,
	Clock,
	DirectionalLight,
	PerspectiveCamera,
	Scene,
	WebGLRenderer
} from 'three';

import { mountCamera, type CameraController } from './camera.ts';
import { mountChainOrbit, type ChainOrbitController } from './chain-orbit.ts';
import { mountSignalSource, type SignalSourceController } from './signal-source.ts';
import { mountDetectorSwarm, type SwarmController } from './detector-swarm.ts';
import { DETECTOR_SWARM } from '../detectors/index.ts';

export interface SceneController {
	chainOrbit: ChainOrbitController;
	signalSource: SignalSourceController;
	swarm: SwarmController;
	start: () => void;
	stop: () => void;
	dispose: () => void;
	resize: (width: number, height: number) => void;
}

export function mountScene(canvas: HTMLCanvasElement): SceneController {
	const renderer = new WebGLRenderer({
		canvas,
		alpha: true,
		antialias: true,
		powerPreference: 'high-performance'
	});
	renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
	renderer.setClearColor(0x000000, 0);

	const scene = new Scene();
	const camera = new PerspectiveCamera(35, canvas.clientWidth / canvas.clientHeight, 0.1, 100);
	const cameraCtrl: CameraController = mountCamera(camera);

	const ambient = new AmbientLight(0x88aaff, 0.35);
	const key = new DirectionalLight(0x22d3ee, 0.6);
	key.position.set(4, 8, 6);
	const fill = new DirectionalLight(0xf59e0b, 0.18);
	fill.position.set(-6, 4, -4);
	scene.add(ambient, key, fill);

	const chainOrbit = mountChainOrbit(scene);
	const signalSource = mountSignalSource(scene);
	const swarm = mountDetectorSwarm(
		scene,
		DETECTOR_SWARM.map((entity) => ({ id: entity.id, personality: entity.personality }))
	);

	const clock = new Clock();
	let rafHandle = 0;
	let running = false;

	const tick = (): void => {
		if (!running) return;
		const delta = clock.getDelta();
		const elapsed = clock.getElapsedTime();
		cameraCtrl.update(delta);
		chainOrbit.update(delta, elapsed);
		signalSource.update(delta, elapsed);
		swarm.update(delta, elapsed);
		renderer.render(scene, camera);
		rafHandle = requestAnimationFrame(tick);
	};

	const resize = (width: number, height: number): void => {
		renderer.setSize(width, height, false);
		camera.aspect = width / height;
		camera.updateProjectionMatrix();
	};

	const start = (): void => {
		if (running) return;
		running = true;
		clock.start();
		rafHandle = requestAnimationFrame(tick);
	};

	const stop = (): void => {
		running = false;
		if (rafHandle !== 0) {
			cancelAnimationFrame(rafHandle);
			rafHandle = 0;
		}
	};

	const dispose = (): void => {
		stop();
		chainOrbit.dispose();
		signalSource.dispose();
		swarm.dispose();
		renderer.dispose();
	};

	resize(canvas.clientWidth, canvas.clientHeight);

	return { chainOrbit, signalSource, swarm, start, stop, dispose, resize };
}

/**
 * Custom camera controller — no OrbitControls.
 *
 * Maintains a slight perpetual yaw around the orbit center (think security
 * camera, not orbit-controls drag). Intentionally minimal: the operator does
 * not interact with the camera; the camera's job is to make the chain orbit
 * read at a glance.
 *
 * Position offset chosen empirically: slightly elevated, slightly back, looking
 * down the -Z axis at the orbit center. FOV 35° in scene.ts gives a tight,
 * cinematic frame without fisheye.
 */

import { PerspectiveCamera, Vector3 } from 'three';

const ORBIT_RADIUS = 14;
const ORBIT_HEIGHT = 9;
const YAW_RATE_RAD_PER_SEC = (Math.PI / 180) * 2.5;

export interface CameraController {
	update: (delta: number) => void;
	getPhase: () => number;
}

export function mountCamera(camera: PerspectiveCamera): CameraController {
	const target = new Vector3(0, 0, 0);
	let phase = 0;

	const reposition = (): void => {
		camera.position.set(
			Math.sin(phase) * ORBIT_RADIUS,
			ORBIT_HEIGHT,
			Math.cos(phase) * ORBIT_RADIUS
		);
		camera.lookAt(target);
	};

	reposition();

	return {
		update(delta: number) {
			phase += delta * YAW_RATE_RAD_PER_SEC;
			reposition();
		},
		getPhase() {
			return phase;
		}
	};
}

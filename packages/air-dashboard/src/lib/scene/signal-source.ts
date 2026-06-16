/**
 * Signal source: the 2D HUD silhouette at the orbit center.
 *
 * Replaces the literal "wireframe humanoid" pattern (which reads as character-
 * in-a-dashboard, not Stark HUD). Instead: three concentric horizontal rings
 * lit cyan, with a thin vertical beam through the center that pulses with the
 * elapsed clock. Layered depth comes from line width, not 3D mass.
 */

import {
	BufferAttribute,
	BufferGeometry,
	Color,
	Line,
	LineBasicMaterial,
	type Scene
} from 'three';

const RING_RADII = [0.6, 1.1, 1.7];
const RING_SEGMENTS = 96;
const COLOR_RING = new Color(0x22d3ee);

export interface SignalSourceController {
	dispose: () => void;
	update: (delta: number, elapsed: number) => void;
}

export function mountSignalSource(scene: Scene): SignalSourceController {
	const rings: Line[] = [];
	const ringMaterials: LineBasicMaterial[] = [];

	for (const r of RING_RADII) {
		const positions = new Float32Array((RING_SEGMENTS + 1) * 3);
		for (let i = 0; i <= RING_SEGMENTS; i++) {
			const angle = (i / RING_SEGMENTS) * Math.PI * 2;
			positions[i * 3 + 0] = Math.cos(angle) * r;
			positions[i * 3 + 1] = 0;
			positions[i * 3 + 2] = Math.sin(angle) * r;
		}
		const geom = new BufferGeometry();
		geom.setAttribute('position', new BufferAttribute(positions, 3));
		const mat = new LineBasicMaterial({
			color: COLOR_RING,
			transparent: true,
			opacity: 0.85
		});
		const line = new Line(geom, mat);
		scene.add(line);
		rings.push(line);
		ringMaterials.push(mat);
	}

	const beamPositions = new Float32Array(2 * 3);
	beamPositions[0] = 0;
	beamPositions[1] = -0.4;
	beamPositions[2] = 0;
	beamPositions[3] = 0;
	beamPositions[4] = 2.2;
	beamPositions[5] = 0;
	const beamGeom = new BufferGeometry();
	beamGeom.setAttribute('position', new BufferAttribute(beamPositions, 3));
	const beamMat = new LineBasicMaterial({ color: 0xf59e0b, transparent: true, opacity: 0.7 });
	const beam = new Line(beamGeom, beamMat);
	scene.add(beam);

	return {
		dispose() {
			for (const r of rings) {
				scene.remove(r);
				r.geometry.dispose();
			}
			for (const m of ringMaterials) m.dispose();
			scene.remove(beam);
			beam.geometry.dispose();
			beamMat.dispose();
		},
		update(_delta, elapsed) {
			for (let i = 0; i < ringMaterials.length; i++) {
				const phase = elapsed * 0.7 + i * 0.6;
				ringMaterials[i]!.opacity = 0.55 + Math.sin(phase) * 0.18;
			}
			beamMat.opacity = 0.55 + Math.sin(elapsed * 1.4) * 0.2;
		}
	};
}

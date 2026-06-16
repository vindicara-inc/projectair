/**
 * Chain orbit: capsules as hexagonal prisms in a circular orbit, signature
 * edges as fat lines connecting consecutive capsules.
 *
 * - Capsules: InstancedMesh of CylinderGeometry (6 sides = hex prism). Color
 *   per-instance via instanceColor attribute.
 * - Edges: one Line2 per consecutive pair, added/removed dynamically.
 * - Tick marks: 12 thin segments around the orbit perimeter as a scale rule.
 *
 * Capsule slot layout: when MAX_VISIBLE = 30 capsules or fewer, distribute
 * evenly around the full circle. When more, compress to a fixed arc spacing
 * and let older capsules slide out of view (Phase 0 caps at 30).
 */

import {
	BufferAttribute,
	BufferGeometry,
	Color,
	CylinderGeometry,
	InstancedMesh,
	Line,
	LineBasicMaterial,
	Matrix4,
	MeshStandardMaterial,
	type Object3D,
	type Scene,
	Vector3
} from 'three';

import { Line2 } from 'three/addons/lines/Line2.js';
import { LineMaterial } from 'three/addons/lines/LineMaterial.js';
import { LineGeometry } from 'three/addons/lines/LineGeometry.js';

const ORBIT_RADIUS = 5.4;
const BROKEN_DRIFT_RADIUS = 6.6;
const HEX_RADIUS = 0.32;
const HEX_HEIGHT = 0.85;
const MAX_VISIBLE = 30;

const COLOR_IDLE = new Color(0x0e7490);
const COLOR_VERIFIED = new Color(0x22d3ee);
const COLOR_FOCUS = new Color(0xf59e0b);
const COLOR_ALERT = new Color(0xef4444);

const COLOR_EDGE_VERIFIED = 0x22d3ee;
const COLOR_EDGE_BROKEN = 0xef4444;

export type CapsuleStateKind = 'pending' | 'verified' | 'flagged' | 'broken';

export interface CapsuleState {
	contentHash: string;
	state: CapsuleStateKind;
	focused: boolean;
}

export interface ChainOrbitController {
	add: (state: CapsuleState) => void;
	updateAt: (index: number, patch: Partial<CapsuleState>) => void;
	clear: () => void;
	count: () => number;
	dispose: () => void;
	update: (delta: number, elapsed: number) => void;
	getPosition: (index: number) => Vector3 | null;
}

export function mountChainOrbit(scene: Scene): ChainOrbitController {
	const capsuleGeom = new CylinderGeometry(HEX_RADIUS, HEX_RADIUS, HEX_HEIGHT, 6, 1, false);
	capsuleGeom.translate(0, HEX_HEIGHT / 2, 0);
	const capsuleMat = new MeshStandardMaterial({
		metalness: 0.1,
		roughness: 0.55,
		emissive: 0x0e7490,
		emissiveIntensity: 0.28
	});
	const capsules = new InstancedMesh(capsuleGeom, capsuleMat, MAX_VISIBLE);
	capsules.count = 0;
	capsules.instanceMatrix.needsUpdate = true;
	scene.add(capsules);

	const ticks = buildTickRing();
	scene.add(ticks);

	const states: CapsuleState[] = [];
	const edges: Line2[] = [];
	const edgeMaterials: LineMaterial[] = [];
	const verifiedEdgeMat = new LineMaterial({
		color: COLOR_EDGE_VERIFIED,
		linewidth: 2.4,
		transparent: true,
		opacity: 0.9
	});
	verifiedEdgeMat.resolution.set(window.innerWidth, window.innerHeight);
	const brokenEdgeMat = new LineMaterial({
		color: COLOR_EDGE_BROKEN,
		linewidth: 3.2,
		transparent: true,
		opacity: 0.95,
		dashed: false
	});
	brokenEdgeMat.resolution.set(window.innerWidth, window.innerHeight);

	const tmpMatrix = new Matrix4();

	const firstBrokenIndex = (): number => {
		for (let i = 0; i < states.length; i++) {
			if (states[i]!.state === 'broken') return i;
		}
		return -1;
	};

	const slotPosition = (index: number, total: number): Vector3 => {
		const slots = Math.max(total, 13);
		const angle = (index / slots) * Math.PI * 2 - Math.PI / 2;
		const broken = firstBrokenIndex();
		const radius = broken !== -1 && index >= broken ? BROKEN_DRIFT_RADIUS : ORBIT_RADIUS;
		const drift = broken !== -1 && index > broken ? (index - broken) * 0.06 : 0;
		return new Vector3(
			Math.cos(angle) * (radius + drift),
			0,
			Math.sin(angle) * (radius + drift)
		);
	};

	const colorFor = (state: CapsuleState): Color => {
		if (state.state === 'broken') return COLOR_ALERT;
		if (state.state === 'flagged') return COLOR_ALERT;
		if (state.focused) return COLOR_FOCUS;
		if (state.state === 'verified') return COLOR_VERIFIED;
		return COLOR_IDLE;
	};

	const refresh = (): void => {
		const total = states.length;
		for (let i = 0; i < Math.min(total, MAX_VISIBLE); i++) {
			const pos = slotPosition(i, total);
			tmpMatrix.makeTranslation(pos.x, pos.y, pos.z);
			capsules.setMatrixAt(i, tmpMatrix);
			capsules.setColorAt(i, colorFor(states[i]!));
		}
		capsules.count = Math.min(total, MAX_VISIBLE);
		capsules.instanceMatrix.needsUpdate = true;
		if (capsules.instanceColor) capsules.instanceColor.needsUpdate = true;

		while (edges.length < total - 1) {
			const e = new Line2(new LineGeometry(), verifiedEdgeMat);
			scene.add(e);
			edges.push(e);
			edgeMaterials.push(verifiedEdgeMat);
		}
		while (edges.length > Math.max(total - 1, 0)) {
			const e = edges.pop()!;
			edgeMaterials.pop();
			scene.remove(e);
			e.geometry.dispose();
		}
		const brokenAt = firstBrokenIndex();
		for (let i = 0; i < edges.length; i++) {
			const a = slotPosition(i, total);
			const b = slotPosition(i + 1, total);
			const lift = 0.05;
			const geom = edges[i]!.geometry as LineGeometry;
			geom.setPositions([a.x, lift, a.z, b.x, lift, b.z]);
			edges[i]!.computeLineDistances();
			const isPostBreak = brokenAt !== -1 && i >= brokenAt;
			const targetMat = isPostBreak ? brokenEdgeMat : verifiedEdgeMat;
			if (edgeMaterials[i] !== targetMat) {
				edges[i]!.material = targetMat;
				edgeMaterials[i] = targetMat;
			}
		}
	};

	return {
		add(state) {
			states.push({ ...state });
			refresh();
		},
		updateAt(index, patch) {
			const cur = states[index];
			if (!cur) return;
			states[index] = { ...cur, ...patch };
			refresh();
		},
		clear() {
			states.length = 0;
			refresh();
		},
		count() {
			return states.length;
		},
		dispose() {
			capsules.geometry.dispose();
			capsuleMat.dispose();
			for (const e of edges) {
				scene.remove(e);
				e.geometry.dispose();
			}
			verifiedEdgeMat.dispose();
			brokenEdgeMat.dispose();
			scene.remove(capsules);
			scene.remove(ticks);
		},
		update(_delta, elapsed) {
			capsuleMat.emissiveIntensity = 0.24 + Math.sin(elapsed * 1.6) * 0.05;
		},
		getPosition(index) {
			if (index < 0 || index >= states.length) return null;
			return slotPosition(index, states.length);
		}
	};
}

function buildTickRing(): Object3D {
	const segments = 36;
	const inner = ORBIT_RADIUS - 0.18;
	const outer = ORBIT_RADIUS + 0.18;
	const positions = new Float32Array(segments * 6);
	for (let i = 0; i < segments; i++) {
		const angle = (i / segments) * Math.PI * 2;
		const cos = Math.cos(angle);
		const sin = Math.sin(angle);
		positions[i * 6 + 0] = cos * inner;
		positions[i * 6 + 1] = -0.001;
		positions[i * 6 + 2] = sin * inner;
		positions[i * 6 + 3] = cos * outer;
		positions[i * 6 + 4] = -0.001;
		positions[i * 6 + 5] = sin * outer;
	}
	const geom = new BufferGeometry();
	geom.setAttribute('position', new BufferAttribute(positions, 3));
	const mat = new LineBasicMaterial({ color: 0x164e63, transparent: true, opacity: 0.55 });
	return new Line(geom, mat);
}

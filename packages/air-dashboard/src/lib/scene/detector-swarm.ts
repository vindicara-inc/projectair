/**
 * Detector swarm: each active detector renders as a distinct geometric entity
 * floating in an outer arc above the chain orbit. When a detector's pattern
 * matches an emitted capsule, the entity "locks on" — the geometry pulses,
 * shifts to alert color, and draws a line back to the offending capsule.
 *
 * Personalities (advisor recommendation): each detector gets its own shape so
 * operators can read findings at a glance without consulting the legend.
 *   - ASI02 reaper (tool args): octahedron
 *   - ASI05 reaper (tool name): tetrahedron
 *   - AIR-02 whisper (all text): torus
 *   - AIR-04 archivist (chain structure): box
 *   - ASI10 warden (agent scope): icosahedron
 *
 * Position: arranged in a 60° arc above the chain orbit's far edge, so the
 * camera (which orbits slowly) catches them in profile then in plan view.
 */

import {
	BoxGeometry,
	BufferAttribute,
	BufferGeometry,
	Color,
	IcosahedronGeometry,
	Line,
	LineBasicMaterial,
	Mesh,
	MeshStandardMaterial,
	OctahedronGeometry,
	type Object3D,
	type Scene,
	TetrahedronGeometry,
	TorusGeometry,
	Vector3
} from 'three';

const SWARM_RADIUS = 9.5;
const SWARM_ELEVATION = 3.2;
const ARC_DEGREES = 100;
const COLOR_IDLE = new Color(0x22d3ee);
const COLOR_SCANNING = new Color(0xf59e0b);
const COLOR_TRIGGERED = new Color(0xef4444);

export type DetectorStatus = 'idle' | 'scanning' | 'triggered';

export interface DetectorEntityConfig {
	id: string;
	personality: 'reaper' | 'whisper' | 'archivist' | 'warden' | 'sentinel';
}

export interface SwarmController {
	setDetectorStatus: (id: string, status: DetectorStatus) => void;
	setLockTarget: (id: string, target: Vector3 | null) => void;
	dispose: () => void;
	update: (delta: number, elapsed: number) => void;
	getEntityPosition: (id: string) => Vector3 | null;
}

interface EntityState {
	id: string;
	mesh: Mesh;
	material: MeshStandardMaterial;
	homePosition: Vector3;
	status: DetectorStatus;
	lockTarget: Vector3 | null;
	lockLine: Line | null;
	lockMaterial: LineBasicMaterial | null;
}

function geometryFor(personality: DetectorEntityConfig['personality']) {
	switch (personality) {
		case 'reaper':
			return new OctahedronGeometry(0.3, 0);
		case 'whisper':
			return new TorusGeometry(0.28, 0.05, 6, 24);
		case 'archivist':
			return new BoxGeometry(0.42, 0.42, 0.42);
		case 'warden':
			return new IcosahedronGeometry(0.32, 0);
		case 'sentinel':
		default:
			return new TetrahedronGeometry(0.32, 0);
	}
}

export function mountDetectorSwarm(
	scene: Scene,
	configs: readonly DetectorEntityConfig[]
): SwarmController {
	const states: EntityState[] = [];
	const arcRad = (ARC_DEGREES * Math.PI) / 180;
	const startAngle = Math.PI / 2 - arcRad / 2;

	configs.forEach((config, i) => {
		const t = configs.length === 1 ? 0.5 : i / (configs.length - 1);
		const angle = startAngle + t * arcRad;
		const home = new Vector3(
			Math.cos(angle) * SWARM_RADIUS,
			SWARM_ELEVATION,
			Math.sin(angle) * SWARM_RADIUS
		);
		const geometry = geometryFor(config.personality);
		const material = new MeshStandardMaterial({
			color: COLOR_IDLE,
			emissive: COLOR_IDLE,
			emissiveIntensity: 0.55,
			metalness: 0.1,
			roughness: 0.4,
			transparent: true,
			opacity: 0.92
		});
		const mesh = new Mesh(geometry, material);
		mesh.position.copy(home);
		scene.add(mesh);
		states.push({
			id: config.id,
			mesh,
			material,
			homePosition: home.clone(),
			status: 'idle',
			lockTarget: null,
			lockLine: null,
			lockMaterial: null
		});
	});

	const colorFor = (status: DetectorStatus): Color => {
		if (status === 'triggered') return COLOR_TRIGGERED;
		if (status === 'scanning') return COLOR_SCANNING;
		return COLOR_IDLE;
	};

	const ensureLockLine = (state: EntityState): void => {
		if (state.lockLine) return;
		const positions = new Float32Array(2 * 3);
		const geom = new BufferGeometry();
		geom.setAttribute('position', new BufferAttribute(positions, 3));
		const mat = new LineBasicMaterial({
			color: COLOR_TRIGGERED,
			transparent: true,
			opacity: 0.0
		});
		const line = new Line(geom, mat);
		scene.add(line);
		state.lockLine = line;
		state.lockMaterial = mat;
	};

	const removeLockLine = (state: EntityState): void => {
		if (!state.lockLine) return;
		scene.remove(state.lockLine);
		state.lockLine.geometry.dispose();
		state.lockMaterial?.dispose();
		state.lockLine = null;
		state.lockMaterial = null;
	};

	const updateLockLineGeometry = (state: EntityState): void => {
		if (!state.lockLine || !state.lockTarget) return;
		const positions = state.lockLine.geometry.attributes.position as BufferAttribute;
		positions.array[0] = state.mesh.position.x;
		positions.array[1] = state.mesh.position.y;
		positions.array[2] = state.mesh.position.z;
		positions.array[3] = state.lockTarget.x;
		positions.array[4] = state.lockTarget.y;
		positions.array[5] = state.lockTarget.z;
		positions.needsUpdate = true;
	};

	return {
		setDetectorStatus(id, status) {
			const state = states.find((s) => s.id === id);
			if (!state) return;
			state.status = status;
			const color = colorFor(status);
			state.material.color.copy(color);
			state.material.emissive.copy(color);
			state.material.emissiveIntensity = status === 'idle' ? 0.45 : 0.85;
		},
		setLockTarget(id, target) {
			const state = states.find((s) => s.id === id);
			if (!state) return;
			state.lockTarget = target ? target.clone() : null;
			if (target === null) {
				removeLockLine(state);
			} else {
				ensureLockLine(state);
				updateLockLineGeometry(state);
			}
		},
		dispose() {
			for (const state of states) {
				removeLockLine(state);
				scene.remove(state.mesh);
				state.mesh.geometry.dispose();
				state.material.dispose();
			}
		},
		update(_delta, elapsed) {
			for (const state of states) {
				const phase = elapsed * 1.4 + state.homePosition.x * 0.3;
				state.mesh.rotation.y = elapsed * 0.6;
				state.mesh.rotation.x = Math.sin(phase) * 0.18;
				const breath = state.status === 'triggered' ? 0.18 : 0.06;
				state.mesh.position.y = state.homePosition.y + Math.sin(phase) * breath;
				if (state.lockMaterial && state.lockTarget) {
					updateLockLineGeometry(state);
					state.lockMaterial.opacity = 0.55 + Math.sin(elapsed * 4) * 0.25;
				}
			}
		},
		getEntityPosition(id) {
			const state = states.find((s) => s.id === id);
			return state ? state.mesh.position.clone() : null;
		}
	};
}

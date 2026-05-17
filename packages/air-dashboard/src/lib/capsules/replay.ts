/**
 * Replay engine: walks an AgDRRecord[] at a configurable cadence, emitting a
 * tick callback per capsule. Determinism uses a tick interval derived from
 * speed multiplier, NOT from the trace timestamps — playback is wall-clock
 * controlled so scenario authors can tune scene drama without re-cutting the
 * underlying signed chain.
 */

import type { AgDRRecord } from '../agdr/types.ts';

export type ReplayStatus = 'idle' | 'playing' | 'paused' | 'finished';

export type ReplaySpeed = 0.5 | 1 | 2 | 5;

export interface ReplayConfig {
	records: AgDRRecord[];
	baseTickMs: number;
	speed: ReplaySpeed;
	onTick: (record: AgDRRecord, index: number) => void;
	onFinish?: () => void;
}

const DEFAULT_BASE_TICK_MS = 900;

export interface ReplayHandle {
	status: ReplayStatus;
	index: number;
	speed: ReplaySpeed;
	play: () => void;
	pause: () => void;
	reset: () => void;
	step: () => void;
	setSpeed: (speed: ReplaySpeed) => void;
}

export function createReplay(args: Omit<ReplayConfig, 'baseTickMs'> & { baseTickMs?: number }): ReplayHandle {
	const baseTickMs = args.baseTickMs ?? DEFAULT_BASE_TICK_MS;
	let status: ReplayStatus = 'idle';
	let index = -1;
	let speed: ReplaySpeed = args.speed;
	let timer: ReturnType<typeof setTimeout> | null = null;

	const tickInterval = (): number => Math.max(60, Math.round(baseTickMs / speed));

	const cancel = (): void => {
		if (timer !== null) {
			clearTimeout(timer);
			timer = null;
		}
	};

	const advance = (): void => {
		index += 1;
		if (index >= args.records.length) {
			status = 'finished';
			args.onFinish?.();
			return;
		}
		const rec = args.records[index]!;
		args.onTick(rec, index);
		if (status === 'playing') {
			timer = setTimeout(advance, tickInterval());
		}
	};

	const play = (): void => {
		if (status === 'playing') return;
		if (status === 'finished') return;
		status = 'playing';
		cancel();
		timer = setTimeout(advance, tickInterval());
	};

	const pause = (): void => {
		if (status !== 'playing') return;
		status = 'paused';
		cancel();
	};

	const reset = (): void => {
		cancel();
		status = 'idle';
		index = -1;
	};

	const step = (): void => {
		if (status === 'finished') return;
		const wasPlaying = status === 'playing';
		cancel();
		status = 'paused';
		advance();
		if (wasPlaying) {
			// play() short-circuits if advance() already finished the chain.
			play();
		}
	};

	const setSpeed = (next: ReplaySpeed): void => {
		speed = next;
		if (status === 'playing') {
			cancel();
			timer = setTimeout(advance, tickInterval());
		}
	};

	return {
		get status() {
			return status;
		},
		get index() {
			return index;
		},
		get speed() {
			return speed;
		},
		play,
		pause,
		reset,
		step,
		setSpeed
	};
}

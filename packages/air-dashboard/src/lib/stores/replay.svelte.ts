/**
 * Replay store — Svelte 5 runes wrapping the imperative replay engine.
 *
 * Discipline: ONLY this file (and its sibling stores) creates runes. Components
 * consume them. Keeps reactivity surface tight and easy to reason about.
 */

import type { AgDRRecord } from '../agdr/types.ts';
import { createReplay, type ReplayHandle, type ReplaySpeed, type ReplayStatus } from '../capsules/replay.ts';

class ReplayStore {
	records = $state<AgDRRecord[]>([]);
	emitted = $state<AgDRRecord[]>([]);
	currentIndex = $state(-1);
	status = $state<ReplayStatus>('idle');
	speed = $state<ReplaySpeed>(1);
	scenarioId = $state<string | null>(null);

	private handle: ReplayHandle | null = null;

	load(records: AgDRRecord[], scenarioId: string): void {
		this.handle?.reset();
		this.records = records;
		this.emitted = [];
		this.currentIndex = -1;
		this.status = 'idle';
		this.scenarioId = scenarioId;
		this.handle = createReplay({
			records,
			speed: this.speed,
			onTick: (record, index) => {
				this.emitted = [...this.emitted, record];
				this.currentIndex = index;
				this.status = this.handle?.status ?? 'playing';
			},
			onFinish: () => {
				this.status = 'finished';
			}
		});
	}

	play(): void {
		this.handle?.play();
		if (this.handle) this.status = this.handle.status;
	}

	pause(): void {
		this.handle?.pause();
		if (this.handle) this.status = this.handle.status;
	}

	reset(): void {
		this.handle?.reset();
		this.emitted = [];
		this.currentIndex = -1;
		this.status = 'idle';
	}

	step(): void {
		this.handle?.step();
		if (this.handle) this.status = this.handle.status;
	}

	setSpeed(next: ReplaySpeed): void {
		this.speed = next;
		this.handle?.setSpeed(next);
	}
}

export const replayStore = new ReplayStore();

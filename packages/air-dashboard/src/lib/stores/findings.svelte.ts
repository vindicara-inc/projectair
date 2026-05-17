/**
 * Findings store — accumulates detector findings emitted as the replay
 * progresses. Each entry binds back to the offending capsule's step_index
 * so the scene layer can render flares anchored to the right node.
 */

import type { Finding } from '../agdr/types.ts';

class FindingsStore {
	all = $state<Finding[]>([]);

	reset(): void {
		this.all = [];
	}

	add(findings: Finding[]): void {
		if (findings.length === 0) return;
		this.all = [...this.all, ...findings];
	}

	bySeverity(): { critical: Finding[]; high: Finding[]; medium: Finding[] } {
		const buckets = { critical: [] as Finding[], high: [] as Finding[], medium: [] as Finding[] };
		for (const f of this.all) {
			buckets[f.severity].push(f);
		}
		return buckets;
	}

	forStep(index: number): Finding[] {
		return this.all.filter((f) => f.step_index === index);
	}
}

export const findingsStore = new FindingsStore();

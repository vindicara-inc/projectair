/**
 * Focus store — which capsule the operator has selected for the readout panel.
 * Defaults to the most recently emitted capsule when nothing is explicitly
 * focused; switches to manual when the operator clicks a node.
 */

import type { AgDRRecord } from '../agdr/types.ts';

class FocusStore {
	manualIndex = $state<number | null>(null);

	resolve(emitted: AgDRRecord[], emittedIndex: number): { record: AgDRRecord | null; index: number } {
		if (emitted.length === 0) return { record: null, index: -1 };
		if (this.manualIndex !== null && this.manualIndex >= 0 && this.manualIndex < emitted.length) {
			return { record: emitted[this.manualIndex]!, index: this.manualIndex };
		}
		const i = Math.max(0, Math.min(emittedIndex, emitted.length - 1));
		return { record: emitted[i]!, index: i };
	}

	select(index: number): void {
		this.manualIndex = index;
	}

	clear(): void {
		this.manualIndex = null;
	}
}

export const focusStore = new FocusStore();

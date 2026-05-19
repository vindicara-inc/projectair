/**
 * Detail panel store — manages multiple floating glass cards.
 * Each card has a unique ID so they can be opened/closed independently.
 */

import type { Finding } from '../agdr/types.ts';

export type DetailView =
	| { kind: 'finding'; finding: Finding }
	| { kind: 'findings-list'; title: string; findings: Finding[] }
	| { kind: 'detector'; detectorId: string; title: string; description: string; findings: Finding[] }
	| { kind: 'capsule'; index: number }
	| { kind: 'severity-info' };

export interface DetailCard {
	id: string;
	view: DetailView;
}

let _nextId = 0;

class DetailStore {
	cards = $state<DetailCard[]>([]);

	open(view: DetailView): void {
		const id = `card-${_nextId++}`;
		this.cards = [...this.cards, { id, view }];
	}

	close(id: string): void {
		this.cards = this.cards.filter((c) => c.id !== id);
	}

	replace(id: string, view: DetailView): void {
		this.cards = this.cards.map((c) => c.id === id ? { ...c, view } : c);
	}

	closeAll(): void {
		this.cards = [];
	}

	get isOpen(): boolean {
		return this.cards.length > 0;
	}
}

export const detailStore = new DetailStore();

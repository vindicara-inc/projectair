/**
 * Verifier store — accumulates per-capsule verification results as the replay
 * engine emits ticks. Each entry feeds the right-rail VerifierLedger panel and
 * the top-strip integrity score.
 *
 * Verification runs synchronously when called; the store is the side-effect
 * sink, not the verifier itself.
 */

import type { AgDRRecord, VerificationStatus } from '../agdr/types.ts';
import { verifyRecord, type RecordVerification } from '../agdr/verify.ts';

export type LedgerStatus = 'pending' | 'ok' | 'tampered' | 'broken_link';

export interface LedgerEntry {
	index: number;
	step_id: string;
	kind: AgDRRecord['kind'];
	contentHashShort: string;
	status: LedgerStatus;
	reason?: string;
}

class VerifierStore {
	entries = $state<LedgerEntry[]>([]);
	chainStatus = $state<VerificationStatus>('ok');
	expectedPrev = $state<string>('0'.repeat(64));

	reset(): void {
		this.entries = [];
		this.chainStatus = 'ok';
		this.expectedPrev = '0'.repeat(64);
	}

	ingest(record: AgDRRecord, index: number): RecordVerification {
		const linkOk = record.prev_hash === this.expectedPrev;
		if (!linkOk) {
			this.chainStatus = 'broken_chain';
			this.entries = [
				...this.entries,
				{
					index,
					step_id: record.step_id,
					kind: record.kind,
					contentHashShort: record.content_hash.slice(0, 12),
					status: 'broken_link',
					reason: `expected prev_hash ${this.expectedPrev.slice(0, 12)}…, got ${record.prev_hash.slice(0, 12)}…`
				}
			];
			return { ok: false, reason: 'broken chain link' };
		}

		const result = verifyRecord(record);
		const status: LedgerStatus = result.ok ? 'ok' : 'tampered';
		this.entries = [
			...this.entries,
			{
				index,
				step_id: record.step_id,
				kind: record.kind,
				contentHashShort: record.content_hash.slice(0, 12),
				status,
				reason: result.reason
			}
		];

		if (!result.ok) {
			this.chainStatus = 'tampered';
		}
		this.expectedPrev = record.content_hash;
		return result;
	}

	get integrityScore(): number {
		if (this.entries.length === 0) return 100;
		const okCount = this.entries.filter((e) => e.status === 'ok').length;
		return Math.round((okCount / this.entries.length) * 100);
	}
}

export const verifierStore = new VerifierStore();

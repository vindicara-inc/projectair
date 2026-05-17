/**
 * Ed25519 signature verification across the full canonical → hash → sign chain.
 *
 * Runs last in the fidelity ladder; if canonical and BLAKE3 already pass and
 * this fails, suspect a key/signature byte-encoding mismatch.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifySignature } from '../../src/lib/agdr/ed25519.ts';
import { verifyRecord } from '../../src/lib/agdr/verify.ts';
import type { AgDRRecord } from '../../src/lib/agdr/types.ts';

interface FidelityCase {
	name: string;
	input_payload: Record<string, unknown>;
	content_hash: string;
	prev_hash: string;
	signature_hex: string;
	signer_key_hex: string;
}
interface FixtureFile {
	cases: FidelityCase[];
}

const FIXTURE_PATH = resolve(__dirname, '../fixtures/canonical-fixtures.json');
const fixtures = JSON.parse(readFileSync(FIXTURE_PATH, 'utf-8')) as FixtureFile;

function stripTopLevelNulls(obj: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(obj)) {
		if (v !== null && v !== undefined) out[k] = v;
	}
	return out;
}

describe('Ed25519 signature verification', () => {
	for (const c of fixtures.cases) {
		it(c.name + ' verifies via direct call', () => {
			const ok = verifySignature({
				signatureHex: c.signature_hex,
				signerKeyHex: c.signer_key_hex,
				prevHash: c.prev_hash,
				contentHash: c.content_hash
			});
			expect(ok).toBe(true);
		});

		it(c.name + ' verifies via verifyRecord (full pipeline)', () => {
			const cleaned = stripTopLevelNulls(c.input_payload);
			const record: AgDRRecord = {
				version: '0.2',
				step_id: '00000000-0000-7000-8000-000000000000',
				timestamp: '2026-05-04T00:00:00Z',
				kind: 'llm_start',
				payload: cleaned,
				prev_hash: c.prev_hash,
				content_hash: c.content_hash,
				signature: c.signature_hex,
				signer_key: c.signer_key_hex
			};
			const result = verifyRecord(record);
			expect(result).toEqual({ ok: true });
		});
	}

	it('rejects a tampered payload via verifyRecord', () => {
		const c = fixtures.cases[0]!;
		const cleaned = stripTopLevelNulls(c.input_payload);
		const record: AgDRRecord = {
			version: '0.2',
			step_id: '00000000-0000-7000-8000-000000000000',
			timestamp: '2026-05-04T00:00:00Z',
			kind: 'llm_start',
			payload: { ...cleaned, prompt: 'TAMPERED' },
			prev_hash: c.prev_hash,
			content_hash: c.content_hash,
			signature: c.signature_hex,
			signer_key: c.signer_key_hex
		};
		const result = verifyRecord(record);
		expect(result.ok).toBe(false);
		expect(result.reason).toMatch(/content_hash mismatch/);
	});
});

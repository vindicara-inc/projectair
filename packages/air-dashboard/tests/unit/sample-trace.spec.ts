/**
 * End-to-end fidelity against the bundled sample trace.
 *
 * The signatures here were produced by an ephemeral key when the trace was
 * generated; we cannot reproduce them. Tests assert the bundled `signature_hex`
 * verifies against the bundled `signer_key_hex` for each record, and that the
 * full chain walks via `verifyChain` to status "ok".
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { canonicalJson } from '../../src/lib/agdr/canonical.ts';
import { blake3Hex } from '../../src/lib/agdr/blake3.ts';
import { verifySignature } from '../../src/lib/agdr/ed25519.ts';
import { verifyChain, verifyRecord } from '../../src/lib/agdr/verify.ts';
import type { AgDRRecord, StepKind } from '../../src/lib/agdr/types.ts';

interface SampleCase {
	index: number;
	step_id: string;
	kind: string;
	prev_hash: string;
	expected_content_hash: string;
	payload_for_canonicalization: Record<string, unknown>;
	signature_hex: string;
	signer_key_hex: string;
}
interface SampleFixture {
	cases: SampleCase[];
	source_log: string;
}

const FIXTURE_PATH = resolve(__dirname, '../fixtures/sample-trace-cases.json');
const fixture = JSON.parse(readFileSync(FIXTURE_PATH, 'utf-8')) as SampleFixture;

function recordFromCase(c: SampleCase): AgDRRecord {
	return {
		version: '0.1',
		step_id: c.step_id,
		timestamp: '2026-04-20T14:37:37.166553Z',
		kind: c.kind as StepKind,
		payload: c.payload_for_canonicalization,
		prev_hash: c.prev_hash,
		content_hash: c.expected_content_hash,
		signature: c.signature_hex,
		signer_key: c.signer_key_hex
	};
}

describe('sample trace per-record fidelity', () => {
	for (const c of fixture.cases) {
		it(`step ${c.index} (${c.kind}): canonical → BLAKE3 reproduces content_hash`, () => {
			const hash = blake3Hex(canonicalJson(c.payload_for_canonicalization));
			expect(hash).toBe(c.expected_content_hash);
		});

		it(`step ${c.index} (${c.kind}): bundled signature verifies`, () => {
			const ok = verifySignature({
				signatureHex: c.signature_hex,
				signerKeyHex: c.signer_key_hex,
				prevHash: c.prev_hash,
				contentHash: c.expected_content_hash
			});
			expect(ok).toBe(true);
		});

		it(`step ${c.index} (${c.kind}): verifyRecord returns ok`, () => {
			const result = verifyRecord(recordFromCase(c));
			expect(result.ok).toBe(true);
		});
	}
});

describe('sample trace full-chain verification', () => {
	it('verifyChain walks all 13 records to status ok', () => {
		const records = fixture.cases.map(recordFromCase);
		const result = verifyChain(records);
		expect(result.status).toBe('ok');
		expect(result.records_verified).toBe(records.length);
	});

	it('verifyChain detects payload tamper at the offending index', () => {
		const records = fixture.cases.map(recordFromCase);
		const targetIndex = 7;
		const tampered = {
			...records[targetIndex]!,
			payload: { ...records[targetIndex]!.payload, tool_output: 'TAMPERED OUTPUT' }
		};
		const mutated = [...records];
		mutated[targetIndex] = tampered;
		const result = verifyChain(mutated);
		expect(result.status).toBe('tampered');
		expect(result.failed_step_id).toBe(tampered.step_id);
	});
});

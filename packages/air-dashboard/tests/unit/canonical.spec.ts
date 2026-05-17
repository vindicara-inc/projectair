/**
 * Canonical JSON byte-equivalence to Python's airsdk._canonical_json.
 *
 * This is the ship-blocker: if any case here fails, every signature fails to
 * verify in the browser and the demo dies on stage.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { canonicalJson, canonicalString } from '../../src/lib/agdr/canonical.ts';
import { bytesToHex } from '@noble/hashes/utils';

interface FidelityCase {
	name: string;
	description: string;
	input_payload: Record<string, unknown>;
	canonical_bytes_hex: string;
	content_hash: string;
	prev_hash: string;
	signature_hex: string;
	signer_key_hex: string;
}

interface FixtureFile {
	schema_version: string;
	signer_key_hex: string;
	cases: FidelityCase[];
}

const FIXTURE_PATH = resolve(__dirname, '../fixtures/canonical-fixtures.json');
const fixtures = JSON.parse(readFileSync(FIXTURE_PATH, 'utf-8')) as FixtureFile;

/**
 * Mirror Python's pydantic `model_dump(exclude_none=True)` at the top level.
 * Production AgDR records arrive over the wire already stripped, but the
 * fixture's `input_payload` field is the raw user input — pre-process here so
 * tests exercise the full pipeline.
 */
function stripTopLevelNulls(obj: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(obj)) {
		if (v !== null && v !== undefined) out[k] = v;
	}
	return out;
}

describe('canonical JSON byte-equivalence', () => {
	for (const c of fixtures.cases) {
		it(c.name, () => {
			const cleaned = stripTopLevelNulls(c.input_payload);
			const bytes = canonicalJson(cleaned);
			expect(bytesToHex(bytes)).toBe(c.canonical_bytes_hex);
		});
	}

	it('round-trips a simple payload through canonicalString', () => {
		expect(canonicalString({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
	});

	it('throws on undefined values to surface caller mistakes', () => {
		expect(() => canonicalJson(undefined)).toThrow();
	});
});

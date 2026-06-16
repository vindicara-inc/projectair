/**
 * BLAKE3 content-hash equivalence to airsdk._blake3_hex(_canonical_json(payload)).
 *
 * Runs second after canonical.spec.ts; meaningful only if canonicalization
 * already passes. If this fails, suspect either canonicalizer drift or a
 * @noble/hashes BLAKE3 import-path issue.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { canonicalJson } from '../../src/lib/agdr/canonical.ts';
import { blake3Hex } from '../../src/lib/agdr/blake3.ts';

interface FidelityCase {
	name: string;
	input_payload: Record<string, unknown>;
	content_hash: string;
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

describe('BLAKE3 content_hash equivalence', () => {
	for (const c of fixtures.cases) {
		it(c.name, () => {
			const cleaned = stripTopLevelNulls(c.input_payload);
			const hash = blake3Hex(canonicalJson(cleaned));
			expect(hash).toBe(c.content_hash);
		});
	}
});

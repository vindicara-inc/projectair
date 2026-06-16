/**
 * Canonical JSON encoding — byte-for-byte mirror of Python's
 *   json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
 * defined at packages/projectair/src/airsdk/agdr.py:40-42.
 *
 * Rules:
 * - Object keys are sorted alphabetically at every level of nesting.
 * - No whitespace anywhere (compact separators).
 * - UTF-8 output (TextEncoder).
 * - Strings escape the same control chars as JSON.stringify (\\, \", \b, \f,
 *   \n, \r, \t); non-ASCII characters are emitted as raw UTF-8 (matches
 *   ensure_ascii=False).
 * - Forward slash is NOT escaped (matches both Python and JS defaults).
 *
 * Caller responsibility: pre-strip undefined and explicit-null fields if you
 * want to mirror Python's `model_dump(exclude_none=True)`. AgDR records on the
 * wire are already pre-stripped by the recorder, so the verifier passes them
 * through as-is.
 *
 * Known limitation: numeric float-vs-int divergence between Python and JS is
 * NOT handled. Python emits `1.0` as `"1.0"`; JS emits `1` as `"1"`. AgDR
 * payload schemas are string-heavy and the bundled traces contain no floats
 * in `tool_args`, so Phase 0 is unaffected. Document and revisit if downstream
 * consumers introduce numeric tool arguments.
 */

const ENCODER = new TextEncoder();

export function canonicalJson(value: unknown): Uint8Array {
	return ENCODER.encode(canonicalize(value));
}

export function canonicalString(value: unknown): string {
	return canonicalize(value);
}

function canonicalize(value: unknown): string {
	if (value === null) return 'null';
	if (value === undefined) {
		throw new Error('canonical JSON cannot encode undefined; pre-strip via exclude_none semantics');
	}
	const t = typeof value;
	if (t === 'boolean' || t === 'number' || t === 'string') {
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) {
		const items = value.map((item) => canonicalize(item));
		return '[' + items.join(',') + ']';
	}
	if (t === 'object') {
		const obj = value as Record<string, unknown>;
		const keys = Object.keys(obj).sort();
		const pairs: string[] = [];
		for (const k of keys) {
			const v = obj[k];
			if (v === undefined) continue;
			pairs.push(JSON.stringify(k) + ':' + canonicalize(v));
		}
		return '{' + pairs.join(',') + '}';
	}
	throw new Error(`canonical JSON does not support type ${t}`);
}

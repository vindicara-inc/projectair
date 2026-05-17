/**
 * verify_record + verify_chain — mirrors packages/projectair/src/airsdk/agdr.py.
 *
 * Walks records forward; each must (1) link to the previous record's
 * content_hash via prev_hash, (2) recompute its content_hash from the
 * canonical-JSON-encoded payload and match the stored value, and (3) verify
 * its Ed25519 signature against (prev_hash || content_hash).
 */

import { canonicalJson } from './canonical.ts';
import { blake3Hex } from './blake3.ts';
import { verifySignature } from './ed25519.ts';
import {
	type AgDRRecord,
	type VerificationResult,
	GENESIS_PREV_HASH
} from './types.ts';

export interface RecordVerification {
	ok: boolean;
	reason?: string;
}

export function verifyRecord(record: AgDRRecord): RecordVerification {
	const expectedHash = blake3Hex(canonicalJson(record.payload));
	if (expectedHash !== record.content_hash) {
		return {
			ok: false,
			reason: `content_hash mismatch: expected ${expectedHash}, got ${record.content_hash}`
		};
	}
	const signatureOk = verifySignature({
		signatureHex: record.signature,
		signerKeyHex: record.signer_key,
		prevHash: record.prev_hash,
		contentHash: record.content_hash
	});
	if (!signatureOk) {
		return { ok: false, reason: 'Ed25519 signature did not verify' };
	}
	return { ok: true };
}

export function verifyChain(records: AgDRRecord[]): VerificationResult {
	if (records.length === 0) {
		return { status: 'ok', records_verified: 0 };
	}
	let expectedPrev = GENESIS_PREV_HASH;
	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		if (record.prev_hash !== expectedPrev) {
			return {
				status: 'broken_chain',
				records_verified: index,
				failed_step_id: record.step_id,
				reason: `chain break at index ${index}: expected prev_hash ${expectedPrev}, got ${record.prev_hash}`
			};
		}
		const result = verifyRecord(record);
		if (!result.ok) {
			return {
				status: 'tampered',
				records_verified: index,
				failed_step_id: record.step_id,
				reason: result.reason
			};
		}
		expectedPrev = record.content_hash;
	}
	return { status: 'ok', records_verified: records.length };
}

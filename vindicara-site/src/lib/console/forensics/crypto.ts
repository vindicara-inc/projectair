// Real, in-browser AgDR chain crypto — the honest core of the tamper showcase.
//
// Mirrors airsdk/agdr.py exactly:
//   content_hash = BLAKE3( canonical_json(payload) )
//   signature    = Ed25519( prev_hash_bytes || content_hash_bytes )
//   verify walks forward: recompute content_hash, check signature, check prev link.
//
// Everything here runs offline in the browser via @noble (pure JS). Signing uses a
// fixed per-scenario seed so chains are byte-for-byte deterministic across reloads.

import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import type { AgDRPayload, AgDRRecord, StepKind, VerificationResult } from './types';

export const GENESIS_PREV_HASH = '0'.repeat(64);
export const AGDR_VERSION = '0.7';

// Stable JSON encoding: recursively sorted keys, compact separators, null/undefined
// dropped. Mirrors Python json.dumps(sort_keys=True, separators=(",",":"),
// ensure_ascii=False) over model_dump(exclude_none=True).
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort()) {
      const v = source[key];
      if (v === null || v === undefined) continue; // exclude_none
      out[key] = sortDeep(v);
    }
    return out;
  }
  return value;
}

export function contentHash(payload: AgDRPayload): string {
  return bytesToHex(blake3(utf8ToBytes(canonicalJson(payload))));
}

// Derive a deterministic 32-byte Ed25519 seed from any seed string (BLAKE3). Lets
// scenarios use memorable labels and removes hex-length foot-guns. Same input ->
// same key every time, so chains are reproducible across reloads.
function deriveSeed(seedMaterial: string): Uint8Array {
  return blake3(utf8ToBytes(seedMaterial), { dkLen: 32 });
}

export interface StepInput {
  kind: StepKind;
  step_id: string;
  timestamp: string;
  payload: AgDRPayload;
}

function signOne(prevHash: string, step: StepInput, seed: Uint8Array, pub: string): AgDRRecord {
  const content_hash = contentHash(step.payload);
  const signature = bytesToHex(ed25519.sign(hexToBytes(prevHash + content_hash), seed));
  return {
    version: AGDR_VERSION,
    step_id: step.step_id,
    timestamp: step.timestamp,
    kind: step.kind,
    payload: step.payload,
    prev_hash: prevHash,
    content_hash,
    signature,
    signer_key: pub,
    signature_algorithm: 'ed25519'
  };
}

// Sign an ordered list of steps into a tamper-evident chain.
export function buildSignedChain(
  steps: StepInput[],
  seedMaterial: string
): { records: AgDRRecord[]; signerKey: string } {
  const seed = deriveSeed(seedMaterial);
  const pub = bytesToHex(ed25519.getPublicKey(seed));
  const records: AgDRRecord[] = [];
  let prev = GENESIS_PREV_HASH;
  for (const step of steps) {
    const record = signOne(prev, step, seed, pub);
    records.push(record);
    prev = record.content_hash;
  }
  return { records, signerKey: pub };
}

// Append one signed step to an existing chain (e.g. a HUMAN_APPROVAL decision).
// Returns a new array; the new record links to the current head.
export function appendSignedStep(
  records: AgDRRecord[],
  step: StepInput,
  seedMaterial: string
): AgDRRecord[] {
  const seed = deriveSeed(seedMaterial);
  const pub = bytesToHex(ed25519.getPublicKey(seed));
  const prev = records.length ? records[records.length - 1].content_hash : GENESIS_PREV_HASH;
  return [...records, signOne(prev, step, seed, pub)];
}

export function verifyRecord(record: AgDRRecord): { ok: boolean; reason?: string } {
  const expected = contentHash(record.payload);
  if (expected !== record.content_hash) {
    return {
      ok: false,
      reason: `content_hash mismatch: expected ${expected.slice(0, 16)}…, got ${record.content_hash.slice(0, 16)}…`
    };
  }
  try {
    const ok = ed25519.verify(
      hexToBytes(record.signature),
      hexToBytes(record.prev_hash + record.content_hash),
      hexToBytes(record.signer_key)
    );
    if (!ok) return { ok: false, reason: 'ed25519 signature did not verify' };
  } catch (error) {
    return { ok: false, reason: `signature or key not valid: ${(error as Error).message}` };
  }
  return { ok: true };
}

// Walk the chain forward. Every record must verify and link to its predecessor.
// Mirrors verify_chain in agdr.py; adds failed_index for UI highlighting.
export function verifyChain(records: AgDRRecord[]): VerificationResult {
  if (records.length === 0) return { status: 'ok', records_verified: 0 };
  let expectedPrev = GENESIS_PREV_HASH;
  for (let index = 0; index < records.length; index++) {
    const record = records[index];
    if (record.prev_hash !== expectedPrev) {
      return {
        status: 'broken_chain',
        records_verified: index,
        failed_index: index,
        failed_step_id: record.step_id,
        reason: `chain break at step ${index + 1}: this record no longer links to the one before it`
      };
    }
    const { ok, reason } = verifyRecord(record);
    if (!ok) {
      return {
        status: 'tampered',
        records_verified: index,
        failed_index: index,
        failed_step_id: record.step_id,
        reason
      };
    }
    expectedPrev = record.content_hash;
  }
  return { status: 'ok', records_verified: records.length };
}

// Produce a tampered copy of a chain by mutating one record's payload in place on
// the clone, leaving its stored content_hash untouched — so verification recomputes
// the hash and fails at exactly that record. Used by "Simulate tamper".
export function tamperChain(
  records: AgDRRecord[],
  stepIndex: number,
  mutate: (payload: AgDRPayload) => void
): AgDRRecord[] {
  // JSON clone (not structuredClone): records may be Svelte $state proxies, which
  // structuredClone rejects. Payloads are plain JSON data, so this is safe.
  const clone: AgDRRecord[] = records.map((r) => ({
    ...r,
    payload: JSON.parse(JSON.stringify(r.payload)) as AgDRPayload
  }));
  if (clone[stepIndex]) mutate(clone[stepIndex].payload);
  return clone;
}

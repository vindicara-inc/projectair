/**
 * AgDR record types — TypeScript mirror of `airsdk.types`.
 *
 * AgDR is the on-disk format Project AIR writes for every agent step. The
 * public product term is "Signed Intent Capsule." Each record is content-
 * hashed with BLAKE3 and signed with Ed25519. The signature covers
 * (prev_hash || content_hash) producing a tamper-evident chain.
 *
 * Source of truth: packages/projectair/src/airsdk/types.py
 * Cross-language fidelity is enforced by tests/unit/canonical.spec.ts.
 */

export const AGDR_VERSION = '0.2';
export const GENESIS_PREV_HASH = '0'.repeat(64);

export type StepKind =
	| 'llm_start'
	| 'llm_end'
	| 'tool_start'
	| 'tool_end'
	| 'agent_finish'
	| 'agent_message';

export interface AgDRPayload {
	prompt?: string;
	response?: string;
	tool_name?: string;
	tool_args?: Record<string, unknown>;
	tool_output?: string;
	user_intent?: string;
	final_output?: string;
	source_agent_id?: string;
	target_agent_id?: string;
	message_content?: string;
	message_id?: string;
	[extra: string]: unknown;
}

export interface AgDRRecord {
	version: string;
	step_id: string;
	timestamp: string;
	kind: StepKind;
	payload: AgDRPayload;
	prev_hash: string;
	content_hash: string;
	signature: string;
	signer_key: string;
}

export type Severity = 'critical' | 'high' | 'medium';

export interface Finding {
	detector_id: string;
	title: string;
	severity: Severity;
	step_id: string;
	step_index: number;
	description: string;
}

export type VerificationStatus = 'ok' | 'tampered' | 'broken_chain';

export interface VerificationResult {
	status: VerificationStatus;
	records_verified: number;
	failed_step_id?: string;
	reason?: string;
}

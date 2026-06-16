/**
 * ASI07 Insecure Inter-Agent Communication -- TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_insecure_inter_agent_communication.
 *
 * Walks agent_message records for five failure modes:
 *   1. Missing identity (source_agent_id or target_agent_id empty)
 *   2. Missing message_id (no replay defense)
 *   3. Sender/key mismatch (impersonation)
 *   4. Replay (duplicate message_id)
 *   5. Protocol downgrade (pair previously used nonce, now omits)
 */

import type { AgDRRecord, Finding } from '../agdr/types';

export function detectInsecureInterAgentCommunication(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];

	const claimedKeys = new Map<string, string>();
	const seenMessageIds = new Set<string>();
	const pairUsedMessageId = new Map<string, boolean>();
	const pairFlaggedNoMsgId = new Set<string>();

	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		if (record.kind !== 'agent_message') continue;

		const src = record.payload.source_agent_id;
		const dst = record.payload.target_agent_id;
		const msgId = record.payload.message_id;
		const key = record.signer_key;

		// Check 1: missing identity
		if (!src || !dst) {
			const missing = !src ? 'source_agent_id' : 'target_agent_id';
			findings.push({
				detector_id: 'ASI07',
				title: 'Insecure Inter-Agent Communication',
				severity: 'high',
				step_id: record.step_id,
				step_index: index,
				description:
					`agent_message at step ${index} missing ${missing}. ` +
					`Inter-agent messages must carry both sender and receiver identity ` +
					`for channel authentication (OWASP ASI07 example #1).`
			});
			continue;
		}

		const pairKey = `${src}\x00${dst}`;

		// Check 3: sender/key mismatch
		const previousKey = claimedKeys.get(src);
		if (previousKey !== undefined && previousKey !== key) {
			findings.push({
				detector_id: 'ASI07',
				title: 'Insecure Inter-Agent Communication',
				severity: 'critical',
				step_id: record.step_id,
				step_index: index,
				description:
					`Agent \`${src}\` previously signed with key ${previousKey.slice(0, 16)}..., ` +
					`but this message is signed with ${key.slice(0, 16)}... ` +
					`Possible A2A descriptor forgery or agent impersonation ` +
					`(OWASP ASI07 example #5).`
			});
		} else if (previousKey === undefined) {
			claimedKeys.set(src, key);
		}

		// Checks 2, 4, 5: message_id handling
		if (msgId) {
			if (seenMessageIds.has(msgId)) {
				// Check 4: replay
				findings.push({
					detector_id: 'ASI07',
					title: 'Insecure Inter-Agent Communication',
					severity: 'high',
					step_id: record.step_id,
					step_index: index,
					description:
						`message_id \`${msgId}\` already observed earlier in this session. ` +
						`Possible replay on trust chains (OWASP ASI07 example #3).`
				});
			} else {
				seenMessageIds.add(msgId);
			}
			pairUsedMessageId.set(pairKey, true);
		} else {
			if (pairUsedMessageId.get(pairKey)) {
				// Check 5: downgrade
				findings.push({
					detector_id: 'ASI07',
					title: 'Insecure Inter-Agent Communication',
					severity: 'high',
					step_id: record.step_id,
					step_index: index,
					description:
						`Pair \`${src}\` -> \`${dst}\` previously exchanged nonced messages; ` +
						`message at step ${index} omits message_id. ` +
						`Possible protocol downgrade (OWASP ASI07 example #4).`
				});
			} else if (!pairFlaggedNoMsgId.has(pairKey)) {
				// Check 2: no nonce at all
				pairFlaggedNoMsgId.add(pairKey);
				findings.push({
					detector_id: 'ASI07',
					title: 'Insecure Inter-Agent Communication',
					severity: 'medium',
					step_id: record.step_id,
					step_index: index,
					description:
						`Pair \`${src}\` -> \`${dst}\` exchanges agent messages without ` +
						`message_id nonces. Replay attacks on this pair cannot be detected ` +
						`(OWASP ASI07 example #3).`
				});
			}
		}
	}

	return findings;
}

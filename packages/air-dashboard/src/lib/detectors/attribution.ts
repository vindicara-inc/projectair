/**
 * Shared agent attribution helper for ASI03 and ASI10.
 *
 * Resolves which registered agent is responsible for a record using the
 * same trust order as the Python _attribute_agent helper: a claimed
 * source_agent_id whose registered signer_key matches the record's actual
 * signer_key is attributed to that entry. A mismatched claim returns null
 * so scope rules are not applied to an identity the record cannot
 * substantiate.
 */

import type { AgDRRecord } from '../agdr/types';
import type { AgentDescriptor, AgentRegistry } from './asi10';

export function attributeAgent(
	record: AgDRRecord,
	registry: AgentRegistry
): AgentDescriptor | null {
	const byId = new Map<string, AgentDescriptor>();
	const bySignerKey = new Map<string, AgentDescriptor>();
	for (const agent of registry.agents) {
		byId.set(agent.id, agent);
		bySignerKey.set(agent.signer_key.toLowerCase(), agent);
	}
	return attributeAgentFromMaps(record, byId, bySignerKey);
}

export function attributeAgentFromMaps(
	record: AgDRRecord,
	byId: Map<string, AgentDescriptor>,
	bySignerKey: Map<string, AgentDescriptor>
): AgentDescriptor | null {
	const src = record.payload.source_agent_id;
	const signerKeyLc = record.signer_key.toLowerCase();
	if (src) {
		const registered = byId.get(src);
		if (registered === undefined) {
			return bySignerKey.get(signerKeyLc) ?? null;
		}
		if (registered.signer_key.toLowerCase() !== signerKeyLc) {
			return null;
		}
		return registered;
	}
	return bySignerKey.get(signerKeyLc) ?? null;
}

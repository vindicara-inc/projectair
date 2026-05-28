/**
 * ASI09 Human-Agent Trust Exploitation -- TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_human_agent_trust_exploitation.
 *
 * Flags LLM responses containing manipulation-pattern language (fabricated
 * authority, fake consensus, urgency, reassurance, false citations) that
 * immediately precede a sensitive tool invocation.
 */

import type { AgDRRecord, Finding } from '../agdr/types';

const SENSITIVE_TOOL_MARKERS = [
	'delete', 'drop', 'truncate', 'exec', 'shell', 'sudo', 'admin',
	'transfer', 'wire', 'refund', 'migrate', 'grant', 'revoke',
	'send_email', 'send_sms', 'post_to', 'publish'
];

const MANIPULATION_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
	[
		'fabricated authority',
		/\b(?:i(?:'|’)?ve|i\s+have)\s+(?:already\s+)?(?:verified|confirmed|validated|approved|cleared|checked|authenticated)\b/i
	],
	[
		'fake consensus',
		/\b(?:as\s+(?:we|you)\s+(?:discussed|agreed|requested)|per\s+(?:your|our)\s+(?:earlier|previous)|as\s+requested\s+earlier|per\s+our\s+prior\s+conversation)\b/i
	],
	[
		'reassurance override',
		/\b(?:this\s+is\s+(?:safe|routine|standard|pre[-\s]?approved|authorized)|no\s+(?:further|additional)\s+(?:checks?|reviews?|approvals?)\s+(?:needed|required)|auto[-\s]?approved|routine\s+action)\b/i
	],
	[
		'urgency pressure',
		/\b(?:urgent(?:ly)?|immediately|asap|before\s+(?:the\s+)?(?:cutoff|deadline|eod|close\s+of\s+business)|time[-\s]?sensitive|critical\s+deadline|right\s+now|without\s+delay)\b/i
	],
	[
		'false trusted-source citation',
		/\b(?:trusted\s+source\s+(?:confirms?|says|indicates|reports)|per\s+(?:the\s+)?(?:trusted|verified|approved)\s+(?:source|channel)|according\s+to\s+(?:a\s+)?verified\s+source)\b/i
	]
];

export function detectHumanAgentTrustExploitation(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];

	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		if (record.kind !== 'tool_start' || !record.payload.tool_name) continue;

		const toolNameLower = record.payload.tool_name.toLowerCase();
		if (!SENSITIVE_TOOL_MARKERS.some((m) => toolNameLower.includes(m))) continue;

		// Strict adjacency: the agent response must be immediately preceding
		if (index === 0) continue;
		const prior = records[index - 1]!;
		if (prior.kind !== 'llm_end' || !prior.payload.response) continue;

		const llmIndex = index - 1;
		const responseText = prior.payload.response;

		for (const [label, pattern] of MANIPULATION_PATTERNS) {
			const match = pattern.exec(responseText);
			if (match) {
				findings.push({
					detector_id: 'ASI09',
					title: 'Human-Agent Trust Exploitation',
					severity: 'high',
					step_id: record.step_id,
					step_index: index,
					description:
						`Sensitive tool \`${record.payload.tool_name}\` was invoked ` +
						`immediately after an agent response (step ${llmIndex}) ` +
						`containing \`${label}\` language ` +
						`(matched: "${match[0].slice(0, 60)}"). Review whether the ` +
						`rationale is grounded in verifiable evidence before ` +
						`the human approves (OWASP ASI09 examples #1/#4/#5/#7).`
				});
				break;
			}
		}
	}

	return findings;
}

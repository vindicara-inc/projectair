/**
 * AIR-01 Prompt Injection -- TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_prompt_injection.
 *
 * Scans llm_start prompts for known injection patterns: ignore-previous,
 * role-reset, fake system markers, jailbreak prefixes, rule overrides,
 * base64 payloads, bidi overrides, credential exfil requests.
 */

import type { AgDRRecord, Finding } from '../agdr/types';

export const INJECTION_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
	[
		'ignore-previous-instructions',
		/\b(?:ignore|disregard|forget)\s+(?:all\s+|the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|rules?|prompts?|messages?|directives?)\b/i
	],
	[
		'role-reset',
		/\b(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as|pretend\s+(?:to\s+be|you\s+are)|new\s+role|switch\s+roles?)\b/i
	],
	[
		'fake system marker',
		/(?:^|\n)\s*\[?(?:system|assistant|user)\s*\]?\s*[:>]\s/im
	],
	[
		'jailbreak prefix (DAN/developer mode)',
		/\b(?:DAN|do anything now|developer\s+mode|jailbreak|unfiltered|no restrictions?)\b/i
	],
	[
		'rule override',
		/\b(?:override|bypass|skip)\s+(?:safety|guard\w*|filter|policy|rules?|restrictions?)\b/i
	],
	[
		'base64 instruction payload',
		/\b(?:decode\s+(?:this|the following)|base64[:\s]+)\s*[A-Za-z0-9+/]{32,}={0,2}\b/i
	],
	[
		'unicode bidi override',
		/[‪-‮⁦-⁩]/
	],
	[
		'inline credential exfil request',
		/\b(?:reveal|print|output|show|list)\s+(?:your|the)\s+(?:system\s+prompt|instructions?|api[_\s-]?key|secret|token)\b/i
	]
];

export function detectPromptInjection(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];
	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		if (record.kind !== 'llm_start' || !record.payload.prompt) continue;
		const prompt = record.payload.prompt;
		for (const [label, pattern] of INJECTION_PATTERNS) {
			const match = pattern.exec(prompt);
			if (match) {
				findings.push({
					detector_id: 'AIR-01',
					title: 'Prompt Injection',
					severity: 'high',
					step_id: record.step_id,
					step_index: index,
					description:
						`Prompt at step ${index} matches the \`${label}\` pattern ` +
						`(matched: "${match[0].slice(0, 80)}").`
				});
				break;
			}
		}
	}
	return findings;
}

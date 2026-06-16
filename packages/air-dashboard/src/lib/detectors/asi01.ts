/**
 * ASI01 Agent Goal Hijack -- TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_goal_hijack.
 *
 * Computes token-overlap between the user's stated intent (first few prompts)
 * and each tool_start invocation. When a sensitive tool is called with low
 * overlap against the user's intent, it flags a goal-hijack finding.
 */

import type { AgDRRecord, Finding } from '../agdr/types';

const STOPWORDS = new Set([
	'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'do', 'for', 'from', 'have',
	'he', 'i', 'in', 'is', 'it', 'of', 'on', 'or', 'please', 'she', 'that', 'the',
	'their', 'them', 'they', 'this', 'to', 'was', 'were', 'will', 'with', 'you',
	'your', 'can', 'could', 'should', 'would', 'help', 'me', 'my', 'us', 'we'
]);

const SENSITIVE_TOOL_MARKERS = [
	'delete', 'drop', 'truncate', 'exec', 'shell', 'sudo', 'admin',
	'transfer', 'wire', 'refund', 'migrate', 'grant', 'revoke',
	'send_email', 'send_sms', 'post_to', 'publish'
];

const GOAL_HIJACK_THRESHOLD = 0.15;

const TOKEN_RE = /[a-zA-Z][a-zA-Z0-9_]{1,}/g;

function tokens(text: string): Set<string> {
	const out = new Set<string>();
	for (const match of text.toLowerCase().matchAll(TOKEN_RE)) {
		const w = match[0];
		if (!STOPWORDS.has(w)) out.add(w);
	}
	return out;
}

function extractUserIntent(records: AgDRRecord[]): string {
	const explicit: string[] = [];
	for (const r of records) {
		if (r.payload.user_intent) explicit.push(r.payload.user_intent);
	}
	if (explicit.length > 0) return explicit.join(' ');
	const prompts: string[] = [];
	for (const r of records) {
		if (r.kind === 'llm_start' && r.payload.prompt) {
			prompts.push(r.payload.prompt);
			if (prompts.length >= 3) break;
		}
	}
	return prompts.join(' ');
}

function toolContextText(record: AgDRRecord): string {
	const parts: string[] = [];
	if (record.payload.tool_name) parts.push(record.payload.tool_name);
	if (record.payload.tool_args) {
		for (const v of Object.values(record.payload.tool_args)) {
			parts.push(String(v));
		}
	}
	return parts.join(' ');
}

export function detectGoalHijack(records: AgDRRecord[]): Finding[] {
	const intentTokens = tokens(extractUserIntent(records));
	if (intentTokens.size === 0) return [];

	const findings: Finding[] = [];
	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		if (record.kind !== 'tool_start') continue;

		const toolText = toolContextText(record);
		const toolTokens = tokens(toolText);
		if (toolTokens.size === 0) continue;

		const union = new Set([...intentTokens, ...toolTokens]);
		let intersectionSize = 0;
		for (const t of intentTokens) {
			if (toolTokens.has(t)) intersectionSize++;
		}
		const overlap = intersectionSize / Math.max(union.size, 1);

		const toolNameLower = (record.payload.tool_name ?? '').toLowerCase();
		const looksSensitive = SENSITIVE_TOOL_MARKERS.some((m) => toolNameLower.includes(m));

		if (overlap < GOAL_HIJACK_THRESHOLD && looksSensitive) {
			findings.push({
				detector_id: 'ASI01',
				title: 'Agent Goal Hijack',
				severity: 'high',
				step_id: record.step_id,
				step_index: index,
				description: `Tool \`${record.payload.tool_name}\` called with token overlap ${overlap.toFixed(2)} against the user's stated intent. Threshold ${GOAL_HIJACK_THRESHOLD}. Tool is in the sensitive-actions list.`
			});
		}
	}
	return findings;
}

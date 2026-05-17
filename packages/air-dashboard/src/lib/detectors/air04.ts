/**
 * AIR-04 Untraceable Action — TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_untraceable_action
 * (line 586). AIR-native (no direct OWASP equivalent).
 *
 * Three sub-heuristics:
 *   1. tool_start without matching tool_end immediately after (high)
 *   2. llm_start without matching llm_end immediately after (high)
 *   3. consecutive timestamp gap > 300s (medium)
 */

import type { AgDRRecord, Finding } from '../agdr/types';

const TIME_GAP_THRESHOLD_SECONDS = 300;

function parseTimestamp(ts: string): number | null {
	const ms = Date.parse(ts);
	return Number.isFinite(ms) ? ms / 1000 : null;
}

export function detectUntraceableAction(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];

	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		const next = records[index + 1];

		if (record.kind === 'tool_start') {
			if (!next || next.kind !== 'tool_end') {
				findings.push({
					detector_id: 'AIR-04',
					title: 'Untraceable Action',
					severity: 'high',
					step_id: record.step_id,
					step_index: index,
					description: `tool_start for \`${record.payload.tool_name ?? '?'}\` at step ${index} is not followed by a matching tool_end. Tool outcome is not in the forensic chain.`
				});
			}
		} else if (record.kind === 'llm_start') {
			if (!next || next.kind !== 'llm_end') {
				findings.push({
					detector_id: 'AIR-04',
					title: 'Untraceable Action',
					severity: 'high',
					step_id: record.step_id,
					step_index: index,
					description: `llm_start at step ${index} is not followed by a matching llm_end. LLM response is not in the forensic chain.`
				});
			}
		}
	}

	for (let index = 1; index < records.length; index++) {
		const tPrev = parseTimestamp(records[index - 1]!.timestamp);
		const tCur = parseTimestamp(records[index]!.timestamp);
		if (tPrev !== null && tCur !== null && tCur - tPrev > TIME_GAP_THRESHOLD_SECONDS) {
			const gap = Math.round(tCur - tPrev);
			findings.push({
				detector_id: 'AIR-04',
				title: 'Untraceable Action',
				severity: 'medium',
				step_id: records[index]!.step_id,
				step_index: index,
				description: `Silent interval of ${gap}s between step ${index - 1} and step ${index} (threshold ${TIME_GAP_THRESHOLD_SECONDS}s). Agent activity during this window is not in the chain.`
			});
		}
	}

	return findings;
}

/**
 * AIR-03 Unrestricted Resource Consumption -- TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_resource_consumption.
 *
 * Three sub-heuristics:
 *   1. Burst: >BURST_THRESHOLD tool_start events in a BURST_WINDOW_SECONDS window
 *   2. Session total: >SESSION_TOTAL_THRESHOLD tool calls in the trace
 *   3. Single-tool loop: same tool_name invoked >=TOOL_REPEAT_THRESHOLD times
 */

import type { AgDRRecord, Finding } from '../agdr/types';

const BURST_WINDOW_SECONDS = 60;
const BURST_THRESHOLD = 20;
const SESSION_TOTAL_THRESHOLD = 50;
const TOOL_REPEAT_THRESHOLD = 10;

function parseTimestamp(ts: string): number | null {
	const ms = Date.parse(ts);
	return Number.isFinite(ms) ? ms / 1000 : null;
}

export function detectResourceConsumption(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];
	const toolStarts: Array<{ index: number; record: AgDRRecord }> = [];
	for (let i = 0; i < records.length; i++) {
		if (records[i]!.kind === 'tool_start') {
			toolStarts.push({ index: i, record: records[i]! });
		}
	}

	// (2) Session total
	if (toolStarts.length > SESSION_TOTAL_THRESHOLD) {
		const last = toolStarts[toolStarts.length - 1]!;
		findings.push({
			detector_id: 'AIR-03',
			title: 'Unrestricted Resource Consumption',
			severity: 'high',
			step_id: last.record.step_id,
			step_index: last.index,
			description:
				`Session total of ${toolStarts.length} tool calls exceeds ` +
				`threshold of ${SESSION_TOTAL_THRESHOLD}. Review for runaway ` +
				`agent behavior.`
		});
	}

	// (3) Single-tool repetition
	const nameCounts = new Map<string, { count: number; lastIndex: number; lastStepId: string }>();
	for (const { index, record } of toolStarts) {
		const name = record.payload.tool_name ?? '<unknown>';
		const existing = nameCounts.get(name);
		nameCounts.set(name, {
			count: (existing?.count ?? 0) + 1,
			lastIndex: index,
			lastStepId: record.step_id
		});
	}
	for (const [name, { count, lastIndex, lastStepId }] of nameCounts) {
		if (count >= TOOL_REPEAT_THRESHOLD) {
			findings.push({
				detector_id: 'AIR-03',
				title: 'Unrestricted Resource Consumption',
				severity: 'medium',
				step_id: lastStepId,
				step_index: lastIndex,
				description:
					`Tool \`${name}\` invoked ${count} times in a single session ` +
					`(threshold ${TOOL_REPEAT_THRESHOLD}). Possible loop or runaway retry.`
			});
		}
	}

	// (1) Burst: rolling window over tool_start timestamps
	const timestamps: Array<{ index: number; record: AgDRRecord; t: number }> = [];
	for (const { index, record } of toolStarts) {
		const t = parseTimestamp(record.timestamp);
		if (t !== null) timestamps.push({ index, record, t });
	}
	for (let left = 0; left < timestamps.length; left++) {
		const windowEnd = timestamps[left]!.t + BURST_WINDOW_SECONDS;
		let right = left;
		while (right < timestamps.length && timestamps[right]!.t <= windowEnd) {
			right++;
		}
		const count = right - left;
		if (count > BURST_THRESHOLD) {
			const last = timestamps[right - 1]!;
			findings.push({
				detector_id: 'AIR-03',
				title: 'Unrestricted Resource Consumption',
				severity: 'high',
				step_id: last.record.step_id,
				step_index: last.index,
				description:
					`${count} tool calls inside a ${BURST_WINDOW_SECONDS}s window ` +
					`(threshold ${BURST_THRESHOLD}). Possible denial-of-service ` +
					`or runaway plan.`
			});
			break; // one burst finding per trace
		}
	}

	return findings;
}

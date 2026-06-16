/**
 * ASI08 Cascading Failures -- TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_cascading_failures.
 *
 * Two structural checks over agent_message records:
 *   1. Oscillating feedback loop between a pair (A->B->A->B beyond threshold)
 *   2. Fan-out burst (one source to many distinct targets in a short window)
 */

import type { AgDRRecord, Finding } from '../agdr/types';

const OSCILLATION_PAIR_THRESHOLD = 4;
const FAN_OUT_TARGET_THRESHOLD = 5;
const FAN_OUT_WINDOW_RECORDS = 10;

interface MessageEntry {
	index: number;
	src: string;
	dst: string;
	record: AgDRRecord;
}

export function detectCascadingFailures(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];

	// Collect inter-agent messages in order
	const messages: MessageEntry[] = [];
	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		if (record.kind !== 'agent_message') continue;
		const src = record.payload.source_agent_id;
		const dst = record.payload.target_agent_id;
		if (src && dst) {
			messages.push({ index, src, dst, record });
		}
	}

	if (messages.length === 0) return findings;

	// Check 1: oscillating feedback loop between an unordered pair
	const pairSequences = new Map<string, MessageEntry[]>();
	for (const entry of messages) {
		const pairKey = [entry.src, entry.dst].sort().join('\x00');
		const seq = pairSequences.get(pairKey) ?? [];
		seq.push(entry);
		pairSequences.set(pairKey, seq);
	}

	for (const [pairKey, seq] of pairSequences) {
		const parts = pairKey.split('\x00');
		if (parts.length !== 2 || parts[0] === parts[1]) continue;
		if (seq.length < OSCILLATION_PAIR_THRESHOLD * 2) continue;

		let flips = 0;
		let lastDir: string | null = null;
		for (const entry of seq) {
			const direction = `${entry.src}\x00${entry.dst}`;
			if (lastDir !== null && direction !== lastDir) {
				flips++;
			}
			lastDir = direction;
		}
		const cycles = Math.floor((flips + 1) / 2);

		if (cycles >= OSCILLATION_PAIR_THRESHOLD) {
			const last = seq[seq.length - 1]!;
			const [a, b] = parts;
			findings.push({
				detector_id: 'ASI08',
				title: 'Cascading Failures',
				severity: 'high',
				step_id: last.record.step_id,
				step_index: last.index,
				description:
					`Pair \`${a}\` <-> \`${b}\` exchanged ${seq.length} messages in an ` +
					`oscillating pattern (${cycles} full cycles, threshold ` +
					`${OSCILLATION_PAIR_THRESHOLD}). Feedback-loop amplification; ` +
					`compounds any initial fault across the pair ` +
					`(OWASP ASI08 example #7).`
			});
		}
	}

	// Check 2: fan-out burst (sliding window over record indices)
	let windowStart = 0;
	const flaggedFanoutSources = new Set<string>();
	for (let windowEnd = 0; windowEnd < messages.length; windowEnd++) {
		while (
			windowStart < windowEnd &&
			messages[windowEnd]!.index - messages[windowStart]!.index > FAN_OUT_WINDOW_RECORDS
		) {
			windowStart++;
		}
		const sourceToTargets = new Map<string, Set<string>>();
		for (let i = windowStart; i <= windowEnd; i++) {
			const entry = messages[i]!;
			const targets = sourceToTargets.get(entry.src) ?? new Set<string>();
			targets.add(entry.dst);
			sourceToTargets.set(entry.src, targets);
		}
		for (const [source, targets] of sourceToTargets) {
			if (flaggedFanoutSources.has(source)) continue;
			if (targets.size >= FAN_OUT_TARGET_THRESHOLD) {
				const last = messages[windowEnd]!;
				findings.push({
					detector_id: 'ASI08',
					title: 'Cascading Failures',
					severity: 'critical',
					step_id: last.record.step_id,
					step_index: last.index,
					description:
						`Agent \`${source}\` sent messages to ${targets.size} distinct ` +
						`agents within ${FAN_OUT_WINDOW_RECORDS} records ` +
						`(threshold ${FAN_OUT_TARGET_THRESHOLD}). High-fan-out hub; ` +
						`compromise multiplies blast radius ` +
						`(OWASP ASI08 example #1/#3).`
				});
				flaggedFanoutSources.add(source);
			}
		}
	}

	return findings;
}

/**
 * AIR-06 NemoGuard Corroboration -- TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_nemoguard_corroboration.
 *
 * Cross-corroboration between AIR heuristic detectors and NemoGuard NIM
 * classifiers. When both agree on a finding near the same step, emits a
 * corroboration finding with critical severity.
 *
 * Must run AFTER all other detectors; takes prior_findings as input.
 */

import type { AgDRRecord, Finding } from '../agdr/types';

const NEMOGUARD_CORROBORATION_MAP: Record<string, string[]> = {
	jailbreak_detect: ['AIR-01'],
	content_safety: ['AIR-01', 'AIR-02', 'ASI09'],
	topic_control: ['ASI01']
};

const NEMOGUARD_CLASSIFIER_LABELS: Record<string, string> = {
	jailbreak_detect: 'NemoGuard JailbreakDetect',
	content_safety: 'NemoGuard ContentSafety',
	topic_control: 'NemoGuard TopicControl'
};

const CORROBORATION_WINDOW = 5;

interface UnsafeEntry {
	index: number;
	classifier: string;
	label: string;
	extra: Record<string, unknown>;
}

export function detectNemoGuardCorroboration(
	records: AgDRRecord[],
	priorFindings: Finding[]
): Finding[] {
	const findings: Finding[] = [];
	if (priorFindings.length === 0) return findings;

	// Collect unsafe NemoGuard entries
	const unsafeEntries: UnsafeEntry[] = [];
	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		if (record.kind !== 'tool_end') continue;
		const payload = record.payload;
		if (!payload.nemoguard_classifier) continue;
		if (payload.nemoguard_safe === true || payload.nemoguard_safe === undefined) continue;

		const classifier = String(payload.nemoguard_classifier);
		const label = NEMOGUARD_CLASSIFIER_LABELS[classifier] ?? classifier;
		unsafeEntries.push({ index, classifier, label, extra: payload as Record<string, unknown> });
	}

	if (unsafeEntries.length === 0) return findings;

	const corroborated = new Set<string>();

	for (const finding of priorFindings) {
		for (const ng of unsafeEntries) {
			const corroborateIds = NEMOGUARD_CORROBORATION_MAP[ng.classifier] ?? [];
			if (!corroborateIds.includes(finding.detector_id)) continue;
			if (Math.abs(finding.step_index - ng.index) > CORROBORATION_WINDOW) continue;

			const key = `${finding.detector_id}:${finding.step_index}:${ng.index}`;
			if (corroborated.has(key)) continue;
			corroborated.add(key);

			let detail = '';
			if (ng.classifier === 'jailbreak_detect') {
				const score = Number(ng.extra['nemoguard_score'] ?? 0);
				detail = ` (score=${score.toFixed(4)})`;
			} else if (ng.classifier === 'content_safety') {
				const cats = (ng.extra['nemoguard_categories'] ?? []) as string[];
				if (cats.length > 0) {
					detail = ` (categories: ${cats.join(', ')})`;
				}
			}

			findings.push({
				detector_id: 'AIR-06',
				title: 'NemoGuard Corroboration',
				severity: 'critical',
				step_id: finding.step_id,
				step_index: finding.step_index,
				description:
					`AIR detector ${finding.detector_id} (${finding.title}) at step ` +
					`${finding.step_index} is independently corroborated by ` +
					`${ng.label}${detail} at step ${ng.index}. ` +
					`Two independent signals agree: AIR heuristic + NVIDIA safety model.`
			});
		}
	}

	return findings;
}

/**
 * AIR-05 NemoGuard Safety Classification -- TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_nemoguard_safety.
 *
 * Walks tool_end records with NemoGuard classifier metadata. When a
 * classifier reports unsafe content, emits a finding.
 *
 * Three classifiers: jailbreak_detect, content_safety, topic_control.
 */

import type { AgDRRecord, Finding, Severity } from '../agdr/types';

const NEMOGUARD_CLASSIFIER_LABELS: Record<string, string> = {
	jailbreak_detect: 'NemoGuard JailbreakDetect',
	content_safety: 'NemoGuard ContentSafety',
	topic_control: 'NemoGuard TopicControl'
};

const CRITICAL_CATEGORIES = new Set(['S1', 'S3', 'S7', 'S17', 'S22']);

function getNemoGuardExtra(record: AgDRRecord): Record<string, unknown> | null {
	const payload = record.payload;
	if (!payload.nemoguard_classifier) return null;
	return payload as Record<string, unknown>;
}

export function detectNemoGuardSafety(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];

	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		if (record.kind !== 'tool_end') continue;
		const extra = getNemoGuardExtra(record);
		if (extra === null) continue;

		const classifier = String(extra['nemoguard_classifier'] ?? '');
		const safe = extra['nemoguard_safe'];
		if (safe === true || safe === undefined) continue;

		const label = NEMOGUARD_CLASSIFIER_LABELS[classifier] ?? classifier;

		if (classifier === 'jailbreak_detect') {
			const score = Number(extra['nemoguard_score'] ?? 0);
			findings.push({
				detector_id: 'AIR-05',
				title: 'NemoGuard Safety Classification',
				severity: 'high',
				step_id: record.step_id,
				step_index: index,
				description:
					`${label} flagged jailbreak attempt ` +
					`(score=${score.toFixed(4)}). NVIDIA-backed classification.`
			});
		} else if (classifier === 'content_safety') {
			const categories = (extra['nemoguard_categories'] ?? []) as string[];
			const catLabels = (extra['nemoguard_category_labels'] ?? []) as string[];
			const hasCritical = categories.some((c) => CRITICAL_CATEGORIES.has(c));
			const severity: Severity = hasCritical ? 'critical' : 'high';
			const catStr =
				categories.length > 0
					? categories.map((cat, i) => `${cat} (${catLabels[i] ?? ''})`).join(', ')
					: 'unspecified';
			findings.push({
				detector_id: 'AIR-05',
				title: 'NemoGuard Safety Classification',
				severity,
				step_id: record.step_id,
				step_index: index,
				description: `${label} flagged unsafe content: ${catStr}. NVIDIA-backed classification.`
			});
		} else if (classifier === 'topic_control') {
			findings.push({
				detector_id: 'AIR-05',
				title: 'NemoGuard Safety Classification',
				severity: 'medium',
				step_id: record.step_id,
				step_index: index,
				description: `${label} flagged off-topic content. NVIDIA-backed classification.`
			});
		}
	}

	return findings;
}

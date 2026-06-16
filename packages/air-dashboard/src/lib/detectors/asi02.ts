/**
 * ASI02 Tool Misuse & Exploitation — TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_tool_misuse (line 345)
 * and DANGEROUS_ARG_PATTERNS (line 96).
 *
 * Inspects each tool_start record's tool_args values for shell metacharacters,
 * path traversal, unbounded SQL, SSRF-shaped URLs, and credential leaks.
 * Emits at most one finding per record (first matching pattern wins).
 */

import type { AgDRRecord, Finding } from '../agdr/types';

const DANGEROUS_ARG_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
	['shell metacharacters', /(?:\||;|&&|\$\(|`).*(?:rm|curl|wget|nc\s|bash|sh\s)/i],
	['path traversal', /\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow|%2e%2e/i],
	['unbounded SQL DELETE', /delete\s+from\s+\w+(?:\s*;|\s*$)/i],
	['unbounded SQL UPDATE', /update\s+\w+\s+set\s+[^;]*?(?:;|$)(?!.*where)/is],
	[
		'SSRF-shaped URL',
		/https?:\/\/(?:127\.|0\.0\.0\.0|localhost|169\.254\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)/i
	],
	['credential leak', /(?:aws_secret|api[_-]?key|password|bearer\s+[a-z0-9]{20,})/i]
];

export function detectToolMisuse(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];
	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		if (record.kind !== 'tool_start' || !record.payload.tool_args) continue;
		const argBlob = Object.values(record.payload.tool_args)
			.map((v) => String(v))
			.join(' ');
		for (const [label, pattern] of DANGEROUS_ARG_PATTERNS) {
			if (pattern.test(argBlob)) {
				findings.push({
					detector_id: 'ASI02',
					title: 'Tool Misuse & Exploitation',
					severity: 'critical',
					step_id: record.step_id,
					step_index: index,
					description: `Tool \`${record.payload.tool_name ?? '?'}\` invoked with arguments matching pattern: ${label}.`
				});
				break;
			}
		}
	}
	return findings;
}

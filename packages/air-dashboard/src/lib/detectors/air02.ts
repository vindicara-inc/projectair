/**
 * AIR-02 Sensitive Data Exposure — TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_sensitive_data_exposure
 * (line 424) and SENSITIVE_DATA_PATTERNS (line 120).
 *
 * Maps to OWASP LLM06 Sensitive Information Disclosure. Scans every text
 * field on every record (prompt, response, tool_output, final_output, every
 * tool_args value as string). Emits one finding per (record, field, pattern).
 */

import type { AgDRRecord, Finding, Severity } from '../agdr/types';

const SENSITIVE_DATA_PATTERNS: ReadonlyArray<readonly [string, Severity, RegExp]> = [
	['PEM private key', 'critical', /-----BEGIN (?:RSA|EC|OPENSSH|PGP|DSA|ENCRYPTED)?\s?PRIVATE KEY-----/],
	['AWS access key', 'critical', /\bAKIA[0-9A-Z]{16}\b/],
	['GitHub PAT (fine-grained)', 'critical', /\bgithub_pat_[0-9a-zA-Z_]{70,}\b/],
	['GitHub token', 'critical', /\bgh[pousr]_[0-9A-Za-z]{30,}\b/],
	['OpenAI API key', 'critical', /\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b/],
	['Anthropic API key', 'critical', /\bsk-ant-[A-Za-z0-9_\-]{32,}\b/],
	['Slack token', 'critical', /\bxox[abprsu]-[A-Za-z0-9-]{10,}\b/],
	['JWT', 'high', /\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/],
	['PyPI token', 'critical', /\bpypi-AgE[A-Za-z0-9_\-]{20,}\b/],
	['SSN (US)', 'high', /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/],
	['credit card (16 digits)', 'high', /\b(?:\d{4}[ -]?){3}\d{4}\b/]
];

function recordTextFields(record: AgDRRecord): Array<readonly [string, string]> {
	const out: Array<readonly [string, string]> = [];
	const p = record.payload;
	if (p.prompt) out.push(['prompt', p.prompt]);
	if (p.response) out.push(['response', p.response]);
	if (p.tool_output) out.push(['tool_output', p.tool_output]);
	if (p.final_output) out.push(['final_output', p.final_output]);
	if (p.tool_args) {
		for (const [k, v] of Object.entries(p.tool_args)) {
			out.push([`tool_args[${k}]`, String(v)]);
		}
	}
	return out;
}

export function detectSensitiveDataExposure(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];
	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		for (const [fieldLabel, text] of recordTextFields(record)) {
			for (const [patternLabel, severity, pattern] of SENSITIVE_DATA_PATTERNS) {
				if (pattern.test(text)) {
					findings.push({
						detector_id: 'AIR-02',
						title: 'Sensitive Data Exposure',
						severity,
						step_id: record.step_id,
						step_index: index,
						description: `Field \`${fieldLabel}\` at step ${index} contains a value matching the \`${patternLabel}\` pattern.`
					});
				}
			}
		}
	}
	return findings;
}

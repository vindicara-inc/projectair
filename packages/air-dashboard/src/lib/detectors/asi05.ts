/**
 * ASI05 Unexpected Code Execution (RCE) — TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_unexpected_code_execution
 * (line 855) and EXECUTION_TOOL_PATTERNS (line 205).
 *
 * Inspects tool_start.tool_name for execution-semantics patterns. Direct
 * evaluators / unsafe deserialization → critical; shell-runners / package
 * installers → high. Highest-priority match wins (first match = stop).
 */

import type { AgDRRecord, Finding, Severity } from '../agdr/types';

const EXECUTION_TOOL_PATTERNS: ReadonlyArray<readonly [string, Severity, RegExp]> = [
	[
		'python/code eval',
		'critical',
		/\b(?:python_?eval|exec_?python|python_?exec|run_python|execute_code|code_interpreter|eval_code|run_code)\b/i
	],
	[
		'javascript eval',
		'critical',
		/\b(?:js_?eval|javascript_?eval|node_?eval|run_javascript|execute_js)\b/i
	],
	[
		'unsafe deserialization',
		'critical',
		/\b(?:unpickle|pickle_?load|yaml_?load_unsafe|yaml_?unsafe_?load|marshal_?load|unserialize|load_pickle)\b/i
	],
	[
		'shell execution',
		'high',
		/\b(?:shell_?exec|run_shell|bash_?exec|exec_?shell|subprocess_run|system_?exec|spawn_shell|run_command|execute_shell)\b/i
	],
	[
		'package install',
		'high',
		/\b(?:pip_?install|npm_?install|yarn_?add|cargo_?install|gem_?install|apt_?install|brew_?install|package_install)\b/i
	]
];

export function detectUnexpectedCodeExecution(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];
	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		if (record.kind !== 'tool_start' || !record.payload.tool_name) continue;
		const toolName = record.payload.tool_name;
		for (const [label, severity, pattern] of EXECUTION_TOOL_PATTERNS) {
			if (pattern.test(toolName)) {
				findings.push({
					detector_id: 'ASI05',
					title: 'Unexpected Code Execution (RCE)',
					severity,
					step_id: record.step_id,
					step_index: index,
					description: `Tool \`${toolName}\` matches the \`${label}\` execution-semantics pattern. Verify the tool runs in a sandboxed, least-privilege environment and that its inputs are validated (OWASP ASI05 mitigation #3/#4/#5).`
				});
				break;
			}
		}
	}
	return findings;
}

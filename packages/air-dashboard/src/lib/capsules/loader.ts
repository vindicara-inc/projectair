/**
 * Scenario loader: fetch a JSONL trace file and parse it into AgDRRecord[].
 *
 * Scenarios live under `static/scenarios/*.jsonl` and are fetched relative to
 * the dashboard root (`/scenarios/<name>.jsonl`). Malformed lines reject the
 * promise; partial loads are not surfaced as success.
 */

import type { AgDRRecord } from '../agdr/types.ts';
import { base } from '$app/paths';

export interface Scenario {
	id: string;
	label: string;
	description: string;
	path: string;
}

export const SCENARIOS: readonly Scenario[] = [
	{
		id: 'baseline',
		label: 'Baseline · clean run',
		description: 'Clean trace with no findings. Verifier ledger fills with all-cyan ✓.',
		path: '/scenarios/baseline.jsonl'
	},
	{
		id: 'sales-exfil',
		label: 'Sales report · exfiltration',
		description:
			'Q3 sales report request. Agent attempts admin_delete_records (blocked) and shell_exec curl exfil.',
		path: '/scenarios/sales-exfil.jsonl'
	},
	{
		id: 'tamper',
		label: 'Tamper · chain integrity break',
		description:
			'Sales-exfil with one capsule payload mutated. Verifier halts, chain visibly snaps, integrity crashes to zero.',
		path: '/scenarios/tamper.jsonl'
	}
] as const;

/**
 * Per-detector demo traces. Each trace is crafted to make exactly one detector
 * fire visibly so the operator can click ASI02 → see ASI02 fire. Used by the
 * DetectorButtons panel.
 */
export interface DetectorScenario {
	detectorId: string;
	scenarioPath: string;
	registryPath?: string;
	headline: string;
}

export const DETECTOR_SCENARIOS: Record<string, DetectorScenario> = {
	ASI02: {
		detectorId: 'ASI02',
		scenarioPath: '/scenarios/asi02-shell-injection.jsonl',
		headline: 'ssh_exec invoked with shell-injection in args (rm + curl | sh)'
	},
	ASI05: {
		detectorId: 'ASI05',
		scenarioPath: '/scenarios/asi05-rce.jsonl',
		headline: 'python_eval invoked — execution-semantics tool name'
	},
	'AIR-02': {
		detectorId: 'AIR-02',
		scenarioPath: '/scenarios/air02-credential-leak.jsonl',
		headline: 'AWS access key returned in tool_output of read_file(.env)'
	},
	'AIR-04': {
		detectorId: 'AIR-04',
		scenarioPath: '/scenarios/air04-untraceable.jsonl',
		headline: 'tool_start with no matching tool_end — outcome not in chain'
	},
	ASI10: {
		detectorId: 'ASI10',
		scenarioPath: '/scenarios/asi10-rogue-tool.jsonl',
		registryPath: '/scenarios/registries/analytics-agent.yaml',
		headline: 'agent invokes wire_transfer outside declared expected_tools'
	}
} as const;

export async function loadScenario(scenario: Scenario, fetchImpl: typeof fetch = fetch): Promise<AgDRRecord[]> {
	const response = await fetchImpl(`${base}${scenario.path}`);
	if (!response.ok) {
		throw new Error(`failed to fetch scenario ${scenario.id}: HTTP ${response.status}`);
	}
	const text = await response.text();
	return parseJsonl(text);
}

export function parseJsonl(text: string): AgDRRecord[] {
	const records: AgDRRecord[] = [];
	const lines = text.split('\n');
	for (let lineNo = 0; lineNo < lines.length; lineNo++) {
		const line = lines[lineNo]!.trim();
		if (line.length === 0) continue;
		try {
			records.push(JSON.parse(line) as AgDRRecord);
		} catch (cause) {
			throw new Error(`malformed JSONL on line ${lineNo + 1}: ${(cause as Error).message}`);
		}
	}
	return records;
}

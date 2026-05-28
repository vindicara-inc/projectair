/**
 * ASI04 Agentic Supply Chain Vulnerabilities -- TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_mcp_supply_chain_risk.
 *
 * Flags tool_start records whose tool_name matches MCP server invocation
 * naming conventions for supply-chain review.
 */

import type { AgDRRecord, Finding } from '../agdr/types';

const MCP_TOOL_PATTERN = /(?:^mcp[_\-.]|[_\-]mcp[_\-]|^mcp\.)/i;

export function detectMcpSupplyChainRisk(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];
	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;
		if (record.kind !== 'tool_start' || !record.payload.tool_name) continue;
		const name = record.payload.tool_name;
		if (MCP_TOOL_PATTERN.test(name)) {
			findings.push({
				detector_id: 'ASI04',
				title: 'Agentic Supply Chain Vulnerabilities',
				severity: 'medium',
				step_id: record.step_id,
				step_index: index,
				description:
					`Tool \`${name}\` matches an MCP server invocation naming ` +
					`pattern. Cross-reference against your MCP inventory and ` +
					`verify server identity, version, and scope.`
			});
		}
	}
	return findings;
}

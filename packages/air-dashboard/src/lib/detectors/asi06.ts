/**
 * ASI06 Memory & Context Poisoning -- TypeScript port of
 * packages/projectair/src/airsdk/detections.py:detect_memory_context_poisoning.
 *
 * Two heuristic checks:
 *   1. Retrieval-class tool outputs containing injection-shaped content.
 *   2. Memory-write-class tool arguments containing injection-shaped content.
 */

import type { AgDRRecord, Finding } from '../agdr/types';
import { INJECTION_PATTERNS } from './air01';

const RETRIEVAL_TOOL_MARKERS = [
	'memory', 'recall', 'retrieve', 'rag', 'vector',
	'knowledge_base', 'kb_read', 'kb_lookup', 'kb_query',
	'embeddings_query', 'context_load', 'lookup_memory',
	'fetch_memory', 'semantic_search'
];

const MEMORY_WRITE_TOOL_MARKERS = [
	'memory_write', 'remember', 'save_context', 'vector_add',
	'vector_upsert', 'rag_upsert', 'rag_add', 'kb_write',
	'store_memory', 'persist_memory', 'memorize', 'embed_and_store'
];

function matchesMarker(nameLower: string, markers: readonly string[]): boolean {
	return markers.some((m) => nameLower.includes(m));
}

export function detectMemoryContextPoisoning(records: AgDRRecord[]): Finding[] {
	const findings: Finding[] = [];

	for (let index = 0; index < records.length; index++) {
		const record = records[index]!;

		// Check 2: poisoned memory write
		if (record.kind === 'tool_start' && record.payload.tool_name && record.payload.tool_args) {
			const nameLower = record.payload.tool_name.toLowerCase();
			if (matchesMarker(nameLower, MEMORY_WRITE_TOOL_MARKERS)) {
				const argBlob = Object.values(record.payload.tool_args)
					.map((v) => String(v))
					.join(' ');
				for (const [label, pattern] of INJECTION_PATTERNS) {
					const match = pattern.exec(argBlob);
					if (match) {
						findings.push({
							detector_id: 'ASI06',
							title: 'Memory & Context Poisoning',
							severity: 'critical',
							step_id: record.step_id,
							step_index: index,
							description:
								`Memory-write tool \`${record.payload.tool_name}\` ` +
								`invoked with argument matching injection pattern ` +
								`\`${label}\` (matched: "${match[0].slice(0, 60)}"). ` +
								`Persisting this risks long-term memory poisoning ` +
								`across sessions (OWASP ASI06 example #4/#5).`
						});
						break;
					}
				}
			}
			continue;
		}

		// Check 1: poisoned retrieval output
		if (record.kind === 'tool_end' && index > 0) {
			const prior = records[index - 1]!;
			if (prior.kind !== 'tool_start' || !prior.payload.tool_name) continue;
			const nameLower = prior.payload.tool_name.toLowerCase();
			if (!matchesMarker(nameLower, RETRIEVAL_TOOL_MARKERS)) continue;
			const output = record.payload.tool_output ?? '';
			for (const [label, pattern] of INJECTION_PATTERNS) {
				const match = pattern.exec(output);
				if (match) {
					findings.push({
						detector_id: 'ASI06',
						title: 'Memory & Context Poisoning',
						severity: 'high',
						step_id: record.step_id,
						step_index: index,
						description:
							`Retrieval tool \`${prior.payload.tool_name}\` returned ` +
							`content matching injection pattern \`${label}\` ` +
							`(matched: "${match[0].slice(0, 60)}"). The memory or ` +
							`retrieval store may be poisoned ` +
							`(OWASP ASI06 example #1/#3).`
					});
					break;
				}
			}
		}
	}

	return findings;
}

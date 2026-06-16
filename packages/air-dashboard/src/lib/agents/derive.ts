import type { AgDRRecord, Finding } from '../agdr/types.ts';
import type { FindingTemplate } from '../templates/types.ts';
import { fillTemplate } from '../templates/fill.ts';

export interface AgentNode {
  id: string;
  status: 'active' | 'halted' | 'flagged' | 'critical';
  ops: number;
  tools: string[];
  lastAction: string;
}

export interface AgentEdge {
  from: string;
  to: string;
  kind: string;
}

export interface IncidentVM {
  id: string;
  title: string;
  description: string;
  agentId: string;
  severity: string;
  detector: string;
  stepIndex: number;
  finding: Finding;
  toolName: string | null;
  timestamp: string;
}

export function inferAgentId(rec: AgDRRecord, idx: number): string {
  if (rec.payload?.source_agent_id) return rec.payload.source_agent_id;
  if (rec.payload?.tool_name) {
    const t = rec.payload.tool_name;
    if (t.includes('crm') || t.includes('email')) return 'sales-agent';
    if (t.includes('admin') || t.includes('delete')) return 'admin-agent';
    if (t.includes('shell') || t.includes('exec')) return 'ops-agent';
    if (t.includes('search') || t.includes('read')) return 'research-agent';
    return 'task-agent';
  }
  if (rec.kind === 'llm_start' || rec.kind === 'llm_end') return 'llm-agent';
  if (rec.kind === 'agent_message') return 'coordinator';
  if (rec.kind === 'agent_finish') return 'coordinator';
  return `agent-${String(Math.floor(idx / 4) + 1).padStart(2, '0')}`;
}

export function buildFleet(
  records: AgDRRecord[],
  findings: Finding[],
  pendingIndices: Set<number>,
): AgentNode[] {
  const m = new Map<string, AgentNode>();
  for (let i = 0; i < records.length; i++) {
    const rec = records[i]!;
    const aid = inferAgentId(rec, i);
    const act = describeAction(rec);
    const ex = m.get(aid);
    if (!ex) {
      m.set(aid, { id: aid, status: 'active', ops: 1, tools: rec.payload?.tool_name ? [rec.payload.tool_name] : [], lastAction: act });
    } else {
      ex.ops++;
      ex.lastAction = act;
      if (rec.payload?.tool_name && !ex.tools.includes(rec.payload.tool_name)) ex.tools.push(rec.payload.tool_name);
    }
  }
  for (const idx of pendingIndices) {
    const rec = records[idx];
    if (!rec) continue;
    const a = m.get(inferAgentId(rec, idx));
    if (a) a.status = 'halted';
  }
  const fc = new Map<string, number>();
  for (const f of findings) {
    const rec = records[f.step_index];
    if (!rec) continue;
    const aid = inferAgentId(rec, f.step_index);
    fc.set(aid, (fc.get(aid) ?? 0) + 1);
  }
  for (const [aid, c] of fc) {
    const a = m.get(aid);
    if (a && a.status !== 'halted') a.status = c > 2 ? 'critical' : 'flagged';
  }
  return [...m.values()];
}

export function buildEdges(records: AgDRRecord[]): AgentEdge[] {
  const seen = new Set<string>();
  const result: AgentEdge[] = [];
  let prev = '';
  for (let i = 0; i < records.length; i++) {
    const aid = inferAgentId(records[i]!, i);
    if (prev && prev !== aid) {
      const key = `${prev}->${aid}`;
      if (!seen.has(key)) { seen.add(key); result.push({ from: prev, to: aid, kind: records[i]!.kind }); }
    }
    prev = aid;
  }
  return result;
}

export function buildIncidents(
  findings: Finding[],
  records: AgDRRecord[],
  templateMap: Map<string, FindingTemplate>,
): IncidentVM[] {
  return findings.slice(0, 20).map((f, i) => {
    const rec = records[f.step_index];
    const aid = rec ? inferAgentId(rec, f.step_index) : 'unknown';
    const tool = rec?.payload?.tool_name ?? null;
    const tpl = templateMap.get(f.detector_id);
    const filled = tpl && rec ? fillTemplate(tpl, rec) : null;
    let title = filled?.text || f.description || f.title;
    if (tool && f.severity === 'critical') title = `Blocked: ${tool} (${f.detector_id})`;
    else if (tool && title === f.title) title = `${f.title} via ${tool}`;
    const ts = rec?.timestamp ? new Date(rec.timestamp) : null;
    const ago = ts ? Math.round((Date.now() - ts.getTime()) / 60000) : 0;
    return {
      id: `INC-${String(i + 1).padStart(4, '0')}`,
      title,
      description: filled?.text || f.description,
      agentId: aid,
      severity: f.severity,
      detector: f.detector_id,
      stepIndex: f.step_index,
      finding: f,
      toolName: tool,
      timestamp: ts ? (ago < 1 ? 'just now' : `${ago}m ago`) : '',
    };
  });
}

export function describeAction(rec: AgDRRecord): string {
  if (rec.kind === 'tool_start') return rec.payload?.tool_name ?? 'tool call';
  if (rec.kind === 'tool_end') return 'tool completed';
  if (rec.kind === 'llm_start') return 'processing prompt';
  if (rec.kind === 'llm_end') return 'generated response';
  if (rec.kind === 'agent_finish') return 'completed';
  if (rec.kind === 'agent_message') return 'sent message';
  if (rec.kind === 'human_approval') return 'human decision';
  if (rec.kind === 'intent_declaration') return 'declared intent';
  if (rec.kind === 'anchor') return 'anchored to Rekor';
  return rec.kind;
}

export function waveformBins(records: AgDRRecord[], count: number, filter?: (r: AgDRRecord) => boolean): number[] {
  const bins = new Array(count).fill(0);
  const total = records.length;
  if (total === 0) return bins;
  for (let i = 0; i < total; i++) {
    if (filter && !filter(records[i]!)) continue;
    bins[Math.min(count - 1, Math.floor((i / total) * count))]++;
  }
  return bins;
}

export function findingBins(findings: Finding[], recordCount: number, binCount: number): number[] {
  const bins = new Array(binCount).fill(0);
  if (recordCount === 0) return bins;
  for (const f of findings) {
    const bin = Math.min(binCount - 1, Math.floor((f.step_index / recordCount) * binCount));
    bins[bin] += f.severity === 'critical' ? 3 : f.severity === 'high' ? 2 : 1;
  }
  return bins;
}

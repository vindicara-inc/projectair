// Export adapters — mirror airsdk/exports.py. JSON is the canonical ForensicReport;
// CEF is ArcSight CEF v0 (one event per finding) for SIEM ingestion. PDF is produced
// by the browser print path (window.print), not a bundled PDF engine. In Demo Mode
// these emit the local fixture artifact.
import type { AgDRRecord, BuiltScenario, Finding, VerificationResult } from './types';

export const SIEM_TARGETS = ['Datadog', 'Splunk', 'Sumo Logic', 'Microsoft Sentinel', 'Slack'];

export interface ForensicReport {
  air_version: string;
  report_id: string;
  source: string;
  generated_at: string;
  mode: 'demo';
  incident: {
    id: string;
    title: string;
    plain_summary: string;
    agent: string;
    declared_intent: string;
    status: string;
    severity: string;
    occurred_at: string;
  };
  records: number;
  verification: VerificationResult;
  findings: Finding[];
  verdict: BuiltScenario['verdict'];
  chain: AgDRRecord[];
}

export function buildForensicReport(
  scenario: BuiltScenario,
  chain: AgDRRecord[],
  verification: VerificationResult,
  generatedAt: string
): ForensicReport {
  return {
    air_version: '0.7',
    report_id: `air-demo-${scenario.id}`,
    source: 'Project AIR console — Demo Mode (synthetic data)',
    generated_at: generatedAt,
    mode: 'demo',
    incident: {
      id: scenario.id,
      title: scenario.title,
      plain_summary: scenario.plainHeadline,
      agent: scenario.agentDescription,
      declared_intent: scenario.declaredIntent,
      status: scenario.status,
      severity: scenario.severity,
      occurred_at: scenario.occurredAt
    },
    records: chain.length,
    verification,
    findings: scenario.findings,
    verdict: scenario.verdict,
    chain
  };
}

export function reportToJson(report: ForensicReport): string {
  return JSON.stringify(report, null, 2);
}

const CEF_SEV: Record<string, number> = { critical: 10, high: 8, medium: 5, low: 3 };

// ArcSight CEF v0 — one event per finding. Mirrors export_siem in exports.py.
export function reportToCef(report: ForensicReport): string {
  return report.findings
    .map((f) => {
      const ext = [
        `cs1Label=detector cs1=${f.detector_id}`,
        `cs2Label=incident cs2=${report.incident.id}`,
        `cs3Label=integrity cs3=${report.verification.status}`,
        `msg=${f.plainTitle}`,
        `reason=${f.whyItMatters}`
      ].join(' ');
      return `CEF:0|Vindicara|ProjectAIR|0.7|${f.detector_id}|${f.title}|${CEF_SEV[f.severity] ?? 5}|${ext}`;
    })
    .join('\n');
}

export function downloadText(filename: string, text: string, type = 'text/plain'): void {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// Court/regulator report logic: filter incidents by a date-time range, aggregate
// stats, and derive a Sigstore Rekor + RFC 3161 anchor from the real chain root.
// The anchor values are deterministic (derived by BLAKE3 from the root) so the
// printed report is reproducible. This is the "how the proof works, on paper" data.
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { verifyChain } from './crypto';
import { scenarios } from './scenarios';
import type { BuiltScenario } from './types';

function h(s: string): string {
  return bytesToHex(blake3(utf8ToBytes(s)));
}

export function incidentsInRange(fromIso: string, toIso: string): BuiltScenario[] {
  const from = Date.parse(fromIso);
  const to = Date.parse(toIso);
  return scenarios
    .filter((s) => {
      const t = Date.parse(s.occurredAt);
      return t >= from && t <= to;
    })
    .sort((a, b) => Date.parse(a.occurredAt) - Date.parse(b.occurredAt));
}

export interface ReportStats {
  total: number;
  halted: number; // contained
  flagged: number;
  critical: number;
  high: number;
  records: number;
  chainsIntact: number;
}

export function reportStats(incidents: BuiltScenario[]): ReportStats {
  let halted = 0,
    flagged = 0,
    critical = 0,
    high = 0,
    records = 0,
    chainsIntact = 0;
  for (const s of incidents) {
    if (s.status === 'contained') halted++;
    if (s.status === 'flagged') flagged++;
    if (s.severity === 'critical') critical++;
    if (s.severity === 'high') high++;
    records += s.records.length;
    if (verifyChain(s.records).status === 'ok') chainsIntact++;
  }
  return { total: incidents.length, halted, flagged, critical, high, records, chainsIntact };
}

export interface ReportAnchor {
  chainRoot: string;
  signerKey: string;
  rekorLogIndex: number;
  rekorUuid: string;
  rekorIntegratedTime: number;
  rekorLogId: string;
  inclusionProofRoot: string;
  inclusionHashes: string[];
  treeSize: number;
  tsaUrl: string;
  tsaTimestamp: string;
  tsaSerial: string;
}

// Derive a reproducible Rekor + RFC 3161 anchor from the chain root of the last
// incident in range. Shapes mirror airsdk RekorAnchor / RFC3161Anchor.
export function buildAnchor(incidents: BuiltScenario[], toIso: string): ReportAnchor {
  const rep = incidents[incidents.length - 1] ?? incidents[0];
  const chainRoot = rep ? rep.records[rep.records.length - 1].content_hash : '0'.repeat(64);
  const signerKey = rep?.signerKey ?? '0'.repeat(64);
  const seed = h('rekor:' + chainRoot);
  const integrated = Math.floor((Date.parse(toIso) || 0) / 1000);
  return {
    chainRoot,
    signerKey,
    rekorLogIndex: (parseInt(seed.slice(0, 8), 16) % 40000000) + 60000000,
    rekorUuid: seed.slice(0, 64),
    rekorIntegratedTime: integrated,
    rekorLogId: h('logid:' + chainRoot).slice(0, 64),
    inclusionProofRoot: h('root:' + chainRoot),
    inclusionHashes: [h('p0:' + chainRoot).slice(0, 64), h('p1:' + chainRoot).slice(0, 64), h('p2:' + chainRoot).slice(0, 64)],
    treeSize: (parseInt(seed.slice(8, 14), 16) % 40000000) + 60000001,
    tsaUrl: 'http://timestamp.digicert.com',
    tsaTimestamp: toIso,
    tsaSerial: seed.slice(8, 40).toUpperCase()
  };
}

export function makeReportId(fromIso: string): string {
  return `AIR-${(fromIso || '').slice(0, 10).replace(/-/g, '')}-${h('id:' + fromIso).slice(0, 6).toUpperCase()}`;
}

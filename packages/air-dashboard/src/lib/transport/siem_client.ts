/**
 * SIEM push client for the AIR Cloud dashboard.
 *
 * Calls the AIR Cloud backend to proxy SIEM pushes server-side.
 * The dashboard never sends credentials directly to vendor endpoints;
 * it sends config to AIR Cloud, which does the actual push using the
 * Python airsdk_pro.siem modules (Splunk HEC, Datadog, Sentinel, Sumo, Slack).
 */

import type { Finding } from '../agdr/types.ts';

export interface SiemPushRequest {
  vendor: string;
  config: Record<string, string>;
  findings: Finding[];
  chain_length: number;
}

export interface SiemPushResult {
  vendor: string;
  ok: boolean;
  events_sent: number;
  error?: string;
}

export interface SiemTestResult {
  ok: boolean;
  error?: string;
}

export async function pushToSiem(
  baseUrl: string,
  headers: Record<string, string>,
  request: SiemPushRequest,
  fetchImpl: typeof fetch = fetch,
): Promise<SiemPushResult> {
  const url = `${baseUrl}/v1/integrations/siem/${encodeURIComponent(request.vendor)}/push`;
  const response = await fetchImpl(url, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    const text = await response.text();
    return { vendor: request.vendor, ok: false, events_sent: 0, error: `HTTP ${response.status}: ${text.slice(0, 200)}` };
  }
  return (await response.json()) as SiemPushResult;
}

export async function testSiemConnection(
  baseUrl: string,
  headers: Record<string, string>,
  vendor: string,
  config: Record<string, string>,
  fetchImpl: typeof fetch = fetch,
): Promise<SiemTestResult> {
  const url = `${baseUrl}/v1/integrations/siem/${encodeURIComponent(vendor)}/test`;
  const response = await fetchImpl(url, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ vendor, config }),
  });
  if (!response.ok) {
    const text = await response.text();
    return { ok: false, error: `HTTP ${response.status}: ${text.slice(0, 200)}` };
  }
  return (await response.json()) as SiemTestResult;
}

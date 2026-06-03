/**
 * SIEM configuration store -- manages vendor integrations for forwarding
 * findings and chain records to external security platforms.
 *
 * Each vendor's config fields match the Python server-side modules in
 * airsdk_pro.siem (splunk.py, datadog.py, sentinel.py, sumo.py, slack.py).
 */

import type { Finding } from '../agdr/types.ts';
import { pushToSiem, testSiemConnection } from '../transport/siem_client.ts';

export type ConnectionStatus = 'idle' | 'ok' | 'error' | 'pushing' | 'testing';

export interface SiemVendor {
  id: string;
  name: string;
  enabled: boolean;
  config: Record<string, string>;
  lastStatus: ConnectionStatus;
  lastError: string | null;
  lastPushAt: string | null;
  eventsSent: number;
}

function makeVendors(): SiemVendor[] {
  return [
    { id: 'splunk', name: 'Splunk HEC', enabled: false, config: { hec_url: '', hec_token: '', sourcetype: 'vindicara_air:finding', index: '' }, lastStatus: 'idle', lastError: null, lastPushAt: null, eventsSent: 0 },
    { id: 'datadog', name: 'Datadog', enabled: false, config: { api_key: '', site: 'datadoghq.com' }, lastStatus: 'idle', lastError: null, lastPushAt: null, eventsSent: 0 },
    { id: 'sentinel', name: 'Microsoft Sentinel', enabled: false, config: { workspace_id: '', shared_key: '', log_type: 'VindicaraAIR' }, lastStatus: 'idle', lastError: null, lastPushAt: null, eventsSent: 0 },
    { id: 'sumo', name: 'Sumo Logic', enabled: false, config: { http_source_url: '', category: '' }, lastStatus: 'idle', lastError: null, lastPushAt: null, eventsSent: 0 },
    { id: 'slack', name: 'Slack', enabled: false, config: { webhook_url: '', channel: '' }, lastStatus: 'idle', lastError: null, lastPushAt: null, eventsSent: 0 },
  ];
}

class SiemStore {
  vendors = $state<SiemVendor[]>(makeVendors());

  toggle(vendorId: string): void {
    this.vendors = this.vendors.map(v => v.id === vendorId ? { ...v, enabled: !v.enabled } : v);
  }

  updateConfig(vendorId: string, field: string, value: string): void {
    this.vendors = this.vendors.map(v => v.id === vendorId ? { ...v, config: { ...v.config, [field]: value } } : v);
  }

  setStatus(vendorId: string, status: ConnectionStatus, error: string | null = null): void {
    this.vendors = this.vendors.map(v => v.id === vendorId ? { ...v, lastStatus: status, lastError: error } : v);
  }

  getVendor(id: string): SiemVendor | undefined {
    return this.vendors.find(v => v.id === id);
  }

  get enabledVendors(): SiemVendor[] {
    return this.vendors.filter(v => v.enabled);
  }

  validateConfig(vendorId: string): { valid: boolean; missing: string[] } {
    const vendor = this.getVendor(vendorId);
    if (!vendor) return { valid: false, missing: ['vendor not found'] };
    const required = Object.entries(vendor.config)
      .filter(([k]) => !['index', 'category', 'channel', 'sourcetype', 'log_type', 'site'].includes(k))
      .filter(([, v]) => v.trim() === '')
      .map(([k]) => k);
    return { valid: required.length === 0, missing: required };
  }

  async testConnection(vendorId: string, baseUrl: string, headers: Record<string, string>): Promise<void> {
    const vendor = this.getVendor(vendorId);
    if (!vendor) return;
    const { valid, missing } = this.validateConfig(vendorId);
    if (!valid) { this.setStatus(vendorId, 'error', `Missing required fields: ${missing.join(', ')}`); return; }
    this.setStatus(vendorId, 'testing');
    try {
      const result = await testSiemConnection(baseUrl, headers, vendorId, vendor.config);
      this.setStatus(vendorId, result.ok ? 'ok' : 'error', result.error ?? null);
    } catch (err) {
      this.setStatus(vendorId, 'error', (err as Error).message);
    }
  }

  async pushFindings(vendorId: string, baseUrl: string, headers: Record<string, string>, findings: Finding[], chainLength: number): Promise<void> {
    const vendor = this.getVendor(vendorId);
    if (!vendor) return;
    const { valid, missing } = this.validateConfig(vendorId);
    if (!valid) { this.setStatus(vendorId, 'error', `Missing: ${missing.join(', ')}`); return; }
    this.setStatus(vendorId, 'pushing');
    try {
      const result = await pushToSiem(baseUrl, headers, { vendor: vendorId, config: vendor.config, findings, chain_length: chainLength });
      if (result.ok) {
        this.vendors = this.vendors.map(v => v.id === vendorId ? { ...v, lastStatus: 'ok' as const, lastError: null, lastPushAt: new Date().toISOString(), eventsSent: v.eventsSent + result.events_sent } : v);
      } else {
        this.setStatus(vendorId, 'error', result.error ?? 'Push failed');
      }
    } catch (err) {
      this.setStatus(vendorId, 'error', (err as Error).message);
    }
  }

  async pushToAllEnabled(baseUrl: string, headers: Record<string, string>, findings: Finding[], chainLength: number): Promise<void> {
    await Promise.allSettled(this.enabledVendors.map(v => this.pushFindings(v.id, baseUrl, headers, findings, chainLength)));
  }
}

export const siemStore = new SiemStore();

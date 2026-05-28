/**
 * Approval store -- tracks pending, approved, and denied containment actions.
 *
 * When the SDK's Layer 3 containment halts a tool_start (via BlockedActionError
 * or StepUpRequiredError), the dashboard shows the action in an approval queue.
 * Operators approve or deny; the store records the decision with attribution.
 *
 * Coupling note: approval decisions also update triage statuses via the caller
 * (acknowledge on approve, resolve on deny). This store carries only the
 * approval-specific metadata (who, when, reason).
 */

import type { AgDRRecord } from '../agdr/types.ts';

export type ApprovalStatus = 'pending' | 'approved' | 'denied';

export interface ApprovalItem {
  record: AgDRRecord;
  recordIndex: number;
  status: ApprovalStatus;
  approvedBy?: string;
  approvedAt?: string;
  deniedReason?: string;
}

class ApprovalStore {
  items = $state<ApprovalItem[]>([]);

  addPending(record: AgDRRecord, index: number): void {
    if (this.items.some(i => i.recordIndex === index)) return;
    this.items = [...this.items, { record, recordIndex: index, status: 'pending' }];
  }

  approve(index: number, approvedBy: string): void {
    this.items = this.items.map(i =>
      i.recordIndex === index
        ? { ...i, status: 'approved' as const, approvedBy, approvedAt: new Date().toISOString() }
        : i
    );
  }

  deny(index: number, reason: string): void {
    this.items = this.items.map(i =>
      i.recordIndex === index
        ? { ...i, status: 'denied' as const, deniedReason: reason }
        : i
    );
  }

  get pending(): ApprovalItem[] {
    return this.items.filter(i => i.status === 'pending');
  }

  reset(): void {
    this.items = [];
  }
}

export const approvalStore = new ApprovalStore();

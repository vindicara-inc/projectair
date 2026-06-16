// Tracks what the operator actually did this session, so clock-out can file an
// honest report: which incidents were reviewed and which Approve/Uphold decisions
// were made (and by whom). Reset on a fresh sign-in and after clocking out.
import { writable } from 'svelte/store';

export interface ReviewedIncident {
  id: string;
  title: string;
  at: string;
}

export interface SessionDecision {
  incidentId: string;
  title: string;
  decision: 'approve' | 'deny';
  approver: string;
  at: string;
}

export const reviewed = writable<ReviewedIncident[]>([]);
export const decisions = writable<SessionDecision[]>([]);
export const clockOutOpen = writable(false);

export function recordReview(id: string, title: string): void {
  reviewed.update((list) => (list.some((r) => r.id === id) ? list : [...list, { id, title, at: new Date().toISOString() }]));
}

export function recordDecision(d: Omit<SessionDecision, 'at'>): void {
  decisions.update((list) => [...list, { ...d, at: new Date().toISOString() }]);
}

export function resetSession(): void {
  reviewed.set([]);
  decisions.set([]);
}

export function openClockOut(): void {
  clockOutOpen.set(true);
}

// The recipient the filed session report is routed to.
export const departmentHead = { name: 'Dr. Evelyn Reyes', title: 'Chief of Staff' };

import { writable } from 'svelte/store';

export interface OverviewToast {
  message: string;
  tone?: 'ok' | 'warn' | 'info';
}

export const overviewToast = writable<OverviewToast | null>(null);

let timer: ReturnType<typeof setTimeout> | undefined;

export function flashOverview(message: string, tone: OverviewToast['tone'] = 'ok'): void {
  if (timer) clearTimeout(timer);
  overviewToast.set({ message, tone });
  timer = setTimeout(() => overviewToast.set(null), 3200);
}
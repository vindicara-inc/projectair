// Single entry point. Screens import { api } from '$lib/console/api/client'.
//
// The Demo / Live toggle (mode store) decides the data source:
//   demo — the bundled mock fixtures (mock.ts). Works fully offline, no network.
//   live — the real AIR API (live.ts), base from PUBLIC_AIR_API_BASE.
// This is why the whole console renders in front of an audience without a backend:
// in Demo Mode every screen reads fixtures instead of hitting the API. The env var
// PUBLIC_AIR_API_MODE is now just the default Live base config; the toggle wins.
import { env } from '$env/dynamic/public';
import { get } from 'svelte/store';
import type { ApiClient } from './types';
import { MockClient } from './mock';
import { LiveClient } from './live';
import { sessionToken } from '$lib/console/stores/session';
import { mode } from '$lib/console/stores/mode';

const mock = new MockClient();
let live: LiveClient | null = null;

function liveClient(): LiveClient {
  if (!live) {
    const base = env.PUBLIC_AIR_API_BASE ?? '';
    if (!base) console.warn('Live Mode selected but PUBLIC_AIR_API_BASE is empty');
    live = new LiveClient(base, () => get(sessionToken));
  }
  return live;
}

function impl(): ApiClient {
  return get(mode) === 'live' ? liveClient() : mock;
}

// Dispatch each call to the implementation for the current mode, so toggling Demo/Live
// switches every screen's data source without rebuilding anything.
export const api: ApiClient = new Proxy({} as ApiClient, {
  get(_target, prop: string) {
    const target = impl() as unknown as Record<string, (...args: unknown[]) => unknown>;
    const value = target[prop];
    return typeof value === 'function' ? value.bind(target) : value;
  }
});

// Single entry point. Screens import { api } from '$lib/console/api/client'.
// PUBLIC_AIR_API_MODE=mock (default) | live  decides the implementation.
import { env } from '$env/dynamic/public';
import type { ApiClient } from './types';
import { MockClient } from './mock';
import { LiveClient } from './live';
import { sessionToken } from '$lib/console/stores/session';
import { get } from 'svelte/store';

function build(): ApiClient {
  const mode = env.PUBLIC_AIR_API_MODE ?? 'mock';
  if (mode === 'live') {
    const base = env.PUBLIC_AIR_API_BASE ?? '';
    if (!base) console.warn('PUBLIC_AIR_API_MODE=live but PUBLIC_AIR_API_BASE is empty');
    return new LiveClient(base, () => get(sessionToken));
  }
  return new MockClient();
}

export const api: ApiClient = build();

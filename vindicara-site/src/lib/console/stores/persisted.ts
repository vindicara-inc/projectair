// A writable store mirrored to localStorage. Guarded with `browser` so it is inert
// during prerender (no localStorage in Node) — mirrors the sessionStorage guards in
// auth/pkce.ts.
import { writable, type Writable } from 'svelte/store';
import { browser } from '$app/environment';

export function persisted<T>(key: string, initial: T): Writable<T> {
  let start = initial;
  if (browser) {
    const raw = localStorage.getItem(key);
    if (raw !== null) {
      try {
        start = JSON.parse(raw) as T;
      } catch {
        // corrupt value — fall back to the initial
      }
    }
  }
  const store = writable<T>(start);
  if (browser) {
    store.subscribe((value) => {
      try {
        localStorage.setItem(key, JSON.stringify(value));
      } catch {
        // storage full / disabled — non-fatal for a demo
      }
    });
  }
  return store;
}

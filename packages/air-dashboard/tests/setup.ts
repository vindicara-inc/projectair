/**
 * Vitest global setup for node-environment tests.
 *
 * Svelte 5 rune functions ($state, $derived, $effect) are not available in a
 * plain node test environment. These shims make module-level singleton
 * instantiation in .svelte.ts files non-fatal for tests that only exercise
 * pure (non-reactive) exported functions. The shims return the initial value
 * unchanged, so Map/array state is accessible as a plain value; reactivity
 * is a no-op, which is exactly what we need for pure-function tests.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
(globalThis as any).$state = <T>(init: T): T => init;
(globalThis as any).$derived = <T>(fn: () => T): T => fn();
(globalThis as any).$effect = (_fn: () => void): void => {};

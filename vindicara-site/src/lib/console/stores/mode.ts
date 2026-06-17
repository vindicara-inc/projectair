// Demo / Live mode for the forensics surface.
//   demo — every view renders from local scenario fixtures, zero network.
//   live — the existing API/data path; unwired views show an honest empty state.
// Persisted so it survives navigation and reload; the always-on DEMO MODE badge
// keeps Demo unmistakable.
import { env } from '$env/dynamic/public';
import { persisted } from './persisted';
import { defaultScenarioId } from '$lib/console/forensics/scenarios';

export type Mode = 'demo' | 'live';

// Seed a fresh visitor's default from the build env: 'live' only when explicitly
// set (PUBLIC_AIR_API_MODE=live), otherwise the public Demo showcase. The persisted
// store then remembers whatever the user toggles to.
const initialMode: Mode = env.PUBLIC_AIR_API_MODE === 'live' ? 'live' : 'demo';

export const mode = persisted<Mode>('air.console.mode', initialMode);
export const selectedScenarioId = persisted<string>('air.console.scenario', defaultScenarioId);

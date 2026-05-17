/**
 * Audio enable store — persisted in localStorage. Even when enabled, the
 * AudioContext only resumes after the first user gesture (browser autoplay
 * policy). Components that produce sound should consult `enabled` AND
 * gracefully fail if the AudioContext is not yet running.
 */

const STORAGE_KEY = 'air-hud:audio-enabled';

class AudioStore {
	enabled = $state(false);

	constructor() {
		if (typeof localStorage !== 'undefined') {
			this.enabled = localStorage.getItem(STORAGE_KEY) === 'true';
		}
	}

	enable(): void {
		this.enabled = true;
		if (typeof localStorage !== 'undefined') {
			localStorage.setItem(STORAGE_KEY, 'true');
		}
	}

	disable(): void {
		this.enabled = false;
		if (typeof localStorage !== 'undefined') {
			localStorage.setItem(STORAGE_KEY, 'false');
		}
	}

	toggle(): void {
		if (this.enabled) this.disable();
		else this.enable();
	}
}

export const audioStore = new AudioStore();

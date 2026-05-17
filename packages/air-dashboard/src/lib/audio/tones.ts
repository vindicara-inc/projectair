/**
 * Tactile audio synthesis for the AIR HUD.
 *
 * Pure Web Audio API — no library, no samples. Every tone is a short
 * oscillator + gain envelope, synthesized on demand. Cheap, deterministic,
 * and avoids shipping audio assets.
 *
 * Audio is gated by audioStore.enabled (persisted in localStorage). Even
 * when enabled, the AudioContext only resumes after the first user gesture
 * (browser autoplay policy). All play() calls fail silently if the context
 * is suspended — operators get visible HUD feedback either way.
 *
 * Palette:
 *   - capsule_click: low tactile click (210 Hz, 60 ms) — fires on each landing
 *   - verify_chime: bright cyan chime (660 Hz square→sine, 180 ms) — fires on verified
 *   - finding_alert: descending alert (880 → 380 Hz, 220 ms) — fires on detector trigger
 *   - tamper_break: dramatic glide-down (520 → 90 Hz, 700 ms) — fires on chain break
 *   - ambient_hum: continuous low drone (78 Hz triangle + 156 Hz sine, very low gain)
 */

import { audioStore } from '../stores/audio.svelte';

let context: AudioContext | null = null;
let masterGain: GainNode | null = null;
let ambientHandle: { stop: () => void } | null = null;

function ensureContext(): AudioContext | null {
	if (typeof window === 'undefined') return null;
	if (!context) {
		const Ctor = window.AudioContext ?? (window as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
		if (!Ctor) return null;
		context = new Ctor();
		masterGain = context.createGain();
		masterGain.gain.value = 0.18;
		masterGain.connect(context.destination);
	}
	return context;
}

async function unlock(): Promise<void> {
	const ctx = ensureContext();
	if (!ctx) return;
	if (ctx.state === 'suspended') {
		try {
			await ctx.resume();
		} catch {
			// browser refused; fail silently
		}
	}
}

export async function unlockAudio(): Promise<void> {
	await unlock();
}

function gated(): { ctx: AudioContext; gain: GainNode } | null {
	if (!audioStore.enabled) return null;
	const ctx = ensureContext();
	if (!ctx || !masterGain) return null;
	if (ctx.state !== 'running') return null;
	return { ctx, gain: masterGain };
}

function envelope(node: GainNode, ctx: AudioContext, attack: number, decay: number, peak: number): void {
	const now = ctx.currentTime;
	node.gain.setValueAtTime(0, now);
	node.gain.linearRampToValueAtTime(peak, now + attack);
	node.gain.exponentialRampToValueAtTime(0.0001, now + attack + decay);
}

function blip(frequency: number, type: OscillatorType, attack: number, decay: number, peak = 0.6): void {
	const slot = gated();
	if (!slot) return;
	const osc = slot.ctx.createOscillator();
	const gain = slot.ctx.createGain();
	osc.type = type;
	osc.frequency.value = frequency;
	envelope(gain, slot.ctx, attack, decay, peak);
	osc.connect(gain).connect(slot.gain);
	osc.start();
	osc.stop(slot.ctx.currentTime + attack + decay + 0.05);
}

function glide(from: number, to: number, type: OscillatorType, attack: number, decay: number, peak = 0.7): void {
	const slot = gated();
	if (!slot) return;
	const osc = slot.ctx.createOscillator();
	const gain = slot.ctx.createGain();
	osc.type = type;
	osc.frequency.setValueAtTime(from, slot.ctx.currentTime);
	osc.frequency.exponentialRampToValueAtTime(Math.max(20, to), slot.ctx.currentTime + attack + decay);
	envelope(gain, slot.ctx, attack, decay, peak);
	osc.connect(gain).connect(slot.gain);
	osc.start();
	osc.stop(slot.ctx.currentTime + attack + decay + 0.05);
}

export function capsuleClick(): void {
	blip(210, 'square', 0.005, 0.06, 0.45);
}

export function verifyChime(): void {
	blip(660, 'sine', 0.005, 0.18, 0.55);
}

export function findingAlert(): void {
	glide(880, 380, 'sawtooth', 0.005, 0.22, 0.7);
}

export function tamperBreak(): void {
	glide(520, 90, 'sawtooth', 0.01, 0.7, 0.9);
}

export function startAmbient(): void {
	if (ambientHandle) return;
	const slot = gated();
	if (!slot) return;
	const osc1 = slot.ctx.createOscillator();
	const osc2 = slot.ctx.createOscillator();
	osc1.type = 'triangle';
	osc1.frequency.value = 78;
	osc2.type = 'sine';
	osc2.frequency.value = 156;
	const gain = slot.ctx.createGain();
	gain.gain.value = 0.04;
	osc1.connect(gain);
	osc2.connect(gain);
	gain.connect(slot.gain);
	osc1.start();
	osc2.start();
	ambientHandle = {
		stop() {
			osc1.stop();
			osc2.stop();
			ambientHandle = null;
		}
	};
}

export function stopAmbient(): void {
	ambientHandle?.stop();
}

<script lang="ts">
	import { onDestroy } from 'svelte';
	import ParticleNetwork from './ParticleNetwork.svelte';
	import { authStore } from '$lib/stores/auth.svelte';

	type Phase = 'welcome' | 'disintegrating';
	let phase = $state<Phase>('welcome');

	let titleEl: HTMLHeadingElement;
	let dCanvas: HTMLCanvasElement;
	let bgGrad = $state('');

	interface DPart { x: number; y: number; vx: number; vy: number; a: number; s: number }
	let dParts: DPart[] = [];
	let dAnimId = 0;

	function trackMouse(e: MouseEvent): void {
		const px = (e.clientX / window.innerWidth) * 100;
		const py = (e.clientY / window.innerHeight) * 100;
		bgGrad = `radial-gradient(circle at ${px}% ${py}%, rgba(0,100,255,0.1) 0%, transparent 50%), `
			+ `radial-gradient(circle at ${100 - px}% ${100 - py}%, rgba(255,0,150,0.1) 0%, transparent 50%), #050505`;
	}

	function disintegrate(): void {
		if (phase !== 'welcome') return;
		phase = 'disintegrating';
		const ctx = dCanvas.getContext('2d', { willReadFrequently: true })!;
		dCanvas.width = window.innerWidth;
		dCanvas.height = window.innerHeight;
		const rect = titleEl.getBoundingClientRect();
		const fs = parseFloat(getComputedStyle(titleEl).fontSize);
		ctx.fillStyle = 'white';
		ctx.font = `700 ${fs}px Orbitron, sans-serif`;
		ctx.textAlign = 'center';
		ctx.textBaseline = 'middle';
		ctx.fillText('WELCOME', rect.left + rect.width / 2, rect.top + rect.height / 2);
		const img = ctx.getImageData(0, 0, dCanvas.width, dCanvas.height);
		dParts = [];
		for (let y = 0; y < dCanvas.height; y += 4) {
			for (let x = 0; x < dCanvas.width; x += 4) {
				if (img.data[(y * dCanvas.width + x) * 4 + 3]! > 128) {
					dParts.push({
						x, y,
						vx: (Math.random() - 0.5) * 10,
						vy: (Math.random() - 0.5) * 10,
						a: 1, s: Math.random() * 2 + 0.5,
					});
				}
			}
		}
		titleEl.style.visibility = 'hidden';
		ctx.clearRect(0, 0, dCanvas.width, dCanvas.height);
		animateD(ctx);
		setTimeout(() => { void authStore.login(); }, 1800);
	}

	function animateD(ctx: CanvasRenderingContext2D): void {
		ctx.clearRect(0, 0, dCanvas.width, dCanvas.height);
		for (const p of dParts) {
			p.x += p.vx; p.y += p.vy;
			p.vx *= 0.98; p.vy *= 0.98;
			p.a -= 0.008;
			if (p.a <= 0) continue;
			ctx.globalAlpha = p.a;
			ctx.fillStyle = 'white';
			ctx.beginPath();
			ctx.arc(p.x, p.y, p.s, 0, Math.PI * 2);
			ctx.fill();
		}
		ctx.globalAlpha = 1;
		dAnimId = requestAnimationFrame(() => animateD(ctx));
	}

	function onKey(e: KeyboardEvent): void {
		if (phase === 'welcome' && (e.key === 'Enter' || e.key === ' ')) disintegrate();
	}

	onDestroy(() => cancelAnimationFrame(dAnimId));
</script>

<svelte:window onkeydown={onKey} />

<div
	class="fixed inset-0 z-[100]"
	style="background:{bgGrad || 'radial-gradient(circle at 20% 30%, rgba(0,100,255,0.15) 0%, transparent 40%), radial-gradient(circle at 80% 70%, rgba(255,0,150,0.15) 0%, transparent 40%), #050505'}; cursor:crosshair;"
	role="presentation"
	onmousemove={trackMouse}
>
	<ParticleNetwork />
	<canvas bind:this={dCanvas} class="fixed inset-0 z-[102] pointer-events-none"></canvas>

	<div class="fixed inset-0 z-[101] flex flex-col items-center justify-center">
		<h1
			bind:this={titleEl}
			class="text-white text-center mb-8"
			style="font-family:'Orbitron',sans-serif; font-size:clamp(3rem,8vw,5rem); font-weight:700; letter-spacing:15px; text-shadow:0 0 20px rgba(0,150,255,0.5);"
		>WELCOME</h1>
		<div class="transition-opacity duration-700" class:opacity-0={phase === 'disintegrating'}>
			<button
				onclick={disintegrate}
				class="px-10 py-4 text-white uppercase transition-all hover:bg-white/20"
				style="font-family:'Orbitron',sans-serif; font-size:0.85rem; letter-spacing:4px; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.3); backdrop-filter:blur(5px);"
			>ENTER HERE</button>
		</div>
	</div>
</div>

<script lang="ts">
	import { onMount } from 'svelte';

	const STORAGE_KEY = 'air-hud:intro-seen';
	const SUBHEAD = 'INTRODUCING';
	const TITLE = 'PROJECT AIR HUD';
	const TAGLINE = 'forensic reconstruction · signed intent capsules · zero-trust enforcement';

	let { onEnter }: { onEnter: () => void } = $props();

	let subRevealed = $state(0);
	let titleRevealed = $state(0);
	let taglineVisible = $state(false);
	let enterVisible = $state(false);
	let dismissing = $state(false);

	function dismiss(): void {
		if (dismissing) return;
		dismissing = true;
		try {
			localStorage.setItem(STORAGE_KEY, 'true');
		} catch {
			/* ignore */
		}
		setTimeout(() => onEnter(), 450);
	}

	onMount(() => {
		const subDelay = 220;
		const titleDelay = 70;
		const taglineDelay = 1800;
		const enterDelay = 2700;

		const timers: ReturnType<typeof setTimeout>[] = [];
		for (let i = 1; i <= SUBHEAD.length; i++) {
			timers.push(setTimeout(() => (subRevealed = i), 200 + i * subDelay));
		}
		const titleStart = 200 + SUBHEAD.length * subDelay + 350;
		for (let i = 1; i <= TITLE.length; i++) {
			timers.push(setTimeout(() => (titleRevealed = i), titleStart + i * titleDelay));
		}
		timers.push(setTimeout(() => (taglineVisible = true), titleStart + TITLE.length * titleDelay + taglineDelay));
		timers.push(setTimeout(() => (enterVisible = true), titleStart + TITLE.length * titleDelay + enterDelay));

		const onKey = (e: KeyboardEvent) => {
			if (e.key === 'Enter' || e.key === ' ' || e.key === 'Escape') dismiss();
		};
		window.addEventListener('keydown', onKey);
		return () => {
			for (const t of timers) clearTimeout(t);
			window.removeEventListener('keydown', onKey);
		};
	});
</script>

<section
	class="fixed inset-0 flex items-center justify-center z-50 transition-opacity duration-500"
	class:opacity-0={dismissing}
	style="background: radial-gradient(circle at 50% 45%, rgba(10,10,12,0.45) 0%, rgba(10,10,12,0.85) 60%, rgba(10,10,12,0.97) 100%);"
>
	<button
		type="button"
		class="absolute inset-0 cursor-pointer focus:outline-none"
		onclick={dismiss}
		aria-label="enter HUD"
	></button>

	<div class="relative z-10 text-center px-6 pointer-events-none">
		<div
			class="hud-label tracking-[0.55em] text-[var(--color-cyan)]"
			style="text-shadow: 0 0 12px rgba(34,211,238,0.55);"
		>
			{SUBHEAD.slice(0, subRevealed)}<span class="opacity-60">_</span>
		</div>

		<h1
			class="mt-8 font-mono font-bold tracking-[0.18em] leading-tight"
			style="font-size: clamp(2.2rem, 7vw, 5.5rem); color: #d6f7ff; text-shadow: 0 0 24px rgba(34,211,238,0.7), 0 0 64px rgba(34,211,238,0.35);"
		>
			{TITLE.slice(0, titleRevealed)}<span class="opacity-50">_</span>
		</h1>

		<p
			class="mt-6 hud-tick text-[var(--color-bone-dim)] tracking-[0.18em] transition-opacity duration-700"
			class:opacity-100={taglineVisible}
			class:opacity-0={!taglineVisible}
		>
			{TAGLINE}
		</p>

		<div
			class="mt-12 transition-opacity duration-700"
			class:opacity-100={enterVisible}
			class:opacity-0={!enterVisible}
		>
			<button
				type="button"
				class="pointer-events-auto px-8 py-3 hud-label tracking-[0.4em] border border-[var(--color-cyan)] text-[var(--color-cyan)] hover:bg-[var(--color-cyan)] hover:text-[var(--color-obsidian)] transition-colors"
				style="background: rgba(10,10,12,0.4); backdrop-filter: blur(6px); box-shadow: 0 0 24px rgba(34,211,238,0.25), inset 0 0 1px rgba(34,211,238,0.6);"
				onclick={dismiss}
			>
				ENTER HUD →
			</button>
		</div>
	</div>
</section>

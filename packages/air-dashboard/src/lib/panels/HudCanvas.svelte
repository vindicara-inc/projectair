<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import type { SceneController } from '$lib/scene/scene';
	import { replayStore } from '$lib/stores/replay.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { findingsStore } from '$lib/stores/findings.svelte';
	import { focusStore } from '$lib/stores/focus.svelte';
	import { capsuleClick, verifyChime, findingAlert, tamperBreak } from '$lib/audio/tones';

	let canvas: HTMLCanvasElement | undefined = $state();
	let controller: SceneController | null = $state(null);
	let loading = $state(true);
	let lastEmittedCount = 0;
	let tamperTriggered = false;
	let resizeObserver: ResizeObserver | null = null;

	onMount(async () => {
		if (!canvas) return;
		// Three.js is split into its own ~500KB chunk via vite manualChunks. Defer
		// loading it until the HUD canvas actually mounts, so the initial JS
		// payload stays under the 350KB budget (TACTICAL mode never downloads it).
		const { mountScene } = await import('$lib/scene/scene');
		if (!canvas) return; // unmounted before chunk loaded
		controller = mountScene(canvas);
		controller.start();
		loading = false;
		resizeObserver = new ResizeObserver(() => {
			if (controller && canvas) {
				controller.resize(canvas.clientWidth, canvas.clientHeight);
			}
		});
		resizeObserver.observe(canvas);
	});

	onDestroy(() => {
		controller?.dispose();
		resizeObserver?.disconnect();
	});

	$effect(() => {
		const ctrl = controller;
		if (!ctrl) return;
		const emitted = replayStore.emitted;
		while (lastEmittedCount < emitted.length) {
			const record = emitted[lastEmittedCount]!;
			const verification = verifierStore.entries[lastEmittedCount];
			const findings = findingsStore.forStep(lastEmittedCount);
			let stateKind: 'pending' | 'verified' | 'flagged' | 'broken' = 'verified';
			if (verification?.status === 'tampered' || verification?.status === 'broken_link') {
				stateKind = 'broken';
			} else if (findings.length > 0) {
				stateKind = 'flagged';
			}
			ctrl.chainOrbit.add({
				contentHash: record.content_hash,
				state: stateKind,
				focused: false
			});

			capsuleClick();
			if (stateKind === 'broken') {
				if (!tamperTriggered) {
					tamperBreak();
					tamperTriggered = true;
				}
			} else if (stateKind === 'flagged') {
				findingAlert();
			} else {
				verifyChime();
			}

			lastEmittedCount++;
		}
		if (emitted.length === 0 && lastEmittedCount > 0) {
			ctrl.chainOrbit.clear();
			lastEmittedCount = 0;
			tamperTriggered = false;
		}
	});

	$effect(() => {
		const ctrl = controller;
		if (!ctrl) return;
		const focusInfo = focusStore.resolve(replayStore.emitted, replayStore.currentIndex);
		const total = ctrl.chainOrbit.count();
		for (let i = 0; i < total; i++) {
			ctrl.chainOrbit.updateAt(i, { focused: i === focusInfo.index });
		}
	});

	$effect(() => {
		const ctrl = controller;
		if (!ctrl) return;
		const findings = findingsStore.all;
		const triggeredIndexById = new Map<string, number>();
		for (const f of findings) {
			triggeredIndexById.set(f.detector_id, f.step_index);
		}
		for (const detectorId of ['ASI02', 'ASI05', 'AIR-02', 'AIR-04', 'ASI10']) {
			const stepIndex = triggeredIndexById.get(detectorId);
			if (stepIndex !== undefined) {
				ctrl.swarm.setDetectorStatus(detectorId, 'triggered');
				ctrl.swarm.setLockTarget(detectorId, ctrl.chainOrbit.getPosition(stepIndex));
			} else {
				ctrl.swarm.setDetectorStatus(detectorId, 'idle');
				ctrl.swarm.setLockTarget(detectorId, null);
			}
		}
	});
</script>

<div class="absolute inset-0">
	<canvas bind:this={canvas} class="block w-full h-full"></canvas>
	{#if loading}
		<div class="absolute inset-0 flex items-center justify-center pointer-events-none">
			<div class="text-center">
				<div class="hud-label hud-pulse">LOADING HUD</div>
				<div class="hud-tick mt-2 text-[var(--color-bone-faint)]">
					initializing scene · BLAKE3 verifier · detector swarm
				</div>
			</div>
		</div>
	{/if}
</div>

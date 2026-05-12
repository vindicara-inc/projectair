<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import StatusStrip from '$lib/panels/StatusStrip.svelte';
	import ReportBuilder from '$lib/panels/ReportBuilder.svelte';
	import GaugePanel from '$lib/panels/GaugePanel.svelte';
	import LiveFeed from '$lib/panels/LiveFeed.svelte';
	import OwaspGrid from '$lib/panels/OwaspGrid.svelte';
	import NetworkGraph from '$lib/panels/NetworkGraph.svelte';
	import CloudConnect from '$lib/panels/CloudConnect.svelte';

	import { replayStore } from '$lib/stores/replay.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { findingsStore } from '$lib/stores/findings.svelte';
	import { focusStore } from '$lib/stores/focus.svelte';
	import { modeStore } from '$lib/stores/mode.svelte';
	import { cloudSession } from '$lib/stores/cloud_session.svelte';
	import { runDetectors } from '$lib/detectors';
	import { SCENARIOS, loadScenario } from '$lib/capsules/loader';

	let unsubscribeMode: (() => void) | null = null;
	let lastDetectorRunSize = 0;
	let loading = $state(false);

	onMount(async () => {
		unsubscribeMode = modeStore.bindMediaQueries();
		await cloudSession.restore();
		if (cloudSession.isConnected) {
			await loadCloudChain();
		}
	});

	onDestroy(() => {
		unsubscribeMode?.();
		cloudSession.stopStream();
	});

	async function loadCloudChain(): Promise<void> {
		if (!cloudSession.isConnected) return;
		loading = true;
		try {
			const records = await cloudSession.loadCurrentChain({ limit: 1000 });
			verifierStore.reset();
			findingsStore.reset();
			focusStore.clear();
			replayStore.load(records, 'cloud');
			replayStore.play();

			cloudSession.startStream((record) => {
				replayStore.emitted = [...replayStore.emitted, record];
				replayStore.currentIndex = replayStore.emitted.length - 1;
			});
		} catch (err) {
			console.error('failed to load cloud chain:', err);
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		const records = replayStore.records;
		const emitted = replayStore.emitted;
		const lastIngested = verifierStore.entries.length;
		for (let i = lastIngested; i < emitted.length; i++) {
			verifierStore.ingest(emitted[i]!, i);
		}
		if (emitted.length !== lastDetectorRunSize) {
			lastDetectorRunSize = emitted.length;
			findingsStore.reset();
			findingsStore.add(runDetectors(emitted, null));
		}
		if (emitted.length === 0 && lastDetectorRunSize > 0) {
			lastDetectorRunSize = 0;
		}
		void records;
	});

	async function selectAndPlay(scenarioId: string): Promise<void> {
		const scenario = SCENARIOS.find((s) => s.id === scenarioId);
		if (!scenario) return;
		loading = true;
		try {
			const records = await loadScenario(scenario);
			verifierStore.reset();
			findingsStore.reset();
			focusStore.clear();
			replayStore.load(records, scenario.id);
			replayStore.play();
		} finally {
			loading = false;
		}
	}

	function formatTime(iso: string): string {
		try {
			const d = new Date(iso);
			return d.toISOString().slice(11, 19);
		} catch {
			return '--:--:--';
		}
	}

	const sevBuckets = $derived(findingsStore.bySeverity());
</script>

<svelte:head>
	<title>AIR Cloud — Project AIR forensic console</title>
</svelte:head>

<StatusStrip />

<main class="relative z-[2] min-h-screen pt-16 pb-20 px-16 max-w-[1600px] mx-auto grid grid-cols-[320px_1fr_320px] gap-8 items-start" style="font-family: var(--font-mono);">

	<!-- ===== LEFT COLUMN ===== -->
	<div class="flex flex-col gap-6 pt-12">
		<ReportBuilder />

		<div>
			<div class="module-label"><span class="id">MOD.02</span> Live Throughput</div>
			<GaugePanel
				value={replayStore.emitted.length}
				max={Math.max(replayStore.records.length, 1)}
				label="Capsules Emitted"
				color="red"
			/>
		</div>

		<div>
			<div class="module-label"><span class="id">MOD.03</span> Chain Integrity</div>
			<GaugePanel
				value={verifierStore.integrityScore}
				max={100}
				label="Verified Signatures"
				suffix="%"
				color={verifierStore.integrityScore === 100 ? 'green' : 'critical'}
			/>
		</div>
	</div>

	<!-- ===== CENTER COLUMN ===== -->
	<div class="flex flex-col gap-6 pt-12">
		<!-- Masthead -->
		<div class="text-center mb-2">
			<div class="text-[10px] tracking-[0.4em] uppercase font-bold flex items-center justify-center gap-3.5" style="color: var(--color-red);">
				<span class="w-2 h-2 rounded-full inline-block" style="background: var(--color-red); box-shadow: 0 0 12px var(--color-red); animation: blink 2s infinite;"></span>
				System Online
				<span class="w-2 h-2 rounded-full inline-block" style="background: var(--color-red); box-shadow: 0 0 12px var(--color-red); animation: blink 2s infinite;"></span>
			</div>
			<h1 class="text-[68px] font-bold tracking-[0.04em] leading-[0.9] uppercase mt-4" style="font-family: var(--font-display); color: var(--color-obsidian);">
				Project <span style="color: var(--color-red); text-shadow: 0 0 24px var(--color-red-soft);">AIR</span>
			</h1>
			<p class="text-[11px] tracking-[0.32em] uppercase mt-3.5" style="color: rgba(5,5,7,.55);">
				Cryptographically Signed Forensic Evidence For AI Agents
			</p>
		</div>

		<!-- Install + Network Graph -->
		<div>
			<div class="module-label"><span class="id">CON.00</span> Install &amp; Initialize</div>
			<div class="obsidian p-6 stagger">
				<span class="sweep"></span>
				<div class="reactor"></div>
				<div class="relative z-[5]">
					<!-- Install row -->
					<div class="flex items-stretch overflow-hidden mb-6" style="background:rgba(0,0,0,.35); border:1px solid rgba(220,38,38,.25); border-radius:8px;">
						<div class="flex-1 px-5 py-4 text-base font-bold flex items-center gap-3" style="font-family: var(--font-term); color: var(--color-white);">
							<span style="color: var(--color-red);">pip install</span>
							<span>projectair</span>
						</div>
						<button
							class="px-5 text-[10px] font-bold tracking-[0.2em] uppercase flex items-center gap-1.5 cursor-pointer transition-all"
							style="background:rgba(220,38,38,.12); border:none; border-left:1px solid rgba(220,38,38,.3); color:var(--color-red);"
							onclick={() => navigator.clipboard?.writeText('pip install projectair')}
						>
							Copy
						</button>
					</div>

					<!-- Scenario picker -->
					<div class="flex items-center gap-3 mb-6 flex-wrap">
						<span class="text-[9px] tracking-[0.3em] uppercase font-bold" style="color: rgba(248,246,241,.5);">Scenario</span>
						{#each SCENARIOS as scenario (scenario.id)}
							<button
								class="px-3 py-1.5 text-[10px] font-bold tracking-[0.1em] uppercase cursor-pointer transition-all"
								style="border:1px solid {replayStore.scenarioId === scenario.id ? 'var(--color-red)' : 'rgba(255,255,255,.15)'};
									   background:{replayStore.scenarioId === scenario.id ? 'rgba(220,38,38,.2)' : 'rgba(0,0,0,.3)'};
									   color:{replayStore.scenarioId === scenario.id ? 'var(--color-red)' : 'var(--color-white-3)'};"
								onclick={() => selectAndPlay(scenario.id)}
								disabled={loading}
								title={scenario.description}
							>
								{scenario.label}
							</button>
						{/each}

						<div class="flex items-center gap-2 ml-auto">
							<button
								class="px-3 py-1.5 text-[10px] font-bold uppercase cursor-pointer transition-all"
								style="border:1px solid rgba(255,255,255,.15); background:rgba(0,0,0,.3); color:var(--color-white-3);"
								onclick={() => replayStore.play()}
								disabled={replayStore.records.length === 0}
							>PLAY</button>
							<button
								class="px-3 py-1.5 text-[10px] font-bold uppercase cursor-pointer transition-all"
								style="border:1px solid rgba(255,255,255,.15); background:rgba(0,0,0,.3); color:var(--color-white-3);"
								onclick={() => replayStore.pause()}
							>PAUSE</button>
							<button
								class="px-3 py-1.5 text-[10px] font-bold uppercase cursor-pointer transition-all"
								style="border:1px solid rgba(255,255,255,.15); background:rgba(0,0,0,.3); color:var(--color-white-3);"
								onclick={() => { replayStore.reset(); verifierStore.reset(); findingsStore.reset(); focusStore.clear(); }}
							>RESET</button>
						</div>
					</div>

					<NetworkGraph />
				</div>
			</div>
		</div>

		<!-- System Vitals -->
		<div>
			<div class="module-label"><span class="id">CON.01</span> System Vitals</div>
			<div class="obsidian px-5 py-4 stagger">
				<span class="sweep"></span>
				<div class="reactor"></div>
				<div class="relative z-[5] grid grid-cols-4 gap-3.5">
					<div>
						<div class="text-[32px] font-bold leading-[.95]" style="font-family:var(--font-display); color:var(--color-red);">{replayStore.emitted.length}</div>
						<div class="text-[9px] tracking-[0.2em] uppercase mt-0.5" style="color:var(--color-white-3);">Records Signed</div>
					</div>
					<div>
						<div class="text-[32px] font-bold leading-[.95]" style="font-family:var(--font-display); color:var(--color-white);">{replayStore.records.length}</div>
						<div class="text-[9px] tracking-[0.2em] uppercase mt-0.5" style="color:var(--color-white-3);">Total In Chain</div>
					</div>
					<div>
						<div class="text-[32px] font-bold leading-[.95]" style="font-family:var(--font-display); color:var(--color-critical);">{findingsStore.all.length}</div>
						<div class="text-[9px] tracking-[0.2em] uppercase mt-0.5" style="color:var(--color-white-3);">Findings</div>
					</div>
					<div>
						<div class="text-[32px] font-bold leading-[.95]" style="font-family:var(--font-display); color:var(--color-terminal-green);">{verifierStore.integrityScore}%</div>
						<div class="text-[9px] tracking-[0.2em] uppercase mt-0.5" style="color:var(--color-white-3);">Chain Verified</div>
					</div>
				</div>
			</div>
		</div>
	</div>

	<!-- ===== RIGHT COLUMN ===== -->
	<div class="flex flex-col gap-6 pt-12">
		<CloudConnect onChainLoaded={loadCloudChain} />
		<LiveFeed />
		<OwaspGrid />
	</div>
</main>

<!-- Corner brackets -->
<div class="fixed bottom-4 left-4 z-[2] pointer-events-none text-sm font-bold" style="color:rgba(5,5,7,.4); font-family:var(--font-mono);">[</div>
<div class="fixed bottom-4 right-4 z-[2] pointer-events-none text-sm font-bold" style="color:rgba(5,5,7,.4); font-family:var(--font-mono);">]</div>
<div class="fixed top-10 left-4 z-[2] pointer-events-none text-sm font-bold" style="color:rgba(5,5,7,.4); font-family:var(--font-mono);">[</div>
<div class="fixed top-10 right-4 z-[2] pointer-events-none text-sm font-bold" style="color:rgba(5,5,7,.4); font-family:var(--font-mono);">]</div>

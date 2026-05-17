<script lang="ts">
	import { DETECTOR_SWARM, type DetectorEntity } from '$lib/detectors';
	import { findingsStore } from '$lib/stores/findings.svelte';

	const SCAN_SCOPE_LABEL: Record<DetectorEntity['scanScope'], string> = {
		tool_args: 'tool args',
		tool_name: 'tool name',
		all_text: 'all text',
		chain_structure: 'chain structure',
		agent_scope: 'agent scope'
	};

	const PERSONALITY_GLYPH: Record<DetectorEntity['personality'], string> = {
		reaper: '◆',
		whisper: '◯',
		archivist: '▣',
		warden: '⬢',
		sentinel: '▲'
	};

	const SEVERITY_COLOR: Record<DetectorEntity['severity'], string> = {
		critical: 'var(--color-alert)',
		high: 'var(--color-amber)',
		medium: 'var(--color-cyan-dim)'
	};

	function findingCountFor(id: string): number {
		return findingsStore.all.filter((f) => f.detector_id === id).length;
	}

	function statusFor(id: string): 'idle' | 'triggered' {
		return findingCountFor(id) > 0 ? 'triggered' : 'idle';
	}
</script>

<aside class="hud-rail h-full overflow-y-auto p-4">
	<header class="hud-bracket pb-2 mb-3">
		<span class="hud-label">DETECTOR SWARM</span>
	</header>
	<p class="hud-tick mb-4 text-[var(--color-bone-faint)]">
		5 active / 9 require backend
	</p>
	<ul class="space-y-2">
		{#each DETECTOR_SWARM as detector}
			{@const count = findingCountFor(detector.id)}
			{@const status = statusFor(detector.id)}
			<li
				class="border border-[var(--color-panel-edge)] p-3 transition-colors"
				class:bg-[var(--color-obsidian-edge)]={status === 'triggered'}
			>
				<div class="flex items-center justify-between gap-2">
					<span
						class="text-2xl leading-none"
						style:color={status === 'triggered'
							? 'var(--color-alert)'
							: SEVERITY_COLOR[detector.severity]}
						class:hud-pulse={status === 'triggered'}
					>
						{PERSONALITY_GLYPH[detector.personality]}
					</span>
					<div class="flex-1 min-w-0">
						<div class="hud-readout text-xs flex items-baseline gap-2">
							<span>{detector.id}</span>
							<span class="hud-tick text-[var(--color-bone-faint)]">{detector.personality}</span>
						</div>
						<div class="text-[10px] text-[var(--color-bone-dim)] truncate">{detector.title}</div>
						<div class="hud-tick text-[var(--color-bone-faint)] mt-1">
							scope · {SCAN_SCOPE_LABEL[detector.scanScope]}
						</div>
					</div>
					<div class="flex flex-col items-end">
						<span
							class="hud-readout text-xs"
							style:color={status === 'triggered' ? 'var(--color-alert)' : 'var(--color-bone-faint)'}
						>
							{count.toString().padStart(2, '0')}
						</span>
						<span class="hud-tick" style:color={SEVERITY_COLOR[detector.severity]}>
							{detector.severity.toUpperCase()}
						</span>
					</div>
				</div>
			</li>
		{/each}
	</ul>
	<details class="mt-6 text-xs text-[var(--color-bone-faint)]">
		<summary class="hud-label cursor-pointer">DORMANT — REQUIRES BACKEND</summary>
		<ul class="mt-3 space-y-1 pl-4">
			<li>ASI01 · Agent Goal Hijack <span class="hud-tick">(fuzzy token overlap)</span></li>
			<li>ASI03 · Identity & Privilege Abuse <span class="hud-tick">(registry attribution)</span></li>
			<li>ASI04 · Supply Chain (MCP) <span class="hud-tick">(naming patterns)</span></li>
			<li>ASI06 · Memory & Context Poisoning <span class="hud-tick">(semantic detection)</span></li>
			<li>ASI07 · Inter-Agent Communication <span class="hud-tick">(replay/downgrade checks)</span></li>
			<li>ASI08 · Cascading Failures <span class="hud-tick">(sliding window)</span></li>
			<li>ASI09 · Trust Exploitation <span class="hud-tick">(manipulation NLP)</span></li>
			<li>AIR-01 · Prompt Injection <span class="hud-tick">(injection patterns)</span></li>
			<li>AIR-03 · Resource Consumption <span class="hud-tick">(burst window stats)</span></li>
		</ul>
	</details>
</aside>

<script lang="ts">
	import { DETECTOR_SWARM } from '$lib/detectors';
	import { findingsStore } from '$lib/stores/findings.svelte';
	import { detailStore } from '$lib/stores/detail.svelte';
	import { filterStore } from '$lib/stores/filter.svelte';

	const allIds = ['ASI01','ASI02','ASI03','ASI04','ASI05','ASI06','ASI07','ASI08','ASI09','ASI10'] as const;

	const TITLES: Record<string, string> = {
		ASI01: 'Agent Goal Hijack',
		ASI02: 'Tool Misuse & Exploitation',
		ASI03: 'Identity & Privilege Abuse',
		ASI04: 'Supply Chain Risk',
		ASI05: 'Unexpected Code Execution',
		ASI06: 'Memory & Context Poisoning',
		ASI07: 'Inter-Agent Communication',
		ASI08: 'Cascading Failures',
		ASI09: 'Human-Agent Trust Exploit',
		ASI10: 'Rogue Agents',
	};

	const DESCRIPTIONS: Record<string, string> = {
		ASI01: 'Detects prompt injection attempts that hijack the agent away from its declared goal.',
		ASI02: 'Flags tool calls with suspicious arguments: path traversal, shell injection, URL exfiltration.',
		ASI03: 'Checks agent identity against the operator-declared AgentRegistry.',
		ASI04: 'Identifies supply-chain risks from MCP tool naming patterns.',
		ASI05: 'Flags execution of shell commands, eval(), or code generation tools.',
		ASI06: 'Detects memory/context poisoning via injected content.',
		ASI07: 'Validates inter-agent message routing for unauthorized communication.',
		ASI08: 'Detects cascading failure patterns: oscillating retries, fan-out explosions.',
		ASI09: 'Flags manipulation language that exploits human trust.',
		ASI10: 'Zero-Trust enforcement: agents acting outside declared BehavioralScope.',
	};

	const activeIds = $derived(new Set(DETECTOR_SWARM.map((d) => d.id)));

	function findingsFor(id: string) {
		return findingsStore.all.filter((f) => f.detector_id === id);
	}

	function cellStyle(id: string): string {
		const count = findingsFor(id).length;
		const isFiltered = filterStore.detectorId === id;

		if (isFiltered) {
			return 'background:rgba(255,255,255,.15); border:2px solid rgba(255,255,255,.5); color:var(--color-white);';
		}
		if (count > 0) {
			return 'background:rgba(255,84,104,.2); border:1px solid rgba(255,84,104,.5); color:var(--color-critical);';
		}
		if (activeIds.has(id)) {
			return 'background:rgba(110,255,179,.12); border:1px solid rgba(110,255,179,.3); color:var(--color-terminal-green);';
		}
		return 'background:rgba(255,181,71,.12); border:1px solid rgba(255,181,71,.3); color:var(--color-high);';
	}

	function handleClick(id: string): void {
		const findings = findingsFor(id);
		detailStore.open({
			kind: 'detector',
			detectorId: id,
			title: TITLES[id] ?? id,
			description: DESCRIPTIONS[id] ?? '',
			findings,
		});
	}

	function handleFilter(id: string): void {
		if (filterStore.detectorId === id) {
			filterStore.setDetector(null);
		} else {
			filterStore.setDetector(id);
		}
	}

	const totalFindings = $derived(findingsStore.all.filter((f) => allIds.includes(f.detector_id as typeof allIds[number])).length);
</script>

<div>
	<div class="module-label"><span class="id">MOD.05</span> OWASP Coverage</div>
	<div class="obsidian">
		<span class="sweep"></span>
		<div class="reactor"></div>
		<div class="relative z-[5] p-5">
			<div class="flex items-center justify-between mb-4">
				<span class="text-xs font-bold tracking-[0.22em] uppercase" style="font-family:var(--font-display); color:var(--color-white);">Agentic Top 10</span>
				<button
					onclick={() => detailStore.open({ kind: 'findings-list', title: 'All OWASP Findings', findings: findingsStore.all.filter((f) => f.detector_id.startsWith('ASI')) })}
					class="text-[9px] tracking-[0.18em] uppercase cursor-pointer hover:underline transition-colors"
					style="color:var(--color-red);"
				>{totalFindings > 0 ? `${totalFindings} FINDINGS` : '10/10'}</button>
			</div>
			<div class="grid grid-cols-5 gap-1.5">
				{#each allIds as id, i}
					<button
						onclick={() => handleClick(id)}
						oncontextmenu={(e) => { e.preventDefault(); handleFilter(id); }}
						class="aspect-square flex flex-col items-center justify-center cursor-pointer transition-all duration-150 hover:scale-110 hover:brightness-125 relative group"
						style="{cellStyle(id)} font-family:var(--font-mono);"
						title="{TITLES[id]} (click: details, right-click: filter)"
					>
						<span class="text-[10px] font-bold">{String(i + 1).padStart(2, '0')}</span>
						{#if findingsFor(id).length > 0}
							<span class="absolute -top-1 -right-1 w-3.5 h-3.5 flex items-center justify-center text-[7px] font-bold" style="background:var(--color-critical); color:white; border-radius:50%;">{findingsFor(id).length}</span>
						{/if}
						<span class="absolute bottom-0 left-0 right-0 text-center text-[6px] tracking-wide opacity-0 group-hover:opacity-100 transition-opacity" style="color:var(--color-white-3); font-family:var(--font-mono); padding:1px;">{TITLES[id]?.split(' ')[0]}</span>
					</button>
				{/each}
			</div>
			{#if filterStore.detectorId}
				<div class="mt-3 flex items-center gap-2">
					<span class="text-[9px] tracking-[0.15em] uppercase" style="color:var(--color-white-3); font-family:var(--font-mono);">Filtered: {filterStore.detectorId}</span>
					<button onclick={() => filterStore.setDetector(null)} class="text-[9px] cursor-pointer" style="color:var(--color-red); font-family:var(--font-mono);">&times; clear</button>
				</div>
			{:else}
				<div class="mt-3.5 text-[9px] tracking-[0.18em] uppercase leading-relaxed" style="color:var(--color-white-3);">
					Click any cell for details. Right-click to filter.
				</div>
			{/if}
		</div>
	</div>
</div>

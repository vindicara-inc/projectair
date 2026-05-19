<script lang="ts">
	import { detailStore, type DetailCard } from '$lib/stores/detail.svelte';
	import { replayStore } from '$lib/stores/replay.svelte';
	import { focusStore } from '$lib/stores/focus.svelte';

	const SEV: Record<string, { plain: string; what: string }> = {
		critical: { plain: 'Critical', what: 'Something dangerous happened. This needs your attention right now.' },
		high: { plain: 'High', what: 'A policy violation was detected. Investigate soon.' },
		medium: { plain: 'Medium', what: 'Worth reviewing at your next check-in. Not urgent.' },
	};

	const DETECTOR_PLAIN: Record<string, string> = {
		ASI01: 'An outside prompt tried to hijack what the agent was doing.',
		ASI02: 'A tool was called with suspicious or dangerous arguments.',
		ASI03: 'An unregistered agent tried to act without authorization.',
		ASI04: 'A tool name looks like it is impersonating a trusted service.',
		ASI05: 'The agent ran code it was not supposed to execute.',
		ASI06: 'Something poisoned the agent\'s memory or context.',
		ASI07: 'Agents communicated without proper routing.',
		ASI08: 'The agent got stuck in a failure loop or cascaded errors.',
		ASI09: 'The agent used language designed to manipulate a human.',
		ASI10: 'An agent acted outside its declared scope.',
		'AIR-01': 'A prompt injection pattern was detected.',
		'AIR-02': 'Sensitive data (credentials, PII) appeared in the chain.',
		'AIR-03': 'Resource usage exceeded the configured budget.',
		'AIR-04': 'A gap or unsigned action was found in the chain.',
		'AIR-05': 'NVIDIA NemoGuard flagged unsafe content.',
		'AIR-06': 'Both AIR and NemoGuard independently flagged the same issue.',
	};

	function jumpTo(card: DetailCard, index: number): void {
		focusStore.select(index);
		detailStore.replace(card.id, { kind: 'capsule', index });
	}

	function kindPlain(kind: string): string {
		const map: Record<string, string> = {
			llm_start: 'Sent a prompt to the AI',
			llm_end: 'AI responded',
			tool_start: 'Called a tool',
			tool_end: 'Tool returned a result',
			agent_finish: 'Agent completed its task',
			agent_message: 'Agent sent a message',
			anchor: 'Anchored to public ledger',
			human_approval: 'Human approved an action',
		};
		return map[kind] ?? kind;
	}
</script>

{#if detailStore.cards.length > 0}
	<div class="glass-tray">
		{#each detailStore.cards as card (card.id)}
			<div class="glass-card">
				<div class="glass-edge"></div>

				<button onclick={() => detailStore.close(card.id)} class="glass-x cursor-pointer">&times;</button>

				{#if card.view.kind === 'finding'}
					{@const f = card.view.finding}
					{@const sev = SEV[f.severity]}
					<span class="glass-badge {f.severity}">{sev?.plain}</span>
					<h3 class="glass-title">{f.title}</h3>
					<p class="glass-body">{DETECTOR_PLAIN[f.detector_id] ?? f.description}</p>
					<div class="glass-meta">{f.detector_id} &middot; Step {f.step_index}</div>
					<p class="glass-hint">{sev?.what}</p>
					<button onclick={() => jumpTo(card, f.step_index)} class="glass-action cursor-pointer">View capsule &rarr;</button>

				{:else if card.view.kind === 'findings-list'}
					<h3 class="glass-title">{card.view.title}</h3>
					{#if card.view.findings.length === 0}
						<div class="glass-ok">All clear. No issues found.</div>
					{:else}
						{#each card.view.findings as f}
							<button onclick={() => detailStore.open({ kind: 'finding', finding: f })} class="glass-row cursor-pointer">
								<span class="glass-dot {f.severity}"></span>
								<span class="glass-row-text">{f.title}</span>
								<span class="glass-row-id">{f.detector_id}</span>
							</button>
						{/each}
					{/if}

				{:else if card.view.kind === 'detector'}
					<span class="glass-badge {card.view.findings.length > 0 ? 'critical' : 'ok'}">{card.view.findings.length > 0 ? `${card.view.findings.length} issues` : 'Clean'}</span>
					<h3 class="glass-title">{card.view.detectorId}</h3>
					<p class="glass-body">{DETECTOR_PLAIN[card.view.detectorId] ?? card.view.description}</p>
					{#if card.view.findings.length > 0}
						{#each card.view.findings as f}
							<button onclick={() => detailStore.open({ kind: 'finding', finding: f })} class="glass-row cursor-pointer">
								<span class="glass-dot {f.severity}"></span>
								<span class="glass-row-text">{f.title}</span>
								<span class="glass-row-id">step {f.step_index}</span>
							</button>
						{/each}
					{:else}
						<div class="glass-ok">No issues for this detector.</div>
					{/if}

				{:else if card.view.kind === 'capsule'}
					{@const rec = replayStore.emitted[card.view.index]}
					{#if rec}
						<span class="glass-badge info">#{card.view.index}</span>
						<h3 class="glass-title">{kindPlain(rec.kind)}</h3>
						<div class="glass-kv"><span class="k">When</span><span class="v">{new Date(rec.timestamp).toLocaleString()}</span></div>
						{#if rec.payload.tool_name}<div class="glass-kv"><span class="k">Tool</span><span class="v">{rec.payload.tool_name}</span></div>{/if}
						{#if rec.payload.prompt}<div class="glass-kv"><span class="k">Prompt</span><span class="v">{rec.payload.prompt.slice(0, 100)}{rec.payload.prompt.length > 100 ? '...' : ''}</span></div>{/if}
						{#if rec.payload.response}<div class="glass-kv"><span class="k">Response</span><span class="v">{rec.payload.response.slice(0, 100)}{rec.payload.response.length > 100 ? '...' : ''}</span></div>{/if}
						<div class="glass-kv"><span class="k">Hash</span><span class="v hash">{rec.content_hash.slice(0, 20)}...</span></div>
						<details class="glass-expand">
							<summary class="cursor-pointer">Full payload</summary>
							<pre class="glass-pre">{JSON.stringify(rec.payload, null, 2)}</pre>
						</details>
						<div class="glass-nav">
							{#if card.view.index > 0}
								<button onclick={() => detailStore.replace(card.id, { kind: 'capsule', index: card.view.kind === 'capsule' ? card.view.index - 1 : 0 })} class="glass-nav-btn cursor-pointer">&larr;</button>
							{/if}
							{#if card.view.index < replayStore.emitted.length - 1}
								<button onclick={() => detailStore.replace(card.id, { kind: 'capsule', index: card.view.kind === 'capsule' ? card.view.index + 1 : 0 })} class="glass-nav-btn cursor-pointer">&rarr;</button>
							{/if}
						</div>
					{/if}

				{:else if card.view.kind === 'severity-info'}
					<h3 class="glass-title">Severity levels</h3>
					{#each Object.entries(SEV) as [key, info]}
						<div class="glass-sev">
							<span class="glass-badge {key}">{info.plain}</span>
							<p class="glass-body">{info.what}</p>
						</div>
					{/each}
				{/if}
			</div>
		{/each}
	</div>
{/if}

<style>
	.glass-tray {
		position: fixed;
		top: 40px;
		right: 550px;
		bottom: 0;
		width: 320px;
		z-index: 150;
		display: flex;
		flex-direction: column;
		gap: 8px;
		overflow-y: auto;
		pointer-events: none;
		padding: 8px 0;
	}

	.glass-card {
		pointer-events: all;
		position: relative;
		padding: 20px;
		background: linear-gradient(
			135deg,
			rgba(16, 16, 22, 0.88) 0%,
			rgba(8, 8, 12, 0.92) 50%,
			rgba(20, 20, 28, 0.88) 100%
		);
		backdrop-filter: blur(32px) saturate(1.5);
		-webkit-backdrop-filter: blur(32px) saturate(1.5);
		border: 1px solid rgba(255, 255, 255, 0.1);
		box-shadow:
			0 20px 50px rgba(0, 0, 0, 0.45),
			0 0 80px rgba(220, 38, 38, 0.04),
			inset 0 1px 0 rgba(255, 255, 255, 0.12);
		animation: cardIn 0.2s cubic-bezier(0.16, 1, 0.3, 1);
		overflow: hidden;
	}

	.glass-edge {
		position: absolute;
		top: 0; left: 6%; right: 6%; height: 1px;
		background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4) 30%, rgba(255,255,255,0.7) 50%, rgba(255,255,255,0.4) 70%, transparent);
	}

	.glass-x {
		position: absolute; top: 8px; right: 8px;
		width: 24px; height: 24px;
		display: flex; align-items: center; justify-content: center;
		font-size: 14px; font-family: var(--font-mono);
		color: rgba(248,246,241,0.25);
		background: rgba(0,0,0,0.3);
		border: 1px solid rgba(255,255,255,0.06);
		transition: all 0.12s;
	}
	.glass-x:hover {
		color: var(--color-white);
		border-color: var(--color-red);
		background: rgba(220,38,38,0.15);
	}

	.glass-title {
		font-family: var(--font-display);
		font-size: 13px; font-weight: 700;
		letter-spacing: 0.08em;
		color: var(--color-white);
		margin-bottom: 8px;
		text-transform: uppercase;
		line-height: 1.3;
		padding-right: 28px;
	}

	.glass-body {
		font-family: var(--font-mono);
		font-size: 11px; line-height: 1.65;
		color: rgba(248,246,241,0.5);
		margin-bottom: 10px;
	}

	.glass-hint {
		font-family: var(--font-mono);
		font-size: 10px; line-height: 1.5;
		color: rgba(248,246,241,0.3);
		font-style: italic;
		margin-bottom: 10px;
	}

	.glass-meta {
		font-family: var(--font-mono);
		font-size: 9px; letter-spacing: 0.12em;
		color: rgba(248,246,241,0.25);
		margin-bottom: 8px;
	}

	.glass-badge {
		display: inline-block;
		font-family: var(--font-mono);
		font-size: 9px; font-weight: 700;
		letter-spacing: 0.15em;
		text-transform: uppercase;
		padding: 3px 8px;
		margin-bottom: 10px;
	}
	.glass-badge.critical { background: rgba(255,84,104,0.15); color: var(--color-critical); border: 1px solid rgba(255,84,104,0.3); }
	.glass-badge.high { background: rgba(255,181,71,0.12); color: var(--color-high); border: 1px solid rgba(255,181,71,0.3); }
	.glass-badge.medium { background: rgba(110,255,179,0.1); color: var(--color-terminal-green); border: 1px solid rgba(110,255,179,0.2); }
	.glass-badge.info { background: rgba(255,255,255,0.06); color: var(--color-white-3); border: 1px solid rgba(255,255,255,0.1); }
	.glass-badge.ok { background: rgba(110,255,179,0.1); color: var(--color-terminal-green); border: 1px solid rgba(110,255,179,0.2); }

	.glass-ok {
		font-family: var(--font-mono); font-size: 11px;
		color: var(--color-terminal-green);
		padding: 10px; margin-top: 6px;
		border: 1px solid rgba(110,255,179,0.12);
		background: rgba(110,255,179,0.03);
	}

	.glass-row {
		width: 100%; text-align: left;
		display: flex; align-items: center; gap: 8px;
		padding: 7px 8px; margin-bottom: 3px;
		border: 1px solid rgba(255,255,255,0.03);
		background: rgba(0,0,0,0.12);
		transition: all 0.1s;
	}
	.glass-row:hover {
		border-color: rgba(220,38,38,0.2);
		background: rgba(220,38,38,0.04);
		transform: translateX(2px);
	}
	.glass-row-text { font-family: var(--font-mono); font-size: 10px; color: rgba(248,246,241,0.6); flex: 1; }
	.glass-row-id { font-family: var(--font-mono); font-size: 8px; color: rgba(248,246,241,0.2); letter-spacing: 0.1em; }

	.glass-dot { width: 5px; height: 5px; flex-shrink: 0; }
	.glass-dot.critical { background: var(--color-critical); box-shadow: 0 0 5px var(--color-critical); }
	.glass-dot.high { background: var(--color-high); box-shadow: 0 0 5px var(--color-high); }
	.glass-dot.medium { background: var(--color-terminal-green); box-shadow: 0 0 5px var(--color-terminal-green); }

	.glass-kv { display: flex; gap: 8px; padding: 3px 0; font-family: var(--font-mono); font-size: 10px; }
	.glass-kv .k { color: rgba(248,246,241,0.25); min-width: 60px; flex-shrink: 0; font-size: 9px; letter-spacing: 0.08em; }
	.glass-kv .v { color: rgba(248,246,241,0.6); word-break: break-all; }
	.glass-kv .v.hash { color: var(--color-red); }

	.glass-expand { margin: 8px 0; }
	.glass-expand summary {
		font-family: var(--font-mono); font-size: 9px;
		letter-spacing: 0.12em; text-transform: uppercase;
		color: rgba(248,246,241,0.25); padding: 4px 0;
	}
	.glass-expand summary:hover { color: var(--color-white-2); }
	.glass-pre {
		font-family: var(--font-term); font-size: 9px; line-height: 1.5;
		color: rgba(248,246,241,0.4);
		background: rgba(0,0,0,0.3);
		border: 1px solid rgba(255,255,255,0.03);
		padding: 8px; margin-top: 4px;
		overflow-x: auto; white-space: pre-wrap; word-break: break-all;
	}

	.glass-action {
		display: block; width: 100%;
		font-family: var(--font-mono); font-size: 10px;
		letter-spacing: 0.1em; text-align: center;
		color: var(--color-red);
		border: 1px solid rgba(220,38,38,0.25);
		background: rgba(220,38,38,0.06);
		padding: 8px; margin-top: 8px;
		transition: all 0.12s;
	}
	.glass-action:hover {
		background: rgba(220,38,38,0.15);
		border-color: rgba(220,38,38,0.5);
		box-shadow: 0 0 16px rgba(220,38,38,0.1);
	}

	.glass-nav { display: flex; gap: 4px; margin-top: 8px; }
	.glass-nav-btn {
		font-family: var(--font-mono); font-size: 12px;
		color: rgba(248,246,241,0.4);
		border: 1px solid rgba(255,255,255,0.06);
		background: rgba(0,0,0,0.2);
		padding: 4px 12px; transition: all 0.1s;
	}
	.glass-nav-btn:hover { color: var(--color-white); border-color: rgba(255,255,255,0.15); }

	.glass-sev { padding: 10px; margin-bottom: 6px; border: 1px solid rgba(255,255,255,0.04); background: rgba(0,0,0,0.1); }

	@keyframes cardIn {
		from { opacity: 0; transform: translateX(20px) scale(0.97); }
		to { opacity: 1; transform: translateX(0) scale(1); }
	}
</style>

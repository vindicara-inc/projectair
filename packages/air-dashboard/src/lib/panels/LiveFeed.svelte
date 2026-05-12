<script lang="ts">
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import { findingsStore } from '$lib/stores/findings.svelte';
	import { replayStore } from '$lib/stores/replay.svelte';

	interface FeedRow {
		time: string;
		tag: 'ANCHOR' | 'SIGN' | 'VERIFY' | 'ALERT' | 'FLAG' | 'EXPORT';
		tagClass: 'info' | 'warn' | 'crit';
		msg: string;
		hash: string;
	}

	const feed = $derived.by<FeedRow[]>(() => {
		const rows: FeedRow[] = [];

		for (const finding of findingsStore.all) {
			const sev = finding.severity;
			const emitted = replayStore.emitted[finding.step_index];
			const ts = emitted?.timestamp ?? '';
			rows.push({
				time: formatTime(ts),
				tag: sev === 'critical' ? 'ALERT' : 'FLAG',
				tagClass: sev === 'critical' ? 'crit' : 'warn',
				msg: `${finding.detector_id} ${finding.title.toLowerCase().replace(/ /g, '_')}`,
				hash: emitted?.step_id?.slice(0, 8) ?? ''
			});
		}

		for (const entry of verifierStore.entries) {
			const emitted = replayStore.emitted[entry.index];
			const ts = emitted?.timestamp ?? '';
			if (entry.status !== 'ok') {
				rows.push({
					time: formatTime(ts),
					tag: 'ALERT',
					tagClass: 'crit',
					msg: `chain integrity breach step ${entry.index}`,
					hash: entry.contentHashShort
				});
			} else {
				rows.push({
					time: formatTime(ts),
					tag: 'SIGN',
					tagClass: 'info',
					msg: `${entry.kind} recorded`,
					hash: entry.contentHashShort
				});
			}
		}

		return rows.slice(-20).reverse();
	});

	function formatTime(iso: string): string {
		try {
			return new Date(iso).toISOString().slice(11, 19);
		} catch {
			return '--:--:--';
		}
	}
</script>

<div>
	<div class="module-label"><span class="id">MOD.04</span> Live Event Stream</div>
	<div class="obsidian flex flex-col max-h-[520px] stagger">
		<span class="sweep"></span>
		<div class="reactor"></div>

		<!-- Chrome bar -->
		<div class="flex items-center justify-between px-4 py-3.5 relative z-[6]" style="border-bottom:1px solid rgba(255,255,255,.06); background:linear-gradient(180deg, rgba(20,20,28,.95), rgba(12,12,16,.95));">
			<div class="flex items-center gap-2 text-[11px] font-bold tracking-[0.22em] uppercase" style="font-family:var(--font-display); color:var(--color-white);">
				<span class="w-1.5 h-1.5 rounded-full" style="background:var(--color-terminal-green); box-shadow:0 0 8px var(--color-terminal-green); animation:blink 1.5s infinite;"></span>
				Live Pulse
			</div>
			<div class="text-[9px] tracking-[0.15em] uppercase" style="color:var(--color-white-4); font-family:var(--font-mono);">tail -f /var/log</div>
		</div>

		<!-- Feed body -->
		<div class="px-4 py-3.5 flex flex-col gap-1.5 overflow-y-auto flex-1 relative z-[5]" style="font-family:var(--font-term); font-size:12px;">
			{#if feed.length === 0}
				<p class="text-[11px]" style="color:var(--color-white-4);">awaiting forensic chain</p>
			{:else}
				{#each feed as row}
					<div class="flex items-start gap-2.5 py-1">
						<span class="text-[10px] flex-shrink-0 min-w-[54px]" style="color:var(--color-white-4);">{row.time}</span>
						<span class="feed-tag {row.tagClass}">{row.tag}</span>
						<span class="flex-1 min-w-0 text-[11.5px] leading-relaxed" style="color:var(--color-white-2);">
							{row.msg}
							<span class="feed-hash">{row.hash}</span>
						</span>
					</div>
				{/each}
			{/if}
		</div>
	</div>
</div>

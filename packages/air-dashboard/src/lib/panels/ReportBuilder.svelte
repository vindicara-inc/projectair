<script lang="ts">
	let format = $state<'PDF' | 'JSON' | 'CEF'>('PDF');
	const formats = ['PDF', 'JSON', 'CEF'] as const;
</script>

<div>
	<div class="module-label"><span class="id">MOD.01</span> Report Builder</div>
	<div class="obsidian stagger">
		<span class="sweep"></span>
		<div class="reactor"></div>
		<div class="relative z-[5] p-5">
			<div class="flex items-center justify-between mb-4">
				<span class="text-xs font-bold tracking-[0.22em] uppercase" style="font-family:var(--font-display); color:var(--color-white);">Forensic Report</span>
				<span class="text-[9px] tracking-[0.18em] uppercase" style="color:var(--color-red);">PDF.GEN</span>
			</div>

			<!-- Date pickers -->
			<div class="grid grid-cols-2 gap-2.5 mb-3.5">
				<div>
					<div class="text-[9px] tracking-[0.2em] uppercase mb-1.5" style="color:var(--color-white-4);">From</div>
					<div class="px-3.5 py-3 flex items-center gap-2 text-[13px] cursor-pointer transition-all" style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white); font-family:var(--font-term);">
						2026.05.01
						<span class="ml-auto text-[10px]" style="color:var(--color-red);">&#9662;</span>
					</div>
				</div>
				<div>
					<div class="text-[9px] tracking-[0.2em] uppercase mb-1.5" style="color:var(--color-white-4);">To</div>
					<div class="px-3.5 py-3 flex items-center gap-2 text-[13px] cursor-pointer transition-all" style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white); font-family:var(--font-term);">
						2026.05.11
						<span class="ml-auto text-[10px]" style="color:var(--color-red);">&#9662;</span>
					</div>
				</div>
			</div>

			<!-- Format toggle -->
			<div class="text-[9px] tracking-[0.2em] uppercase mb-1.5" style="color:var(--color-white-4);">Format</div>
			<div class="flex gap-1.5 mb-3.5">
				{#each formats as f}
					<button
						class="flex-1 px-2.5 py-2.5 text-[10px] font-bold tracking-[0.12em] uppercase text-center cursor-pointer transition-all"
						style="background:{format === f ? 'linear-gradient(135deg, rgba(220,38,38,.25), rgba(220,38,38,.08))' : 'rgba(0,0,0,.3)'};
							   border:1px solid {format === f ? 'var(--color-red)' : 'rgba(255,255,255,.1)'};
							   color:{format === f ? 'var(--color-red)' : 'var(--color-white-3)'};
							   box-shadow:{format === f ? 'inset 0 1px 0 rgba(255,255,255,.1), 0 0 16px rgba(220,38,38,.2)' : 'none'};"
						onclick={() => format = f}
					>{f}</button>
				{/each}
			</div>

			<!-- Actions -->
			<div class="text-[9px] tracking-[0.2em] uppercase mb-1.5 mt-1.5" style="color:var(--color-white-4);">Output</div>
			<div class="grid grid-cols-2 gap-2 mb-3.5">
				<button class="px-3 py-3.5 text-[10px] font-bold tracking-[0.18em] uppercase flex items-center justify-center gap-1.5 cursor-pointer transition-all" style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white-2);">
					Preview
				</button>
				<button class="px-3 py-3.5 text-[10px] font-bold tracking-[0.18em] uppercase flex items-center justify-center gap-1.5 cursor-pointer transition-all" style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white-2);">
					Print
				</button>
			</div>
			<button class="w-full px-3 py-3.5 text-[10px] font-bold tracking-[0.18em] uppercase flex items-center justify-center gap-1.5 cursor-pointer transition-all" style="background:linear-gradient(135deg, rgba(220,38,38,.2), rgba(220,38,38,.05)); border:1px solid rgba(220,38,38,.4); color:var(--color-red); box-shadow:inset 0 1px 0 rgba(255,255,255,.08), 0 0 20px rgba(220,38,38,.15);">
				Generate &amp; Download
			</button>

			<!-- Preview thumb -->
			<div class="flex items-center gap-3 mt-3.5 p-3" style="background:rgba(0,0,0,.3); border:1px solid rgba(255,255,255,.08);">
				<div class="w-12 h-16 flex items-center justify-center relative overflow-hidden" style="background:linear-gradient(135deg, var(--color-white-bg), var(--color-white-bg-2)); border:1px solid rgba(5,5,7,.2);">
				</div>
				<div class="flex-1 min-w-0">
					<div class="text-[11px]" style="color:var(--color-white);">incident-report.{format.toLowerCase()}</div>
					<div class="text-[9px] tracking-[0.05em]" style="color:var(--color-white-4);">SIGNED CHAIN EVIDENCE</div>
				</div>
			</div>
		</div>
	</div>
</div>

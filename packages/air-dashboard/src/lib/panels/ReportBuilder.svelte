<script lang="ts">
	import { replayStore } from '$lib/stores/replay.svelte';
	import { findingsStore } from '$lib/stores/findings.svelte';
	import { verifierStore } from '$lib/stores/verifier.svelte';
	import type { AgDRRecord, Finding } from '$lib/agdr/types';

	let format = $state<'PDF' | 'JSON' | 'CEF'>('PDF');
	const formats = ['PDF', 'JSON', 'CEF'] as const;

	let dateFrom = $state('2026-05-01');
	let dateTo = $state(new Date().toISOString().slice(0, 10));

	function filtered(): AgDRRecord[] {
		return replayStore.emitted.filter(r => {
			const d = r.timestamp.slice(0, 10);
			return d >= dateFrom && d <= dateTo;
		});
	}

	function buildJson(): string {
		return JSON.stringify({
			report_type: 'AIR Forensic Report',
			generated: new Date().toISOString(),
			date_range: { from: dateFrom, to: dateTo },
			chain_integrity_pct: verifierStore.integrityScore,
			total_records: filtered().length,
			total_findings: findingsStore.all.length,
			findings: findingsStore.all,
			records: filtered(),
		}, null, 2);
	}

	function buildCef(): string {
		return findingsStore.all.map((f: Finding) => {
			const sev = f.severity === 'critical' ? 10 : f.severity === 'high' ? 7 : 4;
			return `CEF:0|Vindicara|ProjectAIR|1.0|${f.detector_id}|${f.title}|${sev}|`
				+ `msg=${f.description} stepIndex=${f.step_index} stepId=${f.step_id}`;
		}).join('\n');
	}

	function buildPdfHtml(): string {
		const records = filtered();
		const findings = findingsStore.all;
		const rows = findings.map((f: Finding) =>
			`<tr><td>${f.detector_id}</td><td>${f.severity.toUpperCase()}</td>`
			+ `<td>${f.title}</td><td>${f.description}</td><td>${f.step_index}</td></tr>`
		).join('');
		return `<!DOCTYPE html><html><head><title>AIR Forensic Report</title>
<style>body{font-family:monospace;padding:40px;color:#050507}
h1{letter-spacing:4px;font-size:24px}
table{width:100%;border-collapse:collapse;margin-top:20px}
th,td{border:1px solid #ccc;padding:8px;text-align:left;font-size:12px}
th{background:#050507;color:#f8f6f1}
.meta{display:flex;gap:40px;margin:16px 0;font-size:13px}
.sev-critical{color:#dc2626;font-weight:bold}
.sev-high{color:#ff8c00;font-weight:bold}
.sev-medium{color:#d4a017}</style></head><body>
<h1>PROJECT AIR — FORENSIC REPORT</h1>
<div class="meta"><span>Generated: ${new Date().toISOString()}</span>
<span>Range: ${dateFrom} to ${dateTo}</span>
<span>Records: ${records.length}</span>
<span>Chain Integrity: ${verifierStore.integrityScore}%</span></div>
<h2>Findings (${findings.length})</h2>
<table><tr><th>Detector</th><th>Severity</th><th>Title</th>
<th>Description</th><th>Step</th></tr>${rows}</table></body></html>`;
	}

	function download(content: string, name: string, mime: string): void {
		const blob = new Blob([content], { type: mime });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = name;
		a.click();
		URL.revokeObjectURL(url);
	}

	function handleGenerate(): void {
		const base = `incident-report`;
		if (format === 'JSON') {
			download(buildJson(), `${base}.json`, 'application/json');
		} else if (format === 'CEF') {
			download(buildCef(), `${base}.cef`, 'text/plain');
		} else {
			const w = window.open('', '_blank');
			if (!w) return;
			w.document.write(buildPdfHtml());
			w.document.close();
			w.focus();
			w.print();
		}
	}

	function handlePreview(): void {
		const w = window.open('', '_blank');
		if (!w) return;
		if (format === 'PDF') {
			w.document.write(buildPdfHtml());
		} else {
			const content = format === 'JSON' ? buildJson() : buildCef();
			w.document.write(`<pre style="font-family:monospace;padding:20px;background:#0a0a0f;color:#f8f6f1;">${content.replace(/</g, '&lt;')}</pre>`);
		}
		w.document.close();
		w.document.title = `AIR Report Preview (${format})`;
	}

	function handlePrint(): void {
		const w = window.open('', '_blank');
		if (!w) return;
		w.document.write(buildPdfHtml());
		w.document.close();
		w.focus();
		w.print();
	}

	const filename = $derived(`incident-report.${format.toLowerCase()}`);
</script>

<div>
	<div class="module-label"><span class="id">MOD.01</span> Report Builder</div>
	<div class="obsidian stagger">
		<span class="sweep"></span>
		<div class="reactor"></div>
		<div class="relative z-[5] p-5">
			<div class="flex items-center justify-between mb-4">
				<span class="text-xs font-bold tracking-[0.22em] uppercase" style="font-family:var(--font-display); color:var(--color-white);">Forensic Report</span>
				<span class="text-[9px] tracking-[0.18em] uppercase" style="color:var(--color-red);">{format}.GEN</span>
			</div>

			<div class="grid grid-cols-2 gap-2.5 mb-3.5">
				<div>
					<div class="text-[9px] tracking-[0.2em] uppercase mb-1.5" style="color:var(--color-white-4);">From</div>
					<input type="date" bind:value={dateFrom} class="w-full px-3.5 py-3 text-[13px] cursor-pointer" style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white); font-family:var(--font-term); color-scheme:dark;" />
				</div>
				<div>
					<div class="text-[9px] tracking-[0.2em] uppercase mb-1.5" style="color:var(--color-white-4);">To</div>
					<input type="date" bind:value={dateTo} class="w-full px-3.5 py-3 text-[13px] cursor-pointer" style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white); font-family:var(--font-term); color-scheme:dark;" />
				</div>
			</div>

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

			<div class="text-[9px] tracking-[0.2em] uppercase mb-1.5 mt-1.5" style="color:var(--color-white-4);">Output</div>
			<div class="grid grid-cols-2 gap-2 mb-3.5">
				<button onclick={handlePreview} class="px-3 py-3.5 text-[10px] font-bold tracking-[0.18em] uppercase flex items-center justify-center gap-1.5 cursor-pointer transition-all hover:border-white/30" style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white-2);">
					Preview
				</button>
				<button onclick={handlePrint} class="px-3 py-3.5 text-[10px] font-bold tracking-[0.18em] uppercase flex items-center justify-center gap-1.5 cursor-pointer transition-all hover:border-white/30" style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white-2);">
					Print
				</button>
			</div>
			<button onclick={handleGenerate} class="w-full px-3 py-3.5 text-[10px] font-bold tracking-[0.18em] uppercase flex items-center justify-center gap-1.5 cursor-pointer transition-all" style="background:linear-gradient(135deg, rgba(220,38,38,.2), rgba(220,38,38,.05)); border:1px solid rgba(220,38,38,.4); color:var(--color-red); box-shadow:inset 0 1px 0 rgba(255,255,255,.08), 0 0 20px rgba(220,38,38,.15);">
				Generate &amp; Download
			</button>

			<div class="flex items-center gap-3 mt-3.5 p-3" style="background:rgba(0,0,0,.3); border:1px solid rgba(255,255,255,.08);">
				<div class="w-12 h-16 flex items-center justify-center relative overflow-hidden" style="background:linear-gradient(135deg, var(--color-white-bg), var(--color-white-bg-2)); border:1px solid rgba(5,5,7,.2);">
				</div>
				<div class="flex-1 min-w-0">
					<div class="text-[11px]" style="color:var(--color-white);">{filename}</div>
					<div class="text-[9px] tracking-[0.05em]" style="color:var(--color-white-4);">SIGNED CHAIN EVIDENCE</div>
				</div>
			</div>
		</div>
	</div>
</div>

<script lang="ts">
	let { value, max, label, suffix = '', color = 'red' } = $props<{
		value: number;
		max: number;
		label: string;
		suffix?: string;
		color?: 'red' | 'green' | 'critical';
	}>();

	const pct = $derived(max > 0 ? Math.min((value / max) * 100, 100) : 0);

	const colorMap = {
		red: { text: 'var(--color-red)', fill: 'linear-gradient(90deg, var(--color-red), var(--color-red-bright))', glow: 'var(--color-red-glow)' },
		green: { text: 'var(--color-terminal-green)', fill: 'linear-gradient(90deg, #6effb3, #a8ff5e)', glow: 'rgba(110,255,179,.7)' },
		critical: { text: 'var(--color-critical)', fill: 'linear-gradient(90deg, #ff5468, #ff8a4d)', glow: 'rgba(255,84,104,.7)' }
	} as const;

	const c = $derived(colorMap[color as keyof typeof colorMap]);
</script>

<div class="obsidian p-5">
	<span class="sweep"></span>
	<div class="reactor"></div>
	<div class="relative z-[5]">
		<div class="text-[46px] font-bold tracking-[0.02em] leading-[.9] mb-1.5" style="font-family:var(--font-display); color:{c.text}; text-shadow:0 0 20px {c.glow};">
			{value}{suffix}
		</div>
		<div class="text-[9px] tracking-[0.25em] uppercase mb-3" style="color:var(--color-white-3);">{label}</div>
		<div class="h-1 relative overflow-hidden" style="background:rgba(255,255,255,.06); border-radius:2px;">
			<div class="h-full transition-all duration-300" style="width:{pct}%; background:{c.fill}; box-shadow:0 0 10px {c.glow}; border-radius:2px;"></div>
		</div>
	</div>
</div>

<script lang="ts">
	import '../app.css';

	let { children } = $props();
</script>

<svelte:head>
	<meta name="description" content="AIR Cloud: forensic evidence console for instrumented AI agents." />
</svelte:head>

<!-- Background effects -->
<div class="fixed inset-0 z-0 pointer-events-none overflow-hidden">
	<div class="orb absolute w-[600px] h-[600px] -top-40 -left-36" style="background:radial-gradient(circle, rgba(220,38,38,.5) 0%, transparent 70%);"></div>
	<div class="orb absolute w-[680px] h-[680px] -bottom-60 -right-56" style="background:radial-gradient(circle, rgba(180,210,255,.5) 0%, transparent 70%); animation-delay:-12s;"></div>
	<div class="orb absolute w-[420px] h-[420px] top-[38%] left-[42%]" style="background:radial-gradient(circle, rgba(255,180,140,.4) 0%, transparent 70%); animation-delay:-6s;"></div>
</div>
<div class="ascii-grid"></div>
<div class="hud-scanline" aria-hidden="true"></div>

{@render children()}

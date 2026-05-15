<script lang="ts">
	import '../app.css';
	let { children } = $props();
</script>

<svelte:head>
	<meta name="description" content="AIR Cloud: forensic evidence console for instrumented AI agents." />
</svelte:head>

{@render children()}

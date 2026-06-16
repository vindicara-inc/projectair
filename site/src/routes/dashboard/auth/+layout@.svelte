<script lang="ts">
	import '$lib/console/console.css';

	let { children } = $props();
</script>

<div class="console-shell" data-theme="dark">
	{@render children()}
</div>

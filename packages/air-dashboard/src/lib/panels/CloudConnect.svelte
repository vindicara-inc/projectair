<script lang="ts">
	import { cloudSession } from '$lib/stores/cloud_session.svelte';
	import { roleStore } from '$lib/stores/role.svelte';

	let { onChainLoaded } = $props<{
		onChainLoaded: () => void;
	}>();

	function handleDisconnect(): void {
		cloudSession.disconnect();
	}
</script>

<div>
	<div class="module-label"><span class="id">CLOUD</span> AIR Cloud</div>
	<div class="obsidian stagger">
		<span class="sweep"></span>
		<div class="reactor"></div>
		<div class="relative z-[5] p-5">
			<div class="flex items-center justify-between mb-4">
				<span class="text-xs font-bold tracking-[0.22em] uppercase" style="font-family:var(--font-display); color:var(--color-white);">Live Connect</span>
				{#if cloudSession.status === 'connected'}
					<span class="text-[9px] tracking-[0.18em] uppercase px-1.5 py-0.5" style="color:var(--color-terminal-green); border:1px solid rgba(110,255,179,.4);">CONNECTED</span>
				{:else if cloudSession.status === 'connecting'}
					<span class="text-[9px] tracking-[0.18em] uppercase px-1.5 py-0.5" style="color:var(--color-high); border:1px solid rgba(255,181,71,.4);">CONNECTING</span>
				{:else if cloudSession.status === 'error'}
					<span class="text-[9px] tracking-[0.18em] uppercase px-1.5 py-0.5" style="color:var(--color-critical); border:1px solid rgba(255,84,104,.4);">ERROR</span>
				{:else}
					<span class="text-[9px] tracking-[0.18em] uppercase px-1.5 py-0.5" style="color:var(--color-white-4); border:1px solid rgba(248,246,241,.15);">OFFLINE</span>
				{/if}
			</div>

			{#if cloudSession.isConnected && cloudSession.workspace}
				<!-- Connected: read-only workspace info -->
				<div class="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1.5 mb-4">
					<span class="text-[9px] tracking-[0.14em] uppercase" style="color:var(--color-white-4);">workspace</span>
					<span class="text-[11px]" style="color:var(--color-white);">{cloudSession.workspace.name}</span>
					<span class="text-[9px] tracking-[0.14em] uppercase" style="color:var(--color-white-4);">id</span>
					<span class="text-[10px] font-mono" style="color:var(--color-white-3);">{cloudSession.workspace.workspace_id}</span>
					<span class="text-[9px] tracking-[0.14em] uppercase" style="color:var(--color-white-4);">role</span>
					<span class="text-[10px] font-mono uppercase" style="color:var(--color-white-3);">{roleStore.current}</span>
					<span class="text-[9px] tracking-[0.14em] uppercase" style="color:var(--color-white-4);">endpoint</span>
					<span class="text-[10px] font-mono truncate" style="color:var(--color-white-3);">{cloudSession.baseUrl}</span>
				</div>

				<div class="flex gap-2">
					<button
						class="flex-1 px-3 py-3 text-[10px] font-bold tracking-[0.18em] uppercase cursor-pointer transition-all flex items-center justify-center"
						style="background:linear-gradient(135deg, rgba(220,38,38,.2), rgba(220,38,38,.05)); border:1px solid rgba(220,38,38,.4); color:var(--color-red);"
						onclick={onChainLoaded}
					>
						Refresh Chain
					</button>
					<button
						class="px-3 py-3 text-[10px] font-bold tracking-[0.18em] uppercase cursor-pointer transition-all"
						style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white-3);"
						onclick={handleDisconnect}
					>
						Disconnect
					</button>
				</div>
			{:else if cloudSession.status === 'connecting'}
				<p class="text-[11px]" style="color:var(--color-white-4);">Establishing SSO session...</p>
			{:else if cloudSession.status === 'error'}
				<p class="text-[10px] break-words mb-3" style="color:var(--color-critical);">{cloudSession.error}</p>
				<p class="text-[10px]" style="color:var(--color-white-4);">Sign out and back in to retry.</p>
			{:else}
				<p class="text-[11px]" style="color:var(--color-white-4);">Sign in to connect to AIR Cloud.</p>
			{/if}
		</div>
	</div>
</div>

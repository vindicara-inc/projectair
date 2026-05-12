<script lang="ts">
	import { cloudSession } from '$lib/stores/cloud_session.svelte';
	import { DEFAULT_BASE_URL } from '$lib/transport/index';

	let { onChainLoaded } = $props<{
		onChainLoaded: () => void;
	}>();

	let apiKey = $state('');
	let baseUrl = $state(cloudSession.baseUrl || DEFAULT_BASE_URL);
	let loadingChain = $state(false);

	async function handleConnect(): Promise<void> {
		await cloudSession.connect(baseUrl.trim(), apiKey.trim());
		if (cloudSession.status === 'connected') {
			apiKey = '';
			onChainLoaded();
		}
	}

	function handleDisconnect(): void {
		cloudSession.disconnect();
		apiKey = '';
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
				<!-- Connected state -->
				<div class="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1.5 mb-4">
					<span class="text-[9px] tracking-[0.14em] uppercase" style="color:var(--color-white-4);">workspace</span>
					<span class="text-[11px]" style="color:var(--color-white);">{cloudSession.workspace.name}</span>
					<span class="text-[9px] tracking-[0.14em] uppercase" style="color:var(--color-white-4);">id</span>
					<span class="text-[10px] font-mono" style="color:var(--color-white-3);">{cloudSession.workspace.workspace_id}</span>
					<span class="text-[9px] tracking-[0.14em] uppercase" style="color:var(--color-white-4);">endpoint</span>
					<span class="text-[10px] font-mono truncate" style="color:var(--color-white-3);">{cloudSession.baseUrl}</span>
				</div>

				<div class="flex gap-2">
					<button
						class="flex-1 px-3 py-3 text-[10px] font-bold tracking-[0.18em] uppercase cursor-pointer transition-all flex items-center justify-center"
						style="background:linear-gradient(135deg, rgba(220,38,38,.2), rgba(220,38,38,.05)); border:1px solid rgba(220,38,38,.4); color:var(--color-red);"
						onclick={onChainLoaded}
						disabled={loadingChain}
					>
						{loadingChain ? 'Loading...' : 'Refresh Chain'}
					</button>
					<button
						class="px-3 py-3 text-[10px] font-bold tracking-[0.18em] uppercase cursor-pointer transition-all"
						style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white-3);"
						onclick={handleDisconnect}
					>
						Disconnect
					</button>
				</div>
			{:else}
				<!-- Disconnected state -->
				<form
					onsubmit={(e: SubmitEvent) => { e.preventDefault(); handleConnect(); }}
				>
					<div class="mb-3">
						<div class="text-[9px] tracking-[0.2em] uppercase mb-1.5" style="color:var(--color-white-4);">Endpoint</div>
						<input
							type="url"
							bind:value={baseUrl}
							placeholder="https://cloud.vindicara.io"
							class="w-full px-3.5 py-2.5 text-[12px]"
							style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white); font-family:var(--font-mono); outline:none;"
						/>
					</div>
					<div class="mb-3">
						<div class="text-[9px] tracking-[0.2em] uppercase mb-1.5" style="color:var(--color-white-4);">API Key</div>
						<input
							type="password"
							bind:value={apiKey}
							placeholder="air_..."
							autocomplete="off"
							class="w-full px-3.5 py-2.5 text-[12px]"
							style="background:rgba(0,0,0,.4); border:1px solid rgba(255,255,255,.12); color:var(--color-white); font-family:var(--font-mono); outline:none;"
						/>
					</div>
					<button
						type="submit"
						class="w-full px-3 py-3 text-[10px] font-bold tracking-[0.18em] uppercase cursor-pointer transition-all"
						style="background:linear-gradient(135deg, rgba(220,38,38,.2), rgba(220,38,38,.05)); border:1px solid rgba(220,38,38,.4); color:var(--color-red); box-shadow:inset 0 1px 0 rgba(255,255,255,.08), 0 0 20px rgba(220,38,38,.15);"
						disabled={!apiKey || !baseUrl || cloudSession.status === 'connecting'}
					>
						{cloudSession.status === 'connecting' ? 'Connecting...' : 'Connect'}
					</button>
					{#if cloudSession.error}
						<p class="text-[10px] mt-2 break-words" style="color:var(--color-critical);">{cloudSession.error}</p>
					{/if}
				</form>
			{/if}
		</div>
	</div>
</div>

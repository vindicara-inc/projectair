<!--
  Cloud Connect panel — paste an AIR Cloud API key + base URL, hit Connect,
  and the dashboard pulls the workspace's chain from the live ingest
  endpoint. Disconnect clears the cached credentials.
-->
<script lang="ts">
	import { cloudSession } from '$lib/stores/cloud_session.svelte';
	import { DEFAULT_BASE_URL } from '$lib/transport/index';

	let apiKey = $state('');
	let baseUrl = $state(cloudSession.baseUrl || DEFAULT_BASE_URL);

	async function handleConnect() {
		await cloudSession.connect(baseUrl.trim(), apiKey.trim());
		if (cloudSession.status === 'connected') {
			apiKey = '';
		}
	}

	function handleDisconnect() {
		cloudSession.disconnect();
		apiKey = '';
	}
</script>

<div class="panel">
	<div class="header">
		<span class="label">AIR Cloud</span>
		{#if cloudSession.status === 'connected'}
			<span class="badge ok">connected</span>
		{:else if cloudSession.status === 'connecting'}
			<span class="badge pending">connecting…</span>
		{:else if cloudSession.status === 'error'}
			<span class="badge err">error</span>
		{:else}
			<span class="badge off">disconnected</span>
		{/if}
	</div>

	{#if cloudSession.isConnected && cloudSession.workspace}
		<dl class="info">
			<dt>workspace</dt>
			<dd>{cloudSession.workspace.name}</dd>
			<dt>id</dt>
			<dd><code>{cloudSession.workspace.workspace_id}</code></dd>
			<dt>endpoint</dt>
			<dd><code>{cloudSession.baseUrl}</code></dd>
		</dl>
		<button type="button" class="action" onclick={handleDisconnect}>Disconnect</button>
	{:else}
		<form
			onsubmit={(e: SubmitEvent) => {
				e.preventDefault();
				handleConnect();
			}}
		>
			<label>
				<span>endpoint</span>
				<input type="url" bind:value={baseUrl} placeholder="https://cloud.vindicara.io" />
			</label>
			<label>
				<span>api key</span>
				<input type="password" bind:value={apiKey} placeholder="air_…" autocomplete="off" />
			</label>
			<button type="submit" class="action" disabled={!apiKey || !baseUrl}>
				{cloudSession.status === 'connecting' ? 'connecting…' : 'Connect'}
			</button>
			{#if cloudSession.error}
				<p class="error">{cloudSession.error}</p>
			{/if}
		</form>
	{/if}
</div>

<style>
	.panel {
		font-family: 'JetBrains Mono', ui-monospace, monospace;
		font-size: 11px;
		color: rgba(220, 235, 255, 0.85);
		background: rgba(8, 12, 18, 0.85);
		border: 1px solid rgba(120, 180, 220, 0.2);
		padding: 14px 16px;
		min-width: 280px;
	}
	.header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 10px;
		text-transform: uppercase;
		letter-spacing: 0.18em;
	}
	.label {
		color: rgba(255, 80, 80, 0.85);
		font-weight: 600;
	}
	.badge {
		font-size: 9px;
		padding: 2px 6px;
		border: 1px solid currentColor;
		border-radius: 1px;
		text-transform: uppercase;
		letter-spacing: 0.16em;
	}
	.badge.ok {
		color: rgba(120, 220, 140, 0.95);
	}
	.badge.pending {
		color: rgba(220, 200, 100, 0.95);
	}
	.badge.err {
		color: rgba(255, 90, 90, 0.95);
	}
	.badge.off {
		color: rgba(140, 150, 160, 0.85);
	}
	.info {
		display: grid;
		grid-template-columns: max-content 1fr;
		gap: 4px 12px;
		margin: 0 0 10px;
	}
	.info dt {
		color: rgba(140, 160, 180, 0.85);
		text-transform: uppercase;
		letter-spacing: 0.14em;
		font-size: 9px;
	}
	.info dd {
		margin: 0;
		color: rgba(220, 235, 255, 0.95);
	}
	form label {
		display: block;
		margin-bottom: 8px;
	}
	form span {
		display: block;
		color: rgba(140, 160, 180, 0.85);
		text-transform: uppercase;
		letter-spacing: 0.14em;
		font-size: 9px;
		margin-bottom: 3px;
	}
	form input {
		width: 100%;
		padding: 6px 8px;
		background: rgba(0, 0, 0, 0.4);
		border: 1px solid rgba(120, 180, 220, 0.25);
		color: rgba(220, 235, 255, 0.95);
		font-family: inherit;
		font-size: 11px;
	}
	form input:focus {
		outline: 1px solid rgba(255, 80, 80, 0.6);
	}
	.action {
		display: block;
		width: 100%;
		padding: 7px 12px;
		margin-top: 6px;
		background: rgba(255, 80, 80, 0.15);
		border: 1px solid rgba(255, 80, 80, 0.5);
		color: rgba(255, 200, 200, 0.95);
		font-family: inherit;
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.16em;
		cursor: pointer;
	}
	.action:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}
	.action:hover:not(:disabled) {
		background: rgba(255, 80, 80, 0.25);
	}
	.error {
		color: rgba(255, 120, 120, 0.95);
		font-size: 10px;
		margin: 8px 0 0;
		word-break: break-word;
	}
</style>

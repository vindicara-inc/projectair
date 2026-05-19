<script lang="ts">
	import { roleStore } from '$lib/stores/role.svelte';
	import { cloudSession } from '$lib/stores/cloud_session.svelte';
	import { authStore } from '$lib/stores/auth.svelte';

	let expanded = $state(false);
	let activeSection = $state<string | null>(null);

	function toggle(section: string): void {
		activeSection = activeSection === section ? null : section;
	}

	const settingsItems = [
		{ id: 'profile', label: 'Profile', icon: '⬡' },
		{ id: 'api-keys', label: 'API Keys', icon: '◈' },
		{ id: 'deployment', label: 'Deployment', icon: '◉' },
		{ id: 'extensions', label: 'Extensions', icon: '⬢' },
		{ id: 'branding', label: 'Branding', icon: '△' },
		{ id: 'upgrade', label: 'Upgrade', icon: '◆' },
	];
</script>

<nav
	class="fixed left-0 top-0 h-full z-50 transition-all duration-200 flex flex-col sidebar"
	class:collapsed={!expanded}
	class:expanded={expanded}
	onmouseenter={() => (expanded = true)}
	onmouseleave={() => { expanded = false; activeSection = null; }}
>
	<!-- User section -->
	<div class="sidebar-user">
		{#if expanded}
			<div class="user-avatar">
				{(roleStore.email ?? 'U')[0].toUpperCase()}
			</div>
			<div class="user-info">
				<p class="user-name">{cloudSession.workspace?.name ?? 'Not connected'}</p>
				<p class="user-email">{roleStore.email ?? ''}</p>
				<span class="user-role {roleStore.current === 'owner' ? 'owner' : roleStore.current === 'admin' ? 'admin' : 'member'}">
					{roleStore.current}
				</span>
			</div>
		{:else}
			<div class="user-avatar-sm">
				{(roleStore.email ?? 'U')[0].toUpperCase()}
			</div>
		{/if}
	</div>

	<!-- Settings nav -->
	<div class="sidebar-nav">
		{#each settingsItems as item}
			<button
				onclick={() => toggle(item.id)}
				class="nav-item cursor-pointer"
				class:active={activeSection === item.id}
			>
				<span class="nav-icon">{item.icon}</span>
				{#if expanded}
					<span class="nav-label">{item.label}</span>
					<span class="nav-arrow">{activeSection === item.id ? '−' : '+'}</span>
				{/if}
			</button>

			{#if expanded && activeSection === item.id}
				<div class="nav-panel">
					{#if item.id === 'profile'}
						<div class="panel-field">
							<span class="panel-k">Email</span>
							<span class="panel-v">{roleStore.email ?? 'N/A'}</span>
						</div>
						<div class="panel-field">
							<span class="panel-k">Workspace</span>
							<span class="panel-v">{cloudSession.workspace?.workspace_id ?? 'N/A'}</span>
						</div>
						<div class="panel-field">
							<span class="panel-k">Role</span>
							<span class="panel-v">{roleStore.current}</span>
						</div>
						<div class="panel-field">
							<span class="panel-k">Endpoint</span>
							<span class="panel-v">{cloudSession.baseUrl}</span>
						</div>
					{:else if item.id === 'api-keys'}
						<p class="panel-desc">Manage API keys for SDK ingestion and agent authentication.</p>
						<button class="panel-btn cursor-pointer">View keys</button>
						<button class="panel-btn cursor-pointer">Generate new key</button>
					{:else if item.id === 'deployment'}
						<p class="panel-desc">Configure how AIR Cloud receives capsules from your agents.</p>
						<button class="panel-btn cursor-pointer">Ingestion settings</button>
						<button class="panel-btn cursor-pointer">Webhook config</button>
					{:else if item.id === 'extensions'}
						<p class="panel-desc">Connect third-party tools and integrations.</p>
						<button class="panel-btn cursor-pointer">SIEM export</button>
						<button class="panel-btn cursor-pointer">OpenLineage</button>
						<button class="panel-btn cursor-pointer">Slack alerts</button>
					{:else if item.id === 'branding'}
						<p class="panel-desc">Customize the dashboard appearance for your organization.</p>
						<button class="panel-btn cursor-pointer">Logo & colors</button>
					{:else if item.id === 'upgrade'}
						<p class="panel-desc">You are on the {roleStore.current === 'owner' ? 'Team' : 'Individual'} plan.</p>
						<a href="https://vindicara.io/pricing" target="_blank" class="panel-btn cursor-pointer">View plans</a>
					{/if}
				</div>
			{/if}
		{/each}
	</div>

	<!-- Bottom -->
	<div class="sidebar-bottom">
		{#if expanded}
			<button
				onclick={() => authStore.logout()}
				class="signout-btn cursor-pointer"
			>Sign out</button>
		{/if}
	</div>
</nav>

<style>
	.sidebar {
		background: linear-gradient(180deg, rgba(5,5,7,0.96) 0%, rgba(8,8,12,0.98) 100%);
		border-right: 1px solid rgba(220,38,38,0.12);
		backdrop-filter: blur(20px);
		-webkit-backdrop-filter: blur(20px);
	}

	.collapsed { width: 52px; }
	.expanded { width: 240px; }

	.sidebar-user {
		padding: 16px 12px;
		padding-top: 44px;
		border-bottom: 1px solid rgba(255,255,255,0.04);
		display: flex;
		align-items: center;
		gap: 10px;
		min-height: 64px;
	}

	.user-avatar {
		width: 32px; height: 32px;
		display: flex; align-items: center; justify-content: center;
		font-family: var(--font-display);
		font-size: 12px; font-weight: 700;
		color: var(--color-red);
		background: rgba(220,38,38,0.1);
		border: 1px solid rgba(220,38,38,0.25);
		flex-shrink: 0;
	}

	.user-avatar-sm {
		width: 28px; height: 28px;
		display: flex; align-items: center; justify-content: center;
		font-family: var(--font-display);
		font-size: 10px; font-weight: 700;
		color: var(--color-red);
		background: rgba(220,38,38,0.1);
		border: 1px solid rgba(220,38,38,0.25);
		margin: 0 auto;
	}

	.user-info { overflow: hidden; }

	.user-name {
		font-family: var(--font-mono);
		font-size: 12px; font-weight: 600;
		color: var(--color-white);
		white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
	}

	.user-email {
		font-family: var(--font-mono);
		font-size: 10px;
		color: rgba(248,246,241,0.5);
		white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
		margin-top: 2px;
	}

	.user-role {
		display: inline-block;
		font-family: var(--font-mono);
		font-size: 8px; font-weight: 700;
		letter-spacing: 0.15em;
		text-transform: uppercase;
		padding: 2px 6px;
		margin-top: 4px;
	}

	.user-role.owner { background: rgba(220,38,38,0.15); color: var(--color-red); }
	.user-role.admin { background: rgba(255,181,71,0.12); color: var(--color-high); }
	.user-role.member { background: rgba(255,255,255,0.06); color: var(--color-white-3); }

	.sidebar-nav {
		flex: 1;
		padding: 8px 0;
		overflow-y: auto;
	}

	.nav-item {
		width: 100%;
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 11px 14px;
		font-family: var(--font-mono);
		font-size: 13px;
		color: rgba(248,246,241,0.6);
		background: none;
		border: none;
		text-align: left;
		transition: all 0.12s;
		letter-spacing: 0.05em;
	}

	.nav-item:hover {
		color: var(--color-white);
		background: rgba(255,255,255,0.03);
	}

	.nav-item.active {
		color: var(--color-red);
		background: rgba(220,38,38,0.06);
	}

	.nav-icon {
		width: 24px;
		text-align: center;
		font-size: 16px;
		flex-shrink: 0;
		color: rgba(248,246,241,0.7);
	}

	.nav-label {
		flex: 1;
		text-transform: uppercase;
		letter-spacing: 0.12em;
		font-size: 11px;
	}

	.nav-arrow {
		font-size: 12px;
		color: rgba(248,246,241,0.2);
	}

	.nav-panel {
		padding: 8px 14px 12px 48px;
		animation: panelIn 0.15s ease-out;
	}

	.panel-field {
		display: flex;
		justify-content: space-between;
		padding: 5px 0;
		font-family: var(--font-mono);
		font-size: 12px;
	}

	.panel-k {
		color: rgba(248,246,241,0.5);
		letter-spacing: 0.1em;
		text-transform: uppercase;
		text-shadow: 0 0 8px rgba(248,246,241,0.1);
	}

	.panel-v {
		color: rgba(248,246,241,0.8);
		text-align: right;
		max-width: 120px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		text-shadow: 0 0 6px rgba(248,246,241,0.08);
	}

	.panel-desc {
		font-family: var(--font-mono);
		font-size: 12px;
		line-height: 1.5;
		color: rgba(248,246,241,0.5);
		margin-bottom: 8px;
		text-shadow: 0 0 6px rgba(248,246,241,0.06);
	}

	.panel-btn {
		display: block;
		width: 100%;
		text-align: left;
		font-family: var(--font-mono);
		font-size: 12px;
		letter-spacing: 0.1em;
		text-transform: uppercase;
		color: rgba(248,246,241,0.6);
		padding: 7px 8px;
		margin-bottom: 2px;
		background: none;
		border: 1px solid rgba(255,255,255,0.06);
		transition: all 0.1s;
		text-decoration: none;
		text-shadow: 0 0 6px rgba(248,246,241,0.06);
	}

	.panel-btn:hover {
		color: var(--color-white);
		border-color: rgba(220,38,38,0.2);
		background: rgba(220,38,38,0.04);
	}

	.sidebar-bottom {
		padding: 12px;
		border-top: 1px solid rgba(255,255,255,0.04);
	}

	.signout-btn {
		width: 100%;
		font-family: var(--font-mono);
		font-size: 9px;
		letter-spacing: 0.15em;
		text-transform: uppercase;
		color: rgba(248,246,241,0.25);
		background: none;
		border: none;
		padding: 6px;
		text-align: center;
		transition: color 0.12s;
	}

	.signout-btn:hover { color: var(--color-red); }

	@keyframes panelIn {
		from { opacity: 0; transform: translateY(-4px); }
		to { opacity: 1; transform: translateY(0); }
	}
</style>

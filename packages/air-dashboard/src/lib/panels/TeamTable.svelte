<script lang="ts">
	import { onMount } from 'svelte';
	import { teamStore } from '$lib/stores/team.svelte';
	import { roleStore } from '$lib/stores/role.svelte';

	let inviteEmail = $state('');
	let inviteRole = $state('member');
	let confirmRevoke = $state<string | null>(null);

	onMount(() => {
		teamStore.load();
	});

	async function handleInvite(): Promise<void> {
		if (!inviteEmail.trim()) return;
		const ok = await teamStore.invite(inviteEmail.trim(), inviteRole);
		if (ok) {
			inviteEmail = '';
			inviteRole = 'member';
		}
	}

	async function handleRevoke(keyId: string): Promise<void> {
		await teamStore.revoke(keyId);
		confirmRevoke = null;
	}
</script>

<div class="p-6 max-w-4xl mx-auto">
	<h1
		class="text-xl font-bold text-white mb-6 tracking-wider uppercase"
		style="font-family: var(--font-mono);"
	>
		Team Members
	</h1>

	{#if roleStore.isAdmin}
		<form
			onsubmit={(e) => {
				e.preventDefault();
				handleInvite();
			}}
			class="flex gap-3 mb-8"
		>
			<input
				type="email"
				bind:value={inviteEmail}
				placeholder="email@example.com"
				class="flex-1 bg-zinc-900 border border-zinc-700 text-white text-sm px-3 py-2 focus:border-red-500 focus:outline-none"
				style="font-family: var(--font-mono);"
			/>
			<select
				bind:value={inviteRole}
				class="bg-zinc-900 border border-zinc-700 text-white text-sm px-3 py-2"
				style="font-family: var(--font-mono);"
			>
				<option value="member">member</option>
				{#if roleStore.isOwner}
					<option value="admin">admin</option>
				{/if}
			</select>
			<button
				type="submit"
				class="px-4 py-2 bg-red-600 text-white text-sm uppercase tracking-wider hover:bg-red-500 transition-colors"
				style="font-family: var(--font-mono);"
			>
				Invite
			</button>
		</form>
	{/if}

	{#if teamStore.error}
		<p class="text-red-400 text-sm mb-4" style="font-family: var(--font-mono);">
			{teamStore.error}
		</p>
	{/if}

	<table class="w-full text-sm" style="font-family: var(--font-mono);">
		<thead>
			<tr class="text-zinc-500 text-xs uppercase tracking-wider border-b border-zinc-800">
				<th class="text-left py-2 px-3">Name</th>
				<th class="text-left py-2 px-3">Role</th>
				<th class="text-left py-2 px-3">Status</th>
				<th class="text-left py-2 px-3">Key ID</th>
				<th class="text-right py-2 px-3">Actions</th>
			</tr>
		</thead>
		<tbody>
			{#each teamStore.members as member (member.key_id)}
				<tr class="border-b border-zinc-800/50 hover:bg-zinc-900/50">
					<td class="py-3 px-3 text-white">{member.name ?? 'unnamed'}</td>
					<td class="py-3 px-3">
						{#if roleStore.isOwner && member.role !== 'owner'}
							<select
								value={member.role}
								onchange={(e) =>
									teamStore.changeRole(member.key_id, (e.target as HTMLSelectElement).value)}
								class="bg-zinc-900 border border-zinc-700 text-white text-xs px-2 py-1"
								style="font-family: var(--font-mono);"
							>
								<option value="admin">admin</option>
								<option value="member">member</option>
								<option value="viewer">viewer</option>
							</select>
						{:else}
							<span
								class="px-2 py-0.5 text-xs {member.role === 'owner'
									? 'bg-red-900/50 text-red-400'
									: member.role === 'admin'
										? 'bg-amber-900/50 text-amber-400'
										: 'bg-zinc-800 text-zinc-400'}"
							>
								{member.role}
							</span>
						{/if}
					</td>
					<td class="py-3 px-3">
						<span class="text-xs {member.revoked_at ? 'text-red-400' : 'text-green-400'}">
							{member.revoked_at ? 'revoked' : 'active'}
						</span>
					</td>
					<td class="py-3 px-3 text-zinc-500">{member.key_id.slice(0, 8)}</td>
					<td class="py-3 px-3 text-right">
						{#if roleStore.isAdmin && member.role !== 'owner' && !member.revoked_at}
							{#if confirmRevoke === member.key_id}
								<button
									onclick={() => handleRevoke(member.key_id)}
									class="text-red-400 text-xs hover:text-red-300 mr-2"
									style="font-family: var(--font-mono);"
								>
									confirm
								</button>
								<button
									onclick={() => (confirmRevoke = null)}
									class="text-zinc-500 text-xs hover:text-zinc-300"
									style="font-family: var(--font-mono);"
								>
									cancel
								</button>
							{:else}
								<button
									onclick={() => (confirmRevoke = member.key_id)}
									class="text-zinc-500 text-xs hover:text-red-400 transition-colors"
									style="font-family: var(--font-mono);"
								>
									revoke
								</button>
							{/if}
						{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>

	{#if teamStore.loading}
		<p class="text-zinc-500 text-sm mt-4" style="font-family: var(--font-mono);">Loading...</p>
	{/if}
</div>

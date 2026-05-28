<script lang="ts">
  import { approvalStore, type ApprovalItem } from '$lib/stores/approval.svelte';
  import { triageStore } from '$lib/stores/triage.svelte';
  import { findingsStore } from '$lib/stores/findings.svelte';

  let collapsed = $state(false);
  let denyingIndex = $state<number | null>(null);
  let denyReason = $state('');

  const pendingItems = $derived(approvalStore.pending);
  const hasItems = $derived(approvalStore.items.length > 0);

  function handleApprove(item: ApprovalItem): void {
    approvalStore.approve(item.recordIndex, 'dashboard-operator');
    // Mark related findings as acknowledged
    const related = findingsStore.forStep(item.recordIndex);
    for (const f of related) {
      triageStore.acknowledge(f.step_id);
    }
  }

  function handleDeny(item: ApprovalItem): void {
    const reason = denyReason.trim() || 'Denied by operator';
    approvalStore.deny(item.recordIndex, reason);
    // Mark related findings as resolved (denied = blocked permanently)
    const related = findingsStore.forStep(item.recordIndex);
    for (const f of related) {
      triageStore.resolve(f.step_id);
    }
    denyingIndex = null;
    denyReason = '';
  }

  function formatTime(iso: string): string {
    try { return new Date(iso).toLocaleTimeString(); }
    catch { return '--:--'; }
  }
</script>

{#if hasItems}
  <div>
    <button class="section-label w-full text-left cursor-pointer" onclick={() => collapsed = !collapsed}>
      Approval Queue
      {#if pendingItems.length > 0}
        <span class="ml-1 text-xs" style="color: var(--color-critical);">({pendingItems.length})</span>
      {/if}
      <span class="ml-auto" style="color: var(--color-text-dim);">{collapsed ? '+' : '-'}</span>
    </button>

    {#if !collapsed}
      <div class="stark-panel p-3 flex flex-col gap-3">
        {#each approvalStore.items as item (item.recordIndex)}
          {@const related = findingsStore.forStep(item.recordIndex)}
          <div class="p-3" style="background: rgba(0,0,0,0.3); border: 1px solid {item.status === 'pending' ? 'rgba(220,38,38,0.3)' : 'rgba(255,255,255,0.04)'};">
            <div class="flex items-center gap-2 mb-2">
              <span class="severity-dot {item.status === 'pending' ? 'critical' : ''}"
                style="{item.status !== 'pending' ? 'opacity: 0.4;' : ''}"></span>
              <span class="text-xs font-semibold" style="font-family: var(--font-ui); color: var(--color-text);">
                {item.record.payload.tool_name ?? 'unknown tool'}
              </span>
              <span class="text-data text-xs ml-auto" style="font-size: 10px;">{formatTime(item.record.timestamp)}</span>
            </div>

            {#if item.record.payload.tool_args}
              <pre class="text-xs mb-2 p-1.5 overflow-x-auto" style="font-family: var(--font-data); color: var(--color-text-dim);
                background: rgba(0,0,0,0.3); white-space: pre-wrap; word-break: break-all; max-height: 60px;">
{JSON.stringify(item.record.payload.tool_args, null, 2)}</pre>
            {/if}

            {#if related.length > 0}
              <div class="mb-2">
                {#each related as f}
                  <span class="text-xs block" style="color: var(--color-critical);">{f.detector_id}: {f.title}</span>
                {/each}
              </div>
            {/if}

            {#if item.status === 'pending'}
              {#if denyingIndex === item.recordIndex}
                <div class="flex flex-col gap-2">
                  <input type="text" class="text-xs p-2 w-full" placeholder="Denial reason..."
                    style="background: rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.1); color: var(--color-text); font-family: var(--font-ui);"
                    bind:value={denyReason} />
                  <div class="flex gap-2">
                    <button class="btn-danger text-xs flex-1" onclick={() => handleDeny(item)}>Confirm Deny</button>
                    <button class="btn-secondary text-xs flex-1" onclick={() => { denyingIndex = null; denyReason = ''; }}>Cancel</button>
                  </div>
                </div>
              {:else}
                <div class="flex gap-2 mt-1">
                  <button class="btn-primary text-xs flex-1"
                    style="background: var(--color-success); border-color: var(--color-success);"
                    onclick={() => handleApprove(item)}>Approve</button>
                  <button class="btn-danger text-xs flex-1"
                    onclick={() => { denyingIndex = item.recordIndex; }}>Deny</button>
                </div>
              {/if}
            {:else if item.status === 'approved'}
              <div class="flex items-center gap-2 mt-1">
                <span class="text-xs" style="color: var(--color-success);">Approved</span>
                <span class="text-xs" style="color: var(--color-text-dim);">by {item.approvedBy}</span>
                {#if item.approvedAt}
                  <span class="text-data text-xs ml-auto" style="font-size: 10px;">{formatTime(item.approvedAt)}</span>
                {/if}
              </div>
            {:else}
              <div class="flex items-center gap-2 mt-1">
                <span class="text-xs" style="color: var(--color-critical);">Denied</span>
                {#if item.deniedReason}
                  <span class="text-xs" style="color: var(--color-text-dim);">{item.deniedReason}</span>
                {/if}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>
{/if}

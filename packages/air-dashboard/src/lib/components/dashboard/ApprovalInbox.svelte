<script lang="ts">
  interface PendingApproval {
    id: string;
    agent: string;
    description: string;
    policy: string;
    severity?: string;
    timestamp?: string;
  }

  let {
    items = [],
    onClose,
    onApprove,
    onDeny,
  }: {
    items: PendingApproval[];
    onClose: () => void;
    onApprove?: (id: string) => void;
    onDeny?: (id: string) => void;
  } = $props();
</script>

<div class="fixed inset-0 z-[100] bg-black/80 backdrop-blur-xl flex items-center justify-center">
  <div class="glass-panel w-[920px] max-h-[85vh] rounded-3xl overflow-hidden border border-violet-400/30 shadow-2xl">
    <!-- Header -->
    <div class="bg-gradient-to-r from-red-600 via-violet-600 to-indigo-600 px-8 py-6 flex items-center justify-between">
      <div>
        <h2 class="text-2xl font-semibold">Approval Inbox</h2>
        <p class="text-red-200 text-sm mt-1">Human-in-the-loop decisions required</p>
      </div>
      <button onclick={onClose} class="text-4xl leading-none text-white/70 hover:text-white transition-colors">&times;</button>
    </div>

    <!-- Content -->
    <div class="p-6 overflow-auto max-h-[calc(85vh-120px)] space-y-4 custom-scroll">
      {#each items as item (item.id)}
        <div class="glass-panel p-6 rounded-2xl border border-white/10">
          <div class="flex justify-between items-start">
            <div class="space-y-2">
              <div class="font-mono text-xs text-white/50">AGENT {item.agent}</div>
              <div class="text-lg font-medium text-white">{item.description}</div>
              <div class="text-sm text-white/70">Policy: <span class="font-mono">{item.policy}</span></div>
            </div>

            <div class="text-right">
              <div class="inline-block px-4 py-1 rounded-full text-sm border {(item.severity ?? 'Critical') === 'Critical' ? 'border-red-400 text-red-400' : 'border-orange-400 text-orange-400'}">
                {item.severity ?? 'Critical'}
              </div>
              {#if item.timestamp}
                <div class="text-xs text-white/50 mt-2 font-mono">{item.timestamp}</div>
              {/if}
            </div>
          </div>

          <div class="flex gap-4 mt-8">
            <button
              onclick={() => onApprove?.(item.id)}
              class="flex-1 py-4 bg-teal-500 hover:bg-teal-400 rounded-2xl font-medium text-lg transition-all active:scale-95"
            >
              Approve &amp; Sign
            </button>
            <button
              onclick={() => onDeny?.(item.id)}
              class="flex-1 py-4 bg-violet-600 hover:bg-violet-500 rounded-2xl font-medium text-lg transition-all active:scale-95"
            >
              Deny &amp; Sign
            </button>
          </div>
        </div>
      {:else}
        <div class="text-center py-12 text-white/40">No pending approvals</div>
      {/each}
    </div>

    <div class="p-6 border-t border-white/10 flex justify-end">
      <button onclick={onClose} class="px-8 py-3 text-sm text-white/60 hover:text-white transition-colors">Close</button>
    </div>
  </div>
</div>

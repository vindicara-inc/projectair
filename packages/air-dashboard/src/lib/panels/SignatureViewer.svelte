<script lang="ts">
  import type { AgDRRecord } from '$lib/agdr/types';
  import { verifyRecord, type RecordVerification } from '$lib/agdr/verify';
  import { GENESIS_PREV_HASH } from '$lib/agdr/types';
  import { replayStore } from '$lib/stores/replay.svelte';

  interface Props {
    record: AgDRRecord;
    stepIndex: number;
  }
  let { record, stepIndex }: Props = $props();

  let sigExpanded = $state(false);
  let copied = $state(false);

  const verification = $derived.by((): RecordVerification => {
    try { return verifyRecord(record); }
    catch { return { ok: false, reason: 'Verification threw an exception' }; }
  });

  const chainLinkOk = $derived.by((): boolean => {
    if (stepIndex === 0) return record.prev_hash === GENESIS_PREV_HASH;
    const prev = replayStore.emitted[stepIndex - 1];
    if (!prev) return false;
    return record.prev_hash === prev.content_hash;
  });

  const prevRecordHash = $derived.by((): string => {
    if (stepIndex === 0) return GENESIS_PREV_HASH;
    return replayStore.emitted[stepIndex - 1]?.content_hash ?? '(unavailable)';
  });

  async function copyEvidence(): Promise<void> {
    try {
      await navigator.clipboard.writeText(JSON.stringify(record, null, 2));
      copied = true;
      setTimeout(() => { copied = false; }, 2000);
    } catch { /* clipboard not available */ }
  }
</script>

<div class="flex flex-col gap-2">
  <div class="flex justify-between">
    <span class="text-label">Record</span>
    <span class="text-data text-xs" style="color: var(--color-red);">#{stepIndex}</span>
  </div>

  <div class="flex justify-between">
    <span class="text-label">Kind</span>
    <span class="text-data text-xs">{record.kind}</span>
  </div>

  <div>
    <span class="text-label block mb-1">Content Hash</span>
    <span class="text-data text-xs break-all" style="color: var(--color-red);">{record.content_hash}</span>
  </div>

  <div>
    <span class="text-label block mb-1">Previous Hash</span>
    <span class="text-data text-xs break-all"
      style="color: {chainLinkOk ? 'var(--color-success)' : 'var(--color-critical)'};">
      {record.prev_hash}
    </span>
    {#if !chainLinkOk}
      <span class="text-xs block mt-1" style="color: var(--color-critical);">
        Expected: {prevRecordHash}
      </span>
    {/if}
  </div>

  <div>
    <span class="text-label block mb-1">Signer Public Key</span>
    <span class="text-data text-xs break-all">{record.signer_key}</span>
  </div>

  <div>
    <span class="text-label block mb-1">Signature</span>
    {#if sigExpanded}
      <span class="text-data text-xs break-all">{record.signature}</span>
      <button class="text-xs mt-1 cursor-pointer" style="color: var(--color-text-dim);"
        onclick={() => sigExpanded = false}>Collapse</button>
    {:else}
      <span class="text-data text-xs">{record.signature.slice(0, 32)}...</span>
      <button class="text-xs mt-1 cursor-pointer" style="color: var(--color-text-dim);"
        onclick={() => sigExpanded = true}>Expand</button>
    {/if}
  </div>

  <div class="flex justify-between items-center mt-1 pt-2" style="border-top: 1px solid rgba(255,255,255,0.04);">
    <span class="text-label">Verification</span>
    <span class="text-data text-xs font-bold"
      style="color: {verification.ok ? 'var(--color-success)' : 'var(--color-critical)'};">
      {verification.ok ? 'PASS' : 'FAIL'}
    </span>
  </div>
  {#if !verification.ok && verification.reason}
    <span class="text-xs" style="color: var(--color-critical);">{verification.reason}</span>
  {/if}

  <div class="flex justify-between items-center">
    <span class="text-label">Chain Link</span>
    <span class="text-data text-xs font-bold"
      style="color: {chainLinkOk ? 'var(--color-success)' : 'var(--color-critical)'};">
      {chainLinkOk ? 'LINKED' : 'BROKEN'}
    </span>
  </div>

  <button class="btn-secondary w-full mt-2 text-xs" onclick={copyEvidence}>
    {copied ? 'Copied' : 'Copy Evidence JSON'}
  </button>
</div>

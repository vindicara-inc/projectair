<script lang="ts">
  import type { AgDRRecord } from '$lib/agdr/types';

  interface Props {
    record: AgDRRecord;
  }
  let { record }: Props = $props();

  const payload = $derived(record.payload);
  const approvedBy = $derived((payload.auth0_sub as string) ?? (payload.approved_by as string) ?? 'unknown');
  const approvedAt = $derived(record.timestamp);
  const issuer = $derived((payload.auth0_iss as string) ?? (payload.iss as string) ?? '');
  const audience = $derived((payload.auth0_aud as string) ?? (payload.aud as string) ?? '');
  const subject = $derived((payload.auth0_sub as string) ?? (payload.sub as string) ?? '');
  const originalTool = $derived((payload.approved_tool as string) ?? (payload.tool_name as string) ?? '');

  function formatTime(iso: string): string {
    try { return new Date(iso).toLocaleString(); }
    catch { return '--'; }
  }
</script>

<div class="p-3" style="background: rgba(0,200,100,0.04); border: 1px solid rgba(0,200,100,0.15);">
  <span class="text-micro mb-3 block" style="color: var(--color-success);">Human Approval Record</span>

  <div class="flex flex-col gap-2">
    <div class="flex justify-between">
      <span class="text-label">Approved By</span>
      <span class="text-data text-xs">{approvedBy}</span>
    </div>

    <div class="flex justify-between">
      <span class="text-label">When</span>
      <span class="text-data text-xs">{formatTime(approvedAt)}</span>
    </div>

    {#if originalTool}
      <div class="flex justify-between">
        <span class="text-label">Action Approved</span>
        <span class="text-data text-xs" style="color: var(--color-red);">{originalTool}</span>
      </div>
    {/if}

    {#if issuer || subject || audience}
      <div class="mt-2 pt-2" style="border-top: 1px solid rgba(255,255,255,0.04);">
        <span class="text-label mb-2 block">JWT Claims</span>
        {#if issuer}
          <div class="flex justify-between mb-1">
            <span class="text-xs" style="color: var(--color-text-dim);">iss</span>
            <span class="text-data text-xs">{issuer}</span>
          </div>
        {/if}
        {#if subject}
          <div class="flex justify-between mb-1">
            <span class="text-xs" style="color: var(--color-text-dim);">sub</span>
            <span class="text-data text-xs">{subject}</span>
          </div>
        {/if}
        {#if audience}
          <div class="flex justify-between mb-1">
            <span class="text-xs" style="color: var(--color-text-dim);">aud</span>
            <span class="text-data text-xs">{audience}</span>
          </div>
        {/if}
      </div>
    {/if}
  </div>
</div>

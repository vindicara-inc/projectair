<script lang="ts">
  import type { VerificationResult } from '$lib/console/forensics/types';
  import TechDetails from './TechDetails.svelte';

  let {
    verification = null,
    tampered = false,
    canTamper = true,
    recordCount = 0,
    signerKey = '',
    onverify,
    ontamper,
    onreset
  }: {
    verification: VerificationResult | null;
    tampered: boolean;
    canTamper?: boolean;
    recordCount?: number;
    signerKey?: string;
    onverify: () => void;
    ontamper: () => void;
    onreset: () => void;
  } = $props();

  let state = $derived(
    verification === null ? 'idle' : verification.status === 'ok' ? 'ok' : 'failed'
  );
</script>

<div class="integrity i-{state}">
  {#if state === 'idle'}
    <div class="headline neutral">Is this record authentic?</div>
    <p class="lead">
      Every step was signed when it happened and linked to the one before it. Check the whole
      record, or see what happens if someone tries to alter it.
    </p>
  {:else if state === 'ok'}
    <div class="headline ok"><span class="mark">✓</span>Every step is authentic and unaltered</div>
    <p class="lead">
      All {verification?.records_verified} records check out. Nothing has been changed since the
      moment each step was recorded.
    </p>
  {:else}
    <div class="headline bad"><span class="mark">✕</span>Tampering detected</div>
    <p class="lead bad">
      This record was changed after it was signed. Verification failed at
      <b>step {(verification?.failed_index ?? 0) + 1}</b> — the proof caught it instantly, and
      pinpointed exactly which record was altered.
    </p>
  {/if}

  <div class="actions">
    <button class="btn ok" onclick={onverify}>Verify chain</button>
    {#if canTamper}
      {#if tampered}
        <button class="btn ghost" onclick={onreset}>Reset</button>
      {:else}
        <button class="btn crit" onclick={ontamper}>Simulate tamper</button>
      {/if}
    {/if}
  </div>

  <TechDetails>
    <div><span class="k">content hashing:</span> BLAKE3</div>
    <div><span class="k">signatures:</span> Ed25519 (ML-DSA-65 post-quantum available)</div>
    <div><span class="k">chain:</span> each record signs prev_hash ‖ content_hash — a tamper-evident link</div>
    <div><span class="k">signer key:</span> <span class="hash">{signerKey.slice(0, 16)}…</span></div>
    <div><span class="k">records:</span> {recordCount}</div>
    <div><span class="k">external anchoring:</span> Sigstore Rekor transparency log + RFC 3161 trusted timestamp (verifiable offline, no trust in Vindicara)</div>
    {#if verification && verification.status !== 'ok'}
      <div><span class="k">failure:</span> {verification.reason}</div>
      <div><span class="k">failed step id:</span> {verification.failed_step_id}</div>
    {/if}
  </TechDetails>
</div>

<style>
  .integrity { padding: 4px 0; }
  .headline { font-family: var(--display); font-size: 22px; font-weight: 600; letter-spacing: -.01em; display: flex; align-items: center; gap: 11px; }
  .headline.neutral { color: var(--ink); }
  .headline.ok { color: #bff5df; }
  .headline.bad { color: #ffd0d4; }
  .mark { display: inline-grid; place-items: center; width: 28px; height: 28px; border-radius: 50%; font-size: 15px; }
  .ok .mark { background: rgba(72,230,164,.16); border: 1px solid rgba(72,230,164,.5); color: var(--teal); }
  .bad .mark { background: rgba(230,57,70,.18); border: 1px solid rgba(230,57,70,.55); color: var(--air); }
  .lead { font-size: 13.5px; line-height: 1.55; color: var(--muted); margin-top: 11px; max-width: 62ch; }
  .lead.bad { color: #ffc8cc; }
  .lead b { color: var(--ink); }
  .actions { display: flex; gap: 10px; margin-top: 17px; }
  .actions .btn { font-size: 12px; padding: 9px 16px; }
  .i-ok { animation: glowok .5s ease; }
  .i-failed { animation: shake .4s ease; }
  @keyframes glowok { from { opacity: .4; } to { opacity: 1; } }
  @keyframes shake { 0%,100% { transform: translateX(0); } 25% { transform: translateX(-4px); } 75% { transform: translateX(4px); } }
  @media (prefers-reduced-motion: reduce) { .i-ok, .i-failed { animation: none; } }
</style>

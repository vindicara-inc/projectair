<script lang="ts">
  import { onMount } from 'svelte';

  type Manifest = {
    latest_rekor_log_index: number;
    rekor_url: string;
    chain_prefix: string;
  };

  // Public bucket served via CloudFront / direct S3 origin once OpsChainStack
  // deploys. Until then this URL 404s and the page shows the placeholder
  // state. CDK creates the bucket as vindicara-ops-chain-public-{account}.
  const MANIFEST_URL =
    'https://vindicara-ops-chain-public-399827112476.s3.us-west-2.amazonaws.com/ops-chain/manifest.json';

  let manifest = $state<Manifest | null>(null);
  let manifestError = $state<string | null>(null);
  let loadedAt = $state<string>('');

  onMount(async () => {
    try {
      const response = await fetch(MANIFEST_URL, { cache: 'no-store' });
      if (!response.ok) {
        manifestError = `manifest unavailable (HTTP ${response.status})`;
        return;
      }
      manifest = (await response.json()) as Manifest;
      loadedAt = new Date().toISOString();
    } catch (e) {
      manifestError = e instanceof Error ? e.message : 'manifest fetch failed';
    }
  });
</script>

<svelte:head>
  <title>Vindicara Ops Chain — Verify Our Production Audit Trail</title>
  <meta
    name="description"
    content="Vindicara runs Project AIR on its own production infrastructure. Every API request and dashboard auth event is recorded in a signed AgDR chain anchored to public Sigstore Rekor. Verify it yourself."
  />
</svelte:head>

<main class="min-h-screen bg-zinc-950 text-zinc-100">
  <section class="mx-auto max-w-4xl px-6 pt-20 pb-12">
    <div class="mb-8 flex items-center gap-3">
      <span class="inline-block h-2 w-2 rounded-full bg-green-400"></span>
      <span class="font-mono text-xs uppercase tracking-widest text-zinc-500">live</span>
      <span class="font-mono text-xs text-zinc-500">|</span>
      <span class="font-mono text-xs text-zinc-500">vindicara ops chain</span>
    </div>

    <h1 class="mb-6 text-4xl font-extrabold tracking-tight md:text-5xl">
      We run Project AIR on our own infrastructure.
    </h1>

    <p class="mb-8 max-w-2xl text-lg text-zinc-300">
      Every Vindicara API request and dashboard auth event is recorded as a signed AgDR record using
      the same <code class="font-mono text-cyan-400">airsdk</code> library customers use. Each
      chain is anchored to public Sigstore Rekor. The published JSONL has bodies redacted to
      BLAKE3 hashes, but the cryptographic ordering is preserved end-to-end.
    </p>

    <p class="mb-12 max-w-2xl text-zinc-400">
      This is not a marketing dashboard. The data below is read from a public S3 bucket every page
      load, and the Rekor log index it points to is checked against the public Sigstore transparency
      log. To verify a chain yourself: <code class="font-mono text-cyan-400">pip install projectair</code>,
      <code class="font-mono text-cyan-400">curl</code> the chain JSONL to a file, then
      <code class="font-mono text-cyan-400">air verify-public /tmp/chain.jsonl</code>.
    </p>

    <div class="rounded-lg border border-zinc-800 bg-zinc-900 p-6 font-mono text-sm">
      {#if manifest}
        <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div>
            <div class="mb-1 text-xs uppercase tracking-widest text-zinc-500">latest rekor log index</div>
            <div class="text-2xl font-bold text-cyan-400">{manifest.latest_rekor_log_index.toLocaleString()}</div>
          </div>
          <div>
            <div class="mb-1 text-xs uppercase tracking-widest text-zinc-500">verify on Sigstore</div>
            <a
              href={manifest.rekor_url}
              target="_blank"
              rel="noopener"
              class="block truncate text-cyan-400 underline hover:text-cyan-300"
            >
              {manifest.rekor_url}
            </a>
          </div>
        </div>
        <div class="mt-4 border-t border-zinc-800 pt-4 text-xs text-zinc-500">
          loaded {loadedAt} · chain prefix: <span class="text-zinc-400">{manifest.chain_prefix}</span>
        </div>
      {:else if manifestError}
        <div class="text-zinc-400">
          <div class="mb-2 text-xs uppercase tracking-widest text-amber-400">pending deployment</div>
          <p>
            The ops chain manifest is not yet published. The AnchoringStack deploys the public bucket and
            cron Lambdas; until that ships and produces its first anchor, this page shows nothing live.
          </p>
          <p class="mt-2 text-xs text-zinc-600">debug: {manifestError}</p>
        </div>
      {:else}
        <div class="text-zinc-500">loading manifest...</div>
      {/if}
    </div>

    <div class="mt-10 grid grid-cols-1 gap-6 md:grid-cols-2">
      <div class="rounded-lg border border-zinc-800 bg-zinc-900 p-5">
        <div class="mb-2 text-xs uppercase tracking-widest text-zinc-500">trust model</div>
        <p class="text-sm text-zinc-300">
          Records are signed in-process at the moment of action by the same library customers use.
          Anchoring is async via a separate cron Lambda. The signature on each record was produced
          inside the Lambda that emitted it, not by a downstream reconstruction.
        </p>
      </div>
      <div class="rounded-lg border border-zinc-800 bg-zinc-900 p-5">
        <div class="mb-2 text-xs uppercase tracking-widest text-zinc-500">redaction policy</div>
        <p class="text-sm text-zinc-300">
          Default deny. Only fields explicitly whitelisted per event kind appear in clear in the
          public chain. Everything else is replaced by a BLAKE3 hash of the original value.
          Signatures cover the unredacted internal records; the public JSONL is for narrative,
          and the Rekor anchor binds the chain root.
        </p>
      </div>
    </div>

    <div class="mt-10 text-sm text-zinc-500">
      Source:
      <a
        href="https://github.com/vindicara-inc/projectair/blob/main/src/vindicara/ops/"
        class="text-cyan-400 underline hover:text-cyan-300"
        target="_blank"
        rel="noopener">vindicara/ops/</a
      >
      ·
      <a
        href="https://github.com/vindicara-inc/projectair/blob/main/docs/design/ops-chain.md"
        class="text-cyan-400 underline hover:text-cyan-300"
        target="_blank"
        rel="noopener">design doc</a
      >
    </div>
  </section>
</main>

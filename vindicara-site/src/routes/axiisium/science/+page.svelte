<script>
  import AppShell from '$components/AppShell.svelte';
  const reads = [
    { m: 'NPM1 mutation', s: 'Reads well', t: 'good', d: 'The marker morphology carries best, peer-reviewed and independently reproduced. Two FDA-approved targeted therapies behind it.' },
    { m: 'Core-binding-factor lesions', s: 'Reads well', t: 'good', d: 'inv(16)/CBFB::MYH11 and related changes have a distinctive cell morphology a model can learn.' },
    { m: 'FLT3-ITD', s: 'Deferred to molecular', t: 'defer', d: 'Weakly predictable from morphology and confounded by NPM1. Axiisium never calls it from the image; the molecular assay does.' },
    { m: 'RUNX1, CEBPA, wider panel', s: 'Confirmatory only', t: 'defer', d: 'No reliable image-only signal. Used as inputs once sequenced, never inferred from morphology.' }
  ];
</script>

<svelte:head>
  <title>Axiisium · How it works | Vindicara</title>
  <meta name="description" content="The science behind Axiisium, stated precisely: which signals morphology carries, which are deferred to molecular, and how every decision is bound to a verifiable record." />
</svelte:head>

<AppShell active="axiisium" title="axiisium science" scroll={true}>
  <div class="prose">
    <div class="eyebrow"><a class="crumb" href="/axiisium">Axiisium</a> · How it works</div>
    <h1>The science, stated precisely</h1>
    <p class="big">In a field full of single-modality models that overclaim, precision is the point. Here is exactly what Axiisium reads, what it defers, and how each output is made verifiable.</p>

    <h2>Why one modality is not enough</h2>
    <p>Acute myeloid leukemia is a multimodal disease. The genetics that drive treatment are partly written in the cells and partly invisible to morphology. A model that reads only images, or only flow, leaves the deciding signals on the table. Axiisium fuses pathology, flow cytometry, cytogenetics, molecular, and clinical data into a single assessment, so each signal covers the blind spots of the others.</p>

    <h2>What morphology carries, and what it does not</h2>
    <p>The honest boundary is the credibility. Axiisium reads the markers the literature supports and refuses the ones it does not, deferring those to the molecular assay by design.</p>
    <div class="reads">
      {#each reads as r}
        <div class="r {r.t}">
          <div class="rh"><span class="rm">{r.m}</span><span class="rs">{r.s}</span></div>
          <div class="rd">{r.d}</div>
        </div>
      {/each}
    </div>

    <h2>What Axiisium produces</h2>
    <p>For a single case, Axiisium fuses the available signals into a calibrated, confidence-bounded output, and signs it. For pharma, that is a ranked sequence-first list. For the clinic, it is a provisional read on day zero, an ELN-2022 risk class once genetics return, and a therapy-eligibility map, every claim tied to the signal that triggered it. The model shows its evidence and its confidence on every line.</p>

    <h2>The accountability layer</h2>
    <p>Every output is a signed, tamper-evident record, attributable to a named clinician and independently verifiable, powered by Project <span class="air">AIR</span>. To be precise about what that buys: it makes the evidence auditable across the lifecycle and gives partners and regulators a verifiable chain of custody. It is not a substitute for analytical and clinical validation, which Axiisium pursues on its own track. We never conflate a trustworthy record with a validated prediction.</p>

    <h2>Built on real data</h2>
    <p>Axiisium is grounded in expert-labeled public cytomorphology data and validated against published cohorts with known molecular status, then extended toward multi-site, regulatory-grade evidence through clinical design partners. We report the level of evidence behind every claim, and we do not publish a performance number we have not earned.</p>

    <div class="card callout">
      <h3>Want the technical detail under NDA?</h3>
      <p>The architecture and validation methodology are shared with clinical and pharma partners under agreement. Reach out and we will walk you through it.</p>
      <div class="ctas">
        <a class="btn" href="/design-partner">Become a design partner</a>
        <a class="btn ghost" href="/axiisium/products">See the two products</a>
      </div>
    </div>
  </div>
</AppShell>

<style>
  .prose h1{font-size:40px;margin:10px 0 0}
  .big{font-size:18px;color:var(--white);line-height:1.6;margin:14px 0 8px;font-family:var(--display)}
  .prose a{color:var(--ax2)}
  .crumb{font-weight:600}
  .reads{display:flex;flex-direction:column;gap:10px;margin:16px 0 8px}
  .r{border:1px solid var(--line);background:var(--navy1);padding:14px 16px;border-left-width:3px}
  .r.good{border-left-color:var(--good)}
  .r.defer{border-left-color:var(--ax)}
  .rh{display:flex;align-items:baseline;justify-content:space-between;gap:12px;flex-wrap:wrap}
  .rm{font-size:14.5px;font-weight:700;color:var(--white)}
  .rs{font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase}
  .r.good .rs{color:var(--good)}
  .r.defer .rs{color:var(--ax2)}
  .rd{font-size:13px;color:var(--soft);line-height:1.55;margin-top:7px}
  .callout{padding:18px 20px;margin:26px 0}
  .callout h3{margin-top:0}
  .callout p{font-size:13px;color:var(--soft);line-height:1.55}
  .ctas{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
</style>

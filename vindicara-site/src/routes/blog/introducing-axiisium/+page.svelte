<script>
  import AppShell from '$components/AppShell.svelte';
</script>

<svelte:head>
  <title>Introducing Axiisium: Multimodal AI for Blood Cancer, Built to Be Provable | Vindicara Blog</title>
  <meta name="description" content="Axiisium is Vindicara's healthcare initiative: multimodal AI for acute myeloid leukemia that fuses pathology, flow, cytogenetics, molecular, and clinical data, with every decision a signed, audit-ready record." />
  <link rel="canonical" href="https://vindicara.io/blog/introducing-axiisium" />
  <meta property="og:type" content="article" />
  <meta property="og:url" content="https://vindicara.io/blog/introducing-axiisium" />
  <meta property="og:title" content="Introducing Axiisium: Multimodal AI for Blood Cancer, Built to Be Provable" />
  <meta property="og:description" content="Multimodal AI for acute myeloid leukemia, with every decision a signed, audit-ready record." />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="Introducing Axiisium: Multimodal AI for Blood Cancer, Built to Be Provable" />
  <meta name="twitter:description" content="Multimodal AI for acute myeloid leukemia, with every decision a signed, audit-ready record." />
  <meta name="keywords" content="acute myeloid leukemia AI, multimodal oncology AI, AML mutation prediction, companion diagnostics, clinical trial enrichment, auditable medical AI" />
  {@html `<script type="application/ld+json">${JSON.stringify({
    "@context": "https://schema.org",
    "@type": "Article",
    "headline": "Introducing Axiisium: Multimodal AI for Blood Cancer, Built to Be Provable",
    "description": "Axiisium is Vindicara's healthcare initiative: multimodal AI for acute myeloid leukemia, with every decision a signed, audit-ready record.",
    "datePublished": "2026-06-26",
    "dateModified": "2026-06-26",
    "author": { "@type": "Person", "name": "Kevin Minn", "url": "https://vindicara.io" },
    "publisher": {
      "@type": "Organization",
      "name": "Vindicara",
      "url": "https://vindicara.io",
      "logo": { "@type": "ImageObject", "url": "https://vindicara.io/vindicara-logo.png" }
    },
    "mainEntityOfPage": "https://vindicara.io/blog/introducing-axiisium"
  })}</script>`}
</svelte:head>

<AppShell active="blog" title="blog" scroll={true}>
  <article class="prose">
    <div class="eyebrow">Initiative · Healthcare</div>
    <h1>Introducing Axiisium</h1>
    <p class="sub">Multimodal AI for blood cancer, built to be provable.</p>
    <p class="muted">June 26, 2026 · Kevin Minn</p>
    <p>Vindicara builds the record that proves what an AI system did. Axiisium is where we point that capability at a problem worth all of it: diagnosing acute myeloid leukemia, and making every model decision something a clinician and a regulator can verify.</p>

    <h2>Why acute myeloid leukemia</h2>
    <p>Acute myeloid leukemia is one of the cancers we still cannot reliably cure, and it is diagnosed from many signals at once. Pathologists read the morphology of cells. Flow cytometry reads their immunophenotype. Cytogenetics reads the karyotype. Sequencing reads the mutations. The clinical picture frames all of it. These signals live on different instruments, in different formats, and a single model rarely sees them together. That fragmentation is the opening.</p>

    <h2>The science is not a gamble</h2>
    <p>The hardest question, whether the way cells look carries genetic signal, is already answered. Eckardt et al. (<i>Leukemia</i>, 2022) predict NPM1 mutation status from bone-marrow smears alone, image data only, at an AUROC of 0.92. Subsequent work extends image-based prediction to more therapy-relevant genetics. So Axiisium is not betting on an unproven hypothesis. It reproduces a published result and extends it.</p>
    <p>Extends it how? Every model in that literature is image-only. Real genetics are not all visible in morphology: some mutations are written in the cells, some are not. Axiisium fuses pathology with flow, cytogenetics, molecular, and clinical data, so the model can reach the genetics a single view misses. Multimodal is not a flourish here. It is the whole point.</p>

    <h2>The part nobody else has</h2>
    <p>Here is where Axiisium stops being another medical-imaging model. Every published result in this field is single-institution and research-grade, with no audit trail. Axiisium signs every model decision so it is tamper-evident, attributable to a named clinician, and independently verifiable, the same trust layer that powers Project <span class="air">AIR</span>. Change one byte and verification fails.</p>
    <p>For a pharmaceutical sponsor submitting a trial-enrollment decision to a regulator, that is not a nice-to-have. It is the difference between a research result and a companion-diagnostic-grade output. The trust layer is the moat that survives even when a competitor's accuracy catches up.</p>

    <h2>The first thing it sells</h2>
    <p>A sponsor running an acute myeloid leukemia trial needs patients with a specific molecular profile, and today sequences nearly every candidate to find them. That screening is one of the biggest drivers of enrollment delay and cost. Axiisium pre-screens from the data already collected, ranks who to sequence first, and hands the sponsor a signed, audit-ready record of how each patient was chosen. Enrollment is always confirmed by sequencing. Axiisium decides the order, not the diagnosis.</p>

    <h2>Where this is, honestly</h2>
    <p>Axiisium is early. The pipeline runs end to end on public and synthetic data today, the trust layer is real and verifiable now, and the next step is the first result on real clinical data. It is a triage and enrichment tool used alongside confirmatory sequencing, not a replacement for a pathologist or an oncologist. We will publish numbers when they stand on real data, not before. That discipline is the same one we hold Project <span class="air">AIR</span> to: evidence over assertion.</p>

    <div class="card callout">
      <h3>Design partners wanted</h3>
      <p>We are looking for clinical and pharma partners in hematology. If you run acute myeloid leukemia trials, hold aligned multimodal data, or want auditable AI in a regulated workflow, we would like to talk.</p>
      <div class="ctas">
        <a class="btn" href="/contact">Talk to us</a>
        <a class="btn ghost" href="/axiisium">See Axiisium</a>
      </div>
    </div>
  </article>
</AppShell>

<style>
  .prose h1{font-size:36px;margin:14px 0 0}
  .prose .sub{font-size:19px;font-weight:600;color:var(--white);margin:6px 0 8px}
  .prose .muted{font-size:13px;color:var(--soft);margin:0 0 10px}
  .prose a{color:var(--air2)}
  .callout{padding:18px 20px;margin:24px 0}
  .callout h3{margin-top:0}
  .callout p{font-size:13px;color:var(--soft);line-height:1.55}
  .ctas{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
</style>

<script>
  import AppShell from '$components/AppShell.svelte';
  const modalities = [
    { n: 'Pathology', d: 'Bone-marrow and blood-smear morphology, encoded with a hematology foundation model.' },
    { n: 'Flow cytometry', d: 'Immunophenotype features for classification and measurable residual disease.' },
    { n: 'Cytogenetics', d: 'Karyotype and FISH signals that morphology alone cannot see.' },
    { n: 'Molecular', d: 'Mutation and fusion status (NPM1, FLT3, and the wider panel).' },
    { n: 'Clinical', d: 'Age, blast percentage, and labs that frame the prediction.' }
  ];
</script>

<svelte:head>
  <title>Axiisium · Multimodal AI for acute myeloid leukemia | Vindicara</title>
  <meta name="description" content="Axiisium is Vindicara's healthcare initiative: multimodal AI for acute myeloid leukemia that fuses pathology, flow, cytogenetics, molecular, and clinical data, with every decision a signed, audit-ready record. Built on the NVIDIA stack." />
  <link rel="canonical" href="https://vindicara.io/axiisium" />
</svelte:head>

<AppShell active="axiisium" title="axiisium" scroll={true}>
  <div class="prose">
    <div class="eyebrow">A Vindicara initiative · In development</div>
    <h1>Axiisium</h1>
    <p class="big">Multimodal AI for acute myeloid leukemia, where every model decision is a tamper-evident, audit-ready record.</p>

    <p>Acute myeloid leukemia is diagnosed from many signals at once: the way cells look under a microscope, their immunophenotype on flow cytometry, their karyotype, their mutations, and the patient's clinical picture. The decisive signals are scattered across instruments and rarely brought together by a single model. Axiisium fuses them, and binds each prediction to a record a regulator and a clinical partner can verify.</p>

    <h2>The five signals, fused</h2>
    <div class="mods">
      {#each modalities as m, i}
        <div class="mod"><div class="mn"><span class="mi">{i+1}</span>{m.n}</div><div class="md">{m.d}</div></div>
      {/each}
    </div>
    <p>One model reading one modality leaves the rest on the table. Some of the genetics that drive treatment are written in the cells; some are not. Fusing the modalities is how you reach the ones a single view cannot.</p>

    <h2>The science is already de-risked</h2>
    <p>The core question, whether morphology carries genetic signal, is answered in the published literature. Eckardt et al. (<i>Leukemia</i>, 2022) predict NPM1 mutation status from bone-marrow smears alone at an AUROC of 0.92. Later work extends image-based prediction to additional therapy-relevant genetics. Axiisium reproduces that result and extends it, multimodally, to the mutations morphology cannot see on its own, and toward the workflows that actually move care.</p>

    <h2>Built on the NVIDIA stack</h2>
    <p>Axiisium is built end to end on NVIDIA: <strong>MONAI</strong> for the imaging pipeline, <strong>Parabricks</strong> for genomics, <strong>FLARE</strong> for federated training across institutions that cannot pool data, <strong>Confidential Computing</strong> to keep protected health information inside an attested enclave, and <strong>NIM and Nemotron</strong> for the reasoning and reporting layer. Vindicara is a member of the NVIDIA Inception and Digital Health Developer programs.</p>

    <h2>The trust layer is the difference</h2>
    <p>Every published model in this space is image-only, single-institution, and research-grade with no audit trail. Axiisium signs every training run, model version, and prediction with the same evidence substrate behind Project <span class="air">AIR</span>: hash-chained, tamper-evident, bound to a named clinician, and independently verifiable. For a pharma sponsor submitting a trial decision to a regulator, that is the difference between a research result and a companion-diagnostic-grade output. No image classifier has it.</p>

    <h2>The first wedge: trial enrichment</h2>
    <p>A sponsor running an acute myeloid leukemia trial needs patients with a specific molecular profile, and today sequences nearly every candidate to find them. Axiisium pre-screens from the morphology, flow, and clinical data already collected, ranks who to sequence first, and hands the sponsor a signed, audit-ready record of how each patient was selected. Enrollment is always confirmed by sequencing; Axiisium decides the order, not the diagnosis.</p>

    <div class="status">
      <div class="sh">Honest status</div>
      <p>Axiisium is early and in active development. It is a triage and enrichment tool with confirmatory sequencing, not a replacement for diagnosis. We state what it does not yet do as plainly as what it does, and we will publish results on real data as they stand, not before.</p>
    </div>

    <div class="backed">
      <div class="bh">Built with</div>
      <a href="https://www.nvidia.com/en-us/startups/" target="_blank" rel="noopener" aria-label="NVIDIA Inception Program">
        <img src="/nvidia-inception-program-badge.svg" alt="NVIDIA Inception Program member" />
      </a>
    </div>

    <div class="card callout">
      <h3>Building in this space?</h3>
      <p>We are looking for clinical and pharma design partners in hematology. If you run acute myeloid leukemia trials or hold aligned multimodal data, we would like to talk.</p>
      <div class="ctas">
        <a class="btn" href="/contact">Talk to us</a>
        <a class="btn ghost" href="/blog/introducing-axiisium">Read the announcement</a>
      </div>
    </div>
  </div>
</AppShell>

<style>
  .prose h1{font-size:40px;margin:14px 0 0}
  .big{font-size:18px;color:var(--white);line-height:1.6;margin:14px 0 8px;font-family:var(--display)}
  .prose a{color:var(--air2)}
  .mods{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:16px 0 8px}
  .mod{border:1px solid var(--line);background:var(--navy1);padding:14px}
  .mn{font-size:12.5px;font-weight:700;display:flex;align-items:center;gap:8px}
  .mi{font-family:var(--mono);font-size:10px;color:var(--air2);border:1px solid rgba(230,57,70,.3);width:18px;height:18px;display:grid;place-items:center;flex:none}
  .md{font-size:11px;color:var(--soft);margin-top:8px;line-height:1.45}
  .status{background:#0a1326;border:1px solid var(--line);padding:18px 20px;margin-top:22px}
  .status .sh{font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--air2);margin-bottom:8px}
  .status p{font-size:13px;color:var(--soft);line-height:1.6}
  .backed{margin-top:26px;padding-top:18px;border-top:1px solid var(--line)}
  .backed .bh{font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--soft);margin-bottom:12px}
  .backed img{height:64px;width:auto;display:block}
  .callout{padding:18px 20px;margin:24px 0}
  .callout h3{margin-top:0}
  .callout p{font-size:13px;color:var(--soft);line-height:1.55}
  .ctas{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
  @media (max-width:1080px){ .mods{grid-template-columns:1fr 1fr} }
</style>

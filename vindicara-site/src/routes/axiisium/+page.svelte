<script>
  import AppShell from '$components/AppShell.svelte';
  const modalities = [
    { n: 'Pathology', d: 'Bone-marrow and blood-smear cell morphology.' },
    { n: 'Flow cytometry', d: 'Immunophenotype for classification and measurable residual disease.' },
    { n: 'Cytogenetics', d: 'Karyotype and FISH signals morphology alone cannot see.' },
    { n: 'Molecular', d: 'Mutation and fusion status (NPM1, FLT3, and the wider panel).' },
    { n: 'Clinical', d: 'Age, blast percentage, and labs that frame the prediction.' }
  ];
</script>

<svelte:head>
  <title>Axiisium · Multimodal AI for acute myeloid leukemia | Vindicara</title>
  <meta name="description" content="Axiisium is Vindicara's proprietary healthcare product: multimodal AI for acute myeloid leukemia that fuses pathology, flow, cytogenetics, molecular, and clinical signals, with every decision a signed, verifiable record." />
  <link rel="canonical" href="https://vindicara.io/axiisium" />
</svelte:head>

<AppShell active="axiisium" title="axiisium" scroll={true}>
  <div class="prose">
    <div class="hero">
      <div class="brandmark"><img src="/axiisium-mark.png" alt="Axiisium" /></div>
      <div>
        <div class="eyebrow">A Vindicara product · In development</div>
        <h1>Axiisium</h1>
      </div>
    </div>
    <p class="big">Multimodal AI for acute myeloid leukemia, where every model decision is a signed, tamper-evident, independently verifiable record.</p>

    <p>Acute myeloid leukemia is read from many signals at once: how the cells look under a microscope, their immunophenotype on flow cytometry, their karyotype, their mutations, and the patient's clinical picture. Those signals are scattered across instruments and rarely reach a single model together. Axiisium fuses them, and binds each prediction to a record a clinical partner and a regulator can verify.</p>

    <h2>The five signals, fused</h2>
    <div class="mods">
      {#each modalities as m, i}
        <div class="mod"><div class="mn"><span class="mi">{i+1}</span>{m.n}</div><div class="md">{m.d}</div></div>
      {/each}
    </div>
    <p>One model reading one modality leaves the rest on the table. Some of the genetics that drive treatment are written in the cells; some are not. Fusing the modalities is how you reach the signals a single view cannot.</p>

    <h2>The science is de-risked</h2>
    <p>The core question, whether cell morphology carries genetic signal, is answered in the peer-reviewed literature and has been independently reproduced. Eckardt et al. (<i>Leukemia</i>, 2022) predicted NPM1 mutation status from bone-marrow smears as a proof of concept, and later groups confirmed the signal is real across independent cohorts. Axiisium builds on that foundation and extends it multimodally, anchored first on NPM1, the marker morphology reads best and the one with two newly approved targeted therapies behind it.</p>

    <h2>Accountability is the difference</h2>
    <p>Most published models in this space are single-modality, single-institution, and ship no verifiable record of how a decision was made. Axiisium signs every model decision so it is tamper-evident, attributable to a named clinician, and independently verifiable, the same trust layer that powers Project <span class="air">AIR</span>. That signature does not replace clinical validation; it makes the evidence auditable and gives pharma partners and regulators a verifiable chain of custody. No image classifier offers it.</p>

    <h2>The first wedge: trial enrichment</h2>
    <p>A sponsor running an acute myeloid leukemia trial needs patients with a specific molecular profile, and today sequences nearly every candidate to find them. Axiisium pre-screens from the morphology, flow, and clinical data already collected, ranks who to sequence first, and hands the sponsor a signed record of how each patient was selected. Enrollment is always confirmed by sequencing. Axiisium decides the order, never the diagnosis.</p>

    <div class="next">
      <a class="ncard" href="/axiisium/science">
        <div class="nk">How it works</div>
        <div class="nt">The science, stated precisely</div>
        <div class="nl">Read more →</div>
      </a>
      <a class="ncard" href="/axiisium/products">
        <div class="nk">Two products</div>
        <div class="nt">Enrich for pharma · Decide for the clinic</div>
        <div class="nl">Read more →</div>
      </a>
    </div>

    <div class="status">
      <div class="sh">Honest status</div>
      <p>Axiisium is early and in active development. It is a triage and enrichment tool with confirmatory sequencing, not a replacement for diagnosis. We state what it does not yet do as plainly as what it does, and we publish results on real data as they stand, not before.</p>
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
        <a class="btn" href="/design-partner">Become a design partner</a>
        <a class="btn ghost" href="/contact">Talk to us</a>
      </div>
    </div>
  </div>
</AppShell>

<style>
  .hero{display:flex;align-items:center;gap:18px;margin-bottom:6px}
  .brandmark{width:74px;height:74px;border-radius:18px;background:#fff;display:grid;place-items:center;flex:none;box-shadow:0 18px 40px -20px rgba(0,0,0,.7)}
  .brandmark img{width:82%;height:82%;object-fit:contain}
  .prose h1{font-size:44px;margin:6px 0 0}
  .big{font-size:18px;color:var(--white);line-height:1.6;margin:14px 0 8px;font-family:var(--display)}
  .prose a{color:var(--air2)}
  .mods{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:16px 0 8px}
  .mod{border:1px solid var(--line);background:var(--navy1);padding:14px}
  .mn{font-size:12.5px;font-weight:700;display:flex;align-items:center;gap:8px}
  .mi{font-family:var(--mono);font-size:10px;color:var(--air2);border:1px solid rgba(230,57,70,.3);width:18px;height:18px;display:grid;place-items:center;flex:none}
  .md{font-size:11px;color:var(--soft);margin-top:8px;line-height:1.45}
  .next{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:26px 0 6px}
  .ncard{display:block;text-decoration:none;border:1px solid var(--line);background:var(--navy1);padding:16px 18px;transition:.15s}
  .ncard:hover{border-color:var(--air)}
  .nk{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--air2)}
  .nt{font-size:15px;font-weight:700;color:var(--white);margin-top:7px;font-family:var(--display)}
  .nl{font-size:12.5px;color:var(--air2);font-weight:600;margin-top:12px}
  .status{background:#0a1326;border:1px solid var(--line);padding:18px 20px;margin-top:24px}
  .status .sh{font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--air2);margin-bottom:8px}
  .status p{font-size:13px;color:var(--soft);line-height:1.6}
  .backed{margin-top:26px;padding-top:18px;border-top:1px solid var(--line)}
  .backed .bh{font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--soft);margin-bottom:12px}
  .backed img{height:64px;width:auto;display:block}
  .callout{padding:18px 20px;margin:24px 0}
  .callout h3{margin-top:0}
  .callout p{font-size:13px;color:var(--soft);line-height:1.55}
  .ctas{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
  @media (max-width:1080px){ .mods{grid-template-columns:1fr 1fr} .next{grid-template-columns:1fr} }
</style>

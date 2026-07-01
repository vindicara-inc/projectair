<script>
  import AppShell from '$components/AppShell.svelte';
  import AxiisiumMark from '$components/AxiisiumMark.svelte';
  const rungs = [
    { n: 'Morphology', d: 'Bone-marrow and blood-smear cell morphology, read by the image model.' },
    { n: 'Immunophenotype', d: 'Flow cytometry: lineage assignment and measurable residual disease.' },
    { n: 'Cytogenetics', d: 'Karyotype and FISH: structural signals morphology alone cannot see.' },
    { n: 'Molecular', d: 'Mutation and fusion status (NPM1, FLT3, the defining lesions).' }
  ];
</script>

<svelte:head>
  <title>Axiisium · Provable multimodal AI for blood cancer | Vindicara</title>
  <meta name="description" content="Axiisium is Vindicara's flagship: multimodal AI for acute myeloid leukemia that fuses the four MICM rungs (morphology, immunophenotype, cytogenetics, molecular) into one signed, independently verifiable decision." />
  <link rel="canonical" href="https://vindicara.io/axiisium" />
</svelte:head>

<AppShell active="axiisium" title="axiisium" scroll={true}>
  <div class="prose ax">
    <div class="hero">
      <div class="eyebrow">Vindicara flagship · in development</div>
      <div class="wm"><AxiisiumMark size={76} /></div>
      <p class="tag">Provable AI for blood cancer.</p>
    </div>

    <p class="big">Multimodal AI for acute myeloid leukemia, where every model decision is a signed, tamper-evident, independently verifiable record.</p>

    <p>Acute myeloid leukemia is read from four signals at once, the MICM workup: how the cells look under a microscope, their immunophenotype on flow cytometry, their karyotype, and their mutations. Those signals are scattered across instruments and rarely reach a single model together. Axiisium fuses them, applies the current WHO 2022 and ICC 2022 rules, and binds each decision to a record a clinical partner and a regulator can verify.</p>

    <h2>The four rungs, fused</h2>
    <div class="mods">
      {#each rungs as m, i}
        <div class="mod"><div class="mn"><span class="mi">{i+1}</span>{m.n}</div><div class="md">{m.d}</div></div>
      {/each}
    </div>
    <p>One model reading one rung leaves the rest on the table. Some of the genetics that drive treatment are written in the cells; some are not. Fusing the rungs is how you reach the signals a single view cannot, and the molecular rung can override the blast-count threshold entirely.</p>

    <div class="next">
      <a class="ncard" href="/axiisium/how-it-works">
        <div class="nk">How it works</div>
        <div class="nt">Four rungs to one signed call</div>
        <div class="nl">Read more →</div>
      </a>
      <a class="ncard" href="/axiisium/science">
        <div class="nk">The science</div>
        <div class="nt">Morphology carries genetic signal</div>
        <div class="nl">Read more →</div>
      </a>
      <a class="ncard" href="/axiisium/products">
        <div class="nk">Two products</div>
        <div class="nt">Enrich for pharma · Decide for the clinic</div>
        <div class="nl">Read more →</div>
      </a>
    </div>

    <h2>Accountability is the difference</h2>
    <p>Most published models in this space are single-modality, single-institution, and ship no verifiable record of how a decision was made. Axiisium signs every model decision so it is tamper-evident, attributable to a named clinician, and independently verifiable, the same trust layer that powers Project <span class="air">AIR</span>. That signature does not replace clinical validation; it makes the evidence auditable and gives pharma partners and regulators a verifiable chain of custody. No image classifier offers it.</p>

    <div class="status">
      <div class="sh">Honest status</div>
      <p>Axiisium is early and in active development, a research-use triage and enrichment tool with confirmatory sequencing, not a replacement for diagnosis. We state what it does not yet do as plainly as what it does, and we publish results on real data as they stand, not before.</p>
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
        <a class="btn axbtn" href="/design-partner">Become a design partner</a>
        <a class="btn ghost" href="https://axiisium.com/demo" target="_blank" rel="noopener">See the live demo</a>
      </div>
    </div>
  </div>
</AppShell>

<style>
  .hero{margin-bottom:6px}
  .wm{color:#fff;margin:10px 0 4px}
  .tag{font-family:var(--display);font-size:20px;color:var(--ax2);margin:6px 0 0}
  .big{font-size:18px;color:var(--white);line-height:1.6;margin:18px 0 8px;font-family:var(--display)}
  .prose.ax a{color:var(--ax2)}
  .mods{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0 8px}
  .mod{border:1px solid var(--line);background:var(--navy1);padding:14px}
  .mn{font-size:12.5px;font-weight:700;display:flex;align-items:center;gap:8px}
  .mi{font-family:var(--mono);font-size:10px;color:var(--ax2);border:1px solid var(--axline);width:18px;height:18px;display:grid;place-items:center;flex:none}
  .md{font-size:11px;color:var(--soft);margin-top:8px;line-height:1.45}
  .next{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin:26px 0 6px}
  .ncard{display:block;text-decoration:none;border:1px solid var(--line);background:var(--navy1);padding:16px 18px;transition:.15s}
  .ncard:hover{border-color:var(--ax)}
  .nk{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--ax2)}
  .nt{font-size:15px;font-weight:700;color:var(--white);margin-top:7px;font-family:var(--display)}
  .nl{font-size:12.5px;color:var(--ax2);font-weight:600;margin-top:12px}
  .status{background:#0a1326;border:1px solid var(--line);padding:18px 20px;margin-top:24px}
  .status .sh{font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--ax2);margin-bottom:8px}
  .status p{font-size:13px;color:var(--soft);line-height:1.6}
  .backed{margin-top:26px;padding-top:18px;border-top:1px solid var(--line)}
  .backed .bh{font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--soft);margin-bottom:12px}
  .backed img{height:64px;width:auto;display:block}
  .callout{padding:18px 20px;margin:24px 0}
  .callout h3{margin-top:0}
  .callout p{font-size:13px;color:var(--soft);line-height:1.55}
  .ctas{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
  .axbtn{background:var(--ax);border-color:var(--ax);color:#1a0e02}
  .axbtn:hover{background:var(--ax2);border-color:var(--ax2)}
  @media (max-width:1080px){ .mods{grid-template-columns:1fr 1fr} .next{grid-template-columns:1fr} }
</style>

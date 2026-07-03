<script>
  import AppShell from '$components/AppShell.svelte';
  import AxiisiumMark from '$components/AxiisiumMark.svelte';
  const rungs = [
    { c: 'M', n: 'Morphology', d: 'The image model reads each cell and produces the blast burden across the whole slide.' },
    { c: 'I', n: 'Immunophenotype', d: 'Flow cytometry assigns lineage. It is what separates a myeloid leukemia from a lymphoid one.' },
    { c: 'C', n: 'Cytogenetics', d: 'Karyotype and FISH detect the structural fusions, including ones an NGS panel can miss.' },
    { c: 'M', n: 'Molecular', d: 'NGS reports the defining mutations and fusions. This rung can override the blast threshold.' }
  ];
</script>

<svelte:head>
  <title>Axiisium · How it works | Vindicara</title>
  <meta name="description" content="How Axiisium fuses the four MICM rungs into a single signed call: a clinically correct blast count, a genetics-aware threshold under WHO 2022 and ICC 2022, and a tamper-evident record." />
</svelte:head>

<AppShell active="axiisium" title="how it works" scroll={true}>
  <div class="prose ax">
    <div class="hero">
      <div class="wm"><AxiisiumMark size={34} /></div>
      <div class="eyebrow">How it works</div>
      <h1>Four rungs to one signed call</h1>
    </div>
    <p class="big">Axiisium does not guess a diagnosis from a picture. It fuses the four signals a hematologist actually uses, applies the published rules, and signs the result.</p>

    <h2>The four MICM rungs</h2>
    <div class="rungs">
      {#each rungs as r}
        <div class="rung"><div class="rc">{r.c}</div><div class="rn">{r.n}</div><div class="rd">{r.d}</div></div>
      {/each}
    </div>
    <p>Axiisium generates the morphology rung from images. The other three are structured lab inputs. Each rung guards a failure mode of the others: immunophenotype stops a lymphoid leukemia being called AML, cytogenetics catches fusions NGS can miss. One rung alone is not enough to make the call.</p>

    <h2>The blast count, done correctly</h2>
    <p>The number a diagnosis hinges on is the blast percentage, and it is not "immature cells versus mature." It counts myeloblasts and blast equivalents (monoblasts) over nucleated leukocytes, and excludes erythroblasts and maturing precursors like promyelocytes and myelocytes. Counting those as blasts inflates the figure and can push a borderline case across a threshold. Axiisium uses the clinically correct definition.</p>

    <h2>The threshold is genetics-aware</h2>
    <p>The 20% blast line is not fixed. Under WHO 2022, an AML-defining genetic lesion (NPM1, the core-binding-factor and <span class="mono">PML::RARA</span> fusions, and others) waives the blast requirement entirely. ICC 2022 uses a 10% cutoff for the same cases. Axiisium computes the morphology blast burden, reads the molecular rung, and returns the call under both systems, with the threshold correctly waived or lowered and the reasoning shown in plain language.</p>

    <h2 id="provenance">Signed decisions</h2>
    <p>Every Axiisium decision is bound to a tamper-evident record: a digest of the inputs, the model id and version, the output, an attribution to a named clinician, and a cryptographic signature, the same trust layer that powers Project <span class="air">AIR</span>. Anyone can verify, later and independently, exactly which model version on which inputs produced a call, and that no one altered it. That signature does not replace clinical validation; it makes the evidence auditable.</p>

    <div class="card demo" id="demo">
      <div class="dk">Live demo</div>
      <h3>See the four-rung signed diagnosis</h3>
      <p>The demo scores a sample patient slide, fuses the four rungs, applies WHO 2022 and ICC 2022, and returns one signed, independently verifiable call, with a what-if control that shows the molecular rung overriding the blast threshold in real time.</p>
      <div class="ctas">
        <a class="btn axbtn" href="https://axiisium.com/demo" target="_blank" rel="noopener">Run the live demo</a>
        <a class="btn ghost" href="/design-partner">Become a design partner</a>
      </div>
    </div>

    <div class="status">
      <div class="sh">Research use only</div>
      <p>Decision support, not a diagnostic device. A qualified clinician makes the diagnosis. Confirmatory molecular testing carries the clinical claim.</p>
    </div>
  </div>
</AppShell>

<style>
  .hero{margin-bottom:6px}
  .wm{color:#fff;margin-bottom:12px}
  .prose h1{font-size:40px;margin:6px 0 0}
  .big{font-size:18px;color:var(--white);line-height:1.6;margin:18px 0 8px;font-family:var(--display)}
  .prose.ax a{color:var(--ax2)}
  .rungs{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0 8px}
  .rung{border:1px solid var(--line);background:var(--navy1);padding:15px}
  .rc{font-family:var(--display);font-weight:700;font-size:22px;color:var(--ax2);line-height:1}
  .rn{font-size:13.5px;font-weight:700;color:var(--white);margin-top:8px}
  .rd{font-size:11.5px;color:var(--soft);margin-top:7px;line-height:1.5}
  .demo{padding:20px 22px;margin:26px 0 0}
  .demo .dk{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--ax2);margin-bottom:8px}
  .demo h3{margin:0 0 8px}
  .demo p{font-size:13.5px;color:var(--soft);line-height:1.6}
  .ctas{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
  .axbtn{background:var(--ax);border-color:var(--ax);color:#1a0e02}
  .axbtn:hover{background:var(--ax2);border-color:var(--ax2)}
  .status{background:#0a1326;border:1px solid var(--line);padding:18px 20px;margin-top:24px}
  .status .sh{font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--ax2);margin-bottom:8px}
  .status p{font-size:13px;color:var(--soft);line-height:1.6}
  @media (max-width:1080px){ .rungs{grid-template-columns:1fr 1fr} }
</style>

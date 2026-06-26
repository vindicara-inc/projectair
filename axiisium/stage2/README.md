# Axiisium Stage 2 — multimodal mutation prediction

Predict genetic mutations (NPM1, FLT3-ITD, TP53, RUNX1, CEBPA, IDH2 …) from imaging +
flow + clinical, with every run signed and audit-ready. This is the scientific core of
Axiisium — and, importantly, **the science is already de-risked by prior art.**

## 1. The feasibility is published (you are reproducing, not gambling)

- **Eckardt et al., *Leukemia* 2022** — deep learning on bone-marrow smears detects AML
  (AUROC 0.97) and **predicts NPM1 mutation status from image data alone at AUROC 0.92**.
  They even localized the morphologic features (condensed chromatin + perinuclear
  lightening in NPM1-mutated myeloblasts). https://www.nature.com/articles/s41375-021-01408-w
- **Blood Advances 2024** — deep learning predicts *therapy-relevant genetics* in AML from
  Pappenheim-stained marrow smears (beyond NPM1).
- **2025 (arXiv 2506.12798)** — noise-robust models predict four genetic subtypes from
  single-cell marrow images: PML-RARA (APL), NPM1, CBFB-MYH11, RUNX1-RUNX1T1.
- **Holotomography + DL** — NPM1 detection at AUROC ~0.94.

Conclusion: morphology→genetics in AML is real and reproducible. The open question is not
*whether*, but *how much better* you can do, and *who can trust the result.*

## 2. What Axiisium adds beyond the prior art (the wedge)

Every paper above is (a) **image-only**, (b) **single-institution**, (c) **research-grade
with no audit trail.** Axiisium differs on all three:

1. **Multimodal, not image-only.** Stage 2 shows fusion (morphology + flow + clinical)
   beats image-only most for the mutations morphology can't see — in the demo, FLT3-ITD
   and TP53 gain the most lift while morphology-dominant NPM1 gains little. Real AML
   genetics are exactly this: some written in the cells, some not. One image model leaves
   the rest on the table.
2. **Auditable.** Every run is Ed25519-signed, hash-chained, and bound to a named
   molecular pathologist — a tamper-evident record a pharma sponsor can submit to the FDA.
   None of the published models have this. It is the difference between a research result
   and a companion-diagnostic-grade output.
3. **Pointed at pharma trial enrichment**, not just a classifier benchmark.

## 3. The data-sourcing plan (the real constraint)

The published works used **private institutional cohorts** (Dresden/SAL, Munich MLL).
Clean *public* paired image+genomic AML data barely exists. Sourcing it is Stage 2's gate.
Targets, in order of effort:

1. **AML-Cytomorphology_MLL_Helmholtz (TCIA).** A larger Munich Leukemia Laboratory
   single-cell set; check whether it carries genetic-subtype labels (the 2025 subtype work
   used subtype-annotated single-cell images). If yes, this is a partial public paired set
   to start on — free. Verify the actual annotations before relying on it.
2. **TCGA-LAML (GDC).** Has somatic mutations (MC3) + RNA-seq for ~200 patients. Pairing to
   diagnostic morphology is weaker than for solid tumors (LAML is blood/marrow, not FFPE
   tissue blocks), so confirm image availability per case on the GDC portal before counting
   on it. Useful for molecular + clinical even if imaging is thin.
3. **Institutional research collaboration.** The Eckardt/SAL and MLL groups have the gold
   cohort. A research collaboration (co-authorship, not purchase) is the fastest path to a
   real paired training set — and an NVIDIA Digital Health / Inception intro can warm it.
4. **Pharma cohort (the revenue path).** A pharma sponsor running an AML trial has paired
   screening data (morphology + genetics + flow). This is Stage 4's wedge and the richest
   paired source — Stage 2 results are what get you that conversation.

## 4. Run

```bash
python ../stage2.py            # synthetic paired cohort, runnable now
python ../stage2.py --n 3000   # larger cohort
```

Outputs per-mutation image-only vs multimodal AUC + lift, and writes a signed
`run_record_stage2.json`. Production: replace `make_paired_cohort` with your real paired
cohort; morphology features are per-patient aggregated DinoBloom embeddings from Stage 1.

## 5. The bar

- **Reproduce NPM1 image-only ≈ 0.90** on real paired data (matches Eckardt) — proves your
  morphology pipeline is sound.
- **Show multimodal lift** on ≥2 morphology-weak mutations (FLT3-ITD, TP53) — proves the
  multimodal thesis.
- **Every result signed and verifiable** — proves the moat.

Hit those three on real paired data and you have a companion-diagnostic-grade,
audit-ready, multimodal AML genetics model that no published group and no incumbent has.
That is the artifact for the pharma LOI and the NVIDIA co-marketing moment.

## 6. Honest limits

- Synthetic signal strengths are illustrative; real per-mutation predictability varies and
  some mutations (e.g. FLT3-ITD) may stay hard even multimodally. Report honest per-mutation
  numbers, never an averaged headline that hides a weak mutation.
- Mutation *prediction* is for triage/enrichment, **not** a replacement for sequencing.
  Position it as "prioritize and pre-screen," with confirmatory NGS — both for clinical
  safety and for FDA framing.

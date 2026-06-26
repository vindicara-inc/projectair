# Axiisium — Tech Stack & Build Plan

**One line:** multimodal AML AI for pharma trial enrichment and companion diagnostics, where every model decision is a tamper-evident, FDA-audit-ready record. Built on the NVIDIA stack + the Vindicara signing substrate.

---

## The layered stack

| Layer | Component | What it does in Axiisium |
|---|---|---|
| **Reasoning / agent** | NVIDIA **Nemotron** on NIM | Orchestrates the multimodal pipeline; drafts the structured report; agentic patient-screening logic |
| **Imaging / pathology** | NVIDIA **MONAI** + open pathology foundation model (Virchow / UNI) | Feature extraction from bone-marrow whole-slide images and smears |
| **Genomics** | NVIDIA **Parabricks** | GPU secondary analysis of sequencing (variant calling) when raw reads are in scope |
| **Flow cytometry** | Custom embeddings (MONAI tabular / torch) | Encode flow data for MRD and classification |
| **Fusion model** | torch / MONAI multimodal head | Combine path + flow + cytogenetics + molecular + clinical → prediction (mutation, risk, MRD) |
| **Federated training** | NVIDIA **FLARE** | Train across centers without moving data (the un-poolable AML cohort) |
| **Confidential compute** | NVIDIA **Confidential Computing** + Remote Attestation | PHI stays in an attested enclave; hardware root of trust |
| **Trust / audit (the moat)** | **Vindicara / Project AIR** (`projectair`) | Sign every training run, model version, and prediction; tamper-evident, FRE-902 / 21 CFR Part 11-grade, attestable zero-leakage |

**Division of labor:** NVIDIA gives the compute, the medical-AI models, the federated + confidential infra. Vindicara gives the one thing the NVIDIA stack doesn't — the *attestable* signed record that makes a pharma trial decision FDA-audit-ready. That pairing is the product.

---

## The data reality (be honest about this)

- The **molecular / cytogenetic / clinical** AML data is public and pooled: **BeatAML (~805), TCGA-LAML (~200), HARMONY (~12k)**.
- The **imaging and raw flow** modalities — the clinically decisive, gigapixel, re-identifiable ones — are the gap; **not patient-linked** to the genomic cohorts. Public morphology exists *unpaired* (e.g., the Munich **AML-Cytomorphology** single-cell set on TCIA, ~18k images labeled by cell type, no mutations).
- **Implication:** the *aligned* multimodal cohort is the moat and the bottleneck. The federated/pharma path is how you assemble it. The feasibility build below uses what's public to prove the pipeline and the audit layer *now*, before you have the aligned cohort.

---

## Build sequence (feasibility first)

- **Stage 0 — pipeline + audit proof (this repo, runnable now).** Demonstrate the full shape end-to-end on synthetic data: features → fusion model → metrics → **Vindicara-signed, tamper-evident training-run record**. Proves the architecture and the compliance moat work, with zero data dependency. *This is the artifact you take to NVIDIA's pharma contacts and Capital Connect.*
- **Stage 1 — real morphology pipeline (public data, NVIDIA GPU).** Swap synthetic features for MONAI + a pathology foundation model on the public Munich AML morphology set; prove blast detection / cell classification works on real images. Free on your Inception GPU credits.
- **Stage 2 — mutation-from-morphology feasibility (needs paired data).** The real scientific question. Requires paired image + genomic data — the first thing to source via a data partner or pharma. If accuracy clears a bar, Wedge 1 (Day-Zero) is real.
- **Stage 3 — federated + confidential (FLARE + CC).** Assemble the aligned multimodal cohort across centers/pharma; train without moving data; sign every round.
- **Stage 4 — pharma trial-enrichment product (Wedge 2).** The revenue wedge: screening engine + the audit-ready ledger for the trial.

---

## What runs today

All six stages run end to end in any Python env (`python run_all.py`), each emitting a
signed, hash-chained, tamper-evident record and proving tampering is detected:

- `feasibility.py` (Stage 0) — multimodal fusion + signed training run.
- `stage1.py` (Stage 1) — real AML morphology pipeline (MONAI/DinoBloom); `--smoke` dry run, `--data` on GPU.
- `stage2.py` (Stage 2) — multimodal mutation prediction; fusion beats image-only where morphology is blind.
- `stage3.py` (Stage 3) — federated training + multi-signer federation ledger.
- `stage4.py` (Stage 4) — pharma trial-enrichment screening + signed screening ledger.
- `stage5.py` (Stage 5) — confidential computing: hardware→code→signing-key attestation binding.

Production swaps (MONAI/DinoBloom on GPU, NVIDIA FLARE, Confidential Computing + NRAS,
`airsdk` signing anchored to Sigstore Rekor) are marked inline in each module and detailed
in each `stageN/README.md`. See `BUILD_AND_GTM.md` for the funding + NVIDIA + pharma path.

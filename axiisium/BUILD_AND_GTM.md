# Axiisium — what's built, and the path from here

## What exists now (all runnable, no GPU/download needed for the dry runs)

Six stages, each carrying the same signed, tamper-evident trust layer:

| Stage | What it proves | Entry | Status |
|---|---|---|---|
| 0 | multimodal fusion + signed training run | `feasibility.py` | runs |
| 1 | real AML morphology pipeline (MONAI/DinoBloom) | `stage1.py` | built; dry run works, real run on GPU |
| 2 | mutation prediction, multimodal > image-only | `stage2.py` | runs |
| 3 | federated training unlocks locked data + multi-signer ledger | `stage3.py` | runs |
| 4 | pharma trial-enrichment screening (the buyer) | `stage4.py` | runs |
| 5 | confidential computing: hardware→code→key binding | `stage5.py` | runs |

`python run_all.py` runs all six. Every stage emits a signed `run_record_*.json` and
demonstrates that tampering is detected.

## The thesis, in one paragraph

Morphology→genetics in AML is **already proven** (Eckardt 2022: NPM1 from marrow smears at
AUROC 0.92). Axiisium extends it to **multimodal** (morphology + flow + clinical, for the
mutations morphology can't see), assembles the locked institutional data via **federated +
confidential** training on the **NVIDIA stack**, and wraps every result in a **signed,
attestable, FDA-submittable record** no image-only model and no plain FLARE deployment has.
First buyer: **pharma trial enrichment** — fewer screening NGS tests, faster enrollment, and
a provable record of how every patient was selected.

## Why this is defensible (and not a reword of Project AIR)

Project AIR / Vindicara is a *component* here, exactly like NVIDIA's tools are components.
The product is the AML multimodal model and the trial-enrichment workflow. The trust layer
is what makes it regulated-grade, but it is the plumbing, not the pitch. The defensibility
is the **combination**: the only entrant doing multimodal AML genetics, federated across the
data that's locked today, on the NVIDIA stack, with an end-to-end (silicon→result) chain of
trust. Each piece exists; nobody ships the stack.

## The NVIDIA leverage ladder (you already hold the first two rungs)

1. **Inception** ✓ — use the **GPU credits** to run Stage 1–3 for real (free). The
   feasibility result is the artifact everything else hangs on.
2. **Digital Health Developer** ✓ — the stack (MONAI, Parabricks, BioNeMo, FLARE,
   Confidential Computing) + the healthcare community + events.
3. **The co-build story** — Stage 3 + Stage 5 close the gap **FLARE's own docs admit**
   (attestation proves the enclave, not the application). That is a concrete,
   technically-credible reason for NVIDIA's healthcare team to engage, not a logo grab.
4. **Warm pharma intro** — ask the Inception / Digital Health team to connect you to pharma
   running AML/heme trials on NVIDIA. This is the door the badge actually buys.
5. **Advanced Technology Partner → Agentic AI specialization** — earned as the reference
   deployment and the co-marketing case study land.

## The pharma path (Stage 4 is the wedge)

- **Lead with trials whose molecular driver is morphology- or flow-visible** (NPM1-driven
  menin-inhibitor trials are the cleanest), where the model adds the most enrichment.
- The pitch: "use the data you already collect at screening; we rank who to sequence so you
  fill the trial with fewer NGS tests and enroll faster, and we hand you a signed,
  FDA-submittable record of every selection."
- The durable value even when enrichment is modest: **the audit-ready screening ledger** is
  unique and non-optional for a regulated trial.
- **The falsifier that matters:** will a sponsor sign an LOI? Get one before scaling. No LOI,
  no business (the lesson from every dead diverse-data startup).

## The artifact set that gets you funded

1. **Feasibility result on real public AML data** (Stage 1 on TCIA, your NVIDIA GPU) —
   reproduce NPM1 ≈ 0.90, the load-bearing proof.
2. **The signed, end-to-end-attestable pipeline** (Stages 3+5) — the NVIDIA co-build.
3. **A pharma LOI** for a morphology-visible-driver AML trial (Stage 4 is the demo that
   earns the meeting).

Land those three and you have what no incumbent and no cautionary-tale predecessor had:
proven science + the NVIDIA stack + a paying buyer + provable trust, all at once.

## Honest risks (don't skip)

- **Paired data is the gate.** Stage 2 needs paired image+genomic AML data; the published
  groups used private cohorts. Stage 3 (federation) is the answer, but it requires a real
  institutional or pharma partner. This is the hardest, slowest dependency.
- **Enrichment magnitude is bounded by the hardest criterion.** Don't pitch a universal
  multiple; pitch the right trials.
- **Model accuracy is load-bearing and unproven on real multimodal data** beyond the
  single-modality literature. The Stage 1 real run is what de-risks it.
- **This is deep tech with slow, regulated buyers.** Match funding to that (NVIDIA,
  Inception Capital Connect, mission/health capital), not a fast-SaaS clock.
- **Triage/enrichment, not diagnosis.** Always confirmatory NGS. This is both clinically
  correct and the safe FDA framing.

## Immediate next actions

1. Pull the TCIA AML-Cytomorphology_LMU dataset; run **Stage 1 for real** on your Inception
   GPU with DinoBloom. Target: NPM1 image-only ≈ 0.90 / blast-detection AUC ≥ 0.95.
2. Open the **NVIDIA Digital Health / Inception** conversation with the FLARE-gap co-build
   framing; ask for the **pharma intro** and **Capital Connect**.
3. Identify 3 target **NPM1-driven AML trials / sponsors**; use the Stage 4 demo to earn the
   enrichment + audit conversation; pursue one **LOI**.

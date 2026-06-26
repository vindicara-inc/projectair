# Axiisium Stage 1 — real AML morphology pipeline

Goal: prove the imaging foundation works on **real** single-cell AML images, on your
NVIDIA GPU (Inception credits), with every run signed and tamper-evident. No data partner
required — the dataset is public.

## 1. Get the data (public, free)

**Dataset:** AML-Cytomorphology_LMU — 18,365 expert-labeled single-cell images from
peripheral blood smears of 100 AML patients + 100 controls (Munich, 2014–2017), 15
morphological classes. Matek et al. 2019, *Nature Machine Intelligence*.

- TCIA collection: https://www.cancerimagingarchive.net/collection/aml-cytomorphology_lmu/
- DOI: `10.7937/tcia.2019.36f5o9ld`
- License: TCIA Data Usage Policy — free for research, **citation required**.

Download the image archive from the TCIA page (direct download; large WSI collections use
the NBIA Data Retriever, but this one is single-cell crops). Unzip so the layout is:

```
AML-Cytomorphology_LMU/
  MYB/  *.tif      # myeloblast (an AML blast)
  NGS/  *.tif      # segmented neutrophil
  LYT/  *.tif      # typical lymphocyte
  ...              # 15 class folders total
```

After unzipping, **list the actual folder names** and confirm which are blasts:

```bash
ls AML-Cytomorphology_LMU/
```

Pass them with `--blast-classes` if they differ from the default (`MYB MYO MOB`).

## 2. Install (GPU box)

```bash
pip install -r ../requirements.txt        # numpy, cryptography, Pillow
pip install torch monai timm              # Stage 1 extras (GPU)
```

Get **DinoBloom** weights (DINOv2 ViT trained on hematology cells — the right encoder for
single blood cells): https://github.com/marrlab/DinoBloom — download the ViT checkpoint.

## 3. Run

Dry run first (no data, no torch — proves the code):

```bash
python ../stage1.py --smoke
```

Real run:

```bash
python ../stage1.py \
  --data /path/to/AML-Cytomorphology_LMU \
  --device cuda \
  --weights /path/to/dinobloom_vitb14.pth
```

Outputs blast-detection AUC + 15-class balanced accuracy, and writes
`run_record_stage1.json` — a signed, hash-chained, human-bound record of the exact image
set, encoder, and metrics. Change one byte and verification fails.

## 4. What "good" looks like (the bar)

Matek et al. and follow-ups report strong single-cell classification on this set
(high-90s accuracy on the well-populated classes; blast vs non-blast is easier than the
full 15-way). Targets for this run:

- **Blast detection AUC ≥ 0.95** — the load-bearing result. If morphology cleanly
  separates blasts, the imaging foundation is real.
- **Balanced accuracy ≥ 0.80** across 15 imbalanced classes (rare classes drag it; report
  per-class recall too).

Clearing the blast-detection bar on real data is the artifact for the NVIDIA conversation
and Capital Connect: "multimodal AML model, imaging foundation proven on public data,
every result cryptographically auditable — built on the NVIDIA stack."

## 5. Honest limits

- This is **morphology only** — one of the five modalities. It proves the imaging encoder,
  not the full multimodal fusion.
- It does **not** predict mutation or MRD. That's **Stage 2**, and it needs paired
  image+genomic data this public set does not contain.
- High accuracy here is expected (the task is well-studied); the novelty is not the
  classifier, it's the signed-run trust layer + the path to fusion. Don't oversell the
  classifier as the breakthrough.

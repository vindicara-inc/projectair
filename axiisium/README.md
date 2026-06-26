# Axiisium

Multimodal AI for acute myeloid leukemia (AML) — fusing pathology, flow cytometry,
cytogenetics, molecular, and clinical data — where **every model decision is a
tamper-evident, FDA-audit-ready record**. Built on the NVIDIA stack + the Vindicara
signing substrate.

See `ARCHITECTURE.md` for the full tech stack and build sequence.

## Run the Stage 0 feasibility skeleton

```bash
pip install -r requirements.txt
python feasibility.py
```

It builds a synthetic multimodal AML cohort, trains a late-fusion model, evaluates it on
held-out data, and emits a **signed, hash-chained, tamper-evident training-run record** —
then proves a single altered field breaks verification. Writes `run_record.json`
(independently verifiable, zero vendor calls).

## What's real vs. placeholder

| Real (runs now) | Placeholder (production swap) |
|---|---|
| Ed25519 signing, hash chaining, verification, tamper detection | BLAKE3 + `airsdk.AIRRecorder` anchored to Sigstore Rekor |
| A model that trains, fuses modalities, and is scored by AUC | MONAI/torch encoders on GPU; pathology foundation model (Virchow/UNI) |
| Late-fusion architecture with per-modality heads | Attention fusion with missing-modality masking; NVIDIA FLARE federation |
| Synthetic cohort with a cross-modal signal | Aligned real cohort (the moat + the bottleneck) |

## Layout

```
axiisium/
  ARCHITECTURE.md        # tech stack + build sequence (read first)
  feasibility.py         # Stage 0 entrypoint — runnable now
  requirements.txt
  src/axiisium/
    trust.py             # Vindicara signing substrate (the moat)
    data.py              # synthetic multimodal AML cohort
    model.py             # late-fusion classifier + AUC
```

## Roadmap (from ARCHITECTURE.md)

- **Stage 0** pipeline + audit proof — *done* (`feasibility.py`)
- **Stage 1** real morphology pipeline on public AML data (MONAI/DinoBloom, GPU) — *built, runs in dry mode* (`stage1.py`, `stage1/`)
- **Stage 2** multimodal mutation prediction, de-risked by Eckardt 2022 — *built, runs* (`stage2.py`, `stage2/`)
- **Stage 3** federated training + federation-wide signed ledger (FLARE) — *built, runs* (`stage3.py`, `stage3/`)
- **Stage 4** pharma trial-enrichment product (the revenue wedge) — next
- **Stage 5** confidential computing (TEE + GPU CC) hardening — with Stage 4

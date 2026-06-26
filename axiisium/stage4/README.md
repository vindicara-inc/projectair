# Axiisium Stage 4 — pharma trial-enrichment product (the revenue wedge)

This is the stage that has a buyer. Everything before it is capability; this is the product
a pharma sponsor pays for.

## The problem it sells against

A sponsor running an AML trial needs patients with a specific molecular profile (e.g. a
menin-inhibitor trial wants **NPM1-mutated** AML; a FLT3-inhibitor trial wants **FLT3-ITD+**).
Today they sequence essentially every candidate up front to find them. Molecular screening
is the single biggest driver of enrollment delay and cost, and failed/slow enrollment is
the top reason oncology trials miss timelines.

## What Axiisium does

1. **Pre-screen from data already collected** — morphology + flow + clinical — to predict
   each candidate's molecular profile (the Stage 1–3 model).
2. **Rank** candidates by eligibility and **band by confidence**: likely-eligible /
   confirm-with-NGS / likely-ineligible. Only the gray zone needs sequencing.
3. **Never enroll on a prediction** — eligibility is always confirmed by NGS. Axiisium
   decides *who to sequence first*, shrinking the number of tests to fill the trial.
4. **Emit a signed, audit-ready screening ledger** — criteria + model version hash + each
   candidate's decision + the confirmatory result + the named PI — that the sponsor submits
   to the FDA. No competitor's model produces this.

## Run

```bash
python ../stage4.py --target 30
```

Writes `run_record_stage4.json` — the signed screening ledger, independently verifiable.

## What the run shows (and the honest read)

On a synthetic 800-candidate pool for an **NPM1m / FLT3-ITD-neg** trial:

- Confidence bands separate the pool; only the gray zone is sent to NGS.
- To enroll 30: naive sequencing ≈ 176 tests; Axiisium ≈ 125 → **~29% fewer NGS tests**,
  enrichment ≈ 1.4x.
- The screening ledger verifies clean; flipping any confirmatory result is **tamper-detected**.

**Be honest about enrichment magnitude.** It is bounded by the *hardest-to-predict*
criterion. A conjunctive profile that includes a morphology-invisible exclusion
(FLT3-ITD−) enriches modestly (~1.4x). A trial whose driver is morphology-visible (NPM1+
alone — the real menin-inhibitor population) enriches more (~1.8x at the top of the rank).
The lesson for go-to-market: **lead with trials whose molecular driver is morphology- or
flow-visible**, where the model adds the most. Do not pitch a universal "10x" — pitch the
right trials and the durable differentiator.

## The durable differentiator (regardless of enrichment magnitude)

Even where enrichment is modest, **the signed audit-ready screening ledger is unique and
non-optional for a regulated trial.** Two pharma-facing values, both real:

1. **Lower screening cost / faster enrollment** — scales with how predictable the criteria
   are from morphology+flow.
2. **Provable, tamper-evident, FDA-submittable record of how every enrollment decision was
   made** — this is compliance infrastructure no image-only model has, and it is the moat
   that survives even when a competitor's classifier matches your accuracy.

## Production

Swap the synthetic cohorts for the sponsor's real candidate pool, scored by the model
trained in Stages 1–3 (ideally federated across the sponsor's sites, Stage 3). The screening
ledger is emitted by the production `airsdk.AIRRecorder` and anchored to Sigstore Rekor.

## The pitch this proves

"Give us the morphology, flow, and clinical data you already collect at screening. We rank
who to sequence so you fill the trial with fewer NGS tests and enroll faster — and we hand
you a cryptographically signed, FDA-submittable record of exactly how every patient was
selected. Built on the NVIDIA stack, auditable end to end."

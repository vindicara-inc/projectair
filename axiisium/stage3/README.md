# Axiisium Stage 3 — federated training + federation-wide signed ledger

Turns the Stage 2 blocker ("we need one big paired cohort") into "centers contribute
without surrendering data." Three simulated AML centers train an NPM1 model by FedAvg —
only weights move, never patient data — and every contribution is cryptographically signed
into one tamper-evident federation ledger.

## Why this is the keystone

1. **It unlocks the data.** The Stage 2 gate was paired image+genomic data, locked inside
   institutions by privacy law and competitive caution. Federation is how the cohort gets
   assembled at all: the data never leaves the center.
2. **It's the NVIDIA co-build.** NVIDIA FLARE moves the weights and attests the hardware.
   But FLARE's own docs admit the gap: *"Without proper design ... confidential computing
   attestation will NOT be able to detect deployment-time code modifications or tampering."*
   FLARE proves the enclave is genuine; it does not, by itself, prove **what was computed
   at the application layer or who authorized it.** Axiisium's multi-signer federation
   ledger is exactly that missing application-layer proof. The two compose into an
   end-to-end chain of trust from silicon to computation.

## What the run shows

```
Centralized (data pooled, ceiling) : AUC 0.926
Federated  (data stays put)        : AUC 0.917   <- recovers the ceiling, no data moved
Each site alone: transplant 0.901 | community 0.872 | pediatric 0.848
Federation lift for the weakest site: +0.069      <- the small/skewed center gains most
Federation ledger: 50 records, 4 signers, VERIFY clean VALID, tamper -> DETECTED
```

The honest, load-bearing point: the data-starved center reaches accuracy it could never
get alone, and every site's contribution is provable and unforgeable.

## Run

```bash
python ../stage3.py --rounds 12 --local-epochs 50
```

Writes `run_record_stage3.json` — the multi-signer federation ledger, independently
verifiable with zero vendor calls.

## Mapping to NVIDIA FLARE (production)

The numpy FedAvg loop is a faithful stand-in for a FLARE job. The swap:

| Stage 3 reference | NVIDIA FLARE production |
|---|---|
| `fedavg_round` server loop | FLARE `Controller` running the FedAvg workflow (`nvflare.app_common`) |
| each site's `local_train` | FLARE `Executor` / `Learner` training locally on the site |
| `partition_noniid` | real per-site data on each FLARE client node |
| weight dict passed in-process | FLARE `Shareable` / `FLModel` over the FLARE transport |
| `FederationLedger` records | the same ledger emitted from each Executor + the Controller, anchored to Sigstore Rekor (production `airsdk.AIRRecorder`) |
| in-process loop | `nvflare simulator` first, then POC mode, then real nodes |

Confidential computing: run FLARE clients inside TEEs (AMD SEV-SNP / Intel TDX) + GPU
confidential computing; FLARE attests the hardware, the ledger attests the computation.

Steps to stand it up:
1. `pip install nvflare`
2. Wrap `LogisticModel.local_train` as an `Executor`; configure the FedAvg `Controller`.
3. Emit a federation-ledger record from each Executor (local update) and the Controller
   (aggregation); sign with each party's key.
4. `nvflare simulator -n 3 -t 3 <job>` to reproduce this run on the real framework.
5. Move to POC / real nodes; enable TEE + GPU confidential computing.

## Honest limits

- FedAvg is the simplest aggregation; non-IID skew can hurt it. Production should evaluate
  FedProx / FedOpt and secure aggregation — FLARE ships these.
- The ledger proves *what was computed and by whom*; it does not by itself prevent a
  malicious site from submitting poisoned updates. Pair it with FLARE's robust-aggregation
  / anomaly defenses. Signing makes poisoning **attributable**, not impossible.
- Federated NPM1 here is single-modality (morphology). Full multimodal federation (Stage 2
  fusion across sites) is the next integration and is heavier.

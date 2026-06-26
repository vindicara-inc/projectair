#!/usr/bin/env python3
"""Axiisium Stage 0 — end-to-end feasibility skeleton.

Runs in any Python env with numpy + cryptography. Proves the full shape:

    multimodal AML cohort  ->  late-fusion model  ->  eval (AUC)
                                                        |
                              every step signed (Ed25519, hash-chained, human-bound)
                                                        |
                              -> tamper-evident, FDA-audit-ready training-run record
                              -> single altered field breaks verification

What is REAL here: the signing, hashing, chaining, verification, tamper detection, and a
model that actually trains and is evaluated. What is SYNTHETIC: the cohort (see data.py)
and the per-modality encoders (numpy logistic regression standing in for MONAI/torch on
GPU). Production swaps are marked in each module.

Usage:
    python feasibility.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

import numpy as np  # noqa: E402

from axiisium.data import MODALITY_DIMS, make_cohort, train_test_split  # noqa: E402
from axiisium.model import FusionModel, ModalityHead, roc_auc  # noqa: E402
from axiisium.trust import RunLedger, sha256_array, tamper_copy  # noqa: E402

BAR = "=" * 78


def single_modality_auc(name: str, tr_mods, ytr, te_mods, yte) -> float:
    head = ModalityHead(dim=tr_mods[name].shape[1])
    head.fit(tr_mods[name], ytr)
    from axiisium.model import _sigmoid

    p = _sigmoid(head.logit(te_mods[name]))
    return roc_auc(yte, p)


def run() -> None:
    print(BAR)
    print("AXIISIUM  Stage 0 feasibility  -  multimodal AML model + signed training run")
    print(BAR)

    ledger = RunLedger()
    clinician = "Dr. M. Osei, MD  (hematopathology, NPI 1987654320)"

    # 1. Cohort -------------------------------------------------------------
    mods, y = make_cohort(n=1200, seed=7)
    tr_mods, ytr, te_mods, yte = train_test_split(mods, y, frac=0.75, seed=7)
    data_hash = sha256_array(np.concatenate([mods[k] for k in sorted(mods)], axis=1))
    ledger.record(
        "cohort_loaded",
        {
            "n": int(len(y)),
            "modalities": MODALITY_DIMS,
            "target": "NPM1 mutation status (synthetic)",
            "data_sha256": data_hash,
            "source": "SYNTHETIC (prod: aligned path+flow+cyto+molecular cohort via FLARE)",
        },
    )

    # 2. Train fusion -------------------------------------------------------
    model = FusionModel()
    model.fit(tr_mods, ytr)
    weights_hash = sha256_array(model.weights_blob())
    ledger.record(
        "model_trained",
        {
            "arch": "late-fusion logistic (prod: MONAI/torch per-modality encoders on GPU)",
            "weights_sha256": weights_hash,
            "n_train": int(len(ytr)),
        },
        human_authority=clinician,
    )

    # 3. Evaluate -----------------------------------------------------------
    p = model.predict_proba(te_mods)
    fused_auc = roc_auc(yte, p)
    per_mod = {m: round(single_modality_auc(m, tr_mods, ytr, te_mods, yte), 3) for m in mods}
    ledger.record(
        "evaluated",
        {
            "n_test": int(len(yte)),
            "fused_auc": round(fused_auc, 3),
            "per_modality_auc": per_mod,
            "fusion_lift_over_best_single": round(fused_auc - max(per_mod.values()), 3),
        },
        human_authority=clinician,
    )
    ledger.record("sealed", {"anchor": "Sigstore Rekor (simulated)", "records": len(ledger.records) + 1})

    # ---- report ----
    print("\n--- MODEL RESULT (the science) ---")
    print(f"  Fused AUC (held-out)      : {fused_auc:.3f}")
    for m, a in per_mod.items():
        print(f"    {m:<13}single-modality AUC: {a:.3f}")
    print(f"  Fusion lift over best single: +{fused_auc - max(per_mod.values()):.3f}")
    print("  (synthetic data: validates the pipeline learns + fuses, not real accuracy)")

    print("\n--- SIGNED TRAINING-RUN RECORD (the moat) ---")
    print(f"  Records          : {len(ledger.records)} (each Ed25519-signed, hash-chained)")
    print(f"  Run authorized by: {clinician}")
    print(f"  Data hash        : {data_hash[:48]}...")
    print(f"  Model hash       : {weights_hash[:48]}...")
    print(f"  Chain root       : {ledger.records[-1]['content_hash'][:48]}...")
    print(f"  Public key       : {ledger.pubkey_hex[:48]}...")

    ok, msg = RunLedger.verify(ledger.records, ledger.pubkey_hex)
    print(f"\n  VERIFY (clean)   : {'VALID' if ok else 'FAIL'} - chain {msg}")

    # tamper demo: silently change the reported AUC after the fact
    tampered = tamper_copy(ledger.records, 2, "fused_auc", 0.999)
    ok2, msg2 = RunLedger.verify(tampered, ledger.pubkey_hex)
    print(f"  VERIFY (tampered): {'VALID' if ok2 else 'TAMPER DETECTED'} - {msg2}")

    out = {
        "pubkey": ledger.pubkey_hex,
        "fused_auc": fused_auc,
        "per_modality_auc": per_mod,
        "records": ledger.records,
    }
    Path("run_record.json").write_text(json.dumps(out, indent=2))
    print("\n  run_record.json written (independently verifiable, zero vendor calls)")

    print("\n" + BAR)
    print("This is the artifact you take to NVIDIA's pharma contacts and Capital Connect:")
    print("a multimodal AML model whose every result is provably untampered and human-bound.")
    print("Next: Stage 1 swaps synthetic features for MONAI on real AML morphology (GPU).")
    print(BAR)


if __name__ == "__main__":
    run()

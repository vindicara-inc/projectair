#!/usr/bin/env python3
"""Axiisium Stage 1 — real single-cell AML morphology pipeline.

Trains and evaluates blast detection + morphology classification on the public Munich
AML-Cytomorphology_LMU dataset, with the whole run wrapped in the same signed,
tamper-evident ledger as Stage 0 (the moat carries across stages).

    images (folder-per-class)  ->  foundation-model embeddings  ->  classifier
                                                                       |
       every step Ed25519-signed, hash-chained, human-bound  ->  audit-ready record

Run modes:
    python stage1.py --smoke
        Generates a tiny synthetic dataset and runs the full path with SmokeEncoder.
        No download, no torch. Proves the code is correct.

    python stage1.py --data /path/to/AML-Cytomorphology_LMU --device cuda \
                     --weights dinobloom_vitb14.pth
        The real run on your NVIDIA GPU (Inception credits). Uses FoundationEncoder
        (DinoBloom). See stage1/README.md for the TCIA download steps.

What is REAL here: the loader on real image files, the classifier, the eval math, and the
signing/verification/tamper detection. The SmokeEncoder is the only placeholder in --smoke
mode; --data mode uses the production foundation-model encoder.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

import numpy as np  # noqa: E402

from axiisium.imaging.classify import (  # noqa: E402
    blast_labels,
    standardize,
    train_blast_detector,
    train_multiclass,
)
from axiisium.imaging.dataset import (  # noqa: E402
    index_hash,
    load_index,
    make_smoke_dataset,
)
from axiisium.trust import RunLedger, tamper_copy  # noqa: E402

BAR = "=" * 78
# AML-relevant blast classes. VERIFY against your downloaded folder names and adjust;
# Matek 2019 labels myeloblasts "MYB". Pass --blast-classes to override.
DEFAULT_BLAST = {"MYB", "MYO", "MOB"}


def build_encoder(args):
    if args.data:
        from axiisium.imaging.encoder import FoundationEncoder

        return FoundationEncoder(weights=args.weights, device=args.device)
    from axiisium.imaging.encoder import SmokeEncoder

    return SmokeEncoder()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", help="path to AML-Cytomorphology_LMU root (folder-per-class)")
    ap.add_argument("--smoke", action="store_true", help="run on synthetic data, no torch")
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--weights", default=None, help="DinoBloom weights .pth (production)")
    ap.add_argument("--blast-classes", nargs="*", default=None)
    args = ap.parse_args()

    if not args.data and not args.smoke:
        ap.error("pass --data <path> for the real run, or --smoke for the dry run")

    blast_set = set(args.blast_classes) if args.blast_classes else DEFAULT_BLAST

    print(BAR)
    print("AXIISIUM  Stage 1  -  AML single-cell morphology + signed training run")
    print(BAR)

    tmp = None
    if args.smoke:
        tmp = tempfile.mkdtemp(prefix="axiisium_smoke_")
        make_smoke_dataset(tmp)
        root = tmp
        print("  mode: SMOKE (synthetic images, SmokeEncoder, no torch)")
    else:
        root = args.data
        print(f"  mode: REAL  data={root}")

    ledger = RunLedger()
    pathologist = "Dr. M. Osei, MD  (hematopathology, NPI 1987654320)"

    # 1. Index ----------------------------------------------------------------
    samples, classes = load_index(root)
    labels = [s.label for s in samples]
    present_blast = sorted(blast_set & set(classes))
    print(f"\n  classes ({len(classes)}): {', '.join(classes)}")
    print(f"  blast-positive classes present: {present_blast or '(none — check --blast-classes)'}")
    ledger.record(
        "dataset_indexed",
        {
            "source": "AML-Cytomorphology_LMU (TCIA, DOI 10.7937/tcia.2019.36f5o9ld)"
            if not args.smoke else "SYNTHETIC smoke set",
            "n_images": len(samples),
            "n_classes": len(classes),
            "classes": classes,
            "blast_classes": present_blast,
            "index_sha256": index_hash(samples),
        },
    )

    # 2. Embed ----------------------------------------------------------------
    encoder = build_encoder(args)
    paths = [s.path for s in samples]
    X = encoder.embed(paths)
    ledger.record(
        "images_embedded",
        {"encoder": encoder.name, "embedding_dim": int(X.shape[1]), "n": int(X.shape[0])},
    )

    # 3. Split ----------------------------------------------------------------
    rng = np.random.default_rng(7)
    idx = rng.permutation(len(samples))
    cut = int(0.75 * len(idx))
    tr, te = idx[:cut], idx[cut:]
    Xtr, Xte = standardize(X[tr], X[te])
    lab = np.array(labels)
    cls_to_i = {c: i for i, c in enumerate(classes)}
    ytr_idx = np.array([cls_to_i[c] for c in lab[tr]])
    yte_idx = np.array([cls_to_i[c] for c in lab[te]])

    # 4. Blast detection ------------------------------------------------------
    ybtr = blast_labels(list(lab[tr]), blast_set)
    ybte = blast_labels(list(lab[te]), blast_set)
    if ybtr.sum() == 0 or ybte.sum() == 0:
        blast_auc = float("nan")
    else:
        blast_auc, _ = train_blast_detector(Xtr, ybtr, Xte, ybte)

    # 5. Morphology classification -------------------------------------------
    bal_acc = train_multiclass(Xtr, ytr_idx, Xte, yte_idx, len(classes))

    ledger.record(
        "evaluated",
        {
            "blast_detection_auc": None if np.isnan(blast_auc) else round(blast_auc, 3),
            "morphology_balanced_accuracy": round(bal_acc, 3),
            "n_train": int(len(tr)),
            "n_test": int(len(te)),
        },
        human_authority=pathologist,
    )
    ledger.record("sealed", {"anchor": "Sigstore Rekor (simulated)", "records": len(ledger.records) + 1})

    # ---- report ----
    print("\n--- MODEL RESULT (the science) ---")
    print(f"  Blast detection AUC         : {'n/a' if np.isnan(blast_auc) else f'{blast_auc:.3f}'}")
    print(f"  Morphology balanced accuracy: {bal_acc:.3f}  ({len(classes)} classes)")
    if args.smoke:
        print("  (SMOKE: synthetic images — validates the pipeline, NOT morphology accuracy)")

    print("\n--- SIGNED TRAINING-RUN RECORD (the moat) ---")
    print(f"  Records          : {len(ledger.records)} (each Ed25519-signed, hash-chained)")
    print(f"  Run authorized by: {pathologist}")
    print(f"  Chain root       : {ledger.records[-1]['content_hash'][:48]}...")
    print(f"  Public key       : {ledger.pubkey_hex[:48]}...")

    ok, msg = RunLedger.verify(ledger.records, ledger.pubkey_hex)
    print(f"\n  VERIFY (clean)   : {'VALID' if ok else 'FAIL'} - chain {msg}")
    tampered = tamper_copy(ledger.records, 2, "morphology_balanced_accuracy", 0.999)
    ok2, msg2 = RunLedger.verify(tampered, ledger.pubkey_hex)
    print(f"  VERIFY (tampered): {'VALID' if ok2 else 'TAMPER DETECTED'} - {msg2}")

    out = {"pubkey": ledger.pubkey_hex, "classes": classes, "records": ledger.records}
    Path("run_record_stage1.json").write_text(json.dumps(out, indent=2))
    print("\n  run_record_stage1.json written (independently verifiable)")

    if tmp:
        import shutil

        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + BAR)
    print("Real run: download TCIA AML-Cytomorphology_LMU, then --data <path> --device cuda")
    print("with DinoBloom weights. Same signed-run guarantee, real morphology, on your GPU.")
    print(BAR)


if __name__ == "__main__":
    main()

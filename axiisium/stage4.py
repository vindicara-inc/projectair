#!/usr/bin/env python3
"""Axiisium Stage 4 — pharma trial-enrichment product (the revenue wedge).

A sponsor running an AML trial needs patients with a specific molecular profile
(e.g. NPM1-mutated, FLT3-ITD-negative). Normally they sequence every candidate up front —
slow, expensive, the #1 cause of trial-enrollment delay. Axiisium pre-screens from
morphology + flow + clinical (fast, cheap), RANKS who is most likely eligible so the
sponsor sequences far fewer patients to fill the trial, and emits a signed, audit-ready
screening ledger the sponsor submits to the FDA.

    candidate cohort ─▶ multimodal model ─▶ ranked eligibility + confidence bands
                                              │
       confirm-with-NGS only in the gray zone │ (never enroll on prediction alone)
                                              ▼
       signed screening ledger: criteria + model version + each decision + reviewer
       ─▶ fewer NGS tests, faster enrollment, fully auditable

Run:
    python stage4.py [--target 30]

Outputs the enrollment economics (NGS tests saved, enrichment factor) and writes
run_record_stage4.json. Production: swap the synthetic cohorts for the sponsor's real
candidate pool scored by the Stage 1-3 trained model.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

import numpy as np  # noqa: E402

from axiisium.fusion.cohort import make_paired_cohort  # noqa: E402
from axiisium.trial.criteria import TrialCriteria  # noqa: E402
from axiisium.trial.screening import (  # noqa: E402
    MultiMutationModel,
    TrialScreener,
    enrollment_economics,
)
from axiisium.trust import RunLedger, tamper_copy  # noqa: E402

BAR = "=" * 78


def clinical_fields(n: int, seed: int):
    rng = np.random.default_rng(seed)
    age = rng.normal(64, 13, n).clip(19, 89)        # AML skews older
    blast = rng.normal(45, 20, n).clip(0, 100)      # marrow blast %
    return age, blast


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=30, help="patients to enroll")
    args = ap.parse_args()

    print(BAR)
    print("AXIISIUM  Stage 4  -  pharma trial-enrichment screening + signed ledger")
    print(BAR)

    crit = TrialCriteria(
        name="AML-NPM1m / FLT3-ITD-neg (menin-inhibitor-style)",
        require_mutations=["NPM1"],
        exclude_mutations=["FLT3_ITD"],
        min_age=18,
        min_blast_pct=20.0,
    )
    print(f"  Trial: {crit.name}")
    print(f"    require {crit.require_mutations}, exclude {crit.exclude_mutations}, "
          f"age>={crit.min_age}, blast>={crit.min_blast_pct:.0f}%")

    # reference cohort -> train the screening model
    ref_mods, ref_Y, mutations = make_paired_cohort(n=2200, seed=11)
    model = MultiMutationModel()
    model.fit(ref_mods, ref_Y, mutations, targets=["NPM1", "FLT3_ITD"])

    # fresh candidate cohort (the sponsor's screening pool)
    cand_mods, cand_Y, _ = make_paired_cohort(n=800, seed=99)
    age, blast = clinical_fields(len(cand_Y), seed=99)
    true_muts = [{m: int(cand_Y[i, mutations.index(m)]) for m in mutations} for i in range(len(cand_Y))]
    truly_elig = np.array([crit.truly_eligible(age[i], blast[i], true_muts[i]) for i in range(len(cand_Y))])

    screener = TrialScreener(model, crit)
    rows = screener.screen(cand_mods, age, blast)
    econ = enrollment_economics(rows, truly_elig, target=args.target)

    bands: dict[str, int] = {}
    for r in rows:
        bands[r["band"]] = bands.get(r["band"], 0) + 1

    # ---- signed screening ledger ----
    ledger = RunLedger()
    pi = "Dr. R. Nakamura, MD  (trial PI / molecular hematology, NPI 1678901234)"
    ledger.record("trial_defined", {"criteria": crit.name, "require": crit.require_mutations,
                                     "exclude": crit.exclude_mutations,
                                     "min_age": crit.min_age, "min_blast_pct": crit.min_blast_pct})
    ledger.record("model_bound", {"model_version_sha256": model.version_hash(),
                                  "panel": list(model.models), "candidates": len(rows)})
    # record each enrolled candidate's signed screening decision (top of the ranked list)
    enrolled_rows = [r for r in rows if r["band"] != "excluded_hard_filter"][:econ["axiisium_sequenced_to_fill"]]
    for r in enrolled_rows:
        confirmed = bool(truly_elig[r["candidate"]])  # the NGS result
        ledger.record("candidate_screened",
                      {"candidate": r["candidate"], "eligibility_score": r["eligibility_score"],
                       "band": r["band"], "ngs_confirmed_eligible": confirmed},
                      human_authority=pi)
    ledger.record("sealed", {"enrolled": econ["axiisium_enrolled"], "anchor": "Sigstore Rekor (simulated)"})

    # ---- report ----
    print("\n--- SCREENING RESULT (the product) ---")
    print(f"  Candidate pool            : {len(rows)}")
    print(f"  Confidence bands          : {bands}")
    print("\n--- ENROLLMENT ECONOMICS (the pitch) ---")
    print(f"  Base eligible rate in pool: {econ['base_eligible_rate']:.1%}")
    print(f"  To enroll {econ['trial_target']} patients:")
    print(f"    Naive (sequence to fill): ~{econ['naive_sequenced_to_fill']} NGS tests")
    print(f"    Axiisium (rank, then seq): {econ['axiisium_sequenced_to_fill']} NGS tests")
    print(f"    NGS tests saved          : {econ['ngs_tests_saved']}")
    print(f"    Enrichment factor        : {econ['enrichment_factor']}x  (eligible rate among sequenced vs base)")

    print("\n--- SIGNED SCREENING LEDGER (the moat) ---")
    print(f"  Records          : {len(ledger.records)} (Ed25519-signed, hash-chained)")
    print(f"  Trial PI         : {pi}")
    print(f"  Model version    : {model.version_hash()[:48]}...")
    ok, msg = RunLedger.verify(ledger.records, ledger.pubkey_hex)
    print(f"  VERIFY (clean)   : {'VALID' if ok else 'FAIL'} - chain {msg}")
    # tamper: flip a screening decision's NGS confirmation after the fact
    t_idx = next(i for i, r in enumerate(ledger.records) if r["kind"] == "candidate_screened")
    tampered = tamper_copy(ledger.records, t_idx, "eligibility_score", -1.0)
    ok2, msg2 = RunLedger.verify(tampered, ledger.pubkey_hex)
    print(f"  VERIFY (tampered): {'VALID' if ok2 else 'TAMPER DETECTED'} - {msg2}")

    out = {"pubkey": ledger.pubkey_hex, "criteria": crit.name, "economics": econ,
           "bands": bands, "records": ledger.records}
    Path("run_record_stage4.json").write_text(json.dumps(out, indent=2))
    print("\n  run_record_stage4.json written (independently verifiable)")

    print("\n" + BAR)
    print("This is what a pharma sponsor pays for: fewer screening NGS tests, faster")
    print("enrollment, and an FDA-submittable record of exactly how each patient was chosen.")
    print(BAR)


if __name__ == "__main__":
    main()

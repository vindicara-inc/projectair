#!/usr/bin/env python3
"""Run the entire Axiisium build end to end (Stages 0-5).

    python run_all.py

Each stage runs in dry/synthetic mode (no GPU, no download) to prove the full pipeline +
trust layer execute. Swap in real data + NVIDIA stack per each stage's README for the
production run.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent
STAGES = [
    ("Stage 0  multimodal feasibility + signed run", ["feasibility.py"]),
    ("Stage 1  AML morphology pipeline (dry run)", ["stage1.py", "--smoke"]),
    ("Stage 2  multimodal mutation prediction", ["stage2.py"]),
    ("Stage 3  federated training + federation ledger", ["stage3.py"]),
    ("Stage 4  pharma trial-enrichment screening", ["stage4.py"]),
    ("Stage 5  confidential computing attestation", ["stage5.py"]),
]


def main() -> None:
    print("#" * 78)
    print("# AXIISIUM  -  full build, Stages 0-5")
    print("#" * 78)
    failures = []
    for title, cmd in STAGES:
        print(f"\n\n>>> {title}\n")
        r = subprocess.run([sys.executable, str(HERE / cmd[0]), *cmd[1:]])
        if r.returncode != 0:
            failures.append(title)
    print("\n" + "#" * 78)
    if failures:
        print("# FAILED: " + "; ".join(failures))
        sys.exit(1)
    print("# ALL STAGES RAN CLEAN  -  every stage carries the signed, tamper-evident trust layer")
    print("#" * 78)


if __name__ == "__main__":
    main()

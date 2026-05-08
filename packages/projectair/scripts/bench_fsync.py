"""Micro-benchmark: FileTransport throughput with fsync vs without.

Measures the per-record overhead added by ``os.fsync`` so we can publish
a concrete number rather than a vague "could be a bottleneck" warning.

Run from the package root:

    PYTHONPATH=src python scripts/bench_fsync.py
"""
from __future__ import annotations

import statistics
import tempfile
import time
from pathlib import Path

from airsdk.agdr import Signer
from airsdk.transport import FileTransport
from airsdk.types import StepKind

_RECORDS_PER_RUN = 1_000
_RUNS = 5


def _bench(fsync: bool) -> tuple[float, float]:
    """Return (records_per_second, ms_per_record_p50) over RECORDS_PER_RUN writes."""
    durations: list[float] = []
    for _ in range(_RUNS):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "chain.jsonl"
            transport = FileTransport(log_path, fsync=fsync)
            signer = Signer.generate()
            start = time.perf_counter()
            for i in range(_RECORDS_PER_RUN):
                rec = signer.sign(StepKind.LLM_START, {"prompt": f"step-{i}"})
                transport.emit(rec)
            durations.append(time.perf_counter() - start)

    median = statistics.median(durations)
    rps = _RECORDS_PER_RUN / median
    ms_per_record = (median / _RECORDS_PER_RUN) * 1000
    return rps, ms_per_record


def main() -> None:
    print(f"# FileTransport throughput, {_RECORDS_PER_RUN} records x {_RUNS} runs (median)")
    print()
    print(f"{'mode':<20} {'records/sec':>12} {'ms/record':>12}")
    print(f"{'-' * 20} {'-' * 12} {'-' * 12}")
    for fsync, label in [(False, "fsync=False"), (True, "fsync=True (default)")]:
        rps, ms = _bench(fsync)
        print(f"{label:<20} {rps:>12,.0f} {ms:>12.3f}")


if __name__ == "__main__":
    main()

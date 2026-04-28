"""End-to-end tests for the demo chains and the `air demo` CLI."""
from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from airsdk._concrete_demo import (
    CONCRETE_DEMO_STEPS,
    CONCRETE_DEMO_TAMPER_INDEX,
    CONCRETE_DEMO_USER_INTENT,
    build_concrete_demo_log,
    tamper_one_byte,
)
from airsdk._demo import SAMPLE_STEPS, SAMPLE_USER_INTENT, write_sample_log
from airsdk.agdr import load_chain, verify_chain
from airsdk.detections import run_detectors
from airsdk.types import VerificationStatus
from projectair.cli import app

runner = CliRunner()


DEMO_ASI07_EXTRA_RECORDS = 6  # legit + forged agent_message + 4-target fan-out appended by write_sample_log


def test_sample_chain_round_trips_and_verifies(tmp_path: Path) -> None:
    sample = tmp_path / "demo.log"
    signer = write_sample_log(sample)

    records = load_chain(sample)
    assert len(records) == len(SAMPLE_STEPS) + DEMO_ASI07_EXTRA_RECORDS
    # Chain still verifies end-to-end: the forged signer was initialized with the
    # primary signer's head hash, so prev_hash linkage holds and each record
    # verifies against its own signer_key.
    assert verify_chain(records).status == VerificationStatus.OK
    # Every record up to and including the first (legitimate) agent_message is
    # signed by the primary key; the final forged record is signed by a different key.
    primary_signed = records[: len(SAMPLE_STEPS) + 1]
    assert all(r.signer_key == signer.public_key_hex for r in primary_signed)
    assert records[-1].signer_key != signer.public_key_hex


def test_sample_chain_carries_user_intent_on_every_step(tmp_path: Path) -> None:
    sample = tmp_path / "demo.log"
    write_sample_log(sample)
    records = load_chain(sample)
    assert all(r.payload.user_intent == SAMPLE_USER_INTENT for r in records)


def test_sample_chain_triggers_all_implemented_detectors(tmp_path: Path) -> None:
    sample = tmp_path / "demo.log"
    write_sample_log(sample)
    findings = run_detectors(load_chain(sample))
    detector_ids = {f.detector_id for f in findings}
    for expected in ("ASI01", "ASI02", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI09", "AIR-01", "AIR-02", "AIR-03", "AIR-04"):
        assert expected in detector_ids, f"{expected} missing from demo findings: {detector_ids}"


def test_air_demo_runs_end_to_end(tmp_path: Path) -> None:
    """The brutal 8-step demo writes the trace, exports JSON/PDF/CEF, tampers, and proves break."""
    workdir = tmp_path / "demo-out"

    result = runner.invoke(app, ["demo", "--workdir", str(workdir)])

    assert result.exit_code == 0, result.stdout
    # Each of the 8 steps surfaces a labelled header.
    for step_no in range(1, 9):
        assert f"STEP {step_no}/8" in result.stdout, f"step {step_no} header missing"
    # Cryptographic primitives named for transparency.
    assert "BLAKE3" in result.stdout
    assert "Ed25519" in result.stdout
    assert "UUIDv7" in result.stdout
    # Detector findings surface with real OWASP IDs.
    for detector in ("AIR-01", "AIR-02", "ASI02"):
        assert detector in result.stdout, f"{detector} not surfaced by `air demo`"
    # All three export formats land on disk.
    assert (workdir / "agent-trace.log").exists()
    assert (workdir / "forensic-report.json").exists()
    assert (workdir / "forensic-report.pdf").exists()
    assert (workdir / "forensic-report.cef").exists()
    # Tamper-then-verify climax actually fires.
    assert "tamper" in result.stdout.lower()
    assert "FAILED" in result.stdout
    assert f"index {CONCRETE_DEMO_TAMPER_INDEX}" in result.stdout
    assert "tamper-evident" in result.stdout.lower()


def test_concrete_demo_chain_verifies_before_tamper(tmp_path: Path) -> None:
    log = tmp_path / "concrete.log"
    build_concrete_demo_log(log)
    records = load_chain(log)
    assert len(records) == len(CONCRETE_DEMO_STEPS)
    assert verify_chain(records).status == VerificationStatus.OK
    assert all(r.payload.user_intent == CONCRETE_DEMO_USER_INTENT for r in records)


def test_concrete_demo_tamper_breaks_at_exact_index(tmp_path: Path) -> None:
    log = tmp_path / "concrete.log"
    build_concrete_demo_log(log)
    records_before = load_chain(log)
    target_step_id = records_before[CONCRETE_DEMO_TAMPER_INDEX].step_id

    tamper_one_byte(log, CONCRETE_DEMO_TAMPER_INDEX)

    records_after = load_chain(log)
    result = verify_chain(records_after)
    assert result.status != VerificationStatus.OK
    assert result.failed_step_id == target_step_id, (
        f"verification failed on the wrong record: expected {target_step_id}, got {result.failed_step_id}"
    )


def test_concrete_demo_chain_trips_owasp_findings(tmp_path: Path) -> None:
    log = tmp_path / "concrete.log"
    build_concrete_demo_log(log)
    findings = run_detectors(load_chain(log))
    detector_ids = {f.detector_id for f in findings}
    # Concrete chain is designed to trip these specific detectors cleanly.
    for expected in ("AIR-01", "AIR-02", "ASI02"):
        assert expected in detector_ids, f"{expected} missing from concrete demo findings: {detector_ids}"


def test_air_trace_on_demo_sample(tmp_path: Path) -> None:
    sample = tmp_path / "demo.log"
    report = tmp_path / "report.json"
    write_sample_log(sample)

    result = runner.invoke(app, ["trace", str(sample), "--output", str(report)])

    assert result.exit_code == 0, result.stdout
    assert "[Chain verified]" in result.stdout
    assert report.exists()


def test_air_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "air / airsdk" in result.stdout

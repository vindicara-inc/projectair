"""Shared fixtures for HL7 test suite."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from airsdk.recorder import AIRRecorder
from airsdk_pro.hl7.capture import HL7_FHIR_FEATURE
from airsdk_pro.license import install_license, load_license


@pytest.fixture
def licensed(
    tmp_path: Path,
    issue_token: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Install a Pro license with the HL7 FHIR feature and route the gate to it."""
    token = issue_token(
        email="hl7-tests@vindicara.io",
        tier="individual",
        features=(HL7_FHIR_FEATURE,),
    )
    license_path = tmp_path / "license.json"
    install_license(token, path=license_path)
    monkeypatch.setattr(
        "airsdk_pro.gate.load_license", lambda: load_license(license_path)
    )
    return license_path


@pytest.fixture
def recorder(tmp_path: Path) -> AIRRecorder:
    return AIRRecorder(log_path=tmp_path / "chain.jsonl")


@pytest.fixture(autouse=True)
def _phi_redaction_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide the per-deployment PHI MAC key so REDACTED-mode redaction works.

    redact_identifier fails closed without AIRSDK_PHI_REDACTION_KEY; tests set a
    fixed dummy secret so digests are deterministic within the suite.
    """
    monkeypatch.setenv("AIRSDK_PHI_REDACTION_KEY", "test-phi-secret-not-for-production")

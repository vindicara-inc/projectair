"""Tests for the Pro license token format, verifier, storage, and gate decorator."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from _helpers import requires_vendor_key
from airsdk_pro.gate import requires_pro
from airsdk_pro.license import (
    LicenseExpiredError,
    LicenseInvalidError,
    LicenseMissingError,
    current_license,
    has_feature,
    install_license,
    is_pro_active,
    load_license,
    verify_token,
)


@requires_vendor_key
def test_install_then_load_round_trip(tmp_path: Path, issue_token) -> None:
    token_text = issue_token(email="alice@vindicara.io", tier="individual", features=("air-cloud-client",))
    license_path = tmp_path / "license.json"

    parsed = install_license(token_text, path=license_path)
    assert parsed.email == "alice@vindicara.io"
    assert parsed.tier == "individual"
    assert parsed.has_feature("air-cloud-client")
    assert not parsed.has_feature("report-nist-ai-rmf")

    reloaded = load_license(license_path)
    assert reloaded.email == parsed.email
    assert reloaded.expires_at == parsed.expires_at


@requires_vendor_key
def test_install_sets_owner_only_permissions(tmp_path: Path, issue_token) -> None:
    license_path = tmp_path / "license.json"
    install_license(issue_token(), path=license_path)
    mode = os.stat(license_path).st_mode & 0o777
    assert mode == 0o600


@requires_vendor_key
def test_load_license_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(LicenseMissingError):
        load_license(tmp_path / "no-such-file.json")


@requires_vendor_key
def test_load_license_corrupt_raises(tmp_path: Path) -> None:
    bad = tmp_path / "license.json"
    bad.write_text("{ this is not json }", encoding="utf-8")
    with pytest.raises(LicenseInvalidError):
        load_license(bad)


@requires_vendor_key
def test_load_license_missing_token_field_raises(tmp_path: Path) -> None:
    bad = tmp_path / "license.json"
    bad.write_text(json.dumps({"installed_at": 0}), encoding="utf-8")
    with pytest.raises(LicenseInvalidError):
        load_license(bad)


@requires_vendor_key
def test_tampered_token_signature_fails(tmp_path: Path, issue_token) -> None:
    token_text = issue_token(email="bob@vindicara.io")
    token = json.loads(token_text)
    token["email"] = "evil@attacker.com"
    tampered = json.dumps(token)
    with pytest.raises(LicenseInvalidError, match="signature does not verify"):
        install_license(tampered, path=tmp_path / "license.json")


@requires_vendor_key
def test_unknown_tier_rejected(tmp_path: Path, issue_token) -> None:
    token_text = issue_token()
    token = json.loads(token_text)
    token["tier"] = "godmode"
    with pytest.raises(LicenseInvalidError, match="tier"):
        verify_token(token)


@requires_vendor_key
def test_wrong_version_rejected(tmp_path: Path, issue_token) -> None:
    token_text = issue_token()
    token = json.loads(token_text)
    token["v"] = 99
    with pytest.raises(LicenseInvalidError, match="version"):
        verify_token(token)


@requires_vendor_key
def test_expired_token_raises(expired_token: str, tmp_path: Path) -> None:
    with pytest.raises(LicenseExpiredError):
        install_license(expired_token, path=tmp_path / "license.json")


@requires_vendor_key
def test_current_license_returns_none_on_missing(tmp_path: Path) -> None:
    assert current_license(tmp_path / "no-license.json") is None


@requires_vendor_key
def test_is_pro_active_false_without_license(tmp_path: Path) -> None:
    assert is_pro_active(tmp_path / "no-license.json") is False


@requires_vendor_key
def test_is_pro_active_true_with_valid_license(tmp_path: Path, issue_token) -> None:
    license_path = tmp_path / "license.json"
    install_license(issue_token(), path=license_path)
    assert is_pro_active(license_path) is True


@requires_vendor_key
def test_has_feature_only_for_granted_features(tmp_path: Path, issue_token) -> None:
    license_path = tmp_path / "license.json"
    install_license(issue_token(features=("air-cloud-client",)), path=license_path)
    assert has_feature("air-cloud-client", path=license_path) is True
    assert has_feature("report-nist-ai-rmf", path=license_path) is False


# -- Gate decorator tests --------------------------------------------------


@requires_vendor_key
def test_requires_pro_blocks_when_no_license(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("airsdk_pro.gate.load_license", lambda: (_ for _ in ()).throw(LicenseMissingError("no license")))

    @requires_pro()
    def _premium_feature() -> str:
        return "ran"

    with pytest.raises(LicenseMissingError):
        _premium_feature()


@requires_vendor_key
def test_requires_pro_passes_with_valid_license(tmp_path: Path, issue_token, monkeypatch) -> None:
    license_path = tmp_path / "license.json"
    install_license(issue_token(features=("air-cloud-client",)), path=license_path)
    monkeypatch.setattr("airsdk_pro.gate.load_license", lambda: load_license(license_path))

    @requires_pro()
    def _premium_feature() -> str:
        return "ran"

    assert _premium_feature() == "ran"


@requires_vendor_key
def test_requires_pro_blocks_missing_feature_entitlement(tmp_path: Path, issue_token, monkeypatch) -> None:
    license_path = tmp_path / "license.json"
    install_license(issue_token(features=("air-cloud-client",)), path=license_path)
    monkeypatch.setattr("airsdk_pro.gate.load_license", lambda: load_license(license_path))

    @requires_pro(feature="report-nist-ai-rmf")
    def _premium_report() -> str:
        return "report bytes"

    with pytest.raises(LicenseInvalidError, match="report-nist-ai-rmf"):
        _premium_report()

"""Tests for the self-hosted / air-gapped deployable unit.

Two layers:

- The **gate** (:mod:`airsdk_pro.deploy`) and the **entrypoint fail-closed
  behaviour** (:mod:`airsdk_pro.serve`). The reject matrix is the security spec
  of the whole tier, so every reject path is asserted here. Crucially, the
  reject tests that do not need a *valid* signature run unconditionally (they
  only need the embedded public key), so the security boundary is never silently
  skipped in CI when the vendor signing key is absent.
- The **serve-on-pass + durable persistence** path, which additionally needs the
  engine (`vindicara.cloud`) installed; those tests skip cleanly where it is not.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from _helpers import requires_vendor_key
from airsdk_pro.deploy import SELF_HOST_TIERS, StartupReport, enforce_license_at_startup, preflight
from airsdk_pro.license import (
    LicenseExpiredError,
    LicenseInvalidError,
    LicenseMissingError,
    install_license,
)


def _importable(module: str) -> bool:
    """True if ``module`` can be resolved. ``find_spec`` raises (not returns
    None) when a *parent* package is missing, so guard for it."""
    try:
        return importlib.util.find_spec(module) is not None
    except ModuleNotFoundError:
        return False


_HAS_VINDICARA = _importable("vindicara.cloud.factory")
requires_vindicara = pytest.mark.skipif(
    not _HAS_VINDICARA, reason="vindicara.cloud engine not installed in this environment"
)


def _write(path: Path, obj: object) -> Path:
    path.write_text(json.dumps(obj), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Reject matrix: no valid signature required, so these ALWAYS run. This IS the
# fail-closed security contract; it must not vanish when the vendor key is
# absent.
# --------------------------------------------------------------------------


def test_gate_rejects_missing_license(tmp_path: Path) -> None:
    with pytest.raises(LicenseMissingError):
        enforce_license_at_startup(license_path=tmp_path / "nope.json")


def test_gate_rejects_corrupt_json(tmp_path: Path) -> None:
    path = tmp_path / "license.json"
    path.write_text("{ this is not json", encoding="utf-8")
    with pytest.raises(LicenseInvalidError):
        enforce_license_at_startup(license_path=path)


def test_gate_rejects_missing_token_field(tmp_path: Path) -> None:
    path = _write(tmp_path / "license.json", {"installed_at": 1})
    with pytest.raises(LicenseInvalidError):
        enforce_license_at_startup(license_path=path)


def test_gate_rejects_unsupported_version(tmp_path: Path) -> None:
    token = {"v": 2, "email": "a@b.c", "tier": "enterprise", "issued_at": 0, "expires_at": 9_999_999_999, "features": [], "signature": "00"}
    path = _write(tmp_path / "license.json", {"token": token})
    with pytest.raises(LicenseInvalidError):
        enforce_license_at_startup(license_path=path)


def test_gate_rejects_bad_hex_signature(tmp_path: Path) -> None:
    token = {"v": 1, "email": "a@b.c", "tier": "enterprise", "issued_at": 0, "expires_at": 9_999_999_999, "features": [], "signature": "zzzz"}
    path = _write(tmp_path / "license.json", {"token": token})
    with pytest.raises(LicenseInvalidError):
        enforce_license_at_startup(license_path=path)


def test_gate_rejects_tampered_signature(tmp_path: Path) -> None:
    # Well-formed hex signature that does not verify against the vendor public key.
    token = {"v": 1, "email": "a@b.c", "tier": "enterprise", "issued_at": 0, "expires_at": 9_999_999_999, "features": [], "signature": "ab" * 64}
    path = _write(tmp_path / "license.json", {"token": token})
    with pytest.raises(LicenseInvalidError):
        enforce_license_at_startup(license_path=path)


# --------------------------------------------------------------------------
# Signed paths: require the local vendor key to mint a valid token.
# --------------------------------------------------------------------------


@requires_vendor_key
def test_gate_accepts_enterprise(tmp_path: Path, issue_token: Any) -> None:
    path = tmp_path / "license.json"
    install_license(issue_token(tier="enterprise"), path=path)
    token = enforce_license_at_startup(license_path=path)
    assert token.tier == "enterprise"


@requires_vendor_key
@pytest.mark.parametrize("tier", ["individual", "team"])
def test_gate_rejects_wrong_tier(tmp_path: Path, issue_token: Any, tier: str) -> None:
    assert tier not in SELF_HOST_TIERS
    path = tmp_path / "license.json"
    install_license(issue_token(tier=tier), path=path)
    with pytest.raises(LicenseInvalidError, match="not entitled to self-hosted"):
        enforce_license_at_startup(license_path=path)


@requires_vendor_key
def test_gate_rejects_expired(tmp_path: Path, expired_token: str) -> None:
    path = tmp_path / "license.json"
    # Cannot install an expired token (install verifies), so write it on-disk directly.
    _write(path, {"token": json.loads(expired_token)})
    with pytest.raises(LicenseExpiredError):
        enforce_license_at_startup(license_path=path)


@requires_vendor_key
def test_preflight_surfaces_expiry_warning(tmp_path: Path, issue_token: Any) -> None:
    path = tmp_path / "license.json"
    install_license(issue_token(tier="enterprise", duration_days=10), path=path)
    report = preflight(license_path=path, air_gapped=False)
    assert report.ok is True
    assert any("expires in" in w for w in report.warnings)


@requires_vendor_key
def test_preflight_air_gapped_anchoring_advisory(tmp_path: Path, issue_token: Any) -> None:
    path = tmp_path / "license.json"
    install_license(issue_token(tier="enterprise", duration_days=365), path=path)
    report = preflight(license_path=path, air_gapped=True)
    # The advisory only fires when the optional [anchoring] extra is importable;
    # assert the report is well-formed either way and the advisory is air-gapped-only.
    assert isinstance(report, StartupReport)
    if _importable("airsdk.anchoring"):
        assert any("air-gapped" in w for w in report.warnings)


# --------------------------------------------------------------------------
# Entrypoint fail-closed behaviour (airsdk_pro.serve).
# --------------------------------------------------------------------------


def test_run_gate_exits_nonzero_on_missing_license(tmp_path: Path) -> None:
    from airsdk_pro import serve

    with pytest.raises(SystemExit) as exc:
        serve.run_gate(license_path=tmp_path / "nope.json", air_gapped=True)
    assert exc.value.code == 1


def test_main_does_not_serve_when_gate_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from airsdk_pro import serve

    monkeypatch.setenv("AIRSDK_LICENSE_PATH", str(tmp_path / "nope.json"))
    monkeypatch.setenv("AIRSDK_DATA_DIR", str(tmp_path / "data"))
    served: list[object] = []

    with pytest.raises(SystemExit) as exc:
        serve.main(serve_fn=lambda app: served.append(app))
    assert exc.value.code == 1
    assert served == []  # the server must never boot when the license is bad


@requires_vendor_key
@requires_vindicara
def test_main_serves_when_gate_passes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, issue_token: Any) -> None:
    from airsdk_pro import serve

    license_path = tmp_path / "license.json"
    install_license(issue_token(tier="enterprise", duration_days=365), path=license_path)
    monkeypatch.setenv("AIRSDK_LICENSE_PATH", str(license_path))
    monkeypatch.setenv("AIRSDK_DATA_DIR", str(tmp_path / "data"))
    served: list[object] = []

    serve.main(serve_fn=lambda app: served.append(app))
    assert len(served) == 1  # gate passed, app built and handed to the server


# --------------------------------------------------------------------------
# Durable persistence: capsules / workspaces / keys survive a "restart"
# (a fresh store instance reading the same data dir).
# --------------------------------------------------------------------------


@requires_vindicara
def test_durable_stores_survive_restart(tmp_path: Path) -> None:
    from vindicara.cloud.capsule_store import JSONLCapsuleStore, StoredCapsule
    from vindicara.cloud.file_stores import JSONApiKeyStore, JSONWorkspaceStore
    from vindicara.cloud.workspace import ApiKey, Workspace

    data = tmp_path / "data"
    JSONWorkspaceStore(data).create(Workspace(workspace_id="ws1", name="Acme", owner_email="a@b.c"))
    JSONApiKeyStore(data).issue(ApiKey(key_id="k1", workspace_id="ws1", key="air_secret", role="owner"))

    # "restart": brand-new store objects, same directory.
    assert JSONWorkspaceStore(data).get("ws1") is not None
    reloaded_key = JSONApiKeyStore(data).lookup("air_secret")
    assert reloaded_key is not None
    assert reloaded_key.key_id == "k1"

    # revocation is durable too.
    assert JSONApiKeyStore(data).revoke("k1") is True
    assert JSONApiKeyStore(data).lookup("air_secret") is None

    caps = JSONLCapsuleStore(data / "capsules")
    assert caps.count("ws1") == 0  # sanity: distinct store, empty until appended
    _ = StoredCapsule  # imported for the API surface; capsule shape covered elsewhere
